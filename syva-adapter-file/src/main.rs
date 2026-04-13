//! syva-file — file/ConfigMap policy adapter for syva-core.
//!
//! Reads TOML policy files from a directory, translates them to gRPC calls,
//! and watches containerd for container start/stop events to manage zone
//! membership via syva-core.

mod connect;
mod mapper;
mod policy;
mod reload;
mod translate;
mod types;
mod watcher;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::{
    AllowCommRequest, AttachContainerRequest, DetachContainerRequest,
    RegisterHostPathRequest, RegisterZoneRequest, RemoveZoneRequest,
};
use tonic::transport::Channel;

use crate::reload::{PolicyChange, PolicyDirWatcher, diff_policies};
use crate::translate::to_proto_policy;
use crate::types::ZonePolicy;
use crate::watcher::{WatcherEvent, ZoneAssignment};

#[derive(Parser)]
#[command(name = "syva-file", about = "File/ConfigMap policy adapter for syva-core")]
struct Cli {
    /// Path to the policy directory containing .toml zone policy files.
    #[arg(long, default_value = "./policies")]
    policy_dir: PathBuf,

    /// Unix socket path for connecting to syva-core.
    #[arg(long, default_value = "/run/syva/syva-core.sock")]
    socket_path: String,

    /// Containerd socket path.
    #[arg(long, default_value = "/run/containerd/containerd.sock")]
    containerd_sock: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Dry-run: load and validate policies without connecting to syva-core.
    Verify,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("syva_adapter_file=info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Verify) => run_verify(&cli.policy_dir),
        None => run_adapter(cli).await,
    }
}

// ---------------------------------------------------------------------------
// Verify subcommand
// ---------------------------------------------------------------------------

fn run_verify(policy_dir: &PathBuf) -> anyhow::Result<()> {
    let policies = policy::load_policies(policy_dir)?;

    if policies.is_empty() {
        println!("No policies found in {}", policy_dir.display());
        return Ok(());
    }

    println!("Loaded {} zone policies:", policies.len());

    let mut has_errors = false;

    for (name, pol) in &policies {
        println!("  - {name}");

        // Check allowed_zones symmetry.
        for peer in &pol.network.allowed_zones {
            match policies.get(peer) {
                None => {
                    println!("    WARN: allowed_zones references '{peer}' which has no policy file");
                    has_errors = true;
                }
                Some(peer_pol) => {
                    if !peer_pol.network.allowed_zones.contains(&name.to_string()) {
                        println!("    WARN: allowed_zones lists '{peer}' but '{peer}' does not list '{name}' — comm will NOT be established");
                        has_errors = true;
                    }
                }
            }
        }

        // Check host_paths exist.
        for path in &pol.filesystem.host_paths {
            if !std::path::Path::new(path).exists() {
                println!("    WARN: host_path '{path}' does not exist on this host");
            }
        }
    }

    if has_errors {
        println!("\nVerification completed with warnings.");
        std::process::exit(1);
    } else {
        println!("\nAll policies valid.");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Main adapter loop
// ---------------------------------------------------------------------------

async fn run_adapter(cli: Cli) -> anyhow::Result<()> {
    tracing::info!(
        policy_dir = %cli.policy_dir.display(),
        socket = %cli.socket_path,
        containerd = %cli.containerd_sock,
        "starting syva-file adapter"
    );

    // 1. Connect to syva-core with retry.
    let mut client = connect::connect_with_retry(&cli.socket_path, 10).await?;
    tracing::info!("connected to syva-core");

    // 2. Load all policies from disk.
    let mut current_policies = policy::load_policies(&cli.policy_dir)?;
    tracing::info!(zones = current_policies.len(), "loaded policies");

    // 3. Register zones with syva-core.
    register_all_zones(&mut client, &current_policies).await?;

    // 4. Enumerate existing containers and attach them.
    let zone_names: HashSet<String> = current_policies.keys().cloned().collect();
    let assignments = watcher::enumerate_cgroups(&zone_names)?;
    for assignment in &assignments {
        attach_container(&mut client, assignment).await;
    }
    tracing::info!(containers = assignments.len(), "enumerated existing containers");

    // 5. Set up zone names watch channel for the containerd watcher.
    let (zone_names_tx, zone_names_rx) = tokio::sync::watch::channel(Arc::new(zone_names));

    // 6. Start containerd event watcher.
    let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<WatcherEvent>(256);
    let containerd_sock = cli.containerd_sock.clone();
    tokio::spawn(async move {
        watcher::watch_containerd_events(containerd_sock, zone_names_rx, event_tx).await;
    });

    // 7. Start hot-reload watcher.
    let mut dir_watcher = PolicyDirWatcher::new(cli.policy_dir.clone());
    let mut reload_interval = tokio::time::interval(std::time::Duration::from_secs(5));
    reload_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    // 8. Set up SIGTERM handler.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    tracing::info!("adapter running — watching for events and policy changes");

    loop {
        tokio::select! {
            // Handle containerd events.
            Some(event) = event_rx.recv() => {
                match event {
                    WatcherEvent::Add(assignment) => {
                        tracing::info!(
                            container = assignment.container_id,
                            zone = assignment.zone_name,
                            cgroup_id = assignment.cgroup_id,
                            "attaching container"
                        );
                        attach_container(&mut client, &assignment).await;
                    }
                    WatcherEvent::Remove { container_id, .. } => {
                        tracing::info!(container = container_id, "detaching container");
                        detach_container(&mut client, &container_id).await;
                    }
                }
            }

            // Hot-reload tick.
            _ = reload_interval.tick() => {
                if dir_watcher.check_changed() {
                    if let Err(e) = handle_reload(
                        &mut client,
                        dir_watcher.dir(),
                        &mut current_policies,
                        &zone_names_tx,
                    ).await {
                        tracing::error!(%e, "policy reload failed");
                    }
                }
            }

            // Graceful shutdown.
            _ = sigterm.recv() => {
                tracing::info!("received SIGTERM — shutting down");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("received SIGINT — shutting down");
                break;
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// gRPC helpers
// ---------------------------------------------------------------------------

/// Register all zones and set up comms + host paths.
async fn register_all_zones(
    client: &mut SyvaCoreClient<Channel>,
    policies: &HashMap<String, ZonePolicy>,
) -> anyhow::Result<()> {
    // Phase 1: Register each zone.
    for (name, pol) in policies {
        let resp = client
            .register_zone(RegisterZoneRequest {
                zone_name: name.clone(),
                policy: Some(to_proto_policy(pol)),
            })
            .await?;
        tracing::info!(zone = name, zone_id = resp.into_inner().zone_id, "registered zone");
    }

    // Phase 2: Register host paths.
    for (name, pol) in policies {
        for path in &pol.filesystem.host_paths {
            match client
                .register_host_path(RegisterHostPathRequest {
                    zone_name: name.clone(),
                    path: path.clone(),
                    recursive: true,
                })
                .await
            {
                Ok(resp) => {
                    let inodes = resp.into_inner().inodes_registered;
                    if inodes > 0 {
                        tracing::info!(zone = name, path, inodes, "registered host path");
                    }
                }
                Err(e) => {
                    tracing::warn!(zone = name, path, %e, "failed to register host path");
                }
            }
        }
    }

    // Phase 3: Set up bilateral comms.
    let mut established: HashSet<(String, String)> = HashSet::new();
    for (name, pol) in policies {
        for peer in &pol.network.allowed_zones {
            // Check bilateral: peer must also list this zone.
            let bilateral = policies
                .get(peer)
                .map(|p| p.network.allowed_zones.contains(&name.to_string()))
                .unwrap_or(false);

            if !bilateral {
                tracing::warn!(
                    zone = name,
                    peer = peer,
                    "one-sided allowed_zones — '{name}' lists '{peer}' but not vice versa; comm NOT established"
                );
                continue;
            }

            // Avoid duplicate calls (A,B) and (B,A).
            let pair = if name < peer {
                (name.clone(), peer.clone())
            } else {
                (peer.clone(), name.clone())
            };
            if established.contains(&pair) {
                continue;
            }

            match client
                .allow_comm(AllowCommRequest {
                    zone_a: name.clone(),
                    zone_b: peer.clone(),
                })
                .await
            {
                Ok(_) => {
                    tracing::info!(zone_a = name, zone_b = peer, "established bilateral comm");
                    established.insert(pair);
                }
                Err(e) => {
                    tracing::warn!(zone_a = name, zone_b = peer, %e, "failed to establish comm");
                }
            }
        }
    }

    Ok(())
}

/// Attach a single container to its zone via gRPC.
async fn attach_container(
    client: &mut SyvaCoreClient<Channel>,
    assignment: &ZoneAssignment,
) {
    match client
        .attach_container(AttachContainerRequest {
            container_id: assignment.container_id.clone(),
            zone_name: assignment.zone_name.clone(),
            cgroup_id: assignment.cgroup_id,
        })
        .await
    {
        Ok(_) => {
            tracing::debug!(
                container = assignment.container_id,
                zone = assignment.zone_name,
                "container attached"
            );
        }
        Err(e) => {
            tracing::error!(
                container = assignment.container_id,
                zone = assignment.zone_name,
                %e,
                "failed to attach container"
            );
        }
    }
}

/// Detach a container via gRPC.
async fn detach_container(
    client: &mut SyvaCoreClient<Channel>,
    container_id: &str,
) {
    match client
        .detach_container(DetachContainerRequest {
            container_id: container_id.to_string(),
        })
        .await
    {
        Ok(_) => {
            tracing::debug!(container = container_id, "container detached");
        }
        Err(e) => {
            tracing::error!(container = container_id, %e, "failed to detach container");
        }
    }
}

/// Handle a policy reload: diff, apply changes via gRPC, update zone names channel.
async fn handle_reload(
    client: &mut SyvaCoreClient<Channel>,
    policy_dir: &std::path::Path,
    current_policies: &mut HashMap<String, ZonePolicy>,
    zone_names_tx: &tokio::sync::watch::Sender<Arc<HashSet<String>>>,
) -> anyhow::Result<()> {
    let new_policies = policy::load_policies(policy_dir)?;

    // Guard: empty set during ConfigMap rotation.
    if new_policies.is_empty() && !current_policies.is_empty() {
        tracing::debug!("policy reload returned empty set — skipping (possible ConfigMap rotation)");
        return Ok(());
    }

    let changes = diff_policies(current_policies, &new_policies);
    if changes.is_empty() {
        return Ok(());
    }

    tracing::info!(changes = changes.len(), "policy changes detected — applying");

    let mut applied = 0;

    // Apply additions first.
    for change in &changes {
        if let PolicyChange::Added(name, pol) = change {
            match apply_zone_addition(client, name, pol, &new_policies).await {
                Ok(()) => {
                    current_policies.insert(name.clone(), pol.clone());
                    applied += 1;
                    tracing::info!(zone = name.as_str(), "reload: zone added");
                }
                Err(e) => {
                    tracing::error!(zone = name.as_str(), %e, "reload: failed to add zone");
                }
            }
        }
    }

    // Apply modifications.
    for change in &changes {
        if let PolicyChange::Modified(name, new_pol) = change {
            match apply_zone_modification(client, name, new_pol, &new_policies).await {
                Ok(()) => {
                    current_policies.insert(name.clone(), new_pol.clone());
                    applied += 1;
                    tracing::info!(zone = name.as_str(), "reload: zone policy updated");
                }
                Err(e) => {
                    tracing::error!(zone = name.as_str(), %e, "reload: failed to modify zone");
                }
            }
        }
    }

    // Apply removals last.
    for change in &changes {
        if let PolicyChange::Removed(name) = change {
            match client
                .remove_zone(RemoveZoneRequest {
                    zone_name: name.clone(),
                    drain: true,
                })
                .await
            {
                Ok(resp) => {
                    let resp = resp.into_inner();
                    tracing::info!(zone = name.as_str(), msg = resp.message, "reload: zone removed");
                    current_policies.remove(name);
                    applied += 1;
                }
                Err(e) => {
                    tracing::error!(zone = name.as_str(), %e, "reload: failed to remove zone");
                }
            }
        }
    }

    // Update zone names channel for the watcher.
    if applied > 0 {
        let zone_names: HashSet<String> = current_policies.keys().cloned().collect();
        let _ = zone_names_tx.send(Arc::new(zone_names));
    }

    tracing::info!(applied, "reload complete");
    Ok(())
}

/// Register a new zone and set up its host paths and comms.
async fn apply_zone_addition(
    client: &mut SyvaCoreClient<Channel>,
    zone_name: &str,
    policy: &ZonePolicy,
    all_policies: &HashMap<String, ZonePolicy>,
) -> anyhow::Result<()> {
    // Register the zone.
    client
        .register_zone(RegisterZoneRequest {
            zone_name: zone_name.to_string(),
            policy: Some(to_proto_policy(policy)),
        })
        .await?;

    // Register host paths.
    for path in &policy.filesystem.host_paths {
        if let Err(e) = client
            .register_host_path(RegisterHostPathRequest {
                zone_name: zone_name.to_string(),
                path: path.clone(),
                recursive: true,
            })
            .await
        {
            tracing::warn!(zone = zone_name, path, %e, "failed to register host path during addition");
        }
    }

    // Set up bilateral comms.
    for peer in &policy.network.allowed_zones {
        let bilateral = all_policies
            .get(peer)
            .map(|p| p.network.allowed_zones.contains(&zone_name.to_string()))
            .unwrap_or(false);
        if bilateral {
            let _ = client
                .allow_comm(AllowCommRequest {
                    zone_a: zone_name.to_string(),
                    zone_b: peer.clone(),
                })
                .await;
        }
    }

    Ok(())
}

/// Update an existing zone's policy, host paths, and comms.
async fn apply_zone_modification(
    client: &mut SyvaCoreClient<Channel>,
    zone_name: &str,
    new_policy: &ZonePolicy,
    all_policies: &HashMap<String, ZonePolicy>,
) -> anyhow::Result<()> {
    // Re-register zone with updated policy (idempotent).
    client
        .register_zone(RegisterZoneRequest {
            zone_name: zone_name.to_string(),
            policy: Some(to_proto_policy(new_policy)),
        })
        .await?;

    // Re-register host paths (syva-core handles dedup).
    for path in &new_policy.filesystem.host_paths {
        if let Err(e) = client
            .register_host_path(RegisterHostPathRequest {
                zone_name: zone_name.to_string(),
                path: path.clone(),
                recursive: true,
            })
            .await
        {
            tracing::warn!(zone = zone_name, path, %e, "failed to register host path during modification");
        }
    }

    // Rebuild bilateral comms.
    for peer in &new_policy.network.allowed_zones {
        let bilateral = all_policies
            .get(peer)
            .map(|p| p.network.allowed_zones.contains(&zone_name.to_string()))
            .unwrap_or(false);
        if bilateral {
            let _ = client
                .allow_comm(AllowCommRequest {
                    zone_a: zone_name.to_string(),
                    zone_b: peer.clone(),
                })
                .await;
        }
    }

    Ok(())
}
