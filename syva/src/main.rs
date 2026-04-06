//! syva — deep eBPF enforcement for container isolation.
//!
//! Drops kernel-level zone enforcement onto existing containerd/Docker clusters.
//! No runtime replacement needed. Watches container events, maps workloads to
//! zones by label, and populates BPF maps.
//!
//! Usage:
//!   syva --policy-dir /etc/syva/policies/
//!   syva status
//!   syva events --follow

mod ebpf;
mod events;
mod mapper;
mod policy;
pub mod types;
mod watcher;
mod zone;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "syva", about = "Deep eBPF enforcement for container isolation")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Directory containing zone policy TOML files.
    #[arg(long, default_value = "/etc/syva/policies")]
    policy_dir: PathBuf,

    /// Path to the eBPF object file.
    #[arg(long)]
    ebpf_obj: Option<PathBuf>,

    /// Path to the containerd socket for live event watching.
    #[arg(long, default_value = "/run/containerd/containerd.sock")]
    containerd_sock: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Show current enforcement status.
    Status,
    /// Stream enforcement events.
    Events {
        /// Follow events in real time.
        #[arg(long, short)]
        follow: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("syva=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Status) => cmd_status().await,
        Some(Commands::Events { follow }) => cmd_events(follow).await,
        None => cmd_run(cli.policy_dir, cli.ebpf_obj, cli.containerd_sock).await,
    }
}

/// Main enforcement loop.
async fn cmd_run(
    policy_dir: PathBuf,
    ebpf_obj: Option<PathBuf>,
    containerd_sock: String,
) -> anyhow::Result<()> {
    tracing::info!("syva starting");

    // Load eBPF programs.
    let mut mgr = ebpf::EnforceEbpf::load(ebpf_obj.as_deref())?;
    tracing::info!("eBPF programs loaded and attached");

    // Validate kernel struct offsets via the eBPF self-test.
    mgr.verify_self_test().await?;

    // Load zone policies from disk.
    let policies = policy::load_policies(&policy_dir)?;
    tracing::info!(count = policies.len(), dir = %policy_dir.display(), "loaded zone policies");

    // Start the event reader (ring buffer → logs).
    let cancel = tokio_util::sync::CancellationToken::new();
    if let Some(ring_buf) = mgr.take_event_ring_buf() {
        events::spawn_event_reader(ring_buf, cancel.clone());
    }

    // --- Zone registry: single source of truth for zone lifecycle ---
    let mut registry = zone::ZoneRegistry::new();

    // Register all zones from policy files. Every zone gets an ID and its
    // BPF maps configured, regardless of whether it has running containers.
    for (zone_name, policy) in &policies {
        let zone_id = registry.register_zone(zone_name)?;
        mgr.set_zone_policy(zone_id, policy)?;
        tracing::info!(zone = zone_name.as_str(), zone_id, "registered zone from policy");
    }

    // Populate ZONE_ALLOWED_COMMS — strict bilateral symmetry.
    for (zone_name, policy) in &policies {
        let src_id = registry.zone_id(zone_name).unwrap();
        for allowed_name in &policy.network.allowed_zones {
            if let Some(dst_id) = registry.zone_id(allowed_name) {
                let bilateral = policies
                    .get(allowed_name)
                    .map(|p| p.network.allowed_zones.contains(zone_name))
                    .unwrap_or(false);
                if bilateral {
                    if let Err(e) = mgr.set_zone_allowed_comms(src_id, dst_id) {
                        tracing::warn!(src = zone_name.as_str(), dst = allowed_name.as_str(), %e, "failed to set allowed comms");
                    }
                } else {
                    tracing::warn!(
                        src = zone_name.as_str(), dst = allowed_name.as_str(),
                        "one-sided allowed_zones — both zones must list each other"
                    );
                }
            } else {
                tracing::warn!(
                    zone = zone_name.as_str(), peer = allowed_name.as_str(),
                    "allowed_zones references unknown zone"
                );
            }
        }
    }

    // Populate INODE_ZONE_MAP from host_paths (bind-mounted host paths only).
    // Container-internal paths (writable_paths) have different overlayfs inodes
    // and cannot be correctly matched by the kernel LSM hooks.
    for (zone_name, policy) in &policies {
        if policy.filesystem.host_paths.is_empty() {
            continue;
        }
        let zone_id = registry.zone_id(zone_name).unwrap();
        match mgr.populate_inode_zone_map(zone_id, &policy.filesystem.host_paths) {
            Ok(n) if n > 0 => tracing::info!(zone = zone_name.as_str(), inodes = n, "inode map populated from host_paths"),
            Ok(_) => {}
            Err(e) => tracing::warn!(zone = zone_name.as_str(), %e, "inode map population failed"),
        }
    }

    // Enumerate existing containers and assign to pre-allocated zones.
    let assignments = watcher::enumerate_cgroups(&policies)?;
    for assignment in &assignments {
        let zone_id = registry.add_container(
            &assignment.container_id,
            &assignment.zone_name,
            assignment.cgroup_id,
        )?;
        mgr.add_zone_member(assignment.cgroup_id, zone_id, types::ZoneType::NonGlobal)?;
        tracing::info!(
            zone = assignment.zone_name,
            cgroup_id = assignment.cgroup_id,
            zone_id,
            "enforcing container"
        );
    }

    tracing::info!(
        zones = registry.zone_count(),
        containers = registry.container_count(),
        "startup complete"
    );

    // Start live containerd event watcher.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<watcher::WatcherEvent>(100);
    let policies_arc = Arc::new(policies.clone());

    tokio::spawn(watcher::watch_containerd_events(
        containerd_sock,
        policies_arc.clone(),
        tx,
    ));

    tracing::info!("syva running — watching for container events");

    // Process live events until shutdown.
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
            event = rx.recv() => {
                match event {
                    Some(watcher::WatcherEvent::Add(assignment)) => {
                        // Registry handles zone lookup and refcounting.
                        let zone_id = match registry.add_container(
                            &assignment.container_id,
                            &assignment.zone_name,
                            assignment.cgroup_id,
                        ) {
                            Ok(id) => id,
                            Err(e) => {
                                tracing::warn!(%e, zone = assignment.zone_name, "rejected container");
                                continue;
                            }
                        };
                        if let Err(e) = mgr.add_zone_member(
                            assignment.cgroup_id,
                            zone_id,
                            types::ZoneType::NonGlobal,
                        ) {
                            tracing::error!(%e, zone = assignment.zone_name, "BPF add_zone_member failed");
                            // Rollback registry state.
                            registry.remove_container(&assignment.container_id, None);
                            continue;
                        }
                        tracing::info!(
                            container = assignment.container_id,
                            zone = assignment.zone_name,
                            zone_id,
                            "live: container enforced"
                        );
                    }
                    Some(watcher::WatcherEvent::Remove { container_id, cgroup_id }) => {
                        // Registry handles lookup, refcount, and state transition.
                        if let Some((zone_id, resolved_cgroup, went_to_pending)) =
                            registry.remove_container(&container_id, cgroup_id)
                        {
                            let _ = mgr.remove_zone_member(resolved_cgroup);
                            if went_to_pending {
                                tracing::info!(zone_id, "zone has no active containers (Pending)");
                            }
                        }
                        tracing::info!(container = container_id, "live: container removed");
                    }
                    None => {
                        tracing::warn!("event channel closed");
                        break;
                    }
                }
            }
        }
    }

    cancel.cancel();
    drop(mgr); // Drop impl cleans up BPF pins
    tracing::info!("syva stopped");
    Ok(())
}


async fn cmd_status() -> anyhow::Result<()> {
    use aya::maps::PerCpuArray;
    use syva_ebpf_common::EnforcementCounters;

    let pin_path = std::path::Path::new("/sys/fs/bpf/syva");
    if !pin_path.exists() {
        println!("syva: NOT ACTIVE (no pinned BPF maps)");
        return Ok(());
    }

    println!("syva: ACTIVE");
    println!("  pin path: /sys/fs/bpf/syva");

    // Read enforcement counters from pinned maps.
    let counter_path = pin_path.join("ENFORCEMENT_COUNTERS");
    if counter_path.exists() {
        match PerCpuArray::<_, EnforcementCounters>::try_from(
            aya::maps::MapData::from_pin(&counter_path)
                .map_err(|e| anyhow::anyhow!("failed to open pinned counters: {e}"))?,
        ) {
            Ok(map) => {
                let hook_names = ["file_open", "bprm_check", "ptrace_check", "task_kill", "cgroup_attach"];
                println!("  hooks:");
                for (idx, &name) in hook_names.iter().enumerate() {
                    if let Ok(per_cpu) = map.get(&(idx as u32), 0) {
                        let mut total = EnforcementCounters { allow: 0, deny: 0, error: 0 };
                        for cpu_val in per_cpu.iter() {
                            total.allow += cpu_val.allow;
                            total.deny += cpu_val.deny;
                            total.error += cpu_val.error;
                        }
                        println!(
                            "    {:<16} allow={:<8} deny={:<8} error={}",
                            name, total.allow, total.deny, total.error
                        );
                    }
                }
            }
            Err(e) => {
                println!("  counters: unavailable ({e})");
            }
        }
    }

    Ok(())
}

async fn cmd_events(follow: bool) -> anyhow::Result<()> {
    use aya::maps::RingBuf;
    use syva_ebpf_common::EnforcementEvent;

    if !follow {
        println!("use --follow to stream events in real time");
        return Ok(());
    }

    let pin_path = std::path::Path::new("/sys/fs/bpf/syva/ENFORCEMENT_EVENTS");
    if !pin_path.exists() {
        anyhow::bail!("syva is not running (no pinned ENFORCEMENT_EVENTS map)");
    }

    let map_data = aya::maps::MapData::from_pin(pin_path)
        .map_err(|e| anyhow::anyhow!("failed to open pinned ring buffer: {e}"))?;
    let mut ring_buf = RingBuf::try_from(map_data)?;

    let hook_names = ["file_open", "bprm_check", "ptrace_access_check", "task_kill", "cgroup_attach_task"];

    eprintln!("streaming enforcement events (Ctrl+C to stop)...");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                const MAX_EVENTS_PER_TICK: usize = 1000;
                let events: Vec<EnforcementEvent> = tokio::task::block_in_place(|| {
                    let mut out = Vec::new();
                    while let Some(item) = ring_buf.next() {
                        if item.len() < std::mem::size_of::<EnforcementEvent>() {
                            continue;
                        }
                        let event: EnforcementEvent = unsafe {
                            std::ptr::read_unaligned(item.as_ptr() as *const EnforcementEvent)
                        };
                        out.push(event);
                        if out.len() >= MAX_EVENTS_PER_TICK {
                            break;
                        }
                    }
                    out
                });
                for event in &events {
                    let hook = hook_names.get(event.hook as usize).copied().unwrap_or("unknown");
                    let decision = match event.decision {
                        syva_ebpf_common::DECISION_ALLOW => "ALLOW",
                        syva_ebpf_common::DECISION_DENY => "DENY",
                        _ => "UNKNOWN",
                    };
                    println!(
                        "{} hook={} pid={} caller_zone={} target_zone={} context={}",
                        decision, hook, event.pid, event.caller_zone, event.target_zone, event.context
                    );
                }
            }
        }
    }

    Ok(())
}
