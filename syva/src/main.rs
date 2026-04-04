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

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

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

    // Assign zone IDs from policy files — all zones get IDs regardless of
    // whether they have running containers. This ensures ZONE_ALLOWED_COMMS
    // and INODE_ZONE_MAP are populated for all zones at startup.
    let zone_counter = AtomicU32::new(1);
    let mut zone_id_for_name: HashMap<String, u32> = HashMap::new();
    let mut zone_policies_written: HashSet<u32> = HashSet::new();
    let mut zone_refcount: HashMap<u32, usize> = HashMap::new();
    let mut container_zone: HashMap<String, u32> = HashMap::new();
    let mut cgroup_id_map: HashMap<String, u64> = HashMap::new();

    for (zone_name, policy) in &policies {
        let zone_id = zone_counter.fetch_add(1, Ordering::SeqCst);
        zone_id_for_name.insert(zone_name.clone(), zone_id);
        mgr.set_zone_policy(zone_id, policy)?;
        zone_policies_written.insert(zone_id);
        tracing::info!(zone = zone_name.as_str(), zone_id, "assigned zone ID from policy");
    }

    // Populate ZONE_ALLOWED_COMMS from policy network.allowed_zones.
    // Strict bilateral symmetry: both zones must list each other.
    for (zone_name, policy) in &policies {
        let src_id = zone_id_for_name[zone_name.as_str()];
        for allowed_name in &policy.network.allowed_zones {
            if let Some(&dst_id) = zone_id_for_name.get(allowed_name.as_str()) {
                let other_allows_back = policies
                    .get(allowed_name)
                    .map(|p| p.network.allowed_zones.contains(zone_name))
                    .unwrap_or(false);
                if other_allows_back {
                    if let Err(e) = mgr.set_zone_allowed_comms(src_id, dst_id) {
                        tracing::warn!(src = zone_name.as_str(), dst = allowed_name.as_str(), %e, "failed to set allowed comms");
                    } else {
                        tracing::info!(src = zone_name.as_str(), dst = allowed_name.as_str(), "allowed cross-zone communication");
                    }
                } else {
                    tracing::warn!(
                        src = zone_name.as_str(), dst = allowed_name.as_str(),
                        "one-sided allowed_zones declaration — both zones must list each other. Skipping."
                    );
                }
            } else {
                tracing::warn!(
                    zone = zone_name.as_str(), peer = allowed_name.as_str(),
                    "allowed_zones references unknown zone — no policy file found"
                );
            }
        }
    }

    // Populate INODE_ZONE_MAP from zone filesystem policies.
    for (zone_name, policy) in &policies {
        let zone_id = zone_id_for_name[zone_name.as_str()];
        let paths = &policy.filesystem.writable_paths;
        match mgr.populate_inode_zone_map(zone_id, paths) {
            Ok(count) if count > 0 => {
                tracing::info!(zone = zone_name.as_str(), inodes = count, "populated inode zone map");
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(zone = zone_name.as_str(), %e, "failed to populate inode zone map");
            }
        }
    }

    // Enumerate existing containers and assign to pre-allocated zones.
    let assignments = watcher::enumerate_cgroups(&policies)?;

    for assignment in &assignments {
        let zone_id = zone_id_for_name[&assignment.zone_name];
        mgr.add_zone_member(assignment.cgroup_id, zone_id, types::ZoneType::NonGlobal)?;
        *zone_refcount.entry(zone_id).or_insert(0) += 1;
        cgroup_id_map.insert(assignment.container_id.clone(), assignment.cgroup_id);
        container_zone.insert(assignment.container_id.clone(), zone_id);

        tracing::info!(
            zone = assignment.zone_name,
            cgroup_id = assignment.cgroup_id,
            zone_id,
            "enforcing container"
        );
    }

    print_status_summary(&policies, &assignments, &mgr);

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
                        // Zone IDs are pre-allocated from policy files at startup.
                        // Unknown zones (no policy file) are rejected by the watcher.
                        let zone_id = match zone_id_for_name.get(&assignment.zone_name) {
                            Some(&id) => id,
                            None => {
                                tracing::warn!(zone = assignment.zone_name, "no zone ID for zone — no policy loaded");
                                continue;
                            }
                        };
                        if let Err(e) = mgr.add_zone_member(
                            assignment.cgroup_id,
                            zone_id,
                            types::ZoneType::NonGlobal,
                        ) {
                            tracing::error!(%e, zone = assignment.zone_name, "failed to add zone member");
                            continue;
                        }
                        *zone_refcount.entry(zone_id).or_insert(0) += 1;
                        cgroup_id_map.insert(assignment.container_id.clone(), assignment.cgroup_id);
                        container_zone.insert(assignment.container_id.clone(), zone_id);
                        tracing::info!(
                            container = assignment.container_id,
                            zone = assignment.zone_name,
                            zone_id,
                            "live: container enforced"
                        );
                    }
                    Some(watcher::WatcherEvent::Remove { container_id, cgroup_id }) => {
                        let resolved_cgroup_id = if cgroup_id != 0 {
                            cgroup_id
                        } else {
                            cgroup_id_map.remove(&container_id).unwrap_or(0)
                        };
                        if resolved_cgroup_id != 0 {
                            let _ = mgr.remove_zone_member(resolved_cgroup_id);
                        }
                        // Decrement zone refcount; clean up zone maps when last container leaves.
                        if let Some(zone_id) = container_zone.remove(&container_id) {
                            if let Some(count) = zone_refcount.get_mut(&zone_id) {
                                *count = count.saturating_sub(1);
                                if *count == 0 {
                                    zone_refcount.remove(&zone_id);
                                    zone_policies_written.remove(&zone_id);
                                    let _ = mgr.remove_zone_policy(zone_id);
                                    let _ = mgr.remove_zone_comms(zone_id);
                                    let _ = mgr.remove_zone_inodes(zone_id);
                                    // Remove zone_id_for_name entry.
                                    zone_id_for_name.retain(|_, &mut v| v != zone_id);
                                    tracing::info!(zone_id, "zone emptied — cleaned up BPF maps");
                                }
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

fn print_status_summary(
    policies: &std::collections::HashMap<String, types::ZonePolicy>,
    assignments: &[watcher::ZoneAssignment],
    mgr: &ebpf::EnforceEbpf,
) {
    let enforced = assignments.len();
    let zone_names: std::collections::HashSet<&str> = assignments
        .iter()
        .map(|a| a.zone_name.as_str())
        .collect();

    tracing::info!(
        programs = "5/5",
        zones = zone_names.len(),
        containers_enforced = enforced,
        "enforcement active"
    );

    for zone in &zone_names {
        let count = assignments.iter().filter(|a| a.zone_name == *zone).count();
        let has_policy = policies.contains_key(*zone);
        tracing::info!(
            zone = zone,
            containers = count,
            policy = has_policy,
            "zone summary"
        );
    }

    if let Ok(counters) = mgr.read_counters() {
        for (name, c) in &counters {
            if c.allow > 0 || c.deny > 0 || c.error > 0 {
                tracing::info!(
                    hook = name.as_str(),
                    allow = c.allow,
                    deny = c.deny,
                    error = c.error,
                    "enforcement counters"
                );
            }
        }
    }
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
                while let Some(item) = ring_buf.next() {
                    if item.len() < std::mem::size_of::<EnforcementEvent>() {
                        continue;
                    }
                    let event: EnforcementEvent = unsafe {
                        std::ptr::read_unaligned(item.as_ptr() as *const EnforcementEvent)
                    };
                    let hook = hook_names.get(event.hook as usize).copied().unwrap_or("unknown");
                    println!(
                        "DENY hook={} pid={} caller_zone={} target_zone={} context={}",
                        hook, event.pid, event.caller_zone, event.target_zone, event.context
                    );
                }
            }
        }
    }

    Ok(())
}
