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

    // Load eBPF programs (but do NOT attach — no enforcement yet).
    let mut mgr = ebpf::EnforceEbpf::load(ebpf_obj.as_deref())?;

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
        let src_id = registry.zone_id(zone_name)
            .ok_or_else(|| anyhow::anyhow!("zone '{zone_name}' not in registry after registration"))?;
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
        let zone_id = registry.zone_id(zone_name)
            .ok_or_else(|| anyhow::anyhow!("zone '{zone_name}' not in registry for inode map"))?;
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

    // All zone membership is populated. Now attach eBPF hooks — this
    // eliminates the startup race window (C2). Hooks become active only
    // after ZONE_MEMBERSHIP, ZONE_POLICY, and INODE_ZONE_MAP are filled.
    mgr.attach_programs()?;

    // Validate kernel struct offsets via the eBPF self-test.
    // Must run after attach — the self-test fires on file_open hook.
    mgr.verify_self_test().await?;

    // H8: Drop unnecessary capabilities. After BPF load and map population,
    // we only need open file descriptors (already held by the Bpf struct).
    // CAP_SYS_ADMIN is no longer needed — BPF map operations use existing FDs.
    drop_unnecessary_capabilities();

    tracing::info!(
        zones = registry.zone_count(),
        containers = registry.container_count(),
        "startup complete — enforcement active"
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

    // Periodic error monitoring: check enforcement counters for kernel read errors.
    let mut error_check_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    error_check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_errors: Vec<u64> = Vec::new();

    // Process live events until shutdown.
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
            _ = error_check_interval.tick() => {
                match mgr.read_counters() {
                    Ok(counters) => {
                        // Grow last_errors to match counter count on first read.
                        if last_errors.len() < counters.len() {
                            last_errors.resize(counters.len(), 0);
                        }
                        for (idx, (_, totals)) in counters.iter().enumerate() {
                            if totals.error > last_errors[idx] {
                                let new_errors = totals.error - last_errors[idx];
                                let hook = events::HOOK_NAMES.get(idx).unwrap_or(&"unknown");
                                tracing::warn!(
                                    hook,
                                    new_errors,
                                    total_errors = totals.error,
                                    "enforcement errors detected — kernel struct reads \
                                     failing (fail-open). Run `syva status` to inspect."
                                );
                            }
                            last_errors[idx] = totals.error;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(%e, "failed to read enforcement counters");
                    }
                }
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
                            if let Err(e) = mgr.remove_zone_member(resolved_cgroup) {
                                tracing::warn!(cgroup_id = resolved_cgroup, %e, "failed to remove zone member from BPF map");
                            }
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
println!("  hooks:");
                let mut total_errors: u64 = 0;
                let mut total_lost: u64 = 0;
                let mut had_read_error = false;
                for (idx, hook) in events::HOOK_NAMES.iter().enumerate() {
                    match map.get(&(idx as u32), 0) {
                        Ok(per_cpu) => {
                            let mut total = EnforcementCounters { allow: 0, deny: 0, error: 0, lost: 0 };
                            for cpu_val in per_cpu.iter() {
                                total.allow += cpu_val.allow;
                                total.deny += cpu_val.deny;
                                total.error += cpu_val.error;
                                total.lost += cpu_val.lost;
                            }
                            total_errors += total.error;
                            total_lost += total.lost;
                            let flag = if total.error > 0 || total.lost > 0 { " ⚠" } else { "" };
                            println!(
                                "    {:<16} allow={:<8} deny={:<8} error={:<6} lost={}{}",
                                hook, total.allow, total.deny, total.error, total.lost, flag
                            );
                        }
                        Err(_) => { had_read_error = true; }
                    }
                }

                if had_read_error {
                    println!();
                    println!("  counters: some reads failed");
                } else if total_errors > 0 {
                    println!();
                    println!("  WARNING: {} total enforcement errors detected.", total_errors);
                    println!("  Errors cause fail-open behavior — operations are ALLOWED");
                    println!("  when kernel struct reads fail. This may indicate wrong");
                    println!("  kernel struct offsets. Install pahole and restart syva.");
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

/// Drop capabilities that are no longer needed after BPF programs are loaded
/// and maps are populated. BPF map operations use already-open file descriptors.
fn drop_unnecessary_capabilities() {
    // Drop CAP_SYS_ADMIN from the bounding set. BPF map operations use
    // already-open FDs — the kernel checks FD permissions, not process caps.
    const CAPS_TO_DROP: &[(libc::c_int, &str)] = &[
        (21, "CAP_SYS_ADMIN"),
    ];

    for &(cap, name) in CAPS_TO_DROP {
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if ret == 0 {
            tracing::info!(capability = name, "dropped capability");
        } else {
            tracing::debug!(capability = name, "failed to drop capability (may not be in bounding set)");
        }
    }
}
