//! syva-core — eBPF enforcement engine.
//!
//! The core engine manages BPF programs and maps and consumes desired
//! zone state from syva-cp.
//!
//! Usage:
//!   syva-core                          # Start the enforcement engine
//!   syva-core status                   # Show enforcement counters
//!   syva-core events --follow          # Stream deny events

mod cp_reconcile;
mod btf;
mod ebpf;
mod events;
mod health;
mod ingest;
pub mod types;
mod zone;

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use syva_cp_client::CpClientConfig;
use tokio::sync::{Mutex, RwLock};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "syva-core", about = "eBPF enforcement engine")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to the eBPF object file.
    #[arg(long)]
    ebpf_obj: Option<PathBuf>,

    /// Port for the health/metrics HTTP server.
    #[arg(long, default_value = "9091")]
    health_port: u16,

    /// syva-cp endpoint. Required.
    #[arg(long, env = "SYVA_CP_ENDPOINT")]
    cp_endpoint: String,

    /// Hostname to report to syva-cp. Defaults to the system hostname.
    #[arg(long, env = "SYVA_NODE_NAME")]
    node_name: Option<String>,

    /// Path to the stable node fingerprint file (for example /etc/machine-id).
    #[arg(
        long,
        env = "SYVA_NODE_FINGERPRINT_PATH",
        default_value = "/etc/machine-id"
    )]
    fingerprint_path: PathBuf,

    /// Optional cluster identifier to report at node registration time.
    #[arg(long, env = "SYVA_CLUSTER_ID")]
    cluster_id: Option<String>,

    /// Node labels to send at registration. Format: key=value,key=value
    #[arg(long, env = "SYVA_NODE_LABELS", value_delimiter = ',')]
    node_labels: Vec<String>,

    /// Path where the registered node ID is persisted across restarts.
    #[arg(
        long,
        env = "SYVA_NODE_ID_PATH",
        default_value = "/var/lib/syva/node-id"
    )]
    node_id_path: PathBuf,

    /// Heartbeat interval in seconds for CP mode.
    #[arg(long, env = "SYVA_HEARTBEAT_SECS", default_value = "15")]
    heartbeat_secs: u64,
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
        /// Output format: text or json (ndjson).
        #[arg(long, default_value = "text")]
        format: OutputFormat,
    },
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("syva_core=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Status) => cmd_status().await,
        Some(Commands::Events { follow, format }) => cmd_events(follow, format).await,
        None => cmd_run(cli).await,
    }
}

/// Main enforcement engine loop.
async fn cmd_run(config: Cli) -> anyhow::Result<()> {
    tracing::info!("syva-core starting");

    // Health state — shared with the HTTP server. Starts as unhealthy
    // (not attached, zero zones) and transitions as startup progresses.
    let health_state = health::SharedHealth::new(RwLock::new(
        health::HealthState::new(),
    ));
    health::spawn_health_server(config.health_port, health_state.clone()).await?;

    // Load eBPF programs (but do NOT attach — no enforcement yet).
    let mut mgr = ebpf::EnforceEbpf::load(config.ebpf_obj.as_deref())?;

    // Do not take the ENFORCEMENT_EVENTS ring buffer here — it is single-consumer
    // and the gRPC WatchEvents RPC needs to acquire it. Event logging for the core
    // binary uses the status subcommand or adapter-side streaming instead.
    let cancel = tokio_util::sync::CancellationToken::new();

    // Attach eBPF hooks — enforcement becomes active.
    mgr.attach_programs()?;

    // Validate kernel struct offsets via self-tests.
    mgr.verify_self_test().await?;
    mgr.verify_inode_self_test().await?;
    mgr.verify_unix_self_test().await?;

    // Health: BPF attached and self-tests passed — mark healthy.
    health_state.write().await.attached = true;

    // Drop unnecessary capabilities. After BPF load and map population,
    // we only need open file descriptors (already held by the Bpf struct).
    drop_unnecessary_capabilities();

    // Create zone registry.
    let registry = Arc::new(RwLock::new(zone::ZoneRegistry::new()));
    let ebpf = Arc::new(Mutex::new(mgr));

    tracing::info!("startup complete — enforcement active");

    // Shutdown on SIGINT (ctrl-c) or SIGTERM (Kubernetes pod termination).
    let mut sigterm = tokio::signal::unix::signal(
        tokio::signal::unix::SignalKind::terminate(),
    ).expect("failed to register SIGTERM handler");

    // Periodic error monitoring task.
    let monitor_ebpf = ebpf.clone();
    let monitor_health = health_state.clone();
    let monitor_cancel = cancel.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_errors: Vec<u64> = Vec::new();

        loop {
            tokio::select! {
                _ = monitor_cancel.cancelled() => return,
                _ = interval.tick() => {
                    let ebpf = monitor_ebpf.lock().await;
                    match ebpf.read_counters() {
                        Ok(counters) => {
                            if last_errors.len() < counters.len() {
                                last_errors.resize(counters.len(), 0);
                            }
                            let mut hook_snapshot = Vec::with_capacity(counters.len());
                            for (idx, (_, totals)) in counters.iter().enumerate() {
                                if totals.error > last_errors[idx] {
                                    let new_errors = totals.error - last_errors[idx];
                                    let hook = events::HOOK_NAMES.get(idx).unwrap_or(&"unknown");
                                    tracing::warn!(
                                        hook,
                                        new_errors,
                                        total_errors = totals.error,
                                        "enforcement errors detected — kernel struct reads \
                                         failing (fail-open). Run `syva-core status` to inspect."
                                    );
                                }
                                last_errors[idx] = totals.error;
                                hook_snapshot.push(health::HookCounters {
                                    allow: totals.allow,
                                    deny: totals.deny,
                                    error: totals.error,
                                    lost: totals.lost,
                                });
                            }
                            monitor_health.write().await.hook_counters = hook_snapshot;
                        }
                        Err(e) => {
                            tracing::debug!(%e, "failed to read enforcement counters");
                        }
                    }
                }
            }
        }
    });

    let node_name = config
        .node_name
        .clone()
        .or_else(system_hostname)
        .unwrap_or_else(|| "unknown".to_string());
    let cp_config = CpClientConfig {
        endpoint: config.cp_endpoint.clone(),
        node_name,
        cluster_id: config.cluster_id.clone(),
        fingerprint: read_fingerprint(&config.fingerprint_path),
        labels: parse_labels(&config.node_labels),
        node_id_path: config.node_id_path.clone(),
        heartbeat_interval: std::time::Duration::from_secs(config.heartbeat_secs),
        ..Default::default()
    };

    let cp = syva_cp_client::CpClient::connect(cp_config)
        .await
        .map_err(|error| anyhow::anyhow!("connect to syva-cp at {}: {error}", config.cp_endpoint))?;
    let registration = cp
        .register()
        .await
        .map_err(|error| anyhow::anyhow!("register with syva-cp: {error}"))?;
    tracing::info!(node_id = %registration.node_id, "registered with syva-cp");

    let _heartbeat = cp.spawn_heartbeat_loop();
    let reconciler = cp_reconcile::Reconciler::new(
        cp,
        registry.clone(),
        ebpf.clone(),
        health_state.clone(),
    );
    let mut reconcile_task = tokio::spawn(async move {
        reconciler.run().await;
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("received SIGINT — shutting down");
        }
        _ = sigterm.recv() => {
            tracing::info!("received SIGTERM — shutting down");
        }
        _ = &mut reconcile_task => {
            tracing::warn!("reconcile loop exited");
        }
    }

    cancel.cancel();
    reconcile_task.abort();
    // Drop ebpf manager (cleans up BPF pins).
    drop(ebpf);
    tracing::info!("syva-core stopped");
    Ok(())
}

pub(crate) fn parse_labels(entries: &[String]) -> std::collections::BTreeMap<String, String> {
    let mut labels = std::collections::BTreeMap::new();

    for entry in entries {
        let trimmed = entry.trim();
        if let Some((key, value)) = trimmed.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            if key.is_empty() {
                tracing::warn!(entry = trimmed, "ignoring node label with empty key");
                continue;
            }
            labels.insert(key.to_string(), value.to_string());
        } else {
            tracing::warn!(entry = trimmed, "ignoring malformed node label");
        }
    }

    labels
}

pub(crate) fn read_fingerprint(path: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|contents| contents.trim().to_string())
        .filter(|contents| !contents.is_empty())
}

fn system_hostname() -> Option<String> {
    let mut buffer = [0_u8; 256];
    let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if result != 0 {
        return None;
    }

    let length = buffer
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(buffer.len());
    let hostname = String::from_utf8_lossy(&buffer[..length]).into_owned();
    if hostname.is_empty() {
        None
    } else {
        Some(hostname)
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
        // aya 0.13 TryFrom impls live on `Map`, not `MapData` — wrap the
        // pinned data in the matching variant before converting.
        let map_data = aya::maps::MapData::from_pin(&counter_path)
            .map_err(|e| anyhow::anyhow!("failed to open pinned counters: {e}"))?;
        match PerCpuArray::<_, EnforcementCounters>::try_from(
            aya::maps::Map::PerCpuArray(map_data),
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
                            let flag = if total.error > 0 || total.lost > 0 { " !" } else { "" };
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
                    println!("  Errors cause fail-open behavior -- operations are ALLOWED");
                    println!("  when kernel struct reads fail. This may indicate wrong");
                    println!("  kernel struct offsets. Check BTF availability and restart syva-core.");
                }

                // Suppress unused variable warning for total_lost (used for flag above).
                let _ = total_lost;
            }
            Err(e) => {
                println!("  counters: unavailable ({e})");
            }
        }
    }

    Ok(())
}

async fn cmd_events(follow: bool, format: OutputFormat) -> anyhow::Result<()> {
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
    let mut ring_buf = RingBuf::try_from(aya::maps::Map::RingBuf(map_data))?;
    let json_mode = matches!(format, OutputFormat::Json);

    eprintln!("streaming enforcement events (Ctrl+C to stop)...");

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                break;
            }
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {
                const MAX_EVENTS_PER_TICK: usize = 1000;
                let drained: Vec<EnforcementEvent> = tokio::task::block_in_place(|| {
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
                for event in &drained {
                    let hook = events::HOOK_NAMES.get(event.hook as usize).copied().unwrap_or("unknown");
                    let decision = match event.decision {
                        syva_ebpf_common::DECISION_DENY => "deny",
                        syva_ebpf_common::DECISION_ALLOW => "allow",
                        _ => "unknown",
                    };

                    if json_mode {
                        let json = serde_json::json!({
                            "timestamp_ns": event.timestamp_ns,
                            "hook": hook,
                            "action": decision,
                            "pid": event.pid,
                            "caller_zone": event.caller_zone,
                            "target_zone": event.target_zone,
                            "context": event.context,
                        });
                        if let Ok(line) = serde_json::to_string(&json) {
                            println!("{line}");
                        }
                    } else {
                        println!(
                            "{} hook={} pid={} caller_zone={} target_zone={} context={}",
                            decision.to_uppercase(), hook, event.pid,
                            event.caller_zone, event.target_zone, event.context
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

/// Drop capabilities that are no longer needed after BPF programs are loaded
/// and maps are populated. BPF map operations use already-open file descriptors.
fn drop_unnecessary_capabilities() {
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
