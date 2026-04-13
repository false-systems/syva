//! syva-core — eBPF enforcement engine with gRPC API.
//!
//! The core engine manages BPF programs and maps. Adapters connect via
//! Unix socket gRPC to register zones, attach containers, and manage
//! cross-zone communication policies.
//!
//! Usage:
//!   syva-core                          # Start the enforcement engine
//!   syva-core status                   # Show enforcement counters
//!   syva-core events --follow          # Stream deny events

mod btf;
mod ebpf;
mod events;
mod health;
pub mod rpc;
pub mod types;
mod zone;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use clap::{Parser, Subcommand};
use tokio::sync::{Mutex, RwLock};
use tonic::transport::Server;
use tracing_subscriber::EnvFilter;

use syva_proto::syva_core::syva_core_server::SyvaCoreServer;

#[derive(Parser)]
#[command(name = "syva-core", about = "eBPF enforcement engine with gRPC API")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Path to the eBPF object file.
    #[arg(long)]
    ebpf_obj: Option<PathBuf>,

    /// Port for the health/metrics HTTP server.
    #[arg(long, default_value = "9091")]
    health_port: u16,

    /// Unix socket path for the gRPC server.
    #[arg(long, default_value = "/run/syva/syva-core.sock")]
    socket_path: String,
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
        None => cmd_run(cli.ebpf_obj, cli.health_port, cli.socket_path).await,
    }
}

/// Main enforcement engine loop.
async fn cmd_run(
    ebpf_obj: Option<PathBuf>,
    health_port: u16,
    socket_path: String,
) -> anyhow::Result<()> {
    tracing::info!("syva-core starting");

    let start_time = Instant::now();

    // Health state — shared with the HTTP server. Starts as unhealthy
    // (not attached, zero zones) and transitions as startup progresses.
    let health_state = health::SharedHealth::new(RwLock::new(
        health::HealthState::new(),
    ));
    health::spawn_health_server(health_port, health_state.clone()).await?;

    // Load eBPF programs (but do NOT attach — no enforcement yet).
    let mut mgr = ebpf::EnforceEbpf::load(ebpf_obj.as_deref())?;

    // Start the event reader (ring buffer -> logs).
    let cancel = tokio_util::sync::CancellationToken::new();
    if let Some(ring_buf) = mgr.take_event_ring_buf() {
        events::spawn_event_reader(ring_buf, cancel.clone());
    }

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

    tracing::info!("startup complete — enforcement active, awaiting gRPC connections");

    // Ensure parent directory for socket path exists.
    if let Some(parent) = std::path::Path::new(&socket_path).parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("failed to create socket directory {}: {e}", parent.display()))?;
        }
    }

    // Remove stale socket file if it exists.
    if std::path::Path::new(&socket_path).exists() {
        std::fs::remove_file(&socket_path)
            .map_err(|e| anyhow::anyhow!("failed to remove stale socket {}: {e}", socket_path))?;
    }

    // Build gRPC service.
    let service = rpc::SyvaCoreService {
        registry: registry.clone(),
        ebpf: ebpf.clone(),
        health: health_state.clone(),
        start_time,
    };

    // Start gRPC server on Unix socket.
    let uds = tokio::net::UnixListener::bind(&socket_path)
        .map_err(|e| anyhow::anyhow!("failed to bind Unix socket {}: {e}", socket_path))?;
    let uds_stream = tokio_stream::wrappers::UnixListenerStream::new(uds);

    tracing::info!(socket = socket_path, "gRPC server listening");

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

    // Run gRPC server with graceful shutdown.
    let grpc_server = Server::builder()
        .add_service(SyvaCoreServer::new(service))
        .serve_with_incoming_shutdown(uds_stream, async {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("received SIGINT — shutting down");
                }
                _ = sigterm.recv() => {
                    tracing::info!("received SIGTERM — shutting down");
                }
            }
        });

    grpc_server.await?;

    cancel.cancel();
    // Drop ebpf manager (cleans up BPF pins).
    drop(ebpf);
    tracing::info!("syva-core stopped");
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
    let mut ring_buf = RingBuf::try_from(map_data)?;
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
