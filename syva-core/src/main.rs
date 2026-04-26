//! syva-core — eBPF enforcement engine.
//!
//! The core engine manages BPF programs and maps and consumes desired
//! zone state from syva-cp.
//!
//! Usage:
//!   syva-core                          # Start the enforcement engine
//!   syva-core status                   # Show enforcement counters
//!   syva-core events --follow          # Stream deny events

mod btf;
mod container_id;
mod cp_reconcile;
mod ebpf;
mod events;
mod health;
mod ingest;
mod rpc;
pub mod types;
mod zone;

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use syva_cp_client::CpClientConfig;
use syva_proto::syva_core::syva_core_server::SyvaCoreServer;
use tokio::net::UnixListener;
use tokio::sync::{Mutex, RwLock};
use tokio_stream::wrappers::UnixListenerStream;
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

    /// Policy ingestion source.
    #[arg(long, default_value = "cp")]
    policy_source: PolicySource,

    /// Local syva.core.v1 Unix socket path.
    #[arg(long, default_value = "/run/syva/syva-core.sock")]
    socket_path: PathBuf,

    /// syva-cp endpoint. Required when --policy-source=cp.
    #[arg(long, env = "SYVA_CP_ENDPOINT")]
    cp_endpoint: Option<String>,

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

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum PolicySource {
    Cp,
    Local,
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("syva_core=info".parse()?))
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
    let start_time = Instant::now();

    // Health state — shared with the HTTP server. Starts as unhealthy
    // (not attached, zero zones) and transitions as startup progresses.
    let health_state = health::SharedHealth::new(RwLock::new(health::HealthState::new()));
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

    let local_server_task = if matches!(config.policy_source, PolicySource::Local) {
        Some(
            spawn_local_core_server(
                config.socket_path.clone(),
                registry.clone(),
                ebpf.clone(),
                health_state.clone(),
                start_time,
                cancel.clone(),
            )
            .await?,
        )
    } else {
        None
    };

    tracing::info!("startup complete — enforcement active");

    // Shutdown on SIGINT (ctrl-c) or SIGTERM (Kubernetes pod termination).
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

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

    match config.policy_source {
        PolicySource::Cp => {
            let cp_endpoint = config.cp_endpoint.clone().ok_or_else(|| {
                anyhow::anyhow!(
                    "--cp-endpoint or SYVA_CP_ENDPOINT is required when --policy-source=cp"
                )
            })?;
            let node_name = config
                .node_name
                .clone()
                .or_else(system_hostname)
                .unwrap_or_else(|| "unknown".to_string());
            let cp_config = CpClientConfig {
                endpoint: cp_endpoint,
                node_name,
                cluster_id: config.cluster_id.clone(),
                fingerprint: read_fingerprint(&config.fingerprint_path),
                labels: parse_labels(&config.node_labels),
                node_id_path: config.node_id_path.clone(),
                heartbeat_interval: Duration::from_secs(config.heartbeat_secs),
                ..Default::default()
            };

            let (cp, registration) = connect_and_register_with_retry(cp_config).await;
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
                    tracing::info!("received SIGINT; shutting down");
                }
                _ = sigterm.recv() => {
                    tracing::info!("received SIGTERM; shutting down");
                }
                _ = &mut reconcile_task => {
                    tracing::warn!("reconcile loop exited");
                }
            }

            reconcile_task.abort();
        }
        PolicySource::Local => {
            let mut local_server_task = local_server_task
                .ok_or_else(|| anyhow::anyhow!("local server task was not started"))?;
            let mut local_server_exited = false;

            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("received SIGINT; shutting down");
                }
                _ = sigterm.recv() => {
                    tracing::info!("received SIGTERM; shutting down");
                }
                result = &mut local_server_task => {
                    local_server_exited = true;
                    match result {
                        Ok(Ok(())) => tracing::info!("local gRPC server exited"),
                        Ok(Err(error)) => tracing::warn!(%error, "local gRPC server exited with error"),
                        Err(error) => tracing::warn!(%error, "local gRPC server task failed"),
                    }
                }
            }

            cancel.cancel();
            if !local_server_exited {
                match tokio::time::timeout(Duration::from_secs(10), local_server_task).await {
                    Ok(Ok(Ok(()))) => {}
                    Ok(Ok(Err(error))) => {
                        tracing::warn!(%error, "local gRPC server shutdown failed")
                    }
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "local gRPC server task failed during shutdown")
                    }
                    Err(_) => tracing::warn!("timed out waiting for local gRPC server shutdown"),
                }
            }
        }
    }

    cancel.cancel();
    // Drop ebpf manager (cleans up BPF pins).
    drop(ebpf);
    tracing::info!("syva-core stopped");
    Ok(())
}

async fn spawn_local_core_server(
    socket_path: PathBuf,
    registry: Arc<RwLock<zone::ZoneRegistry>>,
    ebpf: Arc<Mutex<ebpf::EnforceEbpf>>,
    health: health::SharedHealth,
    start_time: Instant,
    cancel: tokio_util::sync::CancellationToken,
) -> anyhow::Result<tokio::task::JoinHandle<anyhow::Result<()>>> {
    if socket_path.exists() {
        anyhow::bail!(
            "refusing to replace existing syva-core socket at {}",
            socket_path.display()
        );
    }

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(&socket_path)?;
    configure_socket_permissions(&socket_path)?;

    let service = rpc::SyvaCoreService {
        registry,
        ebpf,
        health,
        start_time,
    };
    let incoming = UnixListenerStream::new(listener);
    let shutdown = cancel.cancelled_owned();
    let display_path = socket_path.display().to_string();

    let task = tokio::spawn(async move {
        tracing::info!(socket = display_path, "local syva.core.v1 server listening");
        tonic::transport::Server::builder()
            .add_service(SyvaCoreServer::new(service))
            .serve_with_incoming_shutdown(incoming, shutdown)
            .await
            .map_err(|error| anyhow::anyhow!("local gRPC server failed: {error}"))
    });

    Ok(task)
}

fn configure_socket_permissions(socket_path: &std::path::Path) -> anyhow::Result<()> {
    let permissions = std::fs::Permissions::from_mode(0o660);
    std::fs::set_permissions(socket_path, permissions)?;

    let gid = syva_group_gid().ok_or_else(|| {
        anyhow::anyhow!(
            "group 'syva' is required for {} ownership",
            socket_path.display()
        )
    })?;
    let c_path = CString::new(socket_path.as_os_str().as_bytes())?;
    let result = unsafe { libc::chown(c_path.as_ptr(), 0, gid) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        anyhow::bail!(
            "failed to chown {} to root:syva: {error}",
            socket_path.display()
        );
    }

    Ok(())
}

fn syva_group_gid() -> Option<u32> {
    let groups = std::fs::read_to_string("/etc/group").ok()?;
    groups.lines().find_map(|line| {
        let mut parts = line.split(':');
        let name = parts.next()?;
        let _password = parts.next()?;
        let gid = parts.next()?;
        if name == "syva" {
            gid.parse().ok()
        } else {
            None
        }
    })
}

async fn connect_and_register_with_retry(
    config: CpClientConfig,
) -> (syva_cp_client::CpClient, syva_cp_client::NodeRegistration) {
    let mut backoff = Duration::from_millis(250);
    let max_backoff = Duration::from_secs(30);

    loop {
        match syva_cp_client::CpClient::connect(config.clone()).await {
            Ok(cp) => match cp.register().await {
                Ok(registration) => return (cp, registration),
                Err(error) => {
                    tracing::warn!(
                        endpoint = %config.endpoint,
                        error = %error,
                        backoff_ms = backoff.as_millis(),
                        "could not register with syva-cp; retrying"
                    );
                }
            },
            Err(error) => {
                tracing::warn!(
                    endpoint = %config.endpoint,
                    error = %error,
                    backoff_ms = backoff.as_millis(),
                    "could not connect to syva-cp; retrying"
                );
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(max_backoff);
    }
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
        match PerCpuArray::<_, EnforcementCounters>::try_from(aya::maps::Map::PerCpuArray(map_data))
        {
            Ok(map) => {
                println!("  hooks:");
                let mut total_errors: u64 = 0;
                let mut total_lost: u64 = 0;
                let mut had_read_error = false;
                for (idx, hook) in events::HOOK_NAMES.iter().enumerate() {
                    match map.get(&(idx as u32), 0) {
                        Ok(per_cpu) => {
                            let mut total = EnforcementCounters {
                                allow: 0,
                                deny: 0,
                                error: 0,
                                lost: 0,
                            };
                            for cpu_val in per_cpu.iter() {
                                total.allow += cpu_val.allow;
                                total.deny += cpu_val.deny;
                                total.error += cpu_val.error;
                                total.lost += cpu_val.lost;
                            }
                            total_errors += total.error;
                            total_lost += total.lost;
                            let flag = if total.error > 0 || total.lost > 0 {
                                " !"
                            } else {
                                ""
                            };
                            println!(
                                "    {:<16} allow={:<8} deny={:<8} error={:<6} lost={}{}",
                                hook, total.allow, total.deny, total.error, total.lost, flag
                            );
                        }
                        Err(_) => {
                            had_read_error = true;
                        }
                    }
                }

                if had_read_error {
                    println!();
                    println!("  counters: some reads failed");
                } else if total_errors > 0 {
                    println!();
                    println!(
                        "  WARNING: {} total enforcement errors detected.",
                        total_errors
                    );
                    println!("  Errors cause fail-open behavior -- operations are ALLOWED");
                    println!("  when kernel struct reads fail. This may indicate wrong");
                    println!(
                        "  kernel struct offsets. Check BTF availability and restart syva-core."
                    );
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
    const CAPS_TO_DROP: &[(libc::c_int, &str)] = &[(21, "CAP_SYS_ADMIN")];

    for &(cap, name) in CAPS_TO_DROP {
        let ret = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap, 0, 0, 0) };
        if ret == 0 {
            tracing::info!(capability = name, "dropped capability");
        } else {
            tracing::debug!(
                capability = name,
                "failed to drop capability (may not be in bounding set)"
            );
        }
    }
}
