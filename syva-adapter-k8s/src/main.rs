mod crd;
mod mapper;
mod membership;
mod metrics;
mod watcher;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "syva-k8s", version)]
struct Cli {
    /// Kubernetes namespace to watch SyvaZonePolicy CRDs in.
    #[arg(long, env = "SYVA_K8S_NAMESPACE", default_value = "default")]
    namespace: String,

    /// Local syva-core Unix socket.
    #[arg(
        long,
        env = "SYVA_CORE_SOCKET",
        default_value = "/run/syva/syva-core.sock"
    )]
    core_socket: PathBuf,

    /// Kubernetes node name served by this DaemonSet pod.
    #[arg(long, env = "NODE_NAME")]
    node_name: String,

    /// Host procfs path used to resolve container main-process cgroups.
    #[arg(long, env = "SYVA_HOST_PROC", default_value = "/proc")]
    host_proc: PathBuf,

    /// Host cgroup v2 mount used to stat cgroup inode IDs.
    #[arg(long, env = "SYVA_HOST_CGROUP", default_value = "/sys/fs/cgroup")]
    host_cgroup: PathBuf,

    /// Metrics listen address for syva-k8s adapter metrics.
    #[arg(long, env = "SYVA_K8S_METRICS_LISTEN", default_value = "0.0.0.0:9092")]
    metrics_listen: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "syva_k8s=info".into()),
        )
        .init();

    let cli = Cli::parse();
    watcher::run(watcher::Config {
        namespace: cli.namespace,
        core_socket: cli.core_socket,
        node_name: cli.node_name,
        host_proc: cli.host_proc,
        host_cgroup: cli.host_cgroup,
        metrics_listen: cli.metrics_listen,
    })
    .await
}
