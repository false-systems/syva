mod crd;
mod mapper;
mod watcher;

use anyhow::Result;
use clap::Parser;
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
    })
    .await
}
