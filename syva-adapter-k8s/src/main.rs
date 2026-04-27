mod crd;
mod mapper;
mod watcher;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "syva-k8s", version)]
struct Cli {
    /// Kubernetes namespace to watch SyvaZonePolicy CRDs in.
    #[arg(long, env = "SYVA_K8S_NAMESPACE", default_value = "default")]
    namespace: String,

    /// syva-cp gRPC endpoint.
    #[arg(long, env = "SYVA_CP_ENDPOINT", conflicts_with = "core_socket")]
    cp_endpoint: Option<String>,

    /// Local syva-core Unix socket.
    #[arg(long, env = "SYVA_CORE_SOCKET", conflicts_with = "cp_endpoint")]
    core_socket: Option<PathBuf>,

    /// Team UUID this adapter manages zones for.
    #[arg(long, env = "SYVA_TEAM_ID")]
    team_id: Option<Uuid>,
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
        cp_endpoint: cli.cp_endpoint,
        core_socket: cli.core_socket,
        team_id: cli.team_id,
    })
    .await
}
