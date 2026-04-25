mod crd;
mod mapper;
mod watcher;

use anyhow::Result;
use clap::Parser;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "syva-k8s", version)]
struct Cli {
    /// Kubernetes namespace to watch SyvaZonePolicy CRDs in.
    #[arg(long, env = "SYVA_K8S_NAMESPACE", default_value = "default")]
    namespace: String,

    /// syva-cp gRPC endpoint.
    #[arg(long, env = "SYVA_CP_ENDPOINT")]
    cp_endpoint: String,

    /// Team UUID this adapter manages zones for.
    #[arg(long, env = "SYVA_TEAM_ID")]
    team_id: Uuid,
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
        team_id: cli.team_id,
    })
    .await
}
