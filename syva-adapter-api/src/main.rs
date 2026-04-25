mod routes;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use uuid::Uuid;

#[derive(Parser, Debug)]
#[command(name = "syva-api", version)]
struct Cli {
    /// Address to listen on for the REST API.
    #[arg(long, env = "SYVA_API_LISTEN", default_value = "0.0.0.0:8080")]
    listen: SocketAddr,

    /// syva-cp gRPC endpoint.
    #[arg(long, env = "SYVA_CP_ENDPOINT")]
    cp_endpoint: String,

    /// Team UUID this proxy creates and updates zones in.
    #[arg(long, env = "SYVA_TEAM_ID")]
    team_id: Uuid,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "syva_api=info".into()),
        )
        .init();

    let cli = Cli::parse();
    routes::serve(routes::Config {
        listen: cli.listen,
        cp_endpoint: cli.cp_endpoint,
        team_id: cli.team_id,
    })
    .await
}
