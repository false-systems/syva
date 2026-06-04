mod routes;

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "syva-api", version)]
struct Cli {
    /// Address to listen on for the REST API.
    #[arg(long, env = "SYVA_API_LISTEN", default_value = "0.0.0.0:8080")]
    listen: SocketAddr,

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
                .unwrap_or_else(|_| "syva_api=info".into()),
        )
        .init();

    let cli = Cli::parse();
    routes::serve(routes::Config {
        listen: cli.listen,
        core_socket: cli.core_socket,
    })
    .await
}
