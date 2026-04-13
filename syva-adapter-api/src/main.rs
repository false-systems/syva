mod connect;
mod routes;

use clap::Parser;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "syva-api", about = "REST API adapter for syva-core")]
struct Cli {
    /// Path to the syva-core Unix socket.
    #[arg(long, default_value = "/run/syva/syva-core.sock")]
    socket_path: String,

    /// Port for the REST API server.
    #[arg(long, default_value = "8080")]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("syva_api=info".parse()?),
        )
        .init();

    let cli = Cli::parse();
    tracing::info!("syva-api starting");

    let client = connect::connect_with_retry(&cli.socket_path, 30).await?;
    tracing::info!(socket = cli.socket_path, "connected to syva-core");

    let shared = std::sync::Arc::new(tokio::sync::Mutex::new(client));
    let app = routes::router(shared);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], cli.port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "REST API listening");

    // Shutdown on SIGTERM/SIGINT
    let shutdown = async {
        let mut sigterm =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to register SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT"),
            _ = sigterm.recv() => tracing::info!("received SIGTERM"),
        }
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    tracing::info!("syva-api stopped");
    Ok(())
}
