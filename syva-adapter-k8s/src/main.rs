mod connect;
mod crd;
mod mapper;
mod watcher;

use std::sync::Arc;

use clap::Parser;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "syva-k8s", about = "Kubernetes CRD adapter for syva-core")]
struct Cli {
    /// Path to the syva-core Unix socket.
    #[arg(long, default_value = "/run/syva/syva-core.sock")]
    socket_path: String,

    /// Namespace to watch. If omitted, watches all namespaces.
    #[arg(long)]
    namespace: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("syva_k8s=info".parse()?),
        )
        .init();

    let cli = Cli::parse();

    tracing::info!("syva-k8s starting");

    // Connect to syva-core
    let core_client = connect::connect_with_retry(&cli.socket_path, 30).await?;
    tracing::info!(socket = cli.socket_path, "connected to syva-core");
    let client = Arc::new(Mutex::new(core_client));

    // Connect to Kubernetes
    let kube_client = kube::Client::try_default().await?;
    tracing::info!("connected to Kubernetes API");

    // Spawn CRD watcher and pod watcher concurrently
    let crd_client = client.clone();
    let crd_kube = kube_client.clone();
    let crd_ns = cli.namespace.clone();
    let crd_task = tokio::spawn(async move {
        if let Err(e) =
            watcher::watch_zone_policies(crd_client, crd_kube, crd_ns.as_deref()).await
        {
            tracing::error!(%e, "CRD watcher failed");
        }
    });

    let pod_client = client.clone();
    let pod_kube = kube_client.clone();
    let pod_ns = cli.namespace.clone();
    let pod_task = tokio::spawn(async move {
        if let Err(e) = watcher::watch_pods(pod_client, pod_kube, pod_ns.as_deref()).await {
            tracing::error!(%e, "pod watcher failed");
        }
    });

    // Shutdown on SIGTERM/SIGINT
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => tracing::info!("received SIGINT"),
        _ = sigterm.recv() => tracing::info!("received SIGTERM"),
        _ = crd_task => tracing::warn!("CRD watcher exited"),
        _ = pod_task => tracing::warn!("pod watcher exited"),
    }

    tracing::info!("syva-k8s stopped");
    Ok(())
}
