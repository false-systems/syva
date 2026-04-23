//! syva-cp — control plane for syvä.
//!
//! Stores desired state, computes assignments, audits every mutation.
//! See `docs/adr/0002-control-plane.md` for the data model, and
//! `docs/adr/0003-transactional-write-discipline.md` for the rules that
//! govern every mutating operation in this crate.

pub mod bus;
pub mod config;
pub mod db;
pub mod engine;
pub mod error;
pub mod health;
pub mod metrics;
pub mod read;
pub mod rpc;
pub mod write;

use anyhow::Result;
use bus::AssignmentBus;
use config::Config;

pub async fn run(config: Config) -> Result<()> {
    let metrics_handle = metrics::init()?;

    let pool = db::create_pool(&config).await?;
    db::run_migrations(&pool).await?;

    // Health server starts first and reports 503 until gRPC is serving.
    // Mirrors syva-core's pattern: observability before enforcement.
    let (health_handle, health_ready) = health::spawn(config.health_addr, metrics_handle);

    let bus = AssignmentBus::new();
    let listener_handle = bus::spawn_listener(pool.clone(), bus.clone()).await?;
    let rpc_handle = rpc::spawn(pool.clone(), bus.clone(), config.grpc_addr).await?;

    health_ready.set(true);
    tracing::info!("syva-cp ready");

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("SIGINT received, shutting down");
        }
    }

    health_ready.set(false);
    listener_handle.abort();
    rpc_handle.abort();
    health_handle.abort();
    Ok(())
}
