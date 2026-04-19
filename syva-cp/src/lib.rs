//! syva-cp — control plane for syvä.
//!
//! Stores desired state, computes assignments, audits every mutation.
//! See `docs/adr/0002-control-plane.md` for the data model, and
//! `docs/adr/0003-transactional-write-discipline.md` for the rules that
//! govern every mutating operation in this crate.

pub mod config;
pub mod db;
pub mod error;
pub mod metrics;
pub mod write;

use anyhow::Result;
use config::Config;

pub async fn run(_config: Config) -> Result<()> {
    // Wired up in later steps: db pool, migrations, metrics, health, gRPC.
    tracing::info!("syva-cp skeleton — modules land in subsequent commits");
    Ok(())
}
