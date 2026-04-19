//! PostgreSQL connection pool and migration runner.
//!
//! Writes never happen here — this module owns the pool handle and the
//! raw `health_check`/`run_migrations` helpers. Mutations live in
//! `crate::write`, reads in `crate::read`.

use crate::config::Config;
use anyhow::{Context, Result};
use sqlx::postgres::{PgPool, PgPoolOptions};
use std::time::Duration;

pub mod types;

pub async fn create_pool(config: &Config) -> Result<PgPool> {
    PgPoolOptions::new()
        .max_connections(config.db_max_connections)
        .acquire_timeout(Duration::from_secs(config.db_timeout_secs))
        .connect(&config.database_url)
        .await
        .context("failed to connect to postgres")
}

pub async fn run_migrations(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .context("failed to run migrations")?;
    tracing::info!("migrations applied");
    Ok(())
}

pub async fn health_check(pool: &PgPool) -> Result<()> {
    sqlx::query("SELECT 1").execute(pool).await?;
    Ok(())
}
