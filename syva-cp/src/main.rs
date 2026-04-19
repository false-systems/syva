use anyhow::Result;
use clap::Parser;
use syva_cp::{config::Config, run};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "syva_cp=info".into()),
        )
        .init();

    let config = Config::parse();
    run(config).await
}
