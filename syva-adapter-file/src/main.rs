use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "syva-file", version)]
struct Cli {
    /// Directory containing TOML zone policies. One file per zone.
    /// Filename (without .toml) becomes the zone name.
    #[arg(
        long,
        env = "SYVA_FILE_POLICY_DIR",
        default_value = "/etc/syva/policies"
    )]
    policy_dir: PathBuf,

    /// Local syva-core Unix socket.
    #[arg(
        long,
        env = "SYVA_CORE_SOCKET",
        default_value = "/run/syva/syva-core.sock"
    )]
    core_socket: PathBuf,

    /// Reconcile interval in seconds.
    #[arg(long, env = "SYVA_RECONCILE_SECS", default_value = "5")]
    reconcile_secs: u64,

    #[command(subcommand)]
    command: Option<Cmd>,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Validate the TOML files in --policy-dir without connecting to syva-core.
    Verify,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "syva_file=info".into()),
        )
        .init();

    let cli = Cli::parse();

    if let Some(Cmd::Verify) = &cli.command {
        return syva_file::verify::run(&cli.policy_dir);
    }

    syva_file::run::run(syva_file::run::Config {
        policy_dir: cli.policy_dir,
        core_socket: cli.core_socket,
        reconcile_interval: std::time::Duration::from_secs(cli.reconcile_secs),
    })
    .await
}
