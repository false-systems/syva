//! Thin local operator CLI for the `syva.core.v1` API.

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use syva_core_client::syva_core::{
    ListCommsRequest, ListZonesRequest, StatusRequest, WatchEventsRequest,
};

const DEFAULT_SOCKET: &str = "/run/syva/syva-core.sock";

#[derive(Parser)]
#[command(name = "syvactl", about = "Local operator CLI for syva-core")]
struct Cli {
    /// syva-core Unix socket path.
    #[arg(long, default_value = DEFAULT_SOCKET, global = true)]
    socket: PathBuf,

    /// Output format.
    #[arg(long, default_value = "text", global = true)]
    format: OutputFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Command {
    /// Show syva-core status via gRPC Status.
    Status,
    /// Zone commands.
    Zones {
        #[command(subcommand)]
        command: ZonesCommand,
    },
    /// Communication policy commands.
    Comms {
        #[command(subcommand)]
        command: CommsCommand,
    },
    /// Enforcement event commands.
    Events {
        /// Follow future events after draining the current ring buffer.
        #[arg(long)]
        follow: bool,
    },
}

#[derive(Subcommand)]
enum ZonesCommand {
    /// List zones.
    List,
}

#[derive(Subcommand)]
enum CommsCommand {
    /// List allowed communication pairs.
    List {
        /// Optional zone filter.
        #[arg(long)]
        zone: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    run(cli).await
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    // Fail fast before connecting: WatchEvents is a live stream and syva-core
    // hands out a single ring-buffer consumer, so a non-follow call would drain
    // and release it. Require --follow.
    if let Command::Events { follow: false } = cli.command {
        anyhow::bail!(
            "`syvactl events` requires --follow: WatchEvents is a live stream and a \
             non-follow call would consume syva-core's single event-stream handle. \
             Run `syvactl events --follow`."
        );
    }

    let mut client = syva_core_client::connect_unix_socket(&cli.socket)
        .await
        .with_context(|| format!("failed to connect to syva-core at {}", cli.socket.display()))?;

    match cli.command {
        Command::Status => {
            let status = client.status(StatusRequest {}).await?.into_inner();
            print_status(cli.format, &status)?;
        }
        Command::Zones {
            command: ZonesCommand::List,
        } => {
            let zones = client.list_zones(ListZonesRequest {}).await?.into_inner();
            print_zones(cli.format, &zones.zones)?;
        }
        Command::Comms {
            command: CommsCommand::List { zone },
        } => {
            let comms = client
                .list_comms(ListCommsRequest {
                    zone_name: zone.unwrap_or_default(),
                })
                .await?
                .into_inner();
            print_comms(cli.format, &comms.pairs)?;
        }
        Command::Events { follow } => {
            // `follow` is guaranteed true here (checked before connecting).
            let mut stream = client
                .watch_events(WatchEventsRequest { follow })
                .await?
                .into_inner();
            while let Some(event) = stream.message().await? {
                print_event(cli.format, &event)?;
            }
        }
    }

    Ok(())
}

fn print_status(
    format: OutputFormat,
    status: &syva_core_client::syva_core::StatusResponse,
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "attached": status.attached,
                    "zones_active": status.zones_active,
                    "containers_active": status.containers_active,
                    "uptime_secs": status.uptime_secs,
                    "max_zones": status.max_zones,
                    "hooks": status.hooks.iter().map(hook_json).collect::<Vec<_>>(),
                }))?
            );
        }
        OutputFormat::Text => {
            println!("syva-core status");
            println!("  attached: {}", status.attached);
            println!("  zones_active: {}", status.zones_active);
            println!("  containers_active: {}", status.containers_active);
            println!("  uptime_secs: {}", status.uptime_secs);
            println!("  max_zones: {}", status.max_zones);
            println!("  hooks:");
            for hook in &status.hooks {
                println!(
                    "    {:<22} allow={:<8} deny={:<8} error={:<6} lost={}",
                    hook.hook, hook.allow, hook.deny, hook.error, hook.lost
                );
            }
        }
    }
    Ok(())
}

fn print_zones(
    format: OutputFormat,
    zones: &[syva_core_client::syva_core::ZoneSummary],
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &zones
                        .iter()
                        .map(|zone| {
                            serde_json::json!({
                                "name": zone.name,
                                "zone_id": zone.zone_id,
                                "state": zone.state,
                                "containers_active": zone.containers_active,
                            })
                        })
                        .collect::<Vec<_>>()
                )?
            );
        }
        OutputFormat::Text => {
            if zones.is_empty() {
                println!("no zones");
            } else {
                for zone in zones {
                    println!(
                        "{} id={} state={} containers_active={}",
                        zone.name, zone.zone_id, zone.state, zone.containers_active
                    );
                }
            }
        }
    }
    Ok(())
}

fn print_comms(
    format: OutputFormat,
    pairs: &[syva_core_client::syva_core::CommPair],
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &pairs
                        .iter()
                        .map(|pair| {
                            serde_json::json!({
                                "zone_a": pair.zone_a,
                                "zone_b": pair.zone_b,
                            })
                        })
                        .collect::<Vec<_>>()
                )?
            );
        }
        OutputFormat::Text => {
            if pairs.is_empty() {
                println!("no allowed comm pairs");
            } else {
                for pair in pairs {
                    println!("{} <-> {}", pair.zone_a, pair.zone_b);
                }
            }
        }
    }
    Ok(())
}

fn print_event(
    format: OutputFormat,
    event: &syva_core_client::syva_core::DenyEvent,
) -> anyhow::Result<()> {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "event": "syva.enforcement.denied",
                    "timestamp_ns": event.timestamp_ns,
                    "hook": event.hook,
                    "zone_id": event.zone_id,
                    "target_zone_id": event.target_zone_id,
                    "pid": event.pid,
                    "comm": event.comm,
                    "inode": event.inode,
                    "context": event.context,
                    "result": "deny",
                    "errno": "EPERM",
                }))?
            );
        }
        OutputFormat::Text => {
            println!(
                "DENY hook={} pid={} zone={} target_zone={} context={}",
                event.hook, event.pid, event.zone_id, event.target_zone_id, event.context
            );
        }
    }
    Ok(())
}

fn hook_json(hook: &syva_core_client::syva_core::HookStatus) -> serde_json::Value {
    serde_json::json!({
        "hook": hook.hook,
        "allow": hook.allow,
        "deny": hook.deny,
        "error": hook.error,
        "lost": hook.lost,
    })
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_help_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn output_format_parses_json() {
        assert_eq!(
            <OutputFormat as clap::ValueEnum>::from_str("json", true),
            Ok(OutputFormat::Json)
        );
    }
}
