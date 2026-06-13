//! Thin local operator CLI for the `syva.core.v1` API.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use syva_core_client::syva_core::{
    AllowCommRequest, DenyCommRequest, ListCommsRequest, ListZonesRequest, NetworkMode,
    RegisterHostPathRequest, RegisterZoneRequest, RemoveZoneRequest, StatusRequest,
    WatchEventsRequest, ZonePolicy, ZoneType,
};
use tonic::Code;

const DEFAULT_SOCKET: &str = "/run/syva/syva-core.sock";

#[derive(Debug, Parser)]
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

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum ZoneTypeArg {
    Standard,
    Privileged,
    Isolated,
}

impl ZoneTypeArg {
    fn proto_value(self) -> i32 {
        match self {
            Self::Standard => ZoneType::Standard as i32,
            Self::Privileged => ZoneType::Privileged as i32,
            Self::Isolated => ZoneType::Isolated as i32,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Privileged => "privileged",
            Self::Isolated => "isolated",
        }
    }
}

/// The per-zone network lock/open switch.
#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum NetworkArg {
    /// Network-locked: the zone reaches loopback only (default).
    Locked,
    /// Network-open: outbound and inbound network access permitted.
    Open,
    /// Network-open plus the host network namespace.
    Host,
}

impl NetworkArg {
    fn proto_value(self) -> i32 {
        match self {
            Self::Locked => NetworkMode::Isolated as i32,
            Self::Open => NetworkMode::Bridged as i32,
            Self::Host => NetworkMode::Host as i32,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Locked => "locked",
            Self::Open => "open",
            Self::Host => "host",
        }
    }
}

#[derive(Debug, Subcommand)]
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
    /// Host path commands.
    HostPaths {
        #[command(subcommand)]
        command: HostPathsCommand,
    },
    /// Enforcement event commands.
    Events {
        /// Follow future events after draining the current ring buffer.
        #[arg(long)]
        follow: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ZonesCommand {
    /// List zones.
    List,
    /// Register or update a local zone.
    Register {
        /// Logical Syva zone identifier.
        zone_id: String,
        /// Zone type to send to syva-core.
        #[arg(long = "type", default_value = "standard")]
        zone_type: ZoneTypeArg,
        /// Network mode: `locked` (loopback only, default), `open`, or `host`.
        #[arg(long = "network", default_value = "locked")]
        network: NetworkArg,
    },
    /// Remove a local zone if the server accepts the transition.
    Remove {
        /// Logical Syva zone identifier.
        zone_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum CommsCommand {
    /// List allowed communication pairs.
    List {
        /// Optional zone filter.
        #[arg(long)]
        zone: Option<String>,
    },
    /// Allow communication between two zones.
    Allow {
        /// Source zone.
        source_zone: String,
        /// Target zone.
        target_zone: String,
    },
    /// Remove an allowed communication pair.
    Deny {
        /// Source zone.
        source_zone: String,
        /// Target zone.
        target_zone: String,
    },
}

#[derive(Debug, Subcommand)]
enum HostPathsCommand {
    /// Register a host path/inode mapping for file enforcement.
    Register {
        /// Logical Syva zone identifier.
        zone_id: String,
        /// Host path to register.
        path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => error.exit(),
    };
    ExitCode::from(run(cli).await)
}

async fn run(cli: Cli) -> u8 {
    // Fail fast before connecting: WatchEvents is a live broadcast stream;
    // a non-follow call returns nothing (the core's event pump owns the ring
    // buffer, so there is no drainable backlog). Require --follow.
    if let Command::Events { follow: false } = cli.command {
        eprintln!(
            "`syvactl events` requires --follow: WatchEvents is a live stream and a \
non-follow call returns no events. Run `syvactl events --follow`."
        );
        return EXIT_USAGE;
    }

    let operation = operation_name(&cli.command);
    let mut client = match syva_core_client::connect_unix_socket(&cli.socket).await {
        Ok(client) => client,
        Err(error) => {
            print_command_error(
                cli.format,
                operation,
                "transport_error",
                &format!(
                    "failed to connect to syva-core at {}: {error}",
                    cli.socket.display()
                ),
                &[],
            );
            return EXIT_TRANSPORT;
        }
    };

    match cli.command {
        Command::Status => {
            let status = match client.status(StatusRequest {}).await {
                Ok(response) => response.into_inner(),
                Err(status) => return print_rpc_error(cli.format, operation, status, &[]),
            };
            print_status(cli.format, &status);
        }
        Command::Zones {
            command: ZonesCommand::List,
        } => {
            let zones = match client.list_zones(ListZonesRequest {}).await {
                Ok(response) => response.into_inner(),
                Err(status) => return print_rpc_error(cli.format, operation, status, &[]),
            };
            print_zones(cli.format, &zones.zones);
        }
        Command::Zones {
            command:
                ZonesCommand::Register {
                    zone_id,
                    zone_type,
                    network,
                },
        } => {
            let request = RegisterZoneRequest {
                zone_name: zone_id.clone(),
                policy: Some(ZonePolicy {
                    host_paths: Vec::new(),
                    allowed_zones: Vec::new(),
                    allow_ptrace: false,
                    zone_type: zone_type.proto_value(),
                    network_mode: network.proto_value(),
                    allowed_egress_cidrs: Vec::new(),
                }),
            };
            let response = match client.register_zone(request).await {
                Ok(response) => response.into_inner(),
                Err(status) => {
                    return print_rpc_error(
                        cli.format,
                        operation,
                        status,
                        &[
                            ("zone_id", serde_json::json!(zone_id)),
                            ("zone_type", serde_json::json!(zone_type.as_str())),
                            ("network", serde_json::json!(network.as_str())),
                        ],
                    )
                }
            };
            print_write_result(
                cli.format,
                WriteResult::success(operation, "applied")
                    .field("zone_id", zone_id)
                    .field("zone_type", zone_type.as_str())
                    .field("network", network.as_str())
                    .field("numeric_zone_id", response.zone_id),
            );
        }
        Command::Zones {
            command: ZonesCommand::Remove { zone_id },
        } => {
            let response = match client
                .remove_zone(RemoveZoneRequest {
                    zone_name: zone_id.clone(),
                    drain: false,
                })
                .await
            {
                Ok(response) => response.into_inner(),
                Err(status) => {
                    return print_rpc_error(
                        cli.format,
                        operation,
                        status,
                        &[("zone_id", serde_json::json!(zone_id))],
                    )
                }
            };
            let result = if response.ok {
                WriteResult::success(operation, "applied")
            } else {
                WriteResult::rejection(operation, "rejected", non_empty_reason(&response.message))
            }
            .field("zone_id", zone_id);
            let exit = if response.ok {
                EXIT_SUCCESS
            } else {
                EXIT_DOMAIN
            };
            print_write_result(cli.format, result);
            return exit;
        }
        Command::Comms {
            command: CommsCommand::List { zone },
        } => {
            let comms = match client
                .list_comms(ListCommsRequest {
                    zone_name: zone.unwrap_or_default(),
                })
                .await
            {
                Ok(response) => response.into_inner(),
                Err(status) => return print_rpc_error(cli.format, operation, status, &[]),
            };
            print_comms(cli.format, &comms.pairs);
        }
        Command::Comms {
            command:
                CommsCommand::Allow {
                    source_zone,
                    target_zone,
                },
        } => {
            let response = match client
                .allow_comm(AllowCommRequest {
                    zone_a: source_zone.clone(),
                    zone_b: target_zone.clone(),
                })
                .await
            {
                Ok(response) => response.into_inner(),
                Err(status) => {
                    return print_rpc_error(
                        cli.format,
                        operation,
                        status,
                        &[
                            ("source_zone", serde_json::json!(source_zone)),
                            ("target_zone", serde_json::json!(target_zone)),
                        ],
                    )
                }
            };
            let result = if response.ok {
                WriteResult::success(operation, "applied")
            } else {
                WriteResult::rejection(operation, "rejected", Some("server returned ok=false"))
            }
            .field("source_zone", source_zone)
            .field("target_zone", target_zone);
            let exit = if response.ok {
                EXIT_SUCCESS
            } else {
                EXIT_DOMAIN
            };
            print_write_result(cli.format, result);
            return exit;
        }
        Command::Comms {
            command:
                CommsCommand::Deny {
                    source_zone,
                    target_zone,
                },
        } => {
            let response = match client
                .deny_comm(DenyCommRequest {
                    zone_a: source_zone.clone(),
                    zone_b: target_zone.clone(),
                })
                .await
            {
                Ok(response) => response.into_inner(),
                Err(status) => {
                    return print_rpc_error(
                        cli.format,
                        operation,
                        status,
                        &[
                            ("source_zone", serde_json::json!(source_zone)),
                            ("target_zone", serde_json::json!(target_zone)),
                        ],
                    )
                }
            };
            let result = if response.ok {
                WriteResult::success(operation, "applied")
            } else {
                WriteResult::rejection(operation, "rejected", Some("server returned ok=false"))
            }
            .field("source_zone", source_zone)
            .field("target_zone", target_zone);
            let exit = if response.ok {
                EXIT_SUCCESS
            } else {
                EXIT_DOMAIN
            };
            print_write_result(cli.format, result);
            return exit;
        }
        Command::HostPaths {
            command: HostPathsCommand::Register { zone_id, path },
        } => {
            let path_string = path.display().to_string();
            let response = match client
                .register_host_path(RegisterHostPathRequest {
                    zone_name: zone_id.clone(),
                    path: path_string.clone(),
                    recursive: false,
                })
                .await
            {
                Ok(response) => response.into_inner(),
                Err(status) => {
                    return print_rpc_error(
                        cli.format,
                        operation,
                        status,
                        &[
                            ("zone_id", serde_json::json!(zone_id)),
                            ("path", serde_json::json!(path_string)),
                        ],
                    )
                }
            };
            print_write_result(
                cli.format,
                WriteResult::success(operation, "applied")
                    .field("zone_id", zone_id)
                    .field("path", path_string)
                    .field("inodes_registered", response.inodes_registered),
            );
        }
        Command::Events { follow } => {
            // `follow` is guaranteed true here (checked before connecting).
            let mut stream = match client.watch_events(WatchEventsRequest { follow }).await {
                Ok(response) => response.into_inner(),
                Err(status) => return print_rpc_error(cli.format, operation, status, &[]),
            };
            loop {
                match stream.message().await {
                    Ok(Some(event)) => print_event(cli.format, &event),
                    Ok(None) => break,
                    Err(status) => return print_rpc_error(cli.format, operation, status, &[]),
                }
            }
        }
    }

    EXIT_SUCCESS
}

fn print_status(format: OutputFormat, status: &syva_core_client::syva_core::StatusResponse) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&status_json(status)).expect("status JSON serializes")
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
}

fn print_zones(format: OutputFormat, zones: &[syva_core_client::syva_core::ZoneSummary]) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&zones_json(zones)).expect("zone JSON serializes")
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
}

fn print_comms(format: OutputFormat, pairs: &[syva_core_client::syva_core::CommPair]) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&comms_json(pairs)).expect("comms JSON serializes")
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
}

fn print_event(format: OutputFormat, event: &syva_core_client::syva_core::DenyEvent) {
    match format {
        OutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "event": match event.decision.as_str() {
                        "would_deny" => "syva.enforcement.would_deny",
                        "escape" => "syva.cgroup.escape",
                        _ => "syva.enforcement.denied",
                    },
                    // Kernel CLOCK_MONOTONIC ns, not wall clock.
                    "timestamp_ns": event.timestamp_ns,
                    "hook": event.hook,
                    "decision": event.decision,
                    "zone": event.zone,
                    "target_zone": event.target_zone,
                    "zone_id": event.zone_id,
                    "target_zone_id": event.target_zone_id,
                    "pid": event.pid,
                    "comm": event.comm,
                    "inode": event.inode,
                    "path": event.path,
                    "dst_ip": event.dst_ip,
                    "dst_port": event.dst_port,
                    "what_failed": event.what_failed,
                    "why_it_matters": event.why_it_matters,
                    "possible_causes": event.possible_causes,
                    "context": event.context,
                    "result": event.decision,
                    "errno": if event.decision == "deny" { "EPERM" } else { "" },
                }))
                .expect("event JSON serializes")
            );
        }
        OutputFormat::Text => {
            // The human projection: receive time, constant decision/hook
            // columns, zone names not ids, and the most specific target field
            // available for the hook (path, destination, or raw context).
            let target = if !event.path.is_empty() {
                format!("path={}", event.path)
            } else if !event.dst_ip.is_empty() {
                format!("dst={}:{}", event.dst_ip, event.dst_port)
            } else {
                format!("context={}", event.context)
            };
            println!(
                "{}  {:<10} {:<22} {} \u{2192} {}  pid={} comm={} {}",
                receive_time_utc(),
                event.decision.to_uppercase(),
                event.hook,
                event.zone,
                event.target_zone,
                event.pid,
                event.comm,
                target
            );
            if !event.what_failed.is_empty() {
                println!(
                    "              why: {} \u{2014} {}",
                    event.what_failed, event.why_it_matters
                );
            }
        }
    }
}

/// HH:MM:SSZ UTC receive time. The kernel timestamp in the event is
/// CLOCK_MONOTONIC and not directly renderable as wall clock; receive time is
/// the honest human-readable column (raw kernel ns stays in the JSON form).
fn receive_time_utc() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let secs_of_day = now % 86_400;
    format!(
        "{:02}:{:02}:{:02}Z",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60
    )
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

fn status_json(status: &syva_core_client::syva_core::StatusResponse) -> serde_json::Value {
    serde_json::json!({
        "operation": "status",
        "ok": true,
        "status": {
            "attached": status.attached,
            "zones_active": status.zones_active,
            "containers_active": status.containers_active,
            "uptime_secs": status.uptime_secs,
            "max_zones": status.max_zones,
            "hooks": status.hooks.iter().map(hook_json).collect::<Vec<_>>(),
        },
    })
}

fn zones_json(zones: &[syva_core_client::syva_core::ZoneSummary]) -> serde_json::Value {
    serde_json::json!({
        "operation": "list_zones",
        "ok": true,
        "zones": zones
            .iter()
            .map(|zone| {
                serde_json::json!({
                    "name": zone.name,
                    "zone_id": zone.zone_id,
                    "state": zone.state,
                    "containers_active": zone.containers_active,
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn comms_json(pairs: &[syva_core_client::syva_core::CommPair]) -> serde_json::Value {
    serde_json::json!({
        "operation": "list_comms",
        "ok": true,
        "comms": pairs
            .iter()
            .map(|pair| {
                serde_json::json!({
                    "zone_a": pair.zone_a,
                    "zone_b": pair.zone_b,
                })
            })
            .collect::<Vec<_>>(),
    })
}

const EXIT_SUCCESS: u8 = 0;
const EXIT_DOMAIN: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_TRANSPORT: u8 = 3;
const EXIT_INTERNAL: u8 = 4;

#[derive(Debug, Clone)]
struct WriteResult {
    operation: &'static str,
    ok: bool,
    result: &'static str,
    reason: Option<String>,
    fields: Vec<(&'static str, serde_json::Value)>,
}

impl WriteResult {
    fn success(operation: &'static str, result: &'static str) -> Self {
        Self {
            operation,
            ok: true,
            result,
            reason: None,
            fields: Vec::new(),
        }
    }

    fn rejection(operation: &'static str, result: &'static str, reason: Option<&str>) -> Self {
        Self {
            operation,
            ok: false,
            result,
            reason: reason.map(str::to_string),
            fields: Vec::new(),
        }
    }

    fn field(mut self, key: &'static str, value: impl Into<serde_json::Value>) -> Self {
        self.fields.push((key, value.into()));
        self
    }

    fn json_value(&self) -> serde_json::Value {
        let mut object = serde_json::Map::new();
        object.insert("operation".to_string(), serde_json::json!(self.operation));
        object.insert("ok".to_string(), serde_json::json!(self.ok));
        object.insert("result".to_string(), serde_json::json!(self.result));
        object.insert("reason".to_string(), serde_json::json!(self.reason));
        for (key, value) in &self.fields {
            object.insert((*key).to_string(), value.clone());
        }
        serde_json::Value::Object(object)
    }

    fn text(&self) -> String {
        let mut lines = vec![
            format!("operation: {}", self.operation),
            format!("ok: {}", self.ok),
            format!("result: {}", self.result),
        ];
        if let Some(reason) = self.reason.as_deref() {
            lines.push(format!("reason: {reason}"));
        }
        for (key, value) in &self.fields {
            lines.push(format!("{}: {}", key.replace('_', "-"), text_value(value)));
        }
        lines.join("\n")
    }
}

fn print_write_result(format: OutputFormat, result: WriteResult) {
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&result.json_value())
                .expect("write result JSON serializes")
        ),
        OutputFormat::Text => println!("{}", result.text()),
    }
}

fn print_command_error(
    format: OutputFormat,
    operation: &'static str,
    result: &'static str,
    reason: &str,
    fields: &[(&'static str, serde_json::Value)],
) {
    let mut output = WriteResult::rejection(operation, result, Some(reason));
    for (key, value) in fields {
        output = output.field(key, value.clone());
    }
    match format {
        OutputFormat::Json => print_write_result(format, output),
        OutputFormat::Text => eprintln!("{}", output.text()),
    }
}

fn print_rpc_error(
    format: OutputFormat,
    operation: &'static str,
    status: tonic::Status,
    fields: &[(&'static str, serde_json::Value)],
) -> u8 {
    let (exit, result) = classify_grpc_status(status.code());
    print_command_error(format, operation, result, status.message(), fields);
    exit
}

fn classify_grpc_status(code: Code) -> (u8, &'static str) {
    match code {
        Code::Unavailable | Code::DeadlineExceeded => (EXIT_TRANSPORT, "transport_error"),
        Code::Internal | Code::DataLoss | Code::Unknown => (EXIT_INTERNAL, "internal_error"),
        Code::InvalidArgument
        | Code::NotFound
        | Code::AlreadyExists
        | Code::FailedPrecondition
        | Code::OutOfRange
        | Code::PermissionDenied
        | Code::Aborted
        | Code::Unauthenticated => (EXIT_DOMAIN, "rejected"),
        _ => (EXIT_INTERNAL, "internal_error"),
    }
}

fn operation_name(command: &Command) -> &'static str {
    match command {
        Command::Status => "status",
        Command::Zones { command } => match command {
            ZonesCommand::List => "list_zones",
            ZonesCommand::Register { .. } => "register_zone",
            ZonesCommand::Remove { .. } => "remove_zone",
        },
        Command::Comms { command } => match command {
            CommsCommand::List { .. } => "list_comms",
            CommsCommand::Allow { .. } => "allow_comm",
            CommsCommand::Deny { .. } => "deny_comm",
        },
        Command::HostPaths { .. } => "register_host_path",
        Command::Events { .. } => "watch_events",
    }
}

fn non_empty_reason(message: &str) -> Option<&str> {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn text_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    }
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

    #[test]
    fn status_json_uses_read_contract_envelope() {
        let json = status_json(&syva_core_client::syva_core::StatusResponse {
            attached: true,
            zones_active: 2,
            containers_active: 1,
            uptime_secs: 42,
            hooks: vec![syva_core_client::syva_core::HookStatus {
                hook: "file_open".to_string(),
                allow: 3,
                deny: 4,
                error: 0,
                lost: 0,
            }],
            max_zones: 64,
        });

        assert_eq!(json["operation"], "status");
        assert_eq!(json["ok"], true);
        assert_eq!(json["status"]["attached"], true);
        assert_eq!(json["status"]["zones_active"], 2);
        assert_eq!(json["status"]["hooks"][0]["hook"], "file_open");
    }

    #[test]
    fn zones_json_uses_read_contract_envelope() {
        let json = zones_json(&[syva_core_client::syva_core::ZoneSummary {
            name: "zone-a".to_string(),
            zone_id: 7,
            state: "active".to_string(),
            containers_active: 1,
        }]);

        assert_eq!(json["operation"], "list_zones");
        assert_eq!(json["ok"], true);
        assert_eq!(json["zones"][0]["name"], "zone-a");
        assert_eq!(json["zones"][0]["zone_id"], 7);
    }

    #[test]
    fn comms_json_uses_read_contract_envelope() {
        let json = comms_json(&[syva_core_client::syva_core::CommPair {
            zone_a: "zone-a".to_string(),
            zone_b: "zone-b".to_string(),
        }]);

        assert_eq!(json["operation"], "list_comms");
        assert_eq!(json["ok"], true);
        assert_eq!(json["comms"][0]["zone_a"], "zone-a");
        assert_eq!(json["comms"][0]["zone_b"], "zone-b");
    }

    #[test]
    fn zones_register_help_is_valid() {
        Cli::try_parse_from(["syvactl", "zones", "register", "--help"])
            .expect_err("help exits early");
    }

    #[test]
    fn zones_remove_help_is_valid() {
        Cli::try_parse_from(["syvactl", "zones", "remove", "--help"])
            .expect_err("help exits early");
    }

    #[test]
    fn host_paths_register_help_is_valid() {
        Cli::try_parse_from(["syvactl", "host-paths", "register", "--help"])
            .expect_err("help exits early");
    }

    #[test]
    fn comms_allow_help_is_valid() {
        Cli::try_parse_from(["syvactl", "comms", "allow", "--help"]).expect_err("help exits early");
    }

    #[test]
    fn comms_deny_help_is_valid() {
        Cli::try_parse_from(["syvactl", "comms", "deny", "--help"]).expect_err("help exits early");
    }

    #[test]
    fn no_remote_flags_exist() {
        let command = Cli::command();
        assert!(command
            .get_arguments()
            .all(|arg| arg.get_long() != Some("ssh") && arg.get_long() != Some("host")));
    }

    #[test]
    fn write_success_json_has_contract_keys() {
        let result = WriteResult::success("allow_comm", "applied")
            .field("source_zone", "zone-a")
            .field("target_zone", "zone-b");
        let json = result.json_value();
        assert_eq!(json["operation"], "allow_comm");
        assert_eq!(json["ok"], true);
        assert_eq!(json["result"], "applied");
        assert_eq!(json["reason"], serde_json::Value::Null);
        assert_eq!(json["source_zone"], "zone-a");
        assert_eq!(json["target_zone"], "zone-b");
    }

    #[test]
    fn write_rejection_json_has_reason() {
        let result = WriteResult::rejection(
            "remove_zone",
            "rejected",
            Some("zone has active memberships"),
        )
        .field("zone_id", "zone-a");
        let json = result.json_value();
        assert_eq!(json["operation"], "remove_zone");
        assert_eq!(json["ok"], false);
        assert_eq!(json["result"], "rejected");
        assert_eq!(json["reason"], "zone has active memberships");
        assert_eq!(json["zone_id"], "zone-a");
    }

    #[test]
    fn write_success_text_contains_important_fields() {
        let text = WriteResult::success("register_zone", "applied")
            .field("zone_id", "zone-a")
            .field("zone_type", "standard")
            .text();
        assert!(text.contains("operation: register_zone"));
        assert!(text.contains("ok: true"));
        assert!(text.contains("result: applied"));
        assert!(text.contains("zone-id: zone-a"));
        assert!(text.contains("zone-type: standard"));
    }

    #[test]
    fn invalid_args_are_cli_usage() {
        let error =
            Cli::try_parse_from(["syvactl", "zones", "register"]).expect_err("missing zone");
        assert_eq!(error.exit_code(), i32::from(EXIT_USAGE));
    }

    #[test]
    fn grpc_status_classification_matches_contract() {
        assert_eq!(
            classify_grpc_status(Code::Unavailable),
            (EXIT_TRANSPORT, "transport_error")
        );
        assert_eq!(
            classify_grpc_status(Code::Internal),
            (EXIT_INTERNAL, "internal_error")
        );
        assert_eq!(
            classify_grpc_status(Code::NotFound),
            (EXIT_DOMAIN, "rejected")
        );
    }
}
