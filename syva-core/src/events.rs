//! The enforcement event pump: drain → enrich → fan out.
//!
//! The core owns the ENFORCEMENT_EVENTS ring buffer (single-consumer) and
//! drains it continuously, whether or not anyone is watching. Each raw
//! kernel event is enriched once into the canonical proto `DenyEvent`
//! (zone names, comm, path, destination, reason fields) and fanned out to
//! every sink: the gRPC broadcast for `WatchEvents` subscribers, the core
//! log (one constant-named line per event, all variance in fields), and
//! per-zone deny metrics. Deny events are evidence — they are never sampled.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use syva_ebpf_common::{
    EnforcementEvent, AF_INET, AF_INET6, DECISION_DENY, DECISION_ESCAPE, DECISION_WOULD_DENY,
    HOOK_BPRM_CHECK, HOOK_CGROUP_ESCAPE, HOOK_FILE_OPEN, HOOK_MMAP_FILE, HOOK_SOCKET_BIND,
    HOOK_SOCKET_CONNECT, HOOK_SOCKET_SENDMSG,
};
use syva_proto::syva_core::DenyEvent;
use tokio::sync::{broadcast, RwLock};
use tokio_util::sync::CancellationToken;

use crate::ebpf::InodePathIndex;
use crate::health::SharedHealth;
use crate::zone::ZoneRegistry;

pub const HOOK_NAMES: [&str; 9] = [
    "file_open",
    "bprm_check_security",
    "ptrace_access_check",
    "task_kill",
    "mmap_file",
    "unix_stream_connect",
    "socket_connect",
    "socket_sendmsg",
    "socket_bind",
];

/// Maximum events to drain per tick. Prevents the blocking task from
/// holding the thread for too long under high deny rates.
const MAX_EVENTS_PER_TICK: usize = 1000;

/// Broadcast capacity for WatchEvents subscribers. A subscriber that lags
/// more than this many events behind gets a counted gap, not a stall.
const BROADCAST_CAPACITY: usize = 1024;

/// Wire label for an EnforcementEvent decision byte. WOULD_DENY is emitted
/// in audit mode (violation recorded, operation proceeded); ESCAPE is emitted
/// by the cgroup-escape detector (a zoned task left its zone, not prevented).
pub fn decision_label(decision: u8) -> &'static str {
    match decision {
        DECISION_DENY => "deny",
        DECISION_WOULD_DENY => "would_deny",
        DECISION_ESCAPE => "escape",
        _ => "unknown",
    }
}

/// Human label for an EnforcementEvent hook byte, including the cgroup-escape
/// sentinel that intentionally sits outside the nine LSM hook indices.
pub fn hook_label(hook: u8) -> &'static str {
    if hook == HOOK_CGROUP_ESCAPE {
        return "cgroup_escape";
    }
    HOOK_NAMES.get(hook as usize).copied().unwrap_or("unknown")
}

/// Stable FALSE-protocol reason fields, templated per (hook, decision).
/// One phrasing per event type so streams read consistently — never ad-hoc
/// prose per event.
pub struct ReasonTemplate {
    pub what_failed: &'static str,
    pub why_it_matters: &'static str,
    pub possible_causes: &'static [&'static str],
}

pub fn reason_for(hook: u8, decision: u8) -> ReasonTemplate {
    if decision == DECISION_ESCAPE {
        return ReasonTemplate {
            what_failed: "a zoned task migrated out of its zone cgroup",
            why_it_matters: "the task left enforcement scope; its zone policy no longer applies",
            possible_causes: &[
                "operator moved the process between cgroups",
                "container runtime restructured cgroups",
                "deliberate escape attempt",
            ],
        };
    }
    match hook {
        HOOK_FILE_OPEN => ReasonTemplate {
            what_failed: "cross-zone file open",
            why_it_matters: "a workload read another zone's protected file",
            possible_causes: &[
                "missing AllowComm between the zones",
                "file registered to the wrong zone",
                "workload attached to the wrong zone",
            ],
        },
        HOOK_BPRM_CHECK => ReasonTemplate {
            what_failed: "cross-zone exec",
            why_it_matters: "a workload executed another zone's binary",
            possible_causes: &[
                "missing AllowComm between the zones",
                "binary registered to the wrong zone",
            ],
        },
        HOOK_MMAP_FILE => ReasonTemplate {
            what_failed: "cross-zone executable mmap",
            why_it_matters: "a workload mapped another zone's file as executable code",
            possible_causes: &[
                "missing AllowComm between the zones",
                "shared library registered to the wrong zone",
            ],
        },
        HOOK_SOCKET_CONNECT | HOOK_SOCKET_SENDMSG => ReasonTemplate {
            what_failed: "network egress outside zone policy",
            why_it_matters: "a zoned workload reached for a destination its policy does not allow",
            possible_causes: &[
                "zone is network-locked (Isolated) and the destination is not allowlisted",
                "destination pod is in another zone without AllowComm",
                "missing egress CIDR allowlist entry",
            ],
        },
        HOOK_SOCKET_BIND => ReasonTemplate {
            what_failed: "non-loopback listener bind in a locked zone",
            why_it_matters: "a network-locked workload tried to expose a service on the network",
            possible_causes: &[
                "zone is network-locked (Isolated)",
                "service should run in a Bridged zone or be allowlisted",
            ],
        },
        // ptrace / task_kill / unix_stream_connect share the
        // cross-zone-process shape.
        _ => ReasonTemplate {
            what_failed: "cross-zone process interaction",
            why_it_matters: "a workload signaled, traced, or connected to another zone's process",
            possible_causes: &[
                "missing AllowComm between the zones",
                "workload attached to the wrong zone",
            ],
        },
    }
}

/// One sink for enriched events. Batch-level so sinks can aggregate (the
/// metrics sink takes one lock per tick, not per event).
#[tonic::async_trait]
pub trait EventSink: Send + Sync {
    async fn emit(&self, events: &[DenyEvent]);
}

/// Fan events into the WatchEvents broadcast. `send` failing means there are
/// currently zero subscribers — the normal idle state, not an error.
pub struct BroadcastSink(pub broadcast::Sender<DenyEvent>);

#[tonic::async_trait]
impl EventSink for BroadcastSink {
    async fn emit(&self, events: &[DenyEvent]) {
        for event in events {
            let _ = self.0.send(event.clone());
        }
    }
}

/// Emit each event into the core log with a constant event name and all
/// variance in fields. Denies and escapes are WARN; audit-mode would-denies
/// are INFO (audit rollouts are high-volume by design).
pub struct LogSink;

#[tonic::async_trait]
impl EventSink for LogSink {
    async fn emit(&self, events: &[DenyEvent]) {
        for e in events {
            macro_rules! log_event {
                ($level:ident, $name:expr) => {
                    tracing::$level!(
                        event = $name,
                        component = "syva-core",
                        hook = %e.hook,
                        zone = %e.zone,
                        target_zone = %e.target_zone,
                        pid = e.pid,
                        comm = %e.comm,
                        path = %e.path,
                        dst_ip = %e.dst_ip,
                        dst_port = e.dst_port,
                        what_failed = %e.what_failed,
                        "{}", e.why_it_matters
                    )
                };
            }
            match e.decision.as_str() {
                "would_deny" => log_event!(info, "syva.enforcement.would_deny"),
                "escape" => log_event!(warn, "syva.cgroup.escape"),
                _ => log_event!(warn, "syva.enforcement.denied"),
            }
        }
    }
}

/// Aggregate per-(zone, hook) deny counts into health state for /metrics.
pub struct MetricsSink(pub SharedHealth);

#[tonic::async_trait]
impl EventSink for MetricsSink {
    async fn emit(&self, events: &[DenyEvent]) {
        let mut counts: std::collections::HashMap<(String, String), u64> =
            std::collections::HashMap::new();
        for e in events {
            *counts.entry((e.zone.clone(), e.hook.clone())).or_default() += 1;
        }
        if !counts.is_empty() {
            self.0.write().await.record_zone_denies(counts);
        }
    }
}

/// Channel WatchEvents subscribers attach to.
pub fn event_channel() -> broadcast::Sender<DenyEvent> {
    broadcast::channel(BROADCAST_CAPACITY).0
}

/// NUL-trimmed task comm.
fn comm_string(comm: &[u8; 16]) -> String {
    let end = comm.iter().position(|&b| b == 0).unwrap_or(comm.len());
    String::from_utf8_lossy(&comm[..end]).into_owned()
}

/// Render the destination IP for socket hooks; empty for everything else.
/// The address family travels in `context` for the socket hooks.
fn dst_ip_string(event: &EnforcementEvent) -> String {
    let is_socket_hook = event.hook == HOOK_SOCKET_CONNECT
        || event.hook == HOOK_SOCKET_SENDMSG
        || event.hook == HOOK_SOCKET_BIND;
    if !is_socket_hook {
        return String::new();
    }
    match event.context as u16 {
        AF_INET => {
            let mut four = [0u8; 4];
            four.copy_from_slice(&event.dst_addr[..4]);
            Ipv4Addr::from(four).to_string()
        }
        AF_INET6 => Ipv6Addr::from(event.dst_addr).to_string(),
        _ => String::new(),
    }
}

/// Enrich one raw kernel event into the canonical wire event.
pub fn enrich(
    raw: &EnforcementEvent,
    zone_name: impl Fn(u32) -> String,
    paths: &InodePathIndex,
) -> DenyEvent {
    let is_file_hook =
        raw.hook == HOOK_FILE_OPEN || raw.hook == HOOK_BPRM_CHECK || raw.hook == HOOK_MMAP_FILE;
    let inode = if is_file_hook { raw.context } else { 0 };
    let path = if is_file_hook {
        paths
            .read()
            .ok()
            .and_then(|index| index.get(&(raw.target_zone, raw.context)).cloned())
            .unwrap_or_default()
    } else {
        String::new()
    };
    let reason = reason_for(raw.hook, raw.decision);

    DenyEvent {
        timestamp_ns: raw.timestamp_ns,
        hook: hook_label(raw.hook).to_string(),
        zone_id: raw.caller_zone,
        target_zone_id: raw.target_zone,
        pid: raw.pid,
        comm: comm_string(&raw.comm),
        inode,
        context: raw.context.to_string(),
        decision: decision_label(raw.decision).to_string(),
        zone: zone_name(raw.caller_zone),
        target_zone: zone_name(raw.target_zone),
        path,
        dst_ip: dst_ip_string(raw),
        dst_port: u16::from_be(raw.dst_port) as u32,
        what_failed: reason.what_failed.to_string(),
        why_it_matters: reason.why_it_matters.to_string(),
        possible_causes: reason
            .possible_causes
            .iter()
            .map(|c| c.to_string())
            .collect(),
    }
}

/// Spawn the always-on event pump. Owns the ring buffer for the core's
/// lifetime; every enforcement event flows through here exactly once.
pub fn spawn_event_pump(
    ring_buf: RingBuf<MapData>,
    registry: Arc<RwLock<ZoneRegistry>>,
    paths: InodePathIndex,
    sinks: Vec<Box<dyn EventSink>>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let mut ring_buf = ring_buf;
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        tracing::info!(
            event = "syva.events.pump_started",
            component = "syva-core",
            sinks = sinks.len(),
            "enforcement event pump started"
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!(
                        event = "syva.events.pump_stopped",
                        component = "syva-core",
                        "enforcement event pump stopped"
                    );
                    return;
                }
                _ = interval.tick() => {
                    let raw_events = tokio::task::block_in_place(|| {
                        let mut out = Vec::new();
                        while let Some(item) = ring_buf.next() {
                            if item.len() < std::mem::size_of::<EnforcementEvent>() {
                                continue;
                            }
                            let event: EnforcementEvent = unsafe {
                                std::ptr::read_unaligned(item.as_ptr() as *const EnforcementEvent)
                            };
                            out.push(event);
                            if out.len() >= MAX_EVENTS_PER_TICK {
                                break;
                            }
                        }
                        out
                    });
                    if raw_events.is_empty() {
                        continue;
                    }
                    if raw_events.len() >= MAX_EVENTS_PER_TICK {
                        tracing::warn!(
                            drained = raw_events.len(),
                            "event drain hit per-tick cap — backlog continues next tick"
                        );
                    }

                    // One registry read per batch, not per event.
                    let batch: Vec<DenyEvent> = {
                        let registry = registry.read().await;
                        raw_events
                            .iter()
                            .filter(|raw| matches!(
                                raw.decision,
                                DECISION_DENY | DECISION_WOULD_DENY | DECISION_ESCAPE
                            ))
                            .map(|raw| enrich(raw, |id| registry.zone_display_name(id), &paths))
                            .collect()
                    };
                    if batch.is_empty() {
                        continue;
                    }
                    for sink in &sinks {
                        sink.emit(&batch).await;
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use syva_ebpf_common::{HOOK_PTRACE_CHECK, HOOK_TASK_KILL, HOOK_UNIX_CONNECT};

    fn raw_event(hook: u8, decision: u8) -> EnforcementEvent {
        EnforcementEvent {
            timestamp_ns: 1,
            pid: 42,
            hook,
            decision,
            dst_port: 0,
            caller_zone: 1,
            target_zone: 2,
            context: 0,
            comm: *b"cat\0\0\0\0\0\0\0\0\0\0\0\0\0",
            dst_addr: [0; 16],
        }
    }

    #[test]
    fn hook_names_count_is_nine() {
        assert_eq!(HOOK_NAMES.len(), 9);
        assert!(HOOK_NAMES.contains(&"socket_connect"));
        assert!(HOOK_NAMES.contains(&"socket_sendmsg"));
        assert!(HOOK_NAMES.contains(&"socket_bind"));
        assert!(!HOOK_NAMES.contains(&"cgroup_attach_task"));
    }

    #[test]
    fn hook_names_are_non_empty() {
        for name in &HOOK_NAMES {
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn reason_templates_cover_every_hook_and_decision() {
        let hooks = [
            HOOK_FILE_OPEN,
            HOOK_BPRM_CHECK,
            HOOK_PTRACE_CHECK,
            HOOK_TASK_KILL,
            HOOK_MMAP_FILE,
            HOOK_UNIX_CONNECT,
            HOOK_SOCKET_CONNECT,
            HOOK_SOCKET_SENDMSG,
            HOOK_SOCKET_BIND,
            HOOK_CGROUP_ESCAPE,
        ];
        for hook in hooks {
            for decision in [DECISION_DENY, DECISION_WOULD_DENY, DECISION_ESCAPE] {
                let reason = reason_for(hook, decision);
                assert!(!reason.what_failed.is_empty());
                assert!(!reason.why_it_matters.is_empty());
                assert!(!reason.possible_causes.is_empty());
            }
        }
    }

    #[test]
    fn comm_is_nul_trimmed() {
        let raw = raw_event(HOOK_FILE_OPEN, DECISION_DENY);
        let event = enrich(&raw, |id| format!("z{id}"), &InodePathIndex::default());
        assert_eq!(event.comm, "cat");
        assert_eq!(event.zone, "z1");
        assert_eq!(event.target_zone, "z2");
        assert_eq!(event.decision, "deny");
    }

    #[test]
    fn file_hook_gets_inode_and_path() {
        let paths = InodePathIndex::default();
        paths
            .write()
            .unwrap()
            .insert((2, 777), "/srv/secret.txt".to_string());
        let mut raw = raw_event(HOOK_FILE_OPEN, DECISION_DENY);
        raw.context = 777;
        let event = enrich(&raw, |id| format!("z{id}"), &paths);
        assert_eq!(event.inode, 777);
        assert_eq!(event.path, "/srv/secret.txt");
        assert_eq!(event.dst_ip, "");

        // Unregistered inode → empty path, inode still reported.
        raw.context = 778;
        let event = enrich(&raw, |id| format!("z{id}"), &paths);
        assert_eq!(event.inode, 778);
        assert_eq!(event.path, "");
    }

    #[test]
    fn socket_hooks_render_destination() {
        let mut raw = raw_event(HOOK_SOCKET_CONNECT, DECISION_DENY);
        raw.context = AF_INET as u64;
        raw.dst_addr[..4].copy_from_slice(&[10, 1, 2, 3]);
        raw.dst_port = 5432u16.to_be();
        let event = enrich(&raw, |id| format!("z{id}"), &InodePathIndex::default());
        assert_eq!(event.dst_ip, "10.1.2.3");
        assert_eq!(event.dst_port, 5432);
        assert_eq!(event.inode, 0);

        let mut raw6 = raw_event(HOOK_SOCKET_SENDMSG, DECISION_DENY);
        raw6.context = AF_INET6 as u64;
        raw6.dst_addr = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let event6 = enrich(&raw6, |id| format!("z{id}"), &InodePathIndex::default());
        assert_eq!(event6.dst_ip, "::1");

        // Zeroed/unknown family → empty.
        let raw_none = raw_event(HOOK_SOCKET_BIND, DECISION_DENY);
        let event_none = enrich(&raw_none, |id| format!("z{id}"), &InodePathIndex::default());
        assert_eq!(event_none.dst_ip, "");
    }

    #[tokio::test]
    async fn broadcast_sink_tolerates_zero_subscribers() {
        let sink = BroadcastSink(event_channel());
        let raw = raw_event(HOOK_FILE_OPEN, DECISION_DENY);
        let event = enrich(&raw, |id| format!("z{id}"), &InodePathIndex::default());
        sink.emit(&[event]).await; // must not panic or error
    }
}
