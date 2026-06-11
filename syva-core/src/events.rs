//! Ring buffer event reader for syva.

use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use syva_ebpf_common::{EnforcementEvent, DECISION_ALLOW, DECISION_DENY, DECISION_WOULD_DENY};
use tokio_util::sync::CancellationToken;

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

/// Human label for an EnforcementEvent decision byte. WOULD_DENY is emitted
/// in audit mode (violation recorded, operation proceeded); ESCAPE is emitted
/// by the cgroup-escape detector (a zoned task left its zone, not prevented).
pub fn decision_label(decision: u8) -> &'static str {
    match decision {
        DECISION_DENY => "DENY",
        DECISION_ALLOW => "ALLOW",
        DECISION_WOULD_DENY => "WOULD_DENY",
        syva_ebpf_common::DECISION_ESCAPE => "ESCAPE",
        _ => "UNKNOWN",
    }
}

/// Human label for an EnforcementEvent hook byte, including the cgroup-escape
/// sentinel that intentionally sits outside the nine LSM hook indices.
pub fn hook_label(hook: u8) -> &'static str {
    if hook == syva_ebpf_common::HOOK_CGROUP_ESCAPE {
        return "cgroup_escape";
    }
    HOOK_NAMES.get(hook as usize).copied().unwrap_or("unknown")
}

/// Maximum events to drain per tick. Prevents the blocking task from
/// holding the thread for too long under high deny rates.
#[allow(dead_code)]
const MAX_EVENTS_PER_TICK: usize = 1000;

#[allow(dead_code)]
pub fn spawn_event_reader(ring_buf: RingBuf<MapData>, cancel: CancellationToken) {
    tokio::spawn(async move {
        let mut ring_buf = ring_buf;
        let mut interval = tokio::time::interval(Duration::from_millis(100));
        tracing::info!("enforcement event reader started");

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    tracing::info!("enforcement event reader stopped");
                    return;
                }
                _ = interval.tick() => {
                    // Drain ring buffer in a blocking context to avoid starving
                    // the async executor under high deny rates.
                    let events = tokio::task::block_in_place(|| {
                        let mut events = Vec::new();
                        while let Some(item) = ring_buf.next() {
                            if item.len() < std::mem::size_of::<EnforcementEvent>() {
                                continue;
                            }
                            let event: EnforcementEvent = unsafe {
                                std::ptr::read_unaligned(item.as_ptr() as *const EnforcementEvent)
                            };
                            events.push(event);
                            if events.len() >= MAX_EVENTS_PER_TICK {
                                break;
                            }
                        }
                        events
                    });

                    if events.len() >= MAX_EVENTS_PER_TICK {
                        tracing::warn!(
                            drained = events.len(),
                            "ring buffer drain hit cap — events may be lost"
                        );
                    }

                    for event in &events {
                        let hook = hook_label(event.hook);
                        let decision = decision_label(event.decision);
                        if event.caller_zone == 0 {
                            tracing::debug!(
                                hook = hook,
                                pid = event.pid,
                                target_zone = event.target_zone,
                                "unzoned process hit enforcement — possible missing annotation"
                            );
                        }
                        tracing::warn!(
                            hook = hook,
                            decision = decision,
                            pid = event.pid,
                            caller_zone = event.caller_zone,
                            target_zone = event.target_zone,
                            context = event.context,
                            "enforcement event"
                        );
                    }
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn decision_label_distinguishes_audit_would_deny_from_deny() {
        assert_eq!(decision_label(DECISION_DENY), "DENY");
        assert_eq!(decision_label(DECISION_ALLOW), "ALLOW");
        assert_eq!(decision_label(DECISION_WOULD_DENY), "WOULD_DENY");
        assert_eq!(decision_label(syva_ebpf_common::DECISION_ESCAPE), "ESCAPE");
        assert_eq!(decision_label(254), "UNKNOWN");
    }

    #[test]
    fn hook_label_maps_escape_sentinel_outside_the_seven_hooks() {
        assert_eq!(hook_label(0), "file_open");
        assert_eq!(hook_label(6), "socket_connect");
        assert_eq!(
            hook_label(syva_ebpf_common::HOOK_CGROUP_ESCAPE),
            "cgroup_escape"
        );
        assert_eq!(hook_label(50), "unknown");
    }
}
