//! Ring buffer event reader for syva.

use std::time::Duration;

use aya::maps::{MapData, RingBuf};
use syva_ebpf_common::{EnforcementEvent, DECISION_DENY};
use tokio_util::sync::CancellationToken;

const HOOK_NAMES: [&str; 5] = [
    "file_open",
    "bprm_check",
    "ptrace_access_check",
    "task_kill",
    "cgroup_attach_task",
];

/// Maximum events to drain per tick. Prevents the blocking task from
/// holding the thread for too long under high deny rates.
const MAX_EVENTS_PER_TICK: usize = 1000;

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
                        let hook = HOOK_NAMES.get(event.hook as usize).unwrap_or(&"unknown");
                        let decision = match event.decision {
                            DECISION_DENY => "DENY",
                            syva_ebpf_common::DECISION_ALLOW => "ALLOW",
                            _ => "UNKNOWN",
                        };
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
