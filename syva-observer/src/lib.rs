//! Read-only, bounded materialized view of Syvä enforcement.

use serde::{Deserialize, Serialize};
use syva_core_client::syva_core::{DenyEvent, StatusResponse};

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObserverState {
    pub enforcement: EnforcementState,
    pub recent_events: Vec<ObservationEvent>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EnforcementState {
    pub active: bool,
    pub mode: String,
    pub lifecycle: String,
    pub generation: u64,
    pub hooks: Vec<HookState>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HookState {
    pub name: String,
    pub denies: u64,
    pub errors: u64,
    pub lost: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ObservationEvent {
    pub kind: String,
    pub decision: String,
    pub hook: String,
    pub zone: String,
    pub target_zone: String,
    pub path: String,
    pub destination: String,
}

impl ObserverState {
    pub const MAX_RECENT_EVENTS: usize = 1024;
    pub const EXPECTED_HOOKS: usize = 9;

    pub fn from_status(status: StatusResponse) -> Self {
        Self {
            enforcement: EnforcementState {
                active: status.attached,
                mode: status.enforcement_mode,
                lifecycle: status.lifecycle_state,
                generation: status.active_generation,
                hooks: status
                    .hooks
                    .into_iter()
                    .map(|hook| HookState {
                        name: hook.hook,
                        denies: hook.deny,
                        errors: hook.error,
                        lost: hook.lost,
                    })
                    .collect(),
            },
            recent_events: Vec::new(),
        }
    }

    pub fn push_event(&mut self, event: DenyEvent) {
        self.recent_events.push(ObservationEvent {
            kind: "operation.denied".into(),
            decision: event.decision,
            hook: event.hook,
            zone: event.zone,
            target_zone: event.target_zone,
            path: event.path,
            destination: event.dst_ip,
        });
        if self.recent_events.len() > Self::MAX_RECENT_EVENTS {
            self.recent_events.remove(0);
        }
    }

    pub fn posture(&self) -> Posture {
        if !self.enforcement.active {
            return Posture::Unknown;
        }
        if self.enforcement.mode == "enforce"
            && self.enforcement.lifecycle == "active"
            && self.enforcement.generation > 0
            && self.enforcement.hooks.len() == Self::EXPECTED_HOOKS
            && self.enforcement.hooks.iter().all(|hook| hook.errors == 0)
        {
            Posture::Protected
        } else if self.enforcement.lifecycle == "unsafe" {
            Posture::Exposed
        } else {
            Posture::Degraded
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Posture {
    Protected,
    Degraded,
    Exposed,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posture_requires_active_enforcement_and_generation() {
        let mut state = ObserverState::default();
        assert_eq!(state.posture(), Posture::Unknown);
        state.enforcement = EnforcementState {
            active: true,
            mode: "enforce".into(),
            lifecycle: "active".into(),
            generation: 1,
            hooks: (0..ObserverState::EXPECTED_HOOKS)
                .map(|index| HookState {
                    name: index.to_string(),
                    denies: 0,
                    errors: 0,
                    lost: 0,
                })
                .collect(),
        };
        assert_eq!(state.posture(), Posture::Protected);
    }

    #[test]
    fn missing_hooks_cannot_be_protected() {
        let state = ObserverState {
            enforcement: EnforcementState {
                active: true,
                mode: "enforce".into(),
                lifecycle: "active".into(),
                generation: 1,
                hooks: vec![],
            },
            ..ObserverState::default()
        };
        assert_eq!(state.posture(), Posture::Degraded);
    }

    #[test]
    fn unsafe_lifecycle_is_exposed() {
        let state = ObserverState {
            enforcement: EnforcementState {
                active: true,
                lifecycle: "unsafe".into(),
                ..EnforcementState::default()
            },
            ..ObserverState::default()
        };
        assert_eq!(state.posture(), Posture::Exposed);
    }

    #[test]
    fn recent_events_are_bounded() {
        let mut state = ObserverState::default();
        for _ in 0..=ObserverState::MAX_RECENT_EVENTS {
            state.push_event(DenyEvent::default());
        }
        assert_eq!(state.recent_events.len(), ObserverState::MAX_RECENT_EVENTS);
    }
}
