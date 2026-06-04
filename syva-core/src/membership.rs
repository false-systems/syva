//! Workload membership reconciliation.
//!
//! This module owns the userspace view of container/pod/process membership and
//! returns explicit BPF map update intents for the caller to apply.

use std::collections::HashMap;
use std::time::SystemTime;

use crate::types::ZoneType;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodIdentity {
    pub namespace: String,
    pub name: String,
    pub uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipObservation {
    pub container_id: String,
    pub pod: Option<PodIdentity>,
    pub cgroup_id: u64,
    pub zone_name: String,
    pub source: MembershipSource,
    pub generation: u64,
    pub observed_at: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipSource {
    LocalGrpc,
    FileAdapter,
    KubernetesAdapter,
    ApiAdapter,
    Other(String),
}

impl MembershipSource {
    pub fn from_label(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "local" | "local-grpc" | "grpc" => Self::LocalGrpc,
            "file" | "syva-file" => Self::FileAdapter,
            "k8s" | "kubernetes" | "syva-k8s" => Self::KubernetesAdapter,
            "api" | "syva-api" => Self::ApiAdapter,
            other => Self::Other(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipRecord {
    pub observation: MembershipObservation,
    pub zone_id: u32,
    pub zone_type: ZoneType,
    pub applied: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BpfMembershipIntent {
    Add {
        cgroup_id: u64,
        zone_id: u32,
        zone_type: ZoneType,
    },
    Remove {
        cgroup_id: u64,
        zone_id: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipOutcome {
    Applied {
        intent: BpfMembershipIntent,
    },
    Unchanged {
        intent: BpfMembershipIntent,
    },
    Removed {
        intent: BpfMembershipIntent,
    },
    NotFound,
    Stale {
        existing_generation: u64,
    },
    Conflict {
        existing_zone: String,
        requested_zone: String,
        existing_generation: u64,
    },
}

#[derive(Debug, Default)]
pub struct MembershipService {
    by_container: HashMap<String, MembershipRecord>,
    conflicts: u64,
    stale_updates: u64,
}

impl MembershipService {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observe_upsert(
        &mut self,
        observation: MembershipObservation,
        zone_id: u32,
        zone_type: ZoneType,
    ) -> MembershipOutcome {
        if let Some(existing) = self.by_container.get(&observation.container_id) {
            if observation.generation != 0
                && existing.observation.generation != 0
                && observation.generation < existing.observation.generation
            {
                self.stale_updates += 1;
                return MembershipOutcome::Stale {
                    existing_generation: existing.observation.generation,
                };
            }

            if existing.observation.zone_name != observation.zone_name {
                self.conflicts += 1;
                return MembershipOutcome::Conflict {
                    existing_zone: existing.observation.zone_name.clone(),
                    requested_zone: observation.zone_name,
                    existing_generation: existing.observation.generation,
                };
            }

            let intent = BpfMembershipIntent::Add {
                cgroup_id: observation.cgroup_id,
                zone_id,
                zone_type,
            };

            if existing.observation.cgroup_id != observation.cgroup_id {
                self.conflicts += 1;
                return MembershipOutcome::Conflict {
                    existing_zone: existing.observation.zone_name.clone(),
                    requested_zone: observation.zone_name,
                    existing_generation: existing.observation.generation,
                };
            }

            if existing.zone_id != zone_id || existing.zone_type != zone_type {
                self.conflicts += 1;
                return MembershipOutcome::Conflict {
                    existing_zone: existing.observation.zone_name.clone(),
                    requested_zone: observation.zone_name,
                    existing_generation: existing.observation.generation,
                };
            }

            if existing.zone_id == zone_id && existing.zone_type == zone_type {
                let applied = existing.applied;
                let generation = if observation.generation == 0 {
                    existing.observation.generation
                } else {
                    observation.generation
                };
                let mut observation = observation;
                observation.generation = generation;
                self.by_container.insert(
                    observation.container_id.clone(),
                    MembershipRecord {
                        observation,
                        zone_id,
                        zone_type,
                        applied,
                    },
                );
                return MembershipOutcome::Unchanged { intent };
            }
        }

        let intent = BpfMembershipIntent::Add {
            cgroup_id: observation.cgroup_id,
            zone_id,
            zone_type,
        };
        self.by_container.insert(
            observation.container_id.clone(),
            MembershipRecord {
                observation,
                zone_id,
                zone_type,
                applied: false,
            },
        );
        MembershipOutcome::Applied { intent }
    }

    pub fn mark_applied(&mut self, container_id: &str) {
        if let Some(record) = self.by_container.get_mut(container_id) {
            record.applied = true;
        }
    }

    pub fn remove(&mut self, container_id: &str, generation: Option<u64>) -> MembershipOutcome {
        let Some(existing) = self.by_container.get(container_id) else {
            return MembershipOutcome::NotFound;
        };

        if generation
            .map(|generation| generation < existing.observation.generation)
            .unwrap_or(false)
        {
            self.stale_updates += 1;
            return MembershipOutcome::Stale {
                existing_generation: existing.observation.generation,
            };
        }

        let Some(existing) = self.by_container.remove(container_id) else {
            return MembershipOutcome::NotFound;
        };
        MembershipOutcome::Removed {
            intent: BpfMembershipIntent::Remove {
                cgroup_id: existing.observation.cgroup_id,
                zone_id: existing.zone_id,
            },
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn resolve_container(&self, container_id: &str) -> Option<&MembershipRecord> {
        self.by_container.get(container_id)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn resolve_cgroup(&self, cgroup_id: u64) -> Option<&MembershipRecord> {
        self.by_container
            .values()
            .find(|record| record.observation.cgroup_id == cgroup_id)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn list(&self) -> impl Iterator<Item = &MembershipRecord> {
        self.by_container.values()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn conflicts(&self) -> u64 {
        self.conflicts
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn stale_updates(&self) -> u64 {
        self.stale_updates
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn pending_count(&self) -> usize {
        self.by_container
            .values()
            .filter(|record| !record.applied)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(container_id: &str, zone_name: &str, generation: u64) -> MembershipObservation {
        MembershipObservation {
            container_id: container_id.to_string(),
            pod: Some(PodIdentity {
                namespace: "default".to_string(),
                name: "web".to_string(),
                uid: "pod-uid".to_string(),
            }),
            cgroup_id: 42,
            zone_name: zone_name.to_string(),
            source: MembershipSource::KubernetesAdapter,
            generation,
            observed_at: SystemTime::UNIX_EPOCH,
        }
    }

    #[test]
    fn upsert_membership_produces_bpf_intent() {
        let mut service = MembershipService::new();

        let outcome =
            service.observe_upsert(observation("container-a", "web", 1), 7, ZoneType::NonGlobal);

        assert_eq!(
            outcome,
            MembershipOutcome::Applied {
                intent: BpfMembershipIntent::Add {
                    cgroup_id: 42,
                    zone_id: 7,
                    zone_type: ZoneType::NonGlobal,
                },
            }
        );
        assert_eq!(service.resolve_container("container-a").unwrap().zone_id, 7);
        assert_eq!(service.pending_count(), 1);
    }

    #[test]
    fn mark_applied_clears_pending_state() {
        let mut service = MembershipService::new();
        service.observe_upsert(observation("container-a", "web", 1), 7, ZoneType::NonGlobal);

        service.mark_applied("container-a");

        assert_eq!(service.pending_count(), 0);
    }

    #[test]
    fn duplicate_update_is_idempotent() {
        let mut service = MembershipService::new();
        let obs = observation("container-a", "web", 1);
        service.observe_upsert(obs.clone(), 7, ZoneType::NonGlobal);

        let outcome = service.observe_upsert(obs, 7, ZoneType::NonGlobal);

        assert!(matches!(outcome, MembershipOutcome::Unchanged { .. }));
        assert_eq!(service.list().count(), 1);
    }

    #[test]
    fn newer_same_binding_is_idempotent() {
        let mut service = MembershipService::new();
        service.observe_upsert(observation("container-a", "web", 1), 7, ZoneType::NonGlobal);

        let outcome =
            service.observe_upsert(observation("container-a", "web", 2), 7, ZoneType::NonGlobal);

        assert!(matches!(outcome, MembershipOutcome::Unchanged { .. }));
        assert_eq!(
            service
                .resolve_container("container-a")
                .unwrap()
                .observation
                .generation,
            2
        );
        assert_eq!(service.list().count(), 1);
    }

    #[test]
    fn metadata_only_update_is_idempotent() {
        let mut service = MembershipService::new();
        let mut first = observation("container-a", "web", 1);
        first.pod = None;
        first.source = MembershipSource::LocalGrpc;
        service.observe_upsert(first, 7, ZoneType::NonGlobal);
        service.mark_applied("container-a");

        let outcome =
            service.observe_upsert(observation("container-a", "web", 2), 7, ZoneType::NonGlobal);

        assert!(matches!(outcome, MembershipOutcome::Unchanged { .. }));
        let record = service.resolve_container("container-a").unwrap();
        assert_eq!(record.observation.pod.as_ref().unwrap().uid, "pod-uid");
        assert_eq!(
            record.observation.source,
            MembershipSource::KubernetesAdapter
        );
        assert!(record.applied);
        assert_eq!(service.list().count(), 1);
    }

    #[test]
    fn stale_update_is_ignored() {
        let mut service = MembershipService::new();
        service.observe_upsert(
            observation("container-a", "web", 10),
            7,
            ZoneType::NonGlobal,
        );

        let outcome =
            service.observe_upsert(observation("container-a", "web", 9), 7, ZoneType::NonGlobal);

        assert_eq!(
            outcome,
            MembershipOutcome::Stale {
                existing_generation: 10,
            }
        );
        assert_eq!(service.stale_updates(), 1);
    }

    #[test]
    fn zero_generation_update_refreshes_without_rewinding_generation() {
        let mut service = MembershipService::new();
        service.observe_upsert(
            observation("container-a", "web", 10),
            7,
            ZoneType::NonGlobal,
        );
        service.mark_applied("container-a");

        let mut refresh = observation("container-a", "web", 0);
        refresh.source = MembershipSource::LocalGrpc;
        let outcome = service.observe_upsert(refresh, 7, ZoneType::NonGlobal);

        assert!(matches!(outcome, MembershipOutcome::Unchanged { .. }));
        let record = service.resolve_container("container-a").unwrap();
        assert_eq!(record.observation.generation, 10);
        assert_eq!(record.observation.source, MembershipSource::LocalGrpc);
        assert!(record.applied);
        assert_eq!(service.stale_updates(), 0);
    }

    #[test]
    fn conflicting_assignment_is_reported() {
        let mut service = MembershipService::new();
        service.observe_upsert(observation("container-a", "web", 1), 7, ZoneType::NonGlobal);

        let outcome =
            service.observe_upsert(observation("container-a", "db", 2), 8, ZoneType::NonGlobal);

        assert_eq!(
            outcome,
            MembershipOutcome::Conflict {
                existing_zone: "web".to_string(),
                requested_zone: "db".to_string(),
                existing_generation: 1,
            }
        );
        assert_eq!(service.conflicts(), 1);
    }

    #[test]
    fn zone_type_change_for_live_membership_is_conflict() {
        let mut service = MembershipService::new();
        service.observe_upsert(
            observation("container-a", "web", 10),
            7,
            ZoneType::NonGlobal,
        );
        service.mark_applied("container-a");

        let outcome = service.observe_upsert(
            observation("container-a", "web", 11),
            7,
            ZoneType::Privileged,
        );

        assert_eq!(
            outcome,
            MembershipOutcome::Conflict {
                existing_zone: "web".to_string(),
                requested_zone: "web".to_string(),
                existing_generation: 10,
            }
        );
        let record = service.resolve_container("container-a").unwrap();
        assert_eq!(record.zone_type, ZoneType::NonGlobal);
        assert_eq!(record.observation.generation, 10);
        assert_eq!(service.conflicts(), 1);
    }

    #[test]
    fn delete_membership_produces_remove_intent() {
        let mut service = MembershipService::new();
        service.observe_upsert(observation("container-a", "web", 1), 7, ZoneType::NonGlobal);

        let outcome = service.remove("container-a", Some(2));

        assert_eq!(
            outcome,
            MembershipOutcome::Removed {
                intent: BpfMembershipIntent::Remove {
                    cgroup_id: 42,
                    zone_id: 7,
                },
            }
        );
        assert!(service.resolve_container("container-a").is_none());
    }

    #[test]
    fn delete_without_generation_ignores_existing_generation() {
        let mut service = MembershipService::new();
        service.observe_upsert(
            observation("container-a", "web", 10),
            7,
            ZoneType::NonGlobal,
        );

        let outcome = service.remove("container-a", None);

        assert!(matches!(outcome, MembershipOutcome::Removed { .. }));
        assert!(service.resolve_container("container-a").is_none());
    }

    #[test]
    fn stale_delete_is_rejected_when_generation_is_provided() {
        let mut service = MembershipService::new();
        service.observe_upsert(
            observation("container-a", "web", 10),
            7,
            ZoneType::NonGlobal,
        );

        let outcome = service.remove("container-a", Some(9));

        assert_eq!(
            outcome,
            MembershipOutcome::Stale {
                existing_generation: 10,
            }
        );
        assert!(service.resolve_container("container-a").is_some());
    }

    #[test]
    fn resolves_cgroup_to_zone() {
        let mut service = MembershipService::new();
        service.observe_upsert(observation("container-a", "web", 1), 7, ZoneType::NonGlobal);

        let record = service.resolve_cgroup(42).unwrap();

        assert_eq!(record.observation.zone_name, "web");
        assert_eq!(record.zone_id, 7);
    }
}
