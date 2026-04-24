//! Tracks what this node has applied in CP mode. In-memory only.

#![allow(dead_code)]

use std::collections::{BTreeSet, HashMap, HashSet};
use syva_cp_client::ZoneAssignment;
use uuid::Uuid;

type CommPair = (String, String);

pub struct AppliedState {
    by_zone_id: HashMap<Uuid, AppliedEntry>,
    active_comm_pairs: HashSet<CommPair>,
}

pub struct AppliedEntry {
    pub zone_name: String,
    pub policy_id: Uuid,
    pub zone_version: i64,
    pub allowed_zones: BTreeSet<String>,
}

impl AppliedState {
    pub fn new() -> Self {
        Self {
            by_zone_id: HashMap::new(),
            active_comm_pairs: HashSet::new(),
        }
    }

    pub fn diff_against_snapshot(
        &self,
        desired: &[ZoneAssignment],
    ) -> (Vec<ZoneAssignment>, Vec<String>) {
        let mut to_apply = Vec::new();
        let mut desired_ids = HashSet::new();

        for assignment in desired {
            let Ok(zone_id) = Uuid::parse_str(&assignment.zone_id) else {
                continue;
            };
            let Ok(policy_id) = Uuid::parse_str(&assignment.desired_policy_id) else {
                continue;
            };

            desired_ids.insert(zone_id);

            let changed = match self.by_zone_id.get(&zone_id) {
                None => true,
                Some(existing) => {
                    existing.policy_id != policy_id
                        || existing.zone_version != assignment.desired_zone_version
                }
            };

            if changed {
                to_apply.push(assignment.clone());
            }
        }

        let to_remove = self
            .by_zone_id
            .keys()
            .filter(|zone_id| !desired_ids.contains(zone_id))
            .map(Uuid::to_string)
            .collect();

        (to_apply, to_remove)
    }

    pub fn record_applied(&mut self, assignment: &ZoneAssignment) {
        let Ok(zone_id) = Uuid::parse_str(&assignment.zone_id) else {
            return;
        };
        let Ok(policy_id) = Uuid::parse_str(&assignment.desired_policy_id) else {
            return;
        };

        self.by_zone_id.insert(
            zone_id,
            AppliedEntry {
                zone_name: assignment.zone_name.clone(),
                policy_id,
                zone_version: assignment.desired_zone_version,
                allowed_zones: BTreeSet::new(),
            },
        );
    }

    pub fn record_applied_policy(
        &mut self,
        assignment: &ZoneAssignment,
        allowed_zones: impl IntoIterator<Item = String>,
    ) {
        let Ok(zone_id) = Uuid::parse_str(&assignment.zone_id) else {
            return;
        };
        let Ok(policy_id) = Uuid::parse_str(&assignment.desired_policy_id) else {
            return;
        };

        self.by_zone_id.insert(
            zone_id,
            AppliedEntry {
                zone_name: assignment.zone_name.clone(),
                policy_id,
                zone_version: assignment.desired_zone_version,
                allowed_zones: allowed_zones.into_iter().collect(),
            },
        );
    }

    pub fn record_removed(&mut self, zone_id: &Uuid) {
        self.by_zone_id.remove(zone_id);
        let active_zone_names: HashSet<String> = self
            .by_zone_id
            .values()
            .map(|entry| entry.zone_name.clone())
            .collect();
        self.active_comm_pairs.retain(|(zone_a, zone_b)| {
            active_zone_names.contains(zone_a) && active_zone_names.contains(zone_b)
        });
    }

    pub fn zone_name_for(&self, zone_id: &Uuid) -> Option<String> {
        self.by_zone_id.get(zone_id).map(|entry| entry.zone_name.clone())
    }

    pub fn diff_comm_pairs(&self) -> (Vec<CommPair>, Vec<CommPair>) {
        let desired = self.desired_comm_pairs();

        let to_allow = desired
            .difference(&self.active_comm_pairs)
            .cloned()
            .collect();
        let to_deny = self
            .active_comm_pairs
            .difference(&desired)
            .cloned()
            .collect();

        (to_allow, to_deny)
    }

    pub fn record_allowed_pair(&mut self, zone_a: &str, zone_b: &str) {
        self.active_comm_pairs
            .insert(canonical_pair(zone_a, zone_b));
    }

    pub fn record_denied_pair(&mut self, zone_a: &str, zone_b: &str) {
        self.active_comm_pairs
            .remove(&canonical_pair(zone_a, zone_b));
    }

    fn desired_comm_pairs(&self) -> HashSet<CommPair> {
        let mut pairs = HashSet::new();

        for entry in self.by_zone_id.values() {
            for peer in &entry.allowed_zones {
                let Some(peer_entry) = self
                    .by_zone_id
                    .values()
                    .find(|candidate| candidate.zone_name == *peer)
                else {
                    continue;
                };

                if peer_entry.allowed_zones.contains(&entry.zone_name) {
                    pairs.insert(canonical_pair(&entry.zone_name, peer));
                }
            }
        }

        pairs
    }
}

fn canonical_pair(zone_a: &str, zone_b: &str) -> CommPair {
    if zone_a <= zone_b {
        (zone_a.to_string(), zone_b.to_string())
    } else {
        (zone_b.to_string(), zone_a.to_string())
    }
}
