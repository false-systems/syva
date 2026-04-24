use crate::db::types::{NodeLabels, NodeSelector};
use std::collections::HashSet;
use uuid::Uuid;

/// Input: a zone + its current policy + every online node.
/// Output: the desired set of (zone_id, node_id) assignments.
pub fn compute_zone_assignments(
    zone: &ZoneForAssignment,
    nodes: &[NodeForAssignment],
) -> Vec<DesiredAssignment> {
    let selector = match NodeSelector::from_json(&zone.selector_json) {
        Ok(selector) => selector,
        Err(_) => return Vec::new(),
    };

    nodes
        .iter()
        .filter(|node| node.status == "online")
        .filter(|node| selector.matches(&node.node_name, &node.labels))
        .map(|node| DesiredAssignment {
            zone_id: zone.zone_id,
            node_id: node.node_id,
            desired_policy_id: zone.current_policy_id,
            desired_zone_version: zone.zone_version,
        })
        .collect()
}

/// For a single node, across all active zones, compute every assignment that
/// should exist.
pub fn compute_node_assignments(
    node: &NodeForAssignment,
    zones: &[ZoneForAssignment],
) -> Vec<DesiredAssignment> {
    if node.status != "online" {
        return Vec::new();
    }

    zones
        .iter()
        .filter_map(|zone| {
            let selector = NodeSelector::from_json(&zone.selector_json).ok()?;
            if selector.matches(&node.node_name, &node.labels) {
                Some(DesiredAssignment {
                    zone_id: zone.zone_id,
                    node_id: node.node_id,
                    desired_policy_id: zone.current_policy_id,
                    desired_zone_version: zone.zone_version,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Diff current vs desired. Returns (to_upsert, to_remove).
pub fn diff_assignments(
    current: &[ExistingAssignment],
    desired: &[DesiredAssignment],
) -> (Vec<DesiredAssignment>, Vec<Uuid>) {
    let desired_ids: HashSet<(Uuid, Uuid)> =
        desired.iter().map(|a| (a.zone_id, a.node_id)).collect();

    let to_upsert = desired
        .iter()
        .filter(|desired_assignment| {
            match current.iter().find(|existing| {
                existing.zone_id == desired_assignment.zone_id
                    && existing.node_id == desired_assignment.node_id
            }) {
                None => true,
                Some(existing) => {
                    existing.status == "removing"
                        || existing.desired_policy_id != desired_assignment.desired_policy_id
                        || existing.desired_zone_version
                            != desired_assignment.desired_zone_version
                }
            }
        })
        .cloned()
        .collect();

    let to_remove = current
        .iter()
        .filter(|existing| !desired_ids.contains(&(existing.zone_id, existing.node_id)))
        .map(|existing| existing.id)
        .collect();

    (to_upsert, to_remove)
}

pub struct ZoneForAssignment {
    pub zone_id: Uuid,
    pub selector_json: serde_json::Value,
    pub current_policy_id: Uuid,
    pub zone_version: i64,
}

pub struct NodeForAssignment {
    pub node_id: Uuid,
    pub node_name: String,
    pub status: String,
    pub labels: NodeLabels,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredAssignment {
    pub zone_id: Uuid,
    pub node_id: Uuid,
    pub desired_policy_id: Uuid,
    pub desired_zone_version: i64,
}

pub struct ExistingAssignment {
    pub id: Uuid,
    pub zone_id: Uuid,
    pub node_id: Uuid,
    pub desired_policy_id: Uuid,
    pub desired_zone_version: i64,
    pub status: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn zone(zid: Uuid, pid: Uuid, selector: serde_json::Value, ver: i64) -> ZoneForAssignment {
        ZoneForAssignment {
            zone_id: zid,
            selector_json: selector,
            current_policy_id: pid,
            zone_version: ver,
        }
    }

    fn node(nid: Uuid, name: &str, labels: &[(&str, &str)]) -> NodeForAssignment {
        let mut label_map = BTreeMap::new();
        for (key, value) in labels {
            label_map.insert((*key).to_string(), (*value).to_string());
        }

        NodeForAssignment {
            node_id: nid,
            node_name: name.to_string(),
            status: "online".into(),
            labels: label_map,
        }
    }

    #[test]
    fn all_nodes_matches_everything() {
        let zone = zone(Uuid::new_v4(), Uuid::new_v4(), json!({"all_nodes": true}), 1);
        let node_a = node(Uuid::new_v4(), "a", &[]);
        let node_b = node(Uuid::new_v4(), "b", &[("tier", "prod")]);

        let out = compute_zone_assignments(&zone, &[node_a, node_b]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn node_names_matches_specific() {
        let zone = zone(
            Uuid::new_v4(),
            Uuid::new_v4(),
            json!({"node_names": ["a", "c"]}),
            1,
        );
        let node_a = node(Uuid::new_v4(), "a", &[]);
        let node_b = node(Uuid::new_v4(), "b", &[]);
        let node_c = node(Uuid::new_v4(), "c", &[]);

        let out = compute_zone_assignments(&zone, &[node_a, node_b, node_c]);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn match_labels_requires_all_pairs() {
        let zone = zone(
            Uuid::new_v4(),
            Uuid::new_v4(),
            json!({"match_labels": {"tier": "prod", "region": "eu"}}),
            1,
        );
        let matching = node(Uuid::new_v4(), "a", &[("tier", "prod"), ("region", "eu")]);
        let missing_one = node(Uuid::new_v4(), "b", &[("tier", "prod")]);
        let wrong_value = node(Uuid::new_v4(), "c", &[("tier", "dev"), ("region", "eu")]);

        let out = compute_zone_assignments(&zone, &[matching, missing_one, wrong_value]);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn empty_selector_matches_nothing() {
        let zone = zone(Uuid::new_v4(), Uuid::new_v4(), json!({}), 1);
        let node = node(Uuid::new_v4(), "a", &[]);

        let out = compute_zone_assignments(&zone, &[node]);
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn offline_nodes_excluded() {
        let zone = zone(Uuid::new_v4(), Uuid::new_v4(), json!({"all_nodes": true}), 1);
        let mut node = node(Uuid::new_v4(), "a", &[]);
        node.status = "offline".into();

        let out = compute_zone_assignments(&zone, &[node]);
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn diff_finds_additions_removals_updates() {
        let zone_id = Uuid::new_v4();
        let node_one = Uuid::new_v4();
        let node_two = Uuid::new_v4();
        let old_policy = Uuid::new_v4();
        let new_policy = Uuid::new_v4();
        let assignment_id = Uuid::new_v4();

        let current = vec![
            ExistingAssignment {
                id: assignment_id,
                zone_id,
                node_id: node_one,
                desired_policy_id: old_policy,
                desired_zone_version: 1,
                status: "applied".into(),
            },
            ExistingAssignment {
                id: Uuid::new_v4(),
                zone_id,
                node_id: node_two,
                desired_policy_id: old_policy,
                desired_zone_version: 1,
                status: "applied".into(),
            },
        ];

        let desired = vec![
            DesiredAssignment {
                zone_id,
                node_id: node_one,
                desired_policy_id: new_policy,
                desired_zone_version: 2,
            },
            DesiredAssignment {
                zone_id,
                node_id: Uuid::new_v4(),
                desired_policy_id: new_policy,
                desired_zone_version: 2,
            },
        ];

        let (upsert, remove) = diff_assignments(&current, &desired);
        assert_eq!(upsert.len(), 2);
        assert_eq!(remove.len(), 1);
    }

    #[test]
    fn diff_reactivates_removing_assignment() {
        let zone_id = Uuid::new_v4();
        let node_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();

        let current = vec![ExistingAssignment {
            id: Uuid::new_v4(),
            zone_id,
            node_id,
            desired_policy_id: policy_id,
            desired_zone_version: 1,
            status: "removing".into(),
        }];
        let desired = vec![DesiredAssignment {
            zone_id,
            node_id,
            desired_policy_id: policy_id,
            desired_zone_version: 1,
        }];

        let (upsert, remove) = diff_assignments(&current, &desired);
        assert_eq!(upsert.len(), 1);
        assert!(remove.is_empty());
    }
}
