use std::collections::{BTreeSet, HashMap};

use crate::policy::FilePolicy;
use syva_core_client::syva_core::ZoneSummary;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct CoreDiff {
    pub create: Vec<String>,
    pub update: Vec<String>,
    pub remove: Vec<String>,
}

pub fn diff_against_core(
    desired: &HashMap<String, FilePolicy>,
    applied: &[ZoneSummary],
    last_applied: &HashMap<String, serde_json::Value>,
) -> CoreDiff {
    let desired_names: BTreeSet<&str> = desired.keys().map(String::as_str).collect();
    let applied_names: BTreeSet<&str> = applied.iter().map(|zone| zone.name.as_str()).collect();

    let create = desired_names
        .difference(&applied_names)
        .map(|name| (*name).to_string())
        .collect();
    let update = desired_names
        .intersection(&applied_names)
        .filter(|name| {
            let name = **name;
            desired
                .get(name)
                .and_then(|policy| serde_json::to_value(policy).ok())
                .as_ref()
                != last_applied.get(name)
        })
        .map(|name| (*name).to_string())
        .collect();
    let remove = applied_names
        .difference(&desired_names)
        .map(|name| (*name).to_string())
        .collect();

    CoreDiff {
        create,
        update,
        remove,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diffs_desired_against_core_snapshot() {
        let mut desired = HashMap::new();
        desired.insert(
            "web".to_string(),
            FilePolicy {
                display_name: None,
                selector: None,
                policy: Default::default(),
            },
        );
        desired.insert(
            "api".to_string(),
            FilePolicy {
                display_name: None,
                selector: None,
                policy: Default::default(),
            },
        );

        let applied = vec![
            ZoneSummary {
                name: "web".to_string(),
                zone_id: 1,
                state: "active".to_string(),
                containers_active: 1,
            },
            ZoneSummary {
                name: "old".to_string(),
                zone_id: 2,
                state: "pending".to_string(),
                containers_active: 0,
            },
        ];

        assert_eq!(
            diff_against_core(&desired, &applied, &HashMap::new()),
            CoreDiff {
                create: vec!["api".to_string()],
                update: vec!["web".to_string()],
                remove: vec!["old".to_string()],
            }
        );
    }

    #[test]
    fn skips_updates_when_desired_policy_matches_last_applied_snapshot() {
        let policy = FilePolicy {
            display_name: None,
            selector: None,
            policy: Default::default(),
        };
        let mut desired = HashMap::new();
        desired.insert("web".to_string(), policy.clone());
        let applied = vec![ZoneSummary {
            name: "web".to_string(),
            zone_id: 1,
            state: "active".to_string(),
            containers_active: 0,
        }];
        let mut last_applied = HashMap::new();
        last_applied.insert(
            "web".to_string(),
            serde_json::to_value(policy).expect("policy"),
        );

        assert_eq!(
            diff_against_core(&desired, &applied, &last_applied),
            CoreDiff::default()
        );
    }
}
