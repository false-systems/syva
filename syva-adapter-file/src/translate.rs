use crate::policy::FilePolicy;
use anyhow::Result;
use syva_core_client::syva_core::{RegisterZoneRequest, ZonePolicy};
use syva_cp_client::{CreateZoneArgs, UpdateZoneArgs, ZoneSnapshot};
use uuid::Uuid;

pub fn policy_to_create_args(
    team_id: Uuid,
    name: &str,
    policy: &FilePolicy,
) -> Result<CreateZoneArgs> {
    Ok(CreateZoneArgs {
        team_id,
        name: name.to_string(),
        display_name: policy.display_name.clone(),
        policy_json: serde_json::to_value(&policy.policy)?,
        summary_json: None,
        selector_json: policy.selector.clone(),
        metadata_json: None,
    })
}

pub fn policy_to_update_args(
    snapshot: &ZoneSnapshot,
    policy: &FilePolicy,
) -> Result<Option<UpdateZoneArgs>> {
    let desired_policy_json = serde_json::to_value(&policy.policy)?;
    let desired_selector_json = policy.selector.clone();

    let policy_matches = snapshot
        .current_policy_json
        .as_ref()
        .map(|current| current == &desired_policy_json)
        .unwrap_or(false);
    let selector_matches = snapshot.selector_json == desired_selector_json;

    // ZoneService::UpdateZone does not currently accept display_name updates.
    // Ignore display_name drift here so the adapter does not generate a
    // perpetual no-op update loop it can never resolve.
    if policy_matches && selector_matches {
        return Ok(None);
    }

    Ok(Some(UpdateZoneArgs {
        zone_id: snapshot.zone_id,
        if_version: snapshot.version,
        policy_json: Some(desired_policy_json),
        selector_json: desired_selector_json,
        metadata_json: None,
    }))
}

/// Translate a TOML policy into the node-local core API.
///
/// Local core has no team, display-name, node-selector, or metadata concepts:
/// it writes desired state into one node's BPF maps, so CP-only fields are
/// intentionally dropped here. Updates use the same RegisterZone RPC because
/// `syva.core.v1` has no separate UpdateZone operation.
pub fn policy_to_core_register(name: &str, policy: &FilePolicy) -> RegisterZoneRequest {
    RegisterZoneRequest {
        zone_name: name.to_string(),
        policy: Some(ZonePolicy {
            host_paths: policy.policy.filesystem.host_paths.clone(),
            allowed_zones: policy.policy.network.allowed_zones.clone(),
            allow_ptrace: policy
                .policy
                .capabilities
                .allowed
                .iter()
                .any(|cap| is_ptrace_cap(cap)),
            zone_type: if policy
                .policy
                .zone
                .zone_type
                .eq_ignore_ascii_case("privileged")
            {
                1
            } else {
                0
            },
        }),
    }
}

pub fn policy_to_core_update(name: &str, policy: &FilePolicy) -> RegisterZoneRequest {
    policy_to_core_register(name, policy)
}

fn is_ptrace_cap(capability: &str) -> bool {
    let normalized = capability.to_ascii_uppercase();
    normalized == "CAP_SYS_PTRACE" || normalized == "SYS_PTRACE"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ZonePolicy as FileZonePolicy;

    #[test]
    fn maps_file_policy_to_core_register() {
        let mut policy = FileZonePolicy::default();
        policy.filesystem.host_paths = vec!["/srv/web".to_string()];
        policy.network.allowed_zones = vec!["db".to_string()];
        policy.capabilities.allowed = vec!["CAP_SYS_PTRACE".to_string()];
        policy.zone.zone_type = "privileged".to_string();

        let request = policy_to_core_register(
            "web",
            &FilePolicy {
                display_name: Some("Web".to_string()),
                selector: Some(serde_json::json!({"all_nodes": true})),
                policy,
            },
        );

        let core_policy = request.policy.expect("policy");
        assert_eq!(request.zone_name, "web");
        assert_eq!(core_policy.host_paths, vec!["/srv/web"]);
        assert_eq!(core_policy.allowed_zones, vec!["db"]);
        assert!(core_policy.allow_ptrace);
        assert_eq!(core_policy.zone_type, 1);
    }

    #[test]
    fn maps_non_privileged_file_policy_to_standard_core_zone() {
        let mut policy = FileZonePolicy::default();
        policy.zone.zone_type = "isolated".to_string();

        let request = policy_to_core_register(
            "worker",
            &FilePolicy {
                display_name: None,
                selector: None,
                policy,
            },
        );

        assert_eq!(request.policy.expect("policy").zone_type, 0);
    }
}
