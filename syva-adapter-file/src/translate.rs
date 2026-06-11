use crate::policy::FilePolicy;
use crate::types::NetworkMode;
use syva_core_client::syva_core::{
    NetworkMode as ProtoNetworkMode, RegisterZoneRequest, ZonePolicy,
};

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
            network_mode: network_mode_to_proto(policy.policy.network.mode) as i32,
        }),
    }
}

fn network_mode_to_proto(mode: NetworkMode) -> ProtoNetworkMode {
    match mode {
        NetworkMode::Isolated => ProtoNetworkMode::Isolated,
        NetworkMode::Bridged => ProtoNetworkMode::Bridged,
        NetworkMode::Host => ProtoNetworkMode::Host,
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
