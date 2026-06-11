use crate::crd::{SyvaZonePolicy, ZoneTypeSpec};
use syva_core_client::syva_core::{NetworkMode, RegisterZoneRequest, ZonePolicy};

/// Translate a SyvaZonePolicy CRD into the node-local core API.
///
/// Local core applies policy to one node and has no team ownership, selector,
/// display-name, or metadata concepts. The CRD selector is intentionally
/// dropped here; Kubernetes scheduling decides which adapter instance sees the
/// CRD, not the local core.
pub fn spec_to_core_register(name: &str, crd: &SyvaZonePolicy) -> RegisterZoneRequest {
    let spec = &crd.spec;
    RegisterZoneRequest {
        zone_name: name.to_string(),
        policy: Some(ZonePolicy {
            host_paths: spec
                .filesystem
                .as_ref()
                .map(|filesystem| filesystem.host_paths.clone())
                .unwrap_or_default(),
            allowed_zones: spec
                .network
                .as_ref()
                .map(|network| network.allowed_zones.clone())
                .unwrap_or_default(),
            allow_ptrace: spec
                .process
                .as_ref()
                .map(|process| process.allow_ptrace)
                .unwrap_or(false),
            zone_type: match spec.zone_type.as_ref().unwrap_or(&ZoneTypeSpec::Standard) {
                ZoneTypeSpec::Privileged => 1,
                ZoneTypeSpec::Standard | ZoneTypeSpec::Isolated => 0,
            },
            network_mode: network_mode_from_spec(spec) as i32,
        }),
    }
}

/// Resolve the proto network mode from the CRD. An explicit `network.mode`
/// wins; otherwise a `ZoneTypeSpec::Isolated` zone is network-locked, and the
/// default is Isolated (locked) — opening network access is always explicit.
fn network_mode_from_spec(spec: &crate::crd::SyvaZonePolicySpec) -> NetworkMode {
    if let Some(mode) = spec.network.as_ref().and_then(|n| n.mode.as_deref()) {
        return match mode.to_ascii_lowercase().as_str() {
            "bridged" => NetworkMode::Bridged,
            "host" => NetworkMode::Host,
            _ => NetworkMode::Isolated,
        };
    }
    NetworkMode::Isolated
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crd::{FilesystemSpec, NetworkSpec, ProcessSpec, SelectorSpec, SyvaZonePolicySpec};
    use std::collections::BTreeMap;

    fn crd(spec: SyvaZonePolicySpec) -> SyvaZonePolicy {
        SyvaZonePolicy::new("web", spec)
    }

    #[test]
    fn maps_crd_to_core_register_and_drops_selector() {
        let mut labels = BTreeMap::new();
        labels.insert("tier".to_string(), "prod".to_string());
        let resource = crd(SyvaZonePolicySpec {
            filesystem: Some(FilesystemSpec {
                host_paths: vec!["/data".into()],
            }),
            network: Some(NetworkSpec {
                allowed_zones: vec!["db".into()],
                mode: None,
            }),
            process: Some(ProcessSpec { allow_ptrace: true }),
            selector: Some(SelectorSpec {
                all_nodes: false,
                node_names: vec!["node-a".into()],
                match_labels: labels,
            }),
            zone_type: Some(ZoneTypeSpec::Privileged),
        });

        let request = spec_to_core_register("web", &resource);
        let policy = request.policy.expect("policy");

        assert_eq!(request.zone_name, "web");
        assert_eq!(policy.host_paths, vec!["/data"]);
        assert_eq!(policy.allowed_zones, vec!["db"]);
        assert!(policy.allow_ptrace);
        assert_eq!(policy.zone_type, 1);
    }

    #[test]
    fn maps_isolated_crd_to_standard_core_zone_until_core_accepts_isolated() {
        let resource = crd(SyvaZonePolicySpec {
            filesystem: None,
            network: None,
            process: None,
            selector: None,
            zone_type: Some(ZoneTypeSpec::Isolated),
        });

        let request = spec_to_core_register("worker", &resource);

        assert_eq!(request.policy.expect("policy").zone_type, 0);
    }
}
