use crate::crd::{SyvaZonePolicy, ZoneTypeSpec};
use anyhow::Result;
use syva_core_client::syva_core::{RegisterZoneRequest, ZonePolicy};
use syva_cp_client::{CreateZoneArgs, UpdateZoneArgs, ZoneSnapshot};
use uuid::Uuid;

pub fn spec_to_create_args(
    team_id: Uuid,
    name: &str,
    crd: &SyvaZonePolicy,
) -> Result<CreateZoneArgs> {
    Ok(CreateZoneArgs {
        team_id,
        name: name.to_string(),
        display_name: None,
        policy_json: spec_to_policy_json(crd)?,
        summary_json: None,
        selector_json: spec_to_selector_json(crd)?,
        metadata_json: None,
    })
}

pub fn spec_to_update_args(
    snapshot: &ZoneSnapshot,
    crd: &SyvaZonePolicy,
) -> Result<Option<UpdateZoneArgs>> {
    let desired_policy_json = spec_to_policy_json(crd)?;
    let desired_selector_json = spec_to_selector_json(crd)?;

    let policy_matches = snapshot
        .current_policy_json
        .as_ref()
        .map(|current| current == &desired_policy_json)
        .unwrap_or(false);
    let selector_matches = snapshot.selector_json == desired_selector_json;

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
        }),
    }
}

fn spec_to_policy_json(crd: &SyvaZonePolicy) -> Result<serde_json::Value> {
    let spec = &crd.spec;
    Ok(serde_json::json!({
        "host_paths": spec.filesystem.as_ref()
            .map(|filesystem| filesystem.host_paths.clone())
            .unwrap_or_default(),
        "allowed_zones": spec.network.as_ref()
            .map(|network| network.allowed_zones.clone())
            .unwrap_or_default(),
        "allow_ptrace": spec.process.as_ref()
            .map(|process| process.allow_ptrace)
            .unwrap_or(false),
        "zone_type": match spec.zone_type.as_ref().unwrap_or(&ZoneTypeSpec::Standard) {
            ZoneTypeSpec::Standard => "standard",
            ZoneTypeSpec::Privileged => "privileged",
            ZoneTypeSpec::Isolated => "isolated",
        },
    }))
}

fn spec_to_selector_json(crd: &SyvaZonePolicy) -> Result<Option<serde_json::Value>> {
    crd.spec
        .selector
        .as_ref()
        .map(serde_json::to_value)
        .transpose()
        .map_err(Into::into)
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
    fn maps_compact_policy_json() {
        let resource = crd(SyvaZonePolicySpec {
            filesystem: Some(FilesystemSpec {
                host_paths: vec!["/data".into()],
            }),
            network: Some(NetworkSpec {
                allowed_zones: vec!["db".into()],
            }),
            process: Some(ProcessSpec { allow_ptrace: true }),
            selector: None,
            zone_type: Some(ZoneTypeSpec::Privileged),
        });

        let value = spec_to_policy_json(&resource).unwrap();
        assert_eq!(value["host_paths"], serde_json::json!(["/data"]));
        assert_eq!(value["allowed_zones"], serde_json::json!(["db"]));
        assert_eq!(value["allow_ptrace"], serde_json::json!(true));
        assert_eq!(value["zone_type"], serde_json::json!("privileged"));
    }

    #[test]
    fn maps_selector_json() {
        let mut labels = BTreeMap::new();
        labels.insert("tier".to_string(), "prod".to_string());
        let resource = crd(SyvaZonePolicySpec {
            filesystem: None,
            network: None,
            process: None,
            selector: Some(SelectorSpec {
                all_nodes: false,
                node_names: vec!["n1".into()],
                match_labels: labels,
            }),
            zone_type: None,
        });

        let value = spec_to_selector_json(&resource).unwrap().unwrap();
        assert_eq!(value["nodeNames"], serde_json::json!(["n1"]));
        assert_eq!(value["matchLabels"]["tier"], serde_json::json!("prod"));
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
