use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(CustomResource, Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "syva.dev",
    version = "v1alpha1",
    kind = "SyvaZonePolicy",
    namespaced,
    status = "SyvaZonePolicyStatus",
    printcolumn = r#"{"name":"Zone ID","type":"integer","jsonPath":".status.zoneId"}"#,
    printcolumn = r#"{"name":"Containers","type":"integer","jsonPath":".status.activeContainers"}"#
)]
pub struct SyvaZonePolicySpec {
    #[serde(default)]
    pub filesystem: Option<FilesystemSpec>,
    #[serde(default)]
    pub network: Option<NetworkSpec>,
    #[serde(default)]
    pub process: Option<ProcessSpec>,
    #[serde(default)]
    pub selector: Option<SelectorSpec>,
    #[serde(default)]
    pub zone_type: Option<ZoneTypeSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemSpec {
    #[serde(default)]
    pub host_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct NetworkSpec {
    #[serde(default)]
    pub allowed_zones: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct ProcessSpec {
    #[serde(default)]
    pub allow_ptrace: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SelectorSpec {
    #[serde(default)]
    pub all_nodes: bool,
    #[serde(default)]
    pub node_names: Vec<String>,
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "lowercase")]
pub enum ZoneTypeSpec {
    #[default]
    Standard,
    Privileged,
    Isolated,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "camelCase")]
pub struct SyvaZonePolicyStatus {
    #[serde(default)]
    pub zone_id: Option<u32>,
    #[serde(default)]
    pub active_containers: Option<u32>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Condition {
    pub r#type: String,
    pub status: String,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kube::CustomResourceExt;

    #[test]
    fn crd_generates_valid_schema() {
        let _crd = SyvaZonePolicy::crd();
    }

    #[test]
    fn spec_deserializes_minimal() {
        let json = r#"{"filesystem":null,"network":null,"process":null,"selector":null,"zoneType":null}"#;
        let spec: SyvaZonePolicySpec = serde_json::from_str(json).unwrap();
        assert!(spec.filesystem.is_none());
    }

    #[test]
    fn spec_deserializes_full() {
        let json = r#"{
            "filesystem": {"hostPaths": ["/data"]},
            "network": {"allowedZones": ["db"]},
            "process": {"allowPtrace": true},
            "selector": {"matchLabels": {"tier": "prod"}},
            "zoneType": "privileged"
        }"#;
        let spec: SyvaZonePolicySpec = serde_json::from_str(json).unwrap();
        assert_eq!(spec.filesystem.unwrap().host_paths, vec!["/data"]);
        assert!(spec.process.unwrap().allow_ptrace);
        assert_eq!(
            spec.selector.unwrap().match_labels.get("tier").map(String::as_str),
            Some("prod")
        );
    }
}
