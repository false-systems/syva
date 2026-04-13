pub const ANNOTATION_ZONE: &str = "syva.dev/zone";

use k8s_openapi::api::core::v1::Pod;
use syva_proto::syva_core;

use crate::crd::SyvaZonePolicySpec;

pub fn zone_name_from_pod(pod: &Pod) -> Option<String> {
    pod.metadata
        .annotations
        .as_ref()?
        .get(ANNOTATION_ZONE)
        .cloned()
}

pub fn spec_to_proto_policy(spec: &SyvaZonePolicySpec) -> syva_core::ZonePolicy {
    syva_core::ZonePolicy {
        host_paths: spec
            .filesystem
            .as_ref()
            .map(|f| f.host_paths.clone())
            .unwrap_or_default(),
        allowed_zones: spec
            .network
            .as_ref()
            .map(|n| n.allowed_zones.clone())
            .unwrap_or_default(),
        allow_ptrace: spec
            .process
            .as_ref()
            .map(|p| p.allow_ptrace)
            .unwrap_or(false),
        zone_type: match spec
            .zone_type
            .as_ref()
            .unwrap_or(&crate::crd::ZoneTypeSpec::Standard)
        {
            crate::crd::ZoneTypeSpec::Standard => syva_core::ZoneType::Standard.into(),
            crate::crd::ZoneTypeSpec::Privileged => syva_core::ZoneType::Privileged.into(),
            crate::crd::ZoneTypeSpec::Isolated => syva_core::ZoneType::Isolated.into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use std::collections::BTreeMap;

    #[test]
    fn zone_name_from_pod_with_annotation() {
        let mut annotations = BTreeMap::new();
        annotations.insert(ANNOTATION_ZONE.to_string(), "web".to_string());
        let pod = Pod {
            metadata: ObjectMeta {
                annotations: Some(annotations),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(zone_name_from_pod(&pod), Some("web".to_string()));
    }

    #[test]
    fn zone_name_from_pod_without_annotation() {
        let pod = Pod::default();
        assert_eq!(zone_name_from_pod(&pod), None);
    }

    #[test]
    fn spec_to_proto_defaults() {
        let spec = SyvaZonePolicySpec {
            filesystem: None,
            network: None,
            process: None,
            zone_type: None,
        };
        let policy = spec_to_proto_policy(&spec);
        assert!(policy.host_paths.is_empty());
        assert!(policy.allowed_zones.is_empty());
        assert!(!policy.allow_ptrace);
        assert_eq!(policy.zone_type, i32::from(syva_core::ZoneType::Standard));
    }

    #[test]
    fn spec_to_proto_full() {
        use crate::crd::{FilesystemSpec, NetworkSpec, ProcessSpec, ZoneTypeSpec};

        let spec = SyvaZonePolicySpec {
            filesystem: Some(FilesystemSpec {
                host_paths: vec!["/data".to_string()],
            }),
            network: Some(NetworkSpec {
                allowed_zones: vec!["db".to_string()],
            }),
            process: Some(ProcessSpec {
                allow_ptrace: true,
            }),
            zone_type: Some(ZoneTypeSpec::Privileged),
        };
        let policy = spec_to_proto_policy(&spec);
        assert_eq!(policy.host_paths, vec!["/data"]);
        assert_eq!(policy.allowed_zones, vec!["db"]);
        assert!(policy.allow_ptrace);
        assert_eq!(policy.zone_type, i32::from(syva_core::ZoneType::Privileged));
    }
}
