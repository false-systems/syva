//! Translation between adapter-local TOML policy types and proto types.
//!
//! The adapter owns the TOML deserialization format. The proto types are
//! what syva-core understands. This module bridges the two.

use crate::types::ZonePolicy;
use syva_proto::syva_core;

/// Convert a local ZonePolicy (deserialized from TOML) to a proto ZonePolicy.
pub fn to_proto_policy(policy: &ZonePolicy) -> syva_core::ZonePolicy {
    syva_core::ZonePolicy {
        host_paths: policy.filesystem.host_paths.clone(),
        allowed_zones: policy.network.allowed_zones.clone(),
        allow_ptrace: policy.capabilities.allowed.iter()
            .any(|c| c == "CAP_SYS_PTRACE"),
        zone_type: syva_core::ZoneType::Standard.into(),
    }
}
