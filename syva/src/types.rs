//! Zone policy types — defines what a zone can do.
//!
//! Inlined from rauha-common for standalone operation.
//! These types are deserialized directly from TOML policy files.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneType {
    Global,
    NonGlobal,
    Privileged,
}

/// Declarative policy defining what a zone can do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonePolicy {
    pub capabilities: CapabilityPolicy,
    pub resources: ResourcePolicy,
    pub network: NetworkPolicy,
    pub filesystem: FilesystemPolicy,
    pub devices: DevicePolicy,
    pub syscalls: SyscallPolicy,
}

impl Default for ZonePolicy {
    fn default() -> Self {
        Self {
            capabilities: CapabilityPolicy::default(),
            resources: ResourcePolicy::default(),
            network: NetworkPolicy::default(),
            filesystem: FilesystemPolicy::default(),
            devices: DevicePolicy::default(),
            syscalls: SyscallPolicy::default(),
        }
    }
}

/// Allow-list only. Nothing not listed here is permitted.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CapabilityPolicy {
    pub allowed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePolicy {
    pub cpu_shares: u64,
    pub memory_limit: u64,
    pub io_weight: u16,
    pub pids_max: u64,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            cpu_shares: 1024,
            memory_limit: 512 * 1024 * 1024, // 512Mi
            io_weight: 100,
            pids_max: 256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMode {
    Isolated,
    Bridged,
    Host,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub mode: NetworkMode,
    pub allowed_zones: Vec<String>,
    pub allowed_egress: Vec<String>,
    pub allowed_ingress: Vec<String>,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: NetworkMode::Isolated,
            allowed_zones: Vec::new(),
            allowed_egress: Vec::new(),
            allowed_ingress: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemPolicy {
    pub root: String,
    pub shared_layers: bool,
    pub writable_paths: Vec<String>,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            root: String::new(),
            shared_layers: true,
            writable_paths: vec!["/tmp".into(), "/var/log".into()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DevicePolicy {
    pub allowed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyscallPolicy {
    pub deny: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy() {
        let policy = ZonePolicy::default();
        assert!(policy.capabilities.allowed.is_empty());
        assert_eq!(policy.resources.cpu_shares, 1024);
        assert_eq!(policy.network.mode, NetworkMode::Isolated);
    }
}
