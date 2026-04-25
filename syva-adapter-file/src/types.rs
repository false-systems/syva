//! Zone policy types — defines what a zone can do.
//!
//! Inlined from rauha-common for standalone operation.
//! These types are deserialized directly from TOML policy files.

use serde::{Deserialize, Serialize};

/// Memory limit that accepts both bare integers and human-readable strings.
///
/// Supported suffixes: Ki/Mi/Gi/Ti (1024-base), K/M/G/T (1000-base).
/// Bare integers are interpreted as bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryLimit(u64);

impl MemoryLimit {
    pub fn new(bytes: u64) -> Self {
        Self(bytes)
    }

    pub fn bytes(self) -> u64 {
        self.0
    }

    fn checked_parse(n: &str, multiplier: u64) -> Result<u64, String> {
        let value = n.parse::<u64>().map_err(|e| e.to_string())?;
        value.checked_mul(multiplier).ok_or_else(|| "memory limit too large".to_string())
    }

    fn parse(s: &str) -> Result<u64, String> {
        let s = s.trim();
        if let Some(n) = s.strip_suffix("Ti") {
            Self::checked_parse(n, 1024 * 1024 * 1024 * 1024)
        } else if let Some(n) = s.strip_suffix("Gi") {
            Self::checked_parse(n, 1024 * 1024 * 1024)
        } else if let Some(n) = s.strip_suffix("Mi") {
            Self::checked_parse(n, 1024 * 1024)
        } else if let Some(n) = s.strip_suffix("Ki") {
            Self::checked_parse(n, 1024)
        } else if let Some(n) = s.strip_suffix('T') {
            Self::checked_parse(n, 1000 * 1000 * 1000 * 1000)
        } else if let Some(n) = s.strip_suffix('G') {
            Self::checked_parse(n, 1000 * 1000 * 1000)
        } else if let Some(n) = s.strip_suffix('M') {
            Self::checked_parse(n, 1000 * 1000)
        } else if let Some(n) = s.strip_suffix('K') {
            Self::checked_parse(n, 1000)
        } else {
            s.parse::<u64>().map_err(|e| e.to_string())
        }
    }
}

impl Serialize for MemoryLimit {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for MemoryLimit {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MemoryLimitVisitor;

        impl<'de> serde::de::Visitor<'de> for MemoryLimitVisitor {
            type Value = MemoryLimit;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("an integer (bytes) or a string like \"4Gi\", \"512Mi\"")
            }

            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<MemoryLimit, E> {
                Ok(MemoryLimit(v))
            }

            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<MemoryLimit, E> {
                if v < 0 {
                    return Err(E::custom("memory_limit cannot be negative"));
                }
                Ok(MemoryLimit(v as u64))
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<MemoryLimit, E> {
                MemoryLimit::parse(v).map(MemoryLimit).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(MemoryLimitVisitor)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZoneType {
    Global,
    NonGlobal,
    Privileged,
}

/// Metadata section from policy TOML. Parsed but not used for enforcement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ZoneMetadata {
    #[serde(default)]
    pub name: String,
    #[serde(default, rename = "type")]
    pub zone_type: String,
}

/// Declarative policy defining what a zone can do.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ZonePolicy {
    /// Optional metadata section — parsed but not used for enforcement.
    #[serde(default)]
    pub zone: ZoneMetadata,
    pub capabilities: CapabilityPolicy,
    pub resources: ResourcePolicy,
    pub network: NetworkPolicy,
    pub filesystem: FilesystemPolicy,
    pub devices: DevicePolicy,
    pub syscalls: SyscallPolicy,
}

impl ZonePolicy {
    /// Validate policy values against kernel constraints.
    pub fn validate(&self, zone_name: &str) -> anyhow::Result<()> {
        if self.resources.cpu_shares == 0 {
            anyhow::bail!("zone {zone_name}: cpu_shares must be > 0");
        }
        if self.resources.pids_max == 0 {
            anyhow::bail!("zone {zone_name}: pids_max must be > 0");
        }
        if self.resources.io_weight == 0 {
            anyhow::bail!("zone {zone_name}: io_weight must be > 0");
        }

        let (_, unknown) = syva_ebpf_common::caps_to_mask_validated(&self.capabilities.allowed);
        if !unknown.is_empty() {
            tracing::warn!(
                zone = zone_name,
                unknown = ?unknown,
                "unknown capability names — will be ignored by kernel"
            );
        }

        // Warn about policy fields that are parsed but NOT enforced by eBPF hooks.
        // Operators may expect these to have kernel-level enforcement.
        if !self.syscalls.deny.is_empty() {
            tracing::info!(
                zone = zone_name,
                "syscalls.deny is configured but NOT enforced by Syva — \
                 use a seccomp profile for syscall filtering"
            );
        }
        if !self.devices.allowed.is_empty() {
            tracing::info!(
                zone = zone_name,
                "devices.allowed is configured but NOT enforced by Syva — \
                 use device cgroup controller for device access control"
            );
        }
        if !self.network.allowed_egress.is_empty() || !self.network.allowed_ingress.is_empty() {
            tracing::info!(
                zone = zone_name,
                "network egress/ingress rules are configured but NOT enforced by Syva — \
                 use NetworkPolicy or iptables for network filtering"
            );
        }


        // M5: Bound policy arrays to prevent one zone from exhausting BPF maps.
        if self.filesystem.host_paths.len() > 1000 {
            anyhow::bail!("zone {zone_name}: host_paths exceeds limit of 1000 entries");
        }
        if self.network.allowed_zones.len() > 100 {
            anyhow::bail!("zone {zone_name}: allowed_zones exceeds limit of 100 entries");
        }
        if self.capabilities.allowed.len() > 41 {
            anyhow::bail!("zone {zone_name}: capabilities.allowed exceeds maximum of 41 Linux capabilities");
        }

        Ok(())
    }
}

/// Allow-list only. Nothing not listed here is permitted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CapabilityPolicy {
    pub allowed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourcePolicy {
    pub cpu_shares: u64,
    pub memory_limit: MemoryLimit,
    pub io_weight: u16,
    pub pids_max: u64,
}

impl Default for ResourcePolicy {
    fn default() -> Self {
        Self {
            cpu_shares: 1024,
            memory_limit: MemoryLimit::new(512 * 1024 * 1024), // 512Mi
            io_weight: 100,
            pids_max: 256,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    Isolated,
    Bridged,
    Host,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    #[serde(default)]
    pub root: String,
    pub shared_layers: bool,
    pub writable_paths: Vec<String>,
    /// Host-visible paths for INODE_ZONE_MAP population.
    ///
    /// Only bind-mounted host paths can be correctly enumerated by the agent —
    /// container-internal paths (overlayfs layers) have different inodes from
    /// the host perspective and will not match in the kernel LSM hooks.
    #[serde(default)]
    pub host_paths: Vec<String>,
}

impl Default for FilesystemPolicy {
    fn default() -> Self {
        Self {
            root: String::new(),
            shared_layers: true,
            writable_paths: vec!["/tmp".into(), "/var/log".into()],
            host_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DevicePolicy {
    pub allowed: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
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

    #[test]
    fn memory_limit_parse_gi() {
        assert_eq!(MemoryLimit::parse("4Gi").unwrap(), 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn memory_limit_parse_mi() {
        assert_eq!(MemoryLimit::parse("512Mi").unwrap(), 512 * 1024 * 1024);
    }

    #[test]
    fn memory_limit_parse_ki() {
        assert_eq!(MemoryLimit::parse("64Ki").unwrap(), 64 * 1024);
    }

    #[test]
    fn memory_limit_parse_ti() {
        assert_eq!(MemoryLimit::parse("1Ti").unwrap(), 1024u64 * 1024 * 1024 * 1024);
    }

    #[test]
    fn memory_limit_parse_g_decimal() {
        assert_eq!(MemoryLimit::parse("1G").unwrap(), 1_000_000_000);
    }

    #[test]
    fn memory_limit_parse_m_decimal() {
        assert_eq!(MemoryLimit::parse("500M").unwrap(), 500_000_000);
    }

    #[test]
    fn memory_limit_parse_k_decimal() {
        assert_eq!(MemoryLimit::parse("100K").unwrap(), 100_000);
    }

    #[test]
    fn memory_limit_parse_t_decimal() {
        assert_eq!(MemoryLimit::parse("2T").unwrap(), 2_000_000_000_000);
    }

    #[test]
    fn memory_limit_parse_bare_integer() {
        assert_eq!(MemoryLimit::parse("1048576").unwrap(), 1048576);
    }

    #[test]
    fn memory_limit_deserialize_string() {
        let toml_str = r#"memory_limit = "4Gi""#;
        #[derive(Deserialize)]
        struct T { memory_limit: MemoryLimit }
        let t: T = toml::from_str(toml_str).unwrap();
        assert_eq!(t.memory_limit.bytes(), 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn memory_limit_overflow_returns_error() {
        assert!(MemoryLimit::parse("99999999Ti").is_err());
    }

    #[test]
    fn memory_limit_deserialize_integer() {
        let toml_str = "memory_limit = 536870912";
        #[derive(Deserialize)]
        struct T { memory_limit: MemoryLimit }
        let t: T = toml::from_str(toml_str).unwrap();
        assert_eq!(t.memory_limit.bytes(), 536870912);
    }

    #[test]
    fn standard_toml_deserializes() {
        // The canonical example policy must always deserialize.
        // serde ignores unknown sections ([zone]) by default.
        let content = include_str!("../../policies/standard.toml");
        let policy: ZonePolicy = toml::from_str(content).unwrap();
        assert_eq!(policy.resources.cpu_shares, 1024);
        assert_eq!(policy.network.mode, NetworkMode::Bridged);
        assert_eq!(policy.resources.memory_limit.bytes(), 4 * 1024 * 1024 * 1024);
    }

    #[test]
    fn network_mode_lowercase_deserialize() {
        #[derive(Deserialize)]
        struct T { mode: NetworkMode }
        assert_eq!(toml::from_str::<T>("mode = \"bridged\"").unwrap().mode, NetworkMode::Bridged);
        assert_eq!(toml::from_str::<T>("mode = \"isolated\"").unwrap().mode, NetworkMode::Isolated);
        assert_eq!(toml::from_str::<T>("mode = \"host\"").unwrap().mode, NetworkMode::Host);
    }

    #[test]
    fn unknown_field_rejected() {
        let toml_str = r#"
[capabilities]
allowed = []
typo_field = "oops"

[resources]
cpu_shares = 1024
memory_limit = "512Mi"
io_weight = 100
pids_max = 256

[network]
mode = "isolated"
allowed_zones = []
allowed_egress = []
allowed_ingress = []

[filesystem]
shared_layers = true
writable_paths = ["/tmp"]

[devices]
allowed = []

[syscalls]
deny = []
"#;
        let result = toml::from_str::<ZonePolicy>(toml_str);
        assert!(result.is_err(), "unknown field 'typo_field' should be rejected");
    }

    #[test]
    fn network_mode_rejects_pascalcase() {
        #[derive(Deserialize)]
        struct T { _mode: NetworkMode }
        assert!(toml::from_str::<T>("mode = \"Bridged\"").is_err());
    }
}
