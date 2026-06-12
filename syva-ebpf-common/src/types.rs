//! Shared types between eBPF kernel programs and userspace.
//!
//! All types are `#[repr(C)]` with fixed sizes for BPF map compatibility.
//! No pointers, no heap, no padding surprises.

/// Zone ID 0 represents the host (unzoned processes).
/// Used in deny events when the target is a host process.
pub const ZONE_ID_HOST: u32 = 0;

/// Maximum number of zones the system can track.
pub const MAX_ZONES: u32 = 4096;

/// Maximum number of cgroups (zone memberships) tracked in BPF maps.
pub const MAX_CGROUPS: u32 = 65536;

/// Maximum directed zone communication pairs in ZONE_ALLOWED_COMMS.
/// Each bidirectional relationship uses 2 entries (src→dst and dst→src).
/// MAX_ZONES * 4 allows each zone to communicate with ~4 others.
pub const MAX_ZONE_COMM_PAIRS: u32 = MAX_ZONES * 4; // 16384

/// Maximum number of inodes tracked for file-zone ownership.
/// 256K entries × ~76 bytes/entry ≈ 19MB pinned kernel memory.
/// Covers most container rootfs scenarios (Alpine ~800, Ubuntu ~35K).
pub const MAX_INODES: u32 = 262_144;

/// Value in the ZONE_MEMBERSHIP map. Keyed by cgroup_id (u64).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ZoneInfoKernel {
    /// Compact zone identifier (monotonic u32, not the Uuid).
    pub zone_id: u32,
    /// Bit flags for zone properties.
    /// Bit 0: is_privileged
    /// Bit 1: is_global
    pub flags: u32,
}

/// Value in the ZONE_POLICY map. Keyed by zone_id (u32).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ZonePolicyKernel {
    /// reserved: bitmask of allowed Linux capabilities. Written by userspace
    /// but not read by any eBPF hook — capability enforcement is not
    /// implemented at the BPF level. Used only for CAP_SYS_PTRACE detection
    /// in userspace (sets POLICY_FLAG_ALLOW_PTRACE).
    pub caps_mask: u64,
    /// Policy flags.
    /// Bit 0: allow_ptrace
    /// Bit 1: allow_host_network
    pub flags: u32,
    pub _pad: u32,
}

/// Key in the ZONE_ALLOWED_COMMS map. Value is u8 (1 = allowed).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZoneCommKey {
    pub src_zone: u32,
    pub dst_zone: u32,
}

/// LPM-trie key for the per-zone IPv4 egress CIDR allowlist (`EGRESS_CIDR_MAP`).
/// `zone_id` is matched exactly (prefix always covers its 32 bits); `addr` is
/// the IPv4 destination in NETWORK byte order, longest-prefix matched for CIDR
/// semantics. eBPF reads `addr` straight from `sockaddr_in.sin_addr`; userspace
/// writes `u32::from(ipv4).to_be()` — both land as network-order bytes in
/// memory, which is what the kernel LPM trie compares.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressCidrKey {
    pub zone_id: u32,
    pub addr: u32,
}

/// LPM-trie key for the per-zone IPv6 egress CIDR allowlist
/// (`EGRESS_CIDR6_MAP`). The IPv6 address is stored as the 16 raw network-order
/// bytes from `sockaddr_in6.sin6_addr`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressCidr6Key {
    pub zone_id: u32,
    pub addr: [u8; 16],
}

/// Value in both egress CIDR tries. `port == 0` means any destination port;
/// otherwise it is the raw network-order `sin_port` value read by eBPF.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EgressCidrValue {
    pub port: u16,
    pub _pad: u16,
}

/// Bits of an `EgressCidrKey` prefix that pin the zone_id (the leading u32).
pub const EGRESS_CIDR_ZONE_BITS: u32 = 32;
/// Max entries in the egress CIDR allowlist trie (across all zones).
pub const MAX_EGRESS_CIDRS: u32 = 8192;

// Flag constants for ZoneInfoKernel.flags
/// reserved: set by userspace for ZoneType::Privileged but not checked by
/// any eBPF hook. Privileged zones receive standard enforcement.
pub const ZONE_FLAG_PRIVILEGED: u32 = 1 << 0;
pub const ZONE_FLAG_GLOBAL: u32 = 1 << 1;

// Flag constants for ZonePolicyKernel.flags
pub const POLICY_FLAG_ALLOW_PTRACE: u32 = 1 << 0;
/// reserved: set by userspace for NetworkMode::Host but not checked by
/// any eBPF hook. No network namespace enforcement exists yet.
pub const POLICY_FLAG_ALLOW_HOST_NET: u32 = 1 << 1;
/// Allow network access for the zone. Set by userspace for any network mode
/// other than Isolated. Without it, a zoned caller is network-isolated:
/// `socket_connect`, `socket_sendmsg`, and `socket_bind` deny non-loopback
/// AF_INET/AF_INET6 operations (loopback is always allowed).
pub const POLICY_FLAG_ALLOW_NETWORK: u32 = 1 << 2;

/// Address families relevant to the network hooks.
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// Result of the startup self-test that validates kernel struct offsets.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SelfTestResult {
    /// cgroup_id from `bpf_get_current_cgroup_id()` (known-good BPF helper).
    pub helper_cgroup_id: u64,
    /// cgroup_id derived from the hardcoded offset chain.
    pub offset_cgroup_id: u64,
}

/// Result of the file/inode offset self-test.
/// Validates FILE_F_INODE_OFFSET and INODE_I_INO_OFFSET are correct.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SelfTestInodeResult {
    /// Inode number derived via the offset chain (file->f_inode->i_ino).
    pub offset_ino: u64,
}

/// Result of the unix socket offset self-test.
/// Validates SOCK_CGRP_DATA_CGROUP_OFFSET produces a valid cgroup_id.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SelfTestUnixResult {
    /// cgroup_id of the peer socket, derived via sock→sk_cgrp_data→cgroup→kn→id.
    pub peer_cgroup_id: u64,
}

/// Per-hook enforcement decision counters.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EnforcementCounters {
    pub allow: u64,
    pub deny: u64,
    pub error: u64,
    /// Ring buffer events lost (reserve() returned None).
    pub lost: u64,
}

// Program indices in the ENFORCEMENT_COUNTERS array.
pub const PROG_FILE_OPEN: u32 = 0;
pub const PROG_BPRM_CHECK: u32 = 1;
pub const PROG_PTRACE_CHECK: u32 = 2;
pub const PROG_TASK_KILL: u32 = 3;
pub const PROG_MMAP_FILE: u32 = 4;
pub const PROG_UNIX_CONNECT: u32 = 5;
pub const PROG_SOCKET_CONNECT: u32 = 6;
pub const PROG_SOCKET_SENDMSG: u32 = 7;
pub const PROG_SOCKET_BIND: u32 = 8;
/// Sized to 16 for headroom — avoids pin-breaking changes when adding hooks.
pub const ENFORCEMENT_COUNTER_ENTRIES: u32 = 16;

// Hook type constants for EnforcementEvent.
pub const HOOK_FILE_OPEN: u8 = 0;
pub const HOOK_BPRM_CHECK: u8 = 1;
pub const HOOK_PTRACE_CHECK: u8 = 2;
pub const HOOK_TASK_KILL: u8 = 3;
pub const HOOK_MMAP_FILE: u8 = 4;
pub const HOOK_UNIX_CONNECT: u8 = 5;
pub const HOOK_SOCKET_CONNECT: u8 = 6;
pub const HOOK_SOCKET_SENDMSG: u8 = 7;
pub const HOOK_SOCKET_BIND: u8 = 8;

// Decision constants for EnforcementEvent.
/// Used in userspace display only — eBPF hooks never emit allow events.
pub const DECISION_ALLOW: u8 = 0;
pub const DECISION_DENY: u8 = 1;
/// Audit mode converted a deny decision into an allowed-but-recorded
/// operation. The per-hook `deny` counter still counts it as a deny decision.
pub const DECISION_WOULD_DENY: u8 = 2;
/// A zoned task migrated out of its cgroup zone. Detection only — BPF-LSM
/// cannot prevent cgroup migration on supported kernels, so this is recorded
/// (event + counter + degraded health) but the move is not blocked.
pub const DECISION_ESCAPE: u8 = 3;

/// Sentinel `hook` value for cgroup-escape events. Intentionally outside the
/// nine LSM hook indices so escape detection never inflates the hook set.
pub const HOOK_CGROUP_ESCAPE: u8 = 0xFF;

// ENFORCEMENT_MODE map values (single-entry array, index 0).
/// Deny decisions return -1 (surfaced to userspace as EPERM).
pub const MODE_ENFORCE: u32 = 0;
/// Deny decisions are recorded (counter + event) but the operation proceeds.
pub const MODE_AUDIT: u32 = 1;

/// Enforcement event emitted from BPF hooks via ring buffer.
///
/// Fixed 48-byte struct. All hooks populate the common fields;
/// hook-specific context goes in the `context` field:
///   - file_open / bprm_check: the denied inode number
///   - unix_stream_connect: the peer cgroup_id
///   - ptrace / task_kill: 0 (target PID to be added later)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EnforcementEvent {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub hook: u8,
    pub decision: u8,
    pub _pad0: [u8; 2],
    pub caller_zone: u32,
    pub target_zone: u32,
    pub context: u64,
    pub _reserved: [u64; 2],
}

#[cfg(feature = "userspace")]
mod cap_convert {
    use super::ZonePolicyKernel;

    const CAPS: &[&str] = &[
        "CAP_CHOWN",              // 0
        "CAP_DAC_OVERRIDE",       // 1
        "CAP_DAC_READ_SEARCH",    // 2
        "CAP_FOWNER",             // 3
        "CAP_FSETID",             // 4
        "CAP_KILL",               // 5
        "CAP_SETGID",             // 6
        "CAP_SETUID",             // 7
        "CAP_SETPCAP",            // 8
        "CAP_LINUX_IMMUTABLE",    // 9
        "CAP_NET_BIND_SERVICE",   // 10
        "CAP_NET_BROADCAST",      // 11
        "CAP_NET_ADMIN",          // 12
        "CAP_NET_RAW",            // 13
        "CAP_IPC_LOCK",           // 14
        "CAP_IPC_OWNER",          // 15
        "CAP_SYS_MODULE",         // 16
        "CAP_SYS_RAWIO",          // 17
        "CAP_SYS_CHROOT",         // 18
        "CAP_SYS_PTRACE",         // 19
        "CAP_SYS_PACCT",          // 20
        "CAP_SYS_ADMIN",          // 21
        "CAP_SYS_BOOT",           // 22
        "CAP_SYS_NICE",           // 23
        "CAP_SYS_RESOURCE",       // 24
        "CAP_SYS_TIME",           // 25
        "CAP_SYS_TTY_CONFIG",     // 26
        "CAP_MKNOD",              // 27
        "CAP_LEASE",              // 28
        "CAP_AUDIT_WRITE",        // 29
        "CAP_AUDIT_CONTROL",      // 30
        "CAP_SETFCAP",            // 31
        "CAP_MAC_OVERRIDE",       // 32
        "CAP_MAC_ADMIN",          // 33
        "CAP_SYSLOG",             // 34
        "CAP_WAKE_ALARM",         // 35
        "CAP_BLOCK_SUSPEND",      // 36
        "CAP_AUDIT_READ",         // 37
        "CAP_PERFMON",            // 38
        "CAP_BPF",                // 39
        "CAP_CHECKPOINT_RESTORE", // 40
    ];

    fn normalize_cap_name(s: &str) -> String {
        let upper = s.to_uppercase();
        if upper.starts_with("CAP_") {
            upper
        } else {
            format!("CAP_{upper}")
        }
    }

    /// Convert capability names to a bitmask. Unknown names are silently ignored.
    /// Use `caps_to_mask_validated` when you need to detect typos.
    pub fn caps_to_mask(caps: &[impl AsRef<str>]) -> u64 {
        let mut mask = 0u64;
        for cap in caps {
            let name = normalize_cap_name(cap.as_ref());
            if let Some(pos) = CAPS.iter().position(|&c| c == name.as_str()) {
                mask |= 1u64 << pos;
            }
        }
        mask
    }

    /// Convert capability names to a bitmask, also returning any unrecognized names.
    pub fn caps_to_mask_validated(caps: &[impl AsRef<str>]) -> (u64, Vec<String>) {
        let mut mask = 0u64;
        let mut unknown = Vec::new();
        for cap in caps {
            let name = normalize_cap_name(cap.as_ref());
            if let Some(pos) = CAPS.iter().position(|&c| c == name) {
                mask |= 1u64 << pos;
            } else {
                unknown.push(name);
            }
        }
        (mask, unknown)
    }

    impl ZonePolicyKernel {
        pub fn from_caps(
            caps: &[impl AsRef<str>],
            allow_ptrace: bool,
            allow_host_net: bool,
            allow_network: bool,
        ) -> Self {
            let mut flags = 0u32;
            if allow_ptrace {
                flags |= super::POLICY_FLAG_ALLOW_PTRACE;
            }
            if allow_host_net {
                flags |= super::POLICY_FLAG_ALLOW_HOST_NET;
            }
            if allow_network {
                flags |= super::POLICY_FLAG_ALLOW_NETWORK;
            }
            Self {
                caps_mask: caps_to_mask(caps),
                flags,
                _pad: 0,
            }
        }
    }
}

#[cfg(feature = "userspace")]
pub use cap_convert::{caps_to_mask, caps_to_mask_validated};

unsafe impl Sync for ZoneInfoKernel {}
unsafe impl Send for ZoneInfoKernel {}
unsafe impl Sync for ZonePolicyKernel {}
unsafe impl Send for ZonePolicyKernel {}
unsafe impl Sync for ZoneCommKey {}
unsafe impl Send for ZoneCommKey {}
unsafe impl Sync for EgressCidrKey {}
unsafe impl Send for EgressCidrKey {}
unsafe impl Sync for EgressCidr6Key {}
unsafe impl Send for EgressCidr6Key {}
unsafe impl Sync for EgressCidrValue {}
unsafe impl Send for EgressCidrValue {}
unsafe impl Sync for SelfTestResult {}
unsafe impl Send for SelfTestResult {}
unsafe impl Sync for EnforcementCounters {}
unsafe impl Send for EnforcementCounters {}
unsafe impl Sync for EnforcementEvent {}
unsafe impl Send for EnforcementEvent {}
unsafe impl Sync for SelfTestInodeResult {}
unsafe impl Send for SelfTestInodeResult {}
unsafe impl Sync for SelfTestUnixResult {}
unsafe impl Send for SelfTestUnixResult {}

#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ZoneInfoKernel {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ZonePolicyKernel {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for ZoneCommKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for EgressCidrKey {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for EgressCidr6Key {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for EgressCidrValue {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SelfTestResult {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for EnforcementCounters {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for EnforcementEvent {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SelfTestInodeResult {}
#[cfg(feature = "userspace")]
unsafe impl aya::Pod for SelfTestUnixResult {}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn zone_info_kernel_size() {
        assert_eq!(size_of::<ZoneInfoKernel>(), 8);
    }

    #[test]
    fn zone_policy_kernel_size() {
        assert_eq!(size_of::<ZonePolicyKernel>(), 16);
    }

    #[test]
    fn zone_comm_key_size() {
        assert_eq!(size_of::<ZoneCommKey>(), 8);
    }

    #[test]
    fn egress_cidr_keys_and_value_sizes() {
        assert_eq!(size_of::<EgressCidrKey>(), 8);
        assert_eq!(size_of::<EgressCidr6Key>(), 20);
        assert_eq!(size_of::<EgressCidrValue>(), 4);
    }

    #[test]
    fn self_test_result_size() {
        assert_eq!(size_of::<SelfTestResult>(), 16);
    }

    #[test]
    fn enforcement_counters_size() {
        assert_eq!(size_of::<EnforcementCounters>(), 32);
    }

    #[test]
    fn self_test_inode_result_size() {
        assert_eq!(size_of::<SelfTestInodeResult>(), 8);
    }

    #[test]
    fn self_test_unix_result_size() {
        assert_eq!(size_of::<SelfTestUnixResult>(), 8);
    }

    #[test]
    fn enforcement_event_size() {
        assert_eq!(size_of::<EnforcementEvent>(), 48);
    }

    #[test]
    #[cfg(feature = "userspace")]
    fn caps_to_mask_basic() {
        let mask = caps_to_mask(&["CAP_NET_ADMIN", "CAP_SYS_PTRACE"]);
        assert_eq!(mask, (1 << 12) | (1 << 19));
    }

    #[test]
    #[cfg(feature = "userspace")]
    fn caps_to_mask_short_form() {
        let mask = caps_to_mask(&["NET_ADMIN"]);
        assert_eq!(mask, 1 << 12);
    }

    #[test]
    #[cfg(feature = "userspace")]
    fn caps_to_mask_validated_detects_typo() {
        let (mask, unknown) = caps_to_mask_validated(&["CAP_NET_ADMIN", "CPA_NET_ADMIN"]);
        assert_eq!(mask, 1 << 12); // only the valid one
        assert_eq!(unknown.len(), 1);
        assert!(unknown[0].contains("CPA_NET_ADMIN"));
    }

    #[test]
    #[cfg(feature = "userspace")]
    fn caps_to_mask_validated_clean_input() {
        let (_, unknown) = caps_to_mask_validated(&["CAP_KILL", "NET_ADMIN"]);
        assert!(unknown.is_empty());
    }

    #[test]
    #[cfg(feature = "userspace")]
    fn from_caps_sets_network_flag_only_when_allowed() {
        let none: &[&str] = &[];
        let locked = ZonePolicyKernel::from_caps(none, false, false, false);
        assert_eq!(locked.flags & super::POLICY_FLAG_ALLOW_NETWORK, 0);

        let open = ZonePolicyKernel::from_caps(none, false, false, true);
        assert_ne!(open.flags & super::POLICY_FLAG_ALLOW_NETWORK, 0);
        // Network is an independent bit — it must not disturb the others.
        assert_eq!(open.flags & super::POLICY_FLAG_ALLOW_PTRACE, 0);
        assert_eq!(open.flags & super::POLICY_FLAG_ALLOW_HOST_NET, 0);
    }
}
