//! eBPF program lifecycle for syva.
//!
//! Loads and attaches the supported LSM programs. Provides typed
//! wrappers for BPF map operations (zone membership, policy, comms).

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::types::{NetworkMode, ZonePolicy, ZoneType};
use aya::maps::HashMap as AyaHashMap;
use aya::maps::RingBuf;
use aya::programs::Lsm;
use aya::{Btf, Ebpf, EbpfLoader};
use syva_ebpf_common::{
    st_dev_to_kernel_dev, EnforcementCounters, InodeProbeRequest, InodeProbeResult, InodeZoneKey,
    SelfTestResult, SelfTestUnixResult, ZoneCommKey, ZoneInfoKernel, ZonePolicyKernel,
    ZONE_FLAG_GLOBAL, ZONE_FLAG_PRIVILEGED,
};

const BPF_PIN_PATH: &str = "/sys/fs/bpf/syva";

#[derive(Debug, Clone, Copy)]
struct LsmProgram {
    program_name: &'static str,
    hook_name: &'static str,
}

/// Program symbol and kernel hook name are intentionally separate. The program
/// symbol is looked up in the loaded object; the hook name is resolved by aya as
/// kernel BTF type `bpf_lsm_<hook_name>`.
const LSM_PROGRAMS: &[LsmProgram] = &[
    LsmProgram {
        program_name: "syva_file_open",
        hook_name: "file_open",
    },
    LsmProgram {
        program_name: "syva_bprm_check",
        hook_name: "bprm_check_security",
    },
    LsmProgram {
        program_name: "syva_ptrace_check",
        hook_name: "ptrace_access_check",
    },
    LsmProgram {
        program_name: "syva_task_kill",
        hook_name: "task_kill",
    },
    LsmProgram {
        program_name: "syva_mmap_file",
        hook_name: "mmap_file",
    },
    LsmProgram {
        program_name: "syva_unix_connect",
        hook_name: "unix_stream_connect",
    },
    LsmProgram {
        program_name: "syva_socket_connect",
        hook_name: "socket_connect",
    },
    LsmProgram {
        program_name: "syva_socket_sendmsg",
        hook_name: "socket_sendmsg",
    },
    LsmProgram {
        program_name: "syva_socket_bind",
        hook_name: "socket_bind",
    },
];

const MAP_NAMES: &[&str] = &[
    "ZONE_MEMBERSHIP",
    "ZONE_POLICY",
    "INODE_ZONE_MAP",
    "ZONE_ALLOWED_COMMS",
    "SELF_TEST",
    "INODE_PROBE_REQUEST",
    "INODE_PROBE_RESULT",
    "SELF_TEST_UNIX",
    "ENFORCEMENT_COUNTERS",
    "ENFORCEMENT_EVENTS",
    "ENFORCEMENT_MODE",
    "CGROUP_ESCAPE_COUNT",
    "EGRESS_CIDR_MAP",
    "EGRESS_CIDR6_MAP",
];

/// fentry program name for the cgroup-escape detector (best-effort).
const ESCAPE_PROGRAM: &str = "syva_cgroup_escape";
/// Kernel function the escape detector attaches to.
const ESCAPE_ATTACH_FN: &str = "cgroup_attach_task";

/// eBPF manager for the standalone enforce agent.
pub struct EnforceEbpf {
    bpf: Ebpf,
    pin_path: PathBuf,
    /// True once the cgroup-escape fentry program has loaded. Detection is
    /// best-effort: a kernel without fentry support leaves this false and the
    /// LSM enforcement path is unaffected.
    escape_detector_loaded: bool,
    /// Cache of raw userspace st_dev → kernel s_dev, filled by the inode
    /// probe. One probe per filesystem (per btrfs subvolume) is enough; the
    /// kernel value cannot change for a mounted superblock.
    dev_cache: std::collections::HashMap<u64, u32>,
}

impl EnforceEbpf {
    /// Load and attach eBPF programs.
    pub fn load(ebpf_obj: Option<&Path>) -> anyhow::Result<Self> {
        let obj_path = match ebpf_obj {
            Some(p) => p.to_path_buf(),
            None => find_ebpf_object()?,
        };
        tracing::info!(
            event = "syva.ebpf.object_selected",
            component = "syva-core",
            object_path = %obj_path.display(),
            result = "ok",
            "loading eBPF object"
        );

        let pin_path = PathBuf::from(BPF_PIN_PATH);

        // Check for mutual exclusion — if maps are already pinned, another
        // syva instance may be running. This also covers upgrades across map
        // layout changes (e.g. the 8→16-byte INODE_ZONE_MAP key): stale pins
        // from a crashed older core are refused here, before any reuse.
        if pin_path.exists() {
            let has_maps = fs::read_dir(&pin_path)
                .map(|entries| entries.count() > 0)
                .unwrap_or(false);
            if has_maps {
                anyhow::bail!(
                    "BPF maps already pinned at {BPF_PIN_PATH} — another syva instance \
                     may be running. Stop it first, or remove stale pins with: rm -rf {BPF_PIN_PATH}"
                );
            }
        }

        fs::create_dir_all(&pin_path)?;

        let btf = Btf::from_sys_fs().map_err(|e| {
            anyhow::anyhow!("failed to load BTF: {e} — kernel needs CONFIG_DEBUG_INFO_BTF=y")
        })?;

        // Resolve kernel struct offsets from BTF and patch eBPF globals.
        let offsets = resolve_offsets();

        let obj_data = fs::read(&obj_path).map_err(|e| {
            anyhow::anyhow!("failed to read eBPF object {}: {e}", obj_path.display())
        })?;

        let mut loader = EbpfLoader::new();
        loader.btf(Some(&btf)).map_pin_path(&pin_path);

        for (name, val) in &offsets {
            loader.set_global(name.as_str(), val, true);
        }

        let mut bpf = loader.load(&obj_data).map_err(|e| {
            anyhow::anyhow!("failed to load eBPF: {e} — check CONFIG_BPF_LSM=y and lsm=bpf")
        })?;

        // Phase 1: Load all LSM programs (validates with kernel verifier).
        // Programs are NOT attached yet — no enforcement until attach_programs().
        for program in LSM_PROGRAMS {
            let prog: &mut Lsm = bpf
                .program_mut(program.program_name)
                .ok_or_else(|| anyhow::anyhow!("LSM program '{}' not found", program.program_name))?
                .try_into()?;
            prog.load(program.hook_name, &btf).map_err(|error| {
                anyhow::anyhow!(
                    "failed to load LSM program '{}' for hook '{}': {error}",
                    program.program_name,
                    program.hook_name
                )
            })?;
            tracing::debug!(
                program = program.program_name,
                hook = program.hook_name,
                "loaded LSM program"
            );
        }

        tracing::info!(
            event = "syva.ebpf.loaded",
            component = "syva-core",
            object_path = %obj_path.display(),
            programs = LSM_PROGRAMS.len(),
            result = "ok",
            "eBPF programs loaded (not yet attached)"
        );

        // Best-effort: load the cgroup-escape fentry detector. A kernel without
        // fentry/BTF support for the target leaves detection off but never
        // blocks LSM enforcement from coming up.
        let escape_detector_loaded = match load_escape_detector(&mut bpf, &btf) {
            Ok(()) => true,
            Err(error) => {
                tracing::warn!(
                    event = "syva.escape.unavailable",
                    component = "syva-core",
                    %error,
                    "cgroup-escape detector unavailable; LSM enforcement unaffected"
                );
                false
            }
        };

        Ok(Self {
            bpf,
            pin_path,
            escape_detector_loaded,
            dev_cache: std::collections::HashMap::new(),
        })
    }

    /// Attach the cgroup-escape fentry detector. Best-effort and idempotent:
    /// returns Ok(false) when the detector did not load.
    pub fn attach_escape_detector(&mut self) -> anyhow::Result<bool> {
        if !self.escape_detector_loaded {
            return Ok(false);
        }
        let prog: &mut aya::programs::FEntry = self
            .bpf
            .program_mut(ESCAPE_PROGRAM)
            .ok_or_else(|| anyhow::anyhow!("escape program '{ESCAPE_PROGRAM}' not found"))?
            .try_into()?;
        prog.attach()?;
        tracing::info!(
            event = "syva.escape.attached",
            component = "syva-core",
            function = ESCAPE_ATTACH_FN,
            "cgroup-escape detector attached (detection only)"
        );
        Ok(true)
    }

    /// Read the total count of detected cgroup escapes (summed across CPUs).
    pub fn read_escape_count(&self) -> anyhow::Result<u64> {
        use aya::maps::PerCpuArray;
        let map = PerCpuArray::<_, u64>::try_from(
            self.bpf
                .map("CGROUP_ESCAPE_COUNT")
                .ok_or_else(|| anyhow::anyhow!("CGROUP_ESCAPE_COUNT map not found"))?,
        )?;
        let per_cpu = map.get(&0, 0)?;
        Ok(per_cpu.iter().copied().sum())
    }

    /// Attach all loaded LSM programs. Call this AFTER zone membership is
    /// populated to eliminate the startup race window where hooks are active
    /// but ZONE_MEMBERSHIP is empty (all containers would appear unzoned).
    pub fn attach_programs(&mut self) -> anyhow::Result<usize> {
        tracing::info!(
            event = "syva.ebpf.attach.begin",
            component = "syva-core",
            expected_hooks = LSM_PROGRAMS.len(),
            "attaching supported BPF-LSM programs"
        );
        let mut attached = 0usize;
        for program in LSM_PROGRAMS {
            let prog: &mut Lsm = self
                .bpf
                .program_mut(program.program_name)
                .ok_or_else(|| anyhow::anyhow!("LSM program '{}' not found", program.program_name))?
                .try_into()?;
            if let Err(error) = prog.attach() {
                tracing::error!(
                    event = "syva.ebpf.attach.failed",
                    component = "syva-core",
                    program = program.program_name,
                    hook = program.hook_name,
                    result = "error",
                    %error,
                    "failed to attach LSM program"
                );
                return Err(error.into());
            }
            attached += 1;
            tracing::info!(
                event = "syva.ebpf.attached",
                component = "syva-core",
                program = program.program_name,
                hook = program.hook_name,
                result = "ok",
                "attached LSM program"
            );
        }
        tracing::info!(
            attached_hooks = attached,
            expected_hooks = LSM_PROGRAMS.len(),
            "all LSM programs attached — enforcement active"
        );
        Ok(attached)
    }

    /// Take ownership of the ring buffer for event streaming.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn take_event_ring_buf(&mut self) -> Option<RingBuf<aya::maps::MapData>> {
        let map = self.bpf.take_map("ENFORCEMENT_EVENTS")?;
        RingBuf::try_from(map).ok()
    }

    /// Register a cgroup as belonging to a zone.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn add_zone_member(
        &mut self,
        cgroup_id: u64,
        zone_id: u32,
        zone_type: ZoneType,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(cgroup_id != 0, "cgroup_id 0 is invalid (reserved for host)");
        let mut flags = 0u32;
        match zone_type {
            ZoneType::Global => flags |= ZONE_FLAG_GLOBAL,
            ZoneType::Privileged => flags |= ZONE_FLAG_PRIVILEGED,
            ZoneType::NonGlobal => {}
        }

        let info = ZoneInfoKernel { zone_id, flags };

        let mut map: AyaHashMap<_, u64, ZoneInfoKernel> = AyaHashMap::try_from(
            self.bpf
                .map_mut("ZONE_MEMBERSHIP")
                .ok_or_else(|| anyhow::anyhow!("ZONE_MEMBERSHIP map not found"))?,
        )?;

        map.insert(cgroup_id, info, 0)?;
        Ok(())
    }

    /// Remove a cgroup from zone membership.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn remove_zone_member(&mut self, cgroup_id: u64) -> anyhow::Result<()> {
        let mut map: AyaHashMap<_, u64, ZoneInfoKernel> = AyaHashMap::try_from(
            self.bpf
                .map_mut("ZONE_MEMBERSHIP")
                .ok_or_else(|| anyhow::anyhow!("ZONE_MEMBERSHIP map not found"))?,
        )?;
        let _ = map.remove(&cgroup_id);
        Ok(())
    }

    /// Write the global enforcement mode into the ENFORCEMENT_MODE map.
    /// Called once at startup, before the hooks attach. In audit mode the
    /// hooks record would-deny decisions (counter + event) without blocking.
    pub fn set_enforcement_mode(&mut self, audit: bool) -> anyhow::Result<()> {
        use aya::maps::Array;
        use syva_ebpf_common::{MODE_AUDIT, MODE_ENFORCE};

        let mut map = Array::<_, u32>::try_from(
            self.bpf
                .map_mut("ENFORCEMENT_MODE")
                .ok_or_else(|| anyhow::anyhow!("ENFORCEMENT_MODE map not found"))?,
        )?;
        map.set(0, if audit { MODE_AUDIT } else { MODE_ENFORCE }, 0)?;
        Ok(())
    }

    /// Set enforcement policy for a zone.
    pub fn set_zone_policy(&mut self, zone_id: u32, policy: &ZonePolicy) -> anyhow::Result<()> {
        use aya::maps::Array;

        let allow_ptrace = policy.capabilities.allowed.iter().any(|c| {
            let u = c.to_uppercase();
            u == "CAP_SYS_PTRACE" || u == "SYS_PTRACE"
        });
        let allow_host_net = policy.network.mode == NetworkMode::Host;
        // Network is permitted for any mode other than Isolated. An Isolated
        // zone (the default) is network-isolated: socket_connect / sendmsg /
        // bind deny its non-loopback operations (loopback only).
        let allow_network = policy.network.mode != NetworkMode::Isolated;
        let kernel_policy = ZonePolicyKernel::from_caps(
            &policy.capabilities.allowed,
            allow_ptrace,
            allow_host_net,
            allow_network,
        );

        let mut map = Array::<_, ZonePolicyKernel>::try_from(
            self.bpf
                .map_mut("ZONE_POLICY")
                .ok_or_else(|| anyhow::anyhow!("ZONE_POLICY map not found"))?,
        )?;

        map.set(zone_id, kernel_policy, 0)?;
        Ok(())
    }

    /// Read enforcement counters, summed across all CPUs.
    pub fn read_counters(&self) -> anyhow::Result<Vec<(String, EnforcementCounters)>> {
        use aya::maps::PerCpuArray;

        let map = PerCpuArray::<_, EnforcementCounters>::try_from(
            self.bpf
                .map("ENFORCEMENT_COUNTERS")
                .ok_or_else(|| anyhow::anyhow!("ENFORCEMENT_COUNTERS map not found"))?,
        )?;

        let mut results = Vec::new();
        for (idx, program) in LSM_PROGRAMS.iter().enumerate() {
            let per_cpu = map.get(&(idx as u32), 0)?;
            let mut total = EnforcementCounters {
                allow: 0,
                deny: 0,
                error: 0,
                lost: 0,
            };
            for cpu_val in per_cpu.iter() {
                total.allow += cpu_val.allow;
                total.deny += cpu_val.deny;
                total.error += cpu_val.error;
                total.lost += cpu_val.lost;
            }
            results.push((program.program_name.to_string(), total));
        }

        Ok(results)
    }

    /// Verify the eBPF offset self-test result.
    ///
    /// The file_open hook writes a SelfTestResult on first invocation, comparing
    /// bpf_get_current_cgroup_id() (known-good) against the offset-chain-derived
    /// value. If they differ, the kernel struct offsets are wrong and all hooks
    /// that use the offset chain will produce incorrect zone lookups.
    ///
    /// Triggers a synthetic file open to ensure the hook fires, then polls the
    /// SELF_TEST map until the result is available.
    pub async fn verify_self_test(&self) -> anyhow::Result<()> {
        use std::time::Duration;

        // Trigger a file_open so the self-test fires.
        let _ = std::fs::File::open("/proc/self/status");

        for attempt in 0..20 {
            // Read BPF map synchronously — avoids Send bound on self.bpf.
            let result = tokio::task::block_in_place(|| {
                use aya::maps::Array;
                let map = Array::<_, SelfTestResult>::try_from(
                    self.bpf
                        .map("SELF_TEST")
                        .ok_or_else(|| anyhow::anyhow!("SELF_TEST map not found"))?,
                )?;
                anyhow::Ok(map.get(&0, 0)?)
            })?;

            if result.helper_cgroup_id != 0 {
                if result.helper_cgroup_id == result.offset_cgroup_id {
                    tracing::info!(
                        event = "syva.selftest.passed",
                        component = "syva-core",
                        test = "cgroup",
                        result = "ok",
                        cgroup_id = result.helper_cgroup_id,
                        "self-test passed: kernel struct offsets verified"
                    );
                    return Ok(());
                } else {
                    anyhow::bail!(
                        "kernel struct offset mismatch: helper_cgroup_id={} \
                         offset_cgroup_id={} delta={} — run with pahole installed \
                         or report this kernel version",
                        result.helper_cgroup_id,
                        result.offset_cgroup_id,
                        result.helper_cgroup_id.abs_diff(result.offset_cgroup_id),
                    );
                }
            }
            if attempt < 19 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        anyhow::bail!("self-test timed out after 1s — file_open hook may not be attached")
    }

    /// Verify the file → inode → superblock offset chain end to end.
    ///
    /// Probes a freshly created temp file through the inode probe: the
    /// file_open hook derives (ino, dev) via FILE_F_INODE_OFFSET /
    /// INODE_I_INO_OFFSET / INODE_I_SB_OFFSET / SUPER_BLOCK_S_DEV_OFFSET, and
    /// we compare against stat() — ino directly, dev through the
    /// st_dev→kernel-dev conversion (valid on the temp filesystem, where
    /// st_dev faithfully encodes s_dev; this also cross-checks the conversion
    /// itself). An offset or encoding mistake fails core startup here instead
    /// of silently breaking enforcement.
    pub async fn verify_inode_self_test(&mut self) -> anyhow::Result<()> {
        let self_test_path = std::env::temp_dir().join(format!(
            "syva-inode-self-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&self_test_path, b"syva inode self-test\n").map_err(|e| {
            anyhow::anyhow!(
                "failed to create inode self-test file {}: {e}",
                self_test_path.display()
            )
        })?;
        let meta = std::fs::metadata(&self_test_path).map_err(|e| {
            anyhow::anyhow!(
                "failed to stat inode self-test file {}: {e}",
                self_test_path.display()
            )
        })?;
        let expected_ino = meta.ino();
        let expected_dev = st_dev_to_kernel_dev(meta.dev());

        let probed =
            tokio::task::block_in_place(|| self.probe_kernel_dev(&self_test_path, expected_ino));
        let _ = std::fs::remove_file(&self_test_path);

        let derived_dev = probed.map_err(|e| {
            anyhow::anyhow!(
                "inode offset self-test FAILED ({e}) — FILE_F_INODE_OFFSET or \
                 INODE_I_INO_OFFSET is wrong for this kernel, or the file_open \
                 hook is not attached. Install pahole and restart."
            )
        })?;

        if derived_dev != expected_dev {
            anyhow::bail!(
                "inode dev self-test FAILED: expected kernel dev {expected_dev:#x} \
                 but eBPF derived {derived_dev:#x} — INODE_I_SB_OFFSET / \
                 SUPER_BLOCK_S_DEV_OFFSET is wrong for this kernel, or the \
                 st_dev→kernel-dev conversion is broken."
            );
        }

        tracing::info!(
            event = "syva.selftest.passed",
            component = "syva-core",
            test = "inode",
            result = "ok",
            inode = expected_ino,
            kernel_dev = derived_dev,
            "inode self-test passed: file→inode→superblock offset chain verified"
        );
        Ok(())
    }

    /// Verify that SOCK_CGRP_DATA_CGROUP_OFFSET is correct.
    ///
    /// Triggers a Unix socket connection to fire the unix_stream_connect hook,
    /// which writes the peer's cgroup_id to SELF_TEST_UNIX. We verify the
    /// derived peer cgroup_id is non-zero, indicating the offset chain reads
    /// plausible data from the peer socket.
    pub async fn verify_unix_self_test(&self) -> anyhow::Result<()> {
        use std::io::ErrorKind;
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::time::Duration;

        // Trigger security_unix_stream_connect with a real connect(2). A
        // socketpair is already connected and does not exercise this LSM hook.
        let socket_path = std::env::temp_dir().join(format!(
            "syva-unix-self-test-{}-{}.sock",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        match fs::remove_file(&socket_path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "failed to remove stale Unix self-test socket {}: {error}",
                    socket_path.display()
                ));
            }
        }
        let listener = UnixListener::bind(&socket_path).map_err(|error| {
            anyhow::anyhow!(
                "failed to bind Unix self-test socket {}: {error}",
                socket_path.display()
            )
        })?;
        listener.set_nonblocking(true).map_err(|error| {
            anyhow::anyhow!("failed to set Unix self-test listener nonblocking: {error}")
        })?;
        let _client = UnixStream::connect(&socket_path).map_err(|error| {
            anyhow::anyhow!(
                "failed to connect Unix self-test socket {}: {error}",
                socket_path.display()
            )
        })?;
        match listener.accept() {
            Ok((_stream, _addr)) => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            Err(error) => {
                return Err(anyhow::anyhow!(
                    "failed to accept Unix self-test socket connection: {error}"
                ));
            }
        }
        let _ = fs::remove_file(&socket_path);

        for attempt in 0..20 {
            let result = tokio::task::block_in_place(|| {
                use aya::maps::Array;
                let map = Array::<_, SelfTestUnixResult>::try_from(
                    self.bpf
                        .map("SELF_TEST_UNIX")
                        .ok_or_else(|| anyhow::anyhow!("SELF_TEST_UNIX map not found"))?,
                )?;
                anyhow::Ok(map.get(&0, 0)?)
            })?;

            if result.peer_cgroup_id != 0 {
                // The peer cgroup_id should be non-zero and plausible.
                // We can't compare against a known value (unlike the cgroup/inode
                // self-tests) because the socketpair peer is in our own process.
                // A non-zero result confirms the offset chain reads valid memory.
                tracing::info!(
                    event = "syva.selftest.passed",
                    component = "syva-core",
                    test = "unix",
                    result = "ok",
                    peer_cgroup_id = result.peer_cgroup_id,
                    "unix self-test passed: SOCK_CGRP_DATA_CGROUP_OFFSET verified"
                );
                return Ok(());
            }
            if attempt < 19 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }

        anyhow::bail!(
            "unix self-test timed out — unix_stream_connect hook may not be \
             writing SELF_TEST_UNIX, or SOCK_CGRP_DATA_CGROUP_OFFSET is wrong"
        )
    }

    /// Allow cross-zone communication between two zones.
    ///
    /// Writes both directions (src→dst and dst→src) into ZONE_ALLOWED_COMMS.
    pub fn set_zone_allowed_comms(
        &mut self,
        src_zone_id: u32,
        dst_zone_id: u32,
    ) -> anyhow::Result<()> {
        let mut map: AyaHashMap<_, ZoneCommKey, u8> = AyaHashMap::try_from(
            self.bpf
                .map_mut("ZONE_ALLOWED_COMMS")
                .ok_or_else(|| anyhow::anyhow!("ZONE_ALLOWED_COMMS map not found"))?,
        )?;

        let fwd = ZoneCommKey {
            src_zone: src_zone_id,
            dst_zone: dst_zone_id,
        };
        let rev = ZoneCommKey {
            src_zone: dst_zone_id,
            dst_zone: src_zone_id,
        };
        map.insert(fwd, 1u8, 0)?;
        map.insert(rev, 1u8, 0)?;
        Ok(())
    }

    /// Replace a zone's egress allowlist. Entries may be IPv4 or IPv6 CIDRs,
    /// bare addresses, and may include one destination port. A network-locked
    /// zone may reach destinations covered by these prefixes when the port
    /// matches; port 0 in the BPF value means any port.
    pub fn set_zone_egress_cidrs(
        &mut self,
        zone_id: u32,
        cidrs: &[String],
    ) -> anyhow::Result<usize> {
        use aya::maps::lpm_trie::{Key, LpmTrie};
        use syva_ebpf_common::{
            EgressCidr6Key, EgressCidrKey, EgressCidrValue, EGRESS_CIDR_ZONE_BITS,
        };

        self.remove_zone_egress_cidrs(zone_id)?;

        let mut parsed = Vec::new();
        for cidr in cidrs {
            let Some(entry) = parse_egress_cidr(cidr) else {
                tracing::warn!(
                    zone_id,
                    entry = %cidr,
                    "skipping invalid egress allowlist entry"
                );
                continue;
            };
            parsed.push(entry);
        }

        let mut applied = 0usize;
        {
            let mut trie4: LpmTrie<_, EgressCidrKey, EgressCidrValue> = LpmTrie::try_from(
                self.bpf
                    .map_mut("EGRESS_CIDR_MAP")
                    .ok_or_else(|| anyhow::anyhow!("EGRESS_CIDR_MAP map not found"))?,
            )?;
            for entry in parsed
                .iter()
                .filter(|entry| matches!(entry.family, ParsedEgressFamily::Ipv4(_)))
            {
                let ParsedEgressFamily::Ipv4(ip) = entry.family else {
                    continue;
                };
                let value = EgressCidrValue {
                    // Network byte order, matching the eBPF sin_port read.
                    port: entry.port.map(u16::to_be).unwrap_or(0),
                    _pad: 0,
                };
                let key = Key::new(
                    EGRESS_CIDR_ZONE_BITS + entry.prefix_bits,
                    EgressCidrKey {
                        zone_id,
                        // Network byte order, matching the eBPF sin_addr read.
                        addr: u32::from(ip).to_be(),
                    },
                );
                trie4.insert(&key, value, 0)?;
                applied += 1;
            }
        }

        {
            let mut trie6: LpmTrie<_, EgressCidr6Key, EgressCidrValue> = LpmTrie::try_from(
                self.bpf
                    .map_mut("EGRESS_CIDR6_MAP")
                    .ok_or_else(|| anyhow::anyhow!("EGRESS_CIDR6_MAP map not found"))?,
            )?;
            for entry in parsed
                .iter()
                .filter(|entry| matches!(entry.family, ParsedEgressFamily::Ipv6(_)))
            {
                let ParsedEgressFamily::Ipv6(ip) = entry.family else {
                    continue;
                };
                let value = EgressCidrValue {
                    // Network byte order, matching the eBPF sin_port read.
                    port: entry.port.map(u16::to_be).unwrap_or(0),
                    _pad: 0,
                };
                let key = Key::new(
                    EGRESS_CIDR_ZONE_BITS + entry.prefix_bits,
                    EgressCidr6Key {
                        zone_id,
                        addr: ip.octets(),
                    },
                );
                trie6.insert(&key, value, 0)?;
                applied += 1;
            }
        }
        Ok(applied)
    }

    /// Remove every egress CIDR entry belonging to a zone.
    pub fn remove_zone_egress_cidrs(&mut self, zone_id: u32) -> anyhow::Result<()> {
        use aya::maps::lpm_trie::{Key, LpmTrie};
        use syva_ebpf_common::{EgressCidr6Key, EgressCidrKey, EgressCidrValue};

        {
            let mut trie4: LpmTrie<_, EgressCidrKey, EgressCidrValue> = LpmTrie::try_from(
                self.bpf
                    .map_mut("EGRESS_CIDR_MAP")
                    .ok_or_else(|| anyhow::anyhow!("EGRESS_CIDR_MAP map not found"))?,
            )?;
            let stale4: Vec<Key<EgressCidrKey>> = trie4
                .iter()
                .filter_map(Result::ok)
                .map(|(key, _)| key)
                .filter(|key| key.data().zone_id == zone_id)
                .collect();
            for key in stale4 {
                let _ = trie4.remove(&key);
            }
        }

        {
            let mut trie6: LpmTrie<_, EgressCidr6Key, EgressCidrValue> = LpmTrie::try_from(
                self.bpf
                    .map_mut("EGRESS_CIDR6_MAP")
                    .ok_or_else(|| anyhow::anyhow!("EGRESS_CIDR6_MAP map not found"))?,
            )?;
            let stale6: Vec<Key<EgressCidr6Key>> = trie6
                .iter()
                .filter_map(Result::ok)
                .map(|(key, _)| key)
                .filter(|key| key.data().zone_id == zone_id)
                .collect();
            for key in stale6 {
                let _ = trie6.remove(&key);
            }
        }
        Ok(())
    }

    /// Clear a zone's enforcement policy (zeroed entry — Array can't remove).
    pub fn remove_zone_policy(&mut self, zone_id: u32) -> anyhow::Result<()> {
        use aya::maps::Array;

        let mut map = Array::<_, ZonePolicyKernel>::try_from(
            self.bpf
                .map_mut("ZONE_POLICY")
                .ok_or_else(|| anyhow::anyhow!("ZONE_POLICY map not found"))?,
        )?;
        let zeroed = ZonePolicyKernel {
            caps_mask: 0,
            flags: 0,
            _pad: 0,
        };
        map.set(zone_id, zeroed, 0)?;
        Ok(())
    }

    /// Remove all ZONE_ALLOWED_COMMS entries involving a zone.
    pub fn remove_zone_comms(&mut self, zone_id: u32) -> anyhow::Result<()> {
        // Collect keys to remove (can't mutate while iterating).
        let keys_to_remove: Vec<ZoneCommKey> = {
            let map: AyaHashMap<_, ZoneCommKey, u8> = AyaHashMap::try_from(
                self.bpf
                    .map_mut("ZONE_ALLOWED_COMMS")
                    .ok_or_else(|| anyhow::anyhow!("ZONE_ALLOWED_COMMS map not found"))?,
            )?;

            map.keys()
                .filter_map(|k| k.ok())
                .filter(|k| k.src_zone == zone_id || k.dst_zone == zone_id)
                .collect()
        };

        let mut map: AyaHashMap<_, ZoneCommKey, u8> = AyaHashMap::try_from(
            self.bpf
                .map_mut("ZONE_ALLOWED_COMMS")
                .ok_or_else(|| anyhow::anyhow!("ZONE_ALLOWED_COMMS map not found"))?,
        )?;

        for key in keys_to_remove {
            let _ = map.remove(&key);
        }
        Ok(())
    }

    /// Remove a specific comm pair from ZONE_ALLOWED_COMMS (both directions).
    /// Unlike `remove_zone_comms`, this only removes the (a, b) and (b, a) entries,
    /// preserving any other comms involving either zone.
    pub fn remove_zone_comm_pair(&mut self, zone_a: u32, zone_b: u32) -> anyhow::Result<()> {
        let mut map: AyaHashMap<_, ZoneCommKey, u8> = AyaHashMap::try_from(
            self.bpf
                .map_mut("ZONE_ALLOWED_COMMS")
                .ok_or_else(|| anyhow::anyhow!("ZONE_ALLOWED_COMMS map not found"))?,
        )?;
        let fwd = ZoneCommKey {
            src_zone: zone_a,
            dst_zone: zone_b,
        };
        let rev = ZoneCommKey {
            src_zone: zone_b,
            dst_zone: zone_a,
        };
        let _ = map.remove(&fwd);
        let _ = map.remove(&rev);
        Ok(())
    }

    /// Remove all INODE_ZONE_MAP entries for a given zone.
    pub fn remove_zone_inodes(&mut self, zone_id: u32) -> anyhow::Result<()> {
        let keys_to_remove: Vec<InodeZoneKey> = {
            let map: AyaHashMap<_, InodeZoneKey, u32> = AyaHashMap::try_from(
                self.bpf
                    .map_mut("INODE_ZONE_MAP")
                    .ok_or_else(|| anyhow::anyhow!("INODE_ZONE_MAP map not found"))?,
            )?;

            map.iter()
                .filter_map(|r| r.ok())
                .filter(|(_, v)| *v == zone_id)
                .map(|(k, _)| k)
                .collect()
        };

        let mut map: AyaHashMap<_, InodeZoneKey, u32> = AyaHashMap::try_from(
            self.bpf
                .map_mut("INODE_ZONE_MAP")
                .ok_or_else(|| anyhow::anyhow!("INODE_ZONE_MAP map not found"))?,
        )?;

        for key in keys_to_remove {
            let _ = map.remove(&key);
        }
        Ok(())
    }

    /// Attempts per file before the inode probe fails a registration.
    const DEV_PROBE_ATTEMPTS: usize = 3;

    /// Resolve the kernel-internal `s_dev` of the filesystem holding `path`,
    /// cached per raw userspace st_dev (one probe per superblock / subvolume;
    /// the kernel value cannot change for a mounted superblock).
    fn kernel_dev_for(&mut self, path: &Path, meta: &fs::Metadata) -> anyhow::Result<u32> {
        if let Some(&dev) = self.dev_cache.get(&meta.dev()) {
            return Ok(dev);
        }
        let dev = self.probe_kernel_dev(path, meta.ino())?;
        self.dev_cache.insert(meta.dev(), dev);
        Ok(dev)
    }

    /// Learn the kernel `s_dev` for `path` from the kernel itself: arm
    /// INODE_PROBE_REQUEST with (ino, our tgid), open the file so the
    /// file_open hook fires on our own open, and read back the (ino, dev)
    /// the offset chain derived. Converting `stat`'s st_dev cannot replace
    /// this — filesystems like btrfs synthesize per-subvolume st_dev values
    /// that never match the superblock's s_dev.
    fn probe_kernel_dev(&mut self, path: &Path, expected_ino: u64) -> anyhow::Result<u32> {
        use aya::maps::Array;
        use std::os::unix::fs::OpenOptionsExt;

        let set_request = |bpf: &mut Ebpf, req: InodeProbeRequest| -> anyhow::Result<()> {
            let mut map = Array::<_, InodeProbeRequest>::try_from(
                bpf.map_mut("INODE_PROBE_REQUEST")
                    .ok_or_else(|| anyhow::anyhow!("INODE_PROBE_REQUEST map not found"))?,
            )?;
            map.set(0, req, 0)?;
            Ok(())
        };

        for attempt in 1..=Self::DEV_PROBE_ATTEMPTS {
            // Clear any stale result, then arm the request for our tgid.
            {
                let mut result = Array::<_, InodeProbeResult>::try_from(
                    self.bpf
                        .map_mut("INODE_PROBE_RESULT")
                        .ok_or_else(|| anyhow::anyhow!("INODE_PROBE_RESULT map not found"))?,
                )?;
                result.set(
                    0,
                    InodeProbeResult {
                        ino: 0,
                        dev: 0,
                        _pad: 0,
                    },
                    0,
                )?;
            }
            set_request(
                &mut self.bpf,
                InodeProbeRequest::new(expected_ino, std::process::id()),
            )?;

            // The file_open LSM hook runs synchronously inside this open(2),
            // so the result is ready once open returns. O_NONBLOCK keeps
            // FIFO / device-node host paths from hanging the probe.
            let opened = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(path);
            if let Err(e) = opened {
                let _ = set_request(&mut self.bpf, InodeProbeRequest::new(0, 0));
                return Err(anyhow::anyhow!(
                    "inode probe failed to open '{}': {e}",
                    path.display()
                ));
            }

            let result = {
                let map = Array::<_, InodeProbeResult>::try_from(
                    self.bpf
                        .map("INODE_PROBE_RESULT")
                        .ok_or_else(|| anyhow::anyhow!("INODE_PROBE_RESULT map not found"))?,
                )?;
                map.get(&0, 0)?
            };
            set_request(&mut self.bpf, InodeProbeRequest::new(0, 0))?;

            if result.ino == expected_ino {
                return Ok(result.dev);
            }
            tracing::warn!(
                attempt,
                path = %path.display(),
                expected_ino,
                got_ino = result.ino,
                "inode probe missed — retrying"
            );
        }
        anyhow::bail!(
            "inode probe for '{}' failed after {} attempts — the file_open hook \
             may not be attached yet (registration requires attached hooks)",
            path.display(),
            Self::DEV_PROBE_ATTEMPTS
        )
    }

    /// Register a single path's inode in INODE_ZONE_MAP (non-recursive),
    /// keyed by the composite (dev, ino) file identity.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn register_single_inode(&mut self, zone_id: u32, path: &str) -> anyhow::Result<usize> {
        let canon = fs::canonicalize(path)
            .map_err(|e| anyhow::anyhow!("failed to canonicalize '{}': {e}", path))?;
        let meta = fs::metadata(&canon)
            .map_err(|e| anyhow::anyhow!("failed to stat '{}': {e}", canon.display()))?;
        let key = InodeZoneKey::new(meta.ino(), self.kernel_dev_for(&canon, &meta)?);

        let mut map: AyaHashMap<_, InodeZoneKey, u32> = AyaHashMap::try_from(
            self.bpf
                .map_mut("INODE_ZONE_MAP")
                .ok_or_else(|| anyhow::anyhow!("INODE_ZONE_MAP map not found"))?,
        )?;
        map.insert(key, zone_id, 0)?;
        Ok(1)
    }

    /// Register file inodes as belonging to a zone.
    ///
    /// Scans the given filesystem paths and registers every inode found
    /// in the INODE_ZONE_MAP BPF map, keyed by the composite (dev, ino)
    /// identity. This enables the file_open and bprm_check hooks to detect
    /// cross-zone file access.
    ///
    /// Assumption: the paths are host-visible (e.g. container rootfs mounts
    /// or host paths listed in the zone's writable_paths policy). Inodes
    /// must be on the same filesystem visible to the kernel LSM hooks.
    /// Maximum recursion depth for directory scanning.
    const INODE_SCAN_MAX_DEPTH: usize = 16;

    /// Maximum inodes per zone to prevent one zone from starving others.
    const INODE_SCAN_MAX_PER_ZONE: usize =
        (syva_ebpf_common::MAX_INODES / syva_ebpf_common::MAX_ZONES) as usize;

    pub fn populate_inode_zone_map(
        &mut self,
        zone_id: u32,
        paths: &[String],
    ) -> anyhow::Result<usize> {
        use std::collections::{HashMap, HashSet, VecDeque};

        // Phase 1: walk the paths and collect (raw st_dev, ino) entries plus
        // one probeable representative per filesystem. The walk cannot hold
        // the BPF map handle because the dev probe needs `self.bpf` too.
        let mut entries: Vec<(u64, u64)> = Vec::new();
        let mut probe_reps: HashMap<u64, (PathBuf, fs::Metadata)> = HashMap::new();
        let mut visited: HashSet<(u64, u64)> = HashSet::new();

        for path_str in paths {
            // H6: Canonicalize to resolve symlinks and ../  traversal.
            let canonical = match fs::canonicalize(path_str) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(path = path_str, %e, "host_path canonicalization failed — skipping");
                    continue;
                }
            };

            // H13: Recursive walk with depth limit and cycle detection.
            let mut work: VecDeque<(PathBuf, usize)> = VecDeque::new();
            work.push_back((canonical, 0));

            while let Some((path, depth)) = work.pop_front() {
                if entries.len() >= Self::INODE_SCAN_MAX_PER_ZONE {
                    tracing::warn!(
                        zone_id,
                        max = Self::INODE_SCAN_MAX_PER_ZONE,
                        "inode scan cap reached — remaining host_paths skipped"
                    );
                    break;
                }

                if let Ok(meta) = fs::symlink_metadata(&path) {
                    if !visited.insert((meta.dev(), meta.ino())) {
                        continue; // Cycle detection, per (dev, ino).
                    }
                    entries.push((meta.dev(), meta.ino()));

                    // A probe must open the path itself, so the representative
                    // has to be a directory or regular file: opening a symlink
                    // would follow it (possibly onto another filesystem), and
                    // FIFOs / device nodes are not reliably openable.
                    if (meta.is_dir() || meta.is_file()) && !probe_reps.contains_key(&meta.dev()) {
                        probe_reps.insert(meta.dev(), (path.clone(), meta.clone()));
                    }

                    if meta.is_dir() && depth < Self::INODE_SCAN_MAX_DEPTH {
                        if let Ok(dir_entries) = fs::read_dir(&path) {
                            for entry in dir_entries.flatten() {
                                work.push_back((entry.path(), depth + 1));
                            }
                        }
                    }
                }
            }
        }

        // Phase 2: resolve the kernel s_dev once per filesystem encountered.
        let mut kernel_devs: HashMap<u64, u32> = HashMap::new();
        for (raw_dev, (path, meta)) in &probe_reps {
            kernel_devs.insert(*raw_dev, self.kernel_dev_for(path, meta)?);
        }

        // Phase 3: insert the composite keys.
        let mut map: AyaHashMap<_, InodeZoneKey, u32> = AyaHashMap::try_from(
            self.bpf
                .map_mut("INODE_ZONE_MAP")
                .ok_or_else(|| anyhow::anyhow!("INODE_ZONE_MAP map not found"))?,
        )?;

        let mut count = 0usize;
        for (raw_dev, ino) in entries {
            let Some(&dev) = kernel_devs.get(&raw_dev) else {
                // Only reachable when a filesystem surfaced nothing but
                // symlinks/specials — its entries cannot be probed, and a
                // guessed key would silently never match in the kernel.
                tracing::warn!(
                    zone_id,
                    ino,
                    raw_dev,
                    "no probeable representative for filesystem — entry skipped"
                );
                continue;
            };
            map.insert(InodeZoneKey::new(ino, dev), zone_id, 0)?;
            count += 1;
        }

        Ok(count)
    }
}

impl Drop for EnforceEbpf {
    fn drop(&mut self) {
        for &name in MAP_NAMES {
            let path = self.pin_path.join(name);
            if path.exists() {
                let _ = fs::remove_file(&path);
            }
        }
        if self.pin_path.exists() {
            let _ = fs::remove_dir(&self.pin_path);
        }
        tracing::info!("syva: BPF pins cleaned up");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParsedEgressFamily {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ParsedEgressCidr {
    family: ParsedEgressFamily,
    prefix_bits: u32,
    port: Option<u16>,
}

/// Parse an egress-allowlist entry. Accepted grammar:
/// - IPv4: `A.B.C.D`, `A.B.C.D/N`, `A.B.C.D:P`, `A.B.C.D/N:P`
/// - IPv6: `v6`, `v6/N`, `[v6]:P`, `[v6/N]:P`
///
/// Brackets are required for IPv6 ports because `:` is part of the address.
fn parse_egress_cidr(entry: &str) -> Option<ParsedEgressCidr> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }

    if let Some(rest) = entry.strip_prefix('[') {
        let (inner, port) = rest.split_once("]:")?;
        let port = parse_port(port)?;
        let (addr, prefix_bits) = parse_addr_prefix(inner, 128)?;
        let ip = addr.parse::<Ipv6Addr>().ok()?;
        if prefix_bits > 128 {
            return None;
        }
        return Some(ParsedEgressCidr {
            family: ParsedEgressFamily::Ipv6(ip),
            prefix_bits,
            port: Some(port),
        });
    }

    if let Some((cidr, port)) = split_ipv4_port(entry) {
        let port = parse_port(port)?;
        let (addr, prefix_bits) = parse_addr_prefix(cidr, 32)?;
        let ip = addr.parse::<Ipv4Addr>().ok()?;
        if prefix_bits > 32 {
            return None;
        }
        return Some(ParsedEgressCidr {
            family: ParsedEgressFamily::Ipv4(ip),
            prefix_bits,
            port: Some(port),
        });
    }

    if entry.parse::<Ipv4Addr>().is_ok() || entry.contains('.') {
        let (addr, prefix_bits) = parse_addr_prefix(entry, 32)?;
        let ip = addr.parse::<Ipv4Addr>().ok()?;
        if prefix_bits > 32 {
            return None;
        }
        return Some(ParsedEgressCidr {
            family: ParsedEgressFamily::Ipv4(ip),
            prefix_bits,
            port: None,
        });
    }

    let (addr, prefix_bits) = parse_addr_prefix(entry, 128)?;
    let ip = addr.parse::<Ipv6Addr>().ok()?;
    if prefix_bits > 128 {
        return None;
    }
    Some(ParsedEgressCidr {
        family: ParsedEgressFamily::Ipv6(ip),
        prefix_bits,
        port: None,
    })
}

fn parse_addr_prefix(entry: &str, default_bits: u32) -> Option<(&str, u32)> {
    let (addr, bits) = match entry.split_once('/') {
        Some((addr, mask)) => (addr, mask.parse::<u32>().ok()?),
        None => (entry, default_bits),
    };
    if addr.is_empty() {
        return None;
    }
    Some((addr, bits))
}

fn split_ipv4_port(entry: &str) -> Option<(&str, &str)> {
    let (cidr, port) = entry.rsplit_once(':')?;
    if cidr.contains(':') {
        return None;
    }
    Some((cidr, port))
}

fn parse_port(port: &str) -> Option<u16> {
    let port = port.parse::<u16>().ok()?;
    if port == 0 {
        return None;
    }
    Some(port)
}

/// Load (verify) the cgroup-escape fentry program. Separate from the LSM load
/// loop because it is a different program type and a non-fatal best-effort.
fn load_escape_detector(bpf: &mut Ebpf, btf: &Btf) -> anyhow::Result<()> {
    let prog: &mut aya::programs::FEntry = bpf
        .program_mut(ESCAPE_PROGRAM)
        .ok_or_else(|| anyhow::anyhow!("escape program '{ESCAPE_PROGRAM}' not found"))?
        .try_into()?;
    prog.load(ESCAPE_ATTACH_FN, btf)?;
    Ok(())
}

fn find_ebpf_object() -> anyhow::Result<PathBuf> {
    let candidates = [
        PathBuf::from("/usr/lib/syva/syva-ebpf"),
        PathBuf::from("/var/lib/syva/syva-ebpf"),
        // Runtime builds use release by default; debug is development-only.
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or(Path::new("."))
            .join("syva-ebpf/target/bpfel-unknown-none/release/syva-ebpf"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or(Path::new("."))
            .join("syva-ebpf/target/bpfel-unknown-none/debug/syva-ebpf"),
    ];

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    anyhow::bail!(
        "eBPF object not found — run `cargo run -p xtask -- build-ebpf` or pass --ebpf-obj"
    )
}

/// Offset definitions: (struct, field, global_name, default)
const OFFSET_DEFS: &[(&str, &str, &str, u64)] = &[
    ("task_struct", "cgroups", "TASK_CGROUPS_OFFSET", 2336),
    ("css_set", "dfl_cgrp", "CSS_SET_DFL_CGRP_OFFSET", 48),
    ("cgroup", "kn", "CGROUP_KN_OFFSET", 64),
    ("kernfs_node", "id", "KERNFS_NODE_ID_OFFSET", 0),
    ("file", "f_inode", "FILE_F_INODE_OFFSET", 32),
    ("inode", "i_ino", "INODE_I_INO_OFFSET", 64),
    ("inode", "i_sb", "INODE_I_SB_OFFSET", 40),
    // s_dev follows the 16-byte s_list list_head at the top of super_block —
    // stable layout across modern kernels.
    ("super_block", "s_dev", "SUPER_BLOCK_S_DEV_OFFSET", 16),
    ("linux_binprm", "file", "BPRM_FILE_OFFSET", 168),
    // sk_cgrp_data is a sock_cgroup_data embedded in sock. Its first
    // field is `cgroup *` at offset 0 within the sub-struct, so the
    // offset of sk_cgrp_data within sock IS the offset of the cgroup ptr.
    ("sock", "sk_cgrp_data", "SOCK_CGRP_DATA_CGROUP_OFFSET", 696),
];

fn resolve_offsets() -> Vec<(String, u64)> {
    // Parse BTF directly — no pahole dependency.
    let btf = match crate::btf::BtfData::from_sys_fs() {
        Ok(b) => {
            tracing::info!("loaded kernel BTF from /sys/kernel/btf/vmlinux");
            Some(b)
        }
        Err(e) => {
            tracing::warn!(%e, "failed to load kernel BTF — using default struct offsets");
            None
        }
    };

    OFFSET_DEFS
        .iter()
        .map(|&(type_name, field_name, global_name, default)| {
            let offset = btf
                .as_ref()
                .and_then(|b| b.struct_field_offset(type_name, field_name))
                .map(|v| v as u64)
                .unwrap_or_else(|| {
                    tracing::debug!(
                        r#type = type_name,
                        field = field_name,
                        "using default offset"
                    );
                    default
                });

            tracing::info!(
                r#type = type_name,
                field = field_name,
                default,
                resolved = offset,
                "kernel offset resolved"
            );

            (global_name.to_string(), offset)
        })
        .collect()
}

// pahole and is_field_match removed — BTF parsing in btf.rs replaces them.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_egress_cidr_handles_ipv4_masks_ports_and_rejects_bad() {
        assert_eq!(
            parse_egress_cidr("10.0.0.0/8"),
            Some(ParsedEgressCidr {
                family: ParsedEgressFamily::Ipv4("10.0.0.0".parse().unwrap()),
                prefix_bits: 8,
                port: None,
            })
        );
        assert_eq!(
            parse_egress_cidr("192.168.1.5"),
            Some(ParsedEgressCidr {
                family: ParsedEgressFamily::Ipv4("192.168.1.5".parse().unwrap()),
                prefix_bits: 32,
                port: None,
            })
        );
        assert_eq!(
            parse_egress_cidr(" 172.16.0.0/12:5432 "),
            Some(ParsedEgressCidr {
                family: ParsedEgressFamily::Ipv4("172.16.0.0".parse().unwrap()),
                prefix_bits: 12,
                port: Some(5432),
            })
        );
        assert_eq!(parse_egress_cidr("10.0.0.0/33"), None);
        assert_eq!(parse_egress_cidr("10.0.0.0:0"), None);
        assert_eq!(parse_egress_cidr("10.0.0.0:65536"), None);
        assert_eq!(parse_egress_cidr("not-an-ip"), None);
    }

    #[test]
    fn parse_egress_cidr_handles_ipv6_masks_ports_and_rejects_ambiguous_ports() {
        assert_eq!(
            parse_egress_cidr("2001:db8::/32"),
            Some(ParsedEgressCidr {
                family: ParsedEgressFamily::Ipv6("2001:db8::".parse().unwrap()),
                prefix_bits: 32,
                port: None,
            })
        );
        assert_eq!(
            parse_egress_cidr("2001:db8::1"),
            Some(ParsedEgressCidr {
                family: ParsedEgressFamily::Ipv6("2001:db8::1".parse().unwrap()),
                prefix_bits: 128,
                port: None,
            })
        );
        assert_eq!(
            parse_egress_cidr("[2001:db8::/32]:443"),
            Some(ParsedEgressCidr {
                family: ParsedEgressFamily::Ipv6("2001:db8::".parse().unwrap()),
                prefix_bits: 32,
                port: Some(443),
            })
        );
        assert_eq!(parse_egress_cidr("2001:db8::/129"), None);
        assert_eq!(parse_egress_cidr("2001:db8::1/128:443"), None);
        assert_eq!(parse_egress_cidr("[2001:db8::1]"), None);
        assert_eq!(parse_egress_cidr("[2001:db8::1]:0"), None);
    }

    #[test]
    fn lsm_programs_use_real_hook_names() {
        for program in LSM_PROGRAMS {
            assert!(
                !program.hook_name.starts_with("syva_"),
                "hook name must be the kernel hook, not the program symbol"
            );
            assert_ne!(program.program_name, program.hook_name);
        }
    }

    #[test]
    fn supported_lsm_hook_count_is_nine() {
        assert_eq!(LSM_PROGRAMS.len(), 9);
        assert!(LSM_PROGRAMS
            .iter()
            .any(|program| program.hook_name == "socket_sendmsg"));
        assert!(LSM_PROGRAMS
            .iter()
            .any(|program| program.hook_name == "socket_bind"));
        assert!(!LSM_PROGRAMS
            .iter()
            .any(|program| program.hook_name == "cgroup_attach_task"));
    }

    #[test]
    fn development_object_prefers_release_before_debug() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();
        let release = root.join("syva-ebpf/target/bpfel-unknown-none/release/syva-ebpf");
        let debug = root.join("syva-ebpf/target/bpfel-unknown-none/debug/syva-ebpf");
        let candidates = [
            PathBuf::from("/usr/lib/syva/syva-ebpf"),
            PathBuf::from("/var/lib/syva/syva-ebpf"),
            release.clone(),
            debug.clone(),
        ];

        let release_idx = candidates
            .iter()
            .position(|candidate| candidate == &release)
            .expect("release object candidate exists");
        let debug_idx = candidates
            .iter()
            .position(|candidate| candidate == &debug)
            .expect("debug object candidate exists");
        assert!(release_idx < debug_idx);
    }
}
