//! eBPF program lifecycle for syva.
//!
//! Loads and attaches the 5 LSM programs. Provides typed
//! wrappers for BPF map operations (zone membership, policy, comms).

use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use aya::maps::HashMap as AyaHashMap;
use aya::maps::RingBuf;
use aya::programs::Lsm;
use aya::{Bpf, BpfLoader, Btf};
use crate::types::{ZonePolicy, ZoneType, NetworkMode};
use syva_ebpf_common::{
    ZoneInfoKernel, ZonePolicyKernel, ZoneCommKey, SelfTestResult, EnforcementCounters,
    ZONE_FLAG_GLOBAL, ZONE_FLAG_PRIVILEGED,
};

const BPF_PIN_PATH: &str = "/sys/fs/bpf/syva";

const LSM_PROGRAMS: &[&str] = &[
    "syva_file_open",
    "syva_bprm_check",
    "syva_ptrace_check",
    "syva_task_kill",
    "syva_cgroup_attach",
    "syva_mmap_file",
    "syva_unix_connect",
];

const MAP_NAMES: &[&str] = &[
    "ZONE_MEMBERSHIP",
    "ZONE_POLICY",
    "INODE_ZONE_MAP",
    "ZONE_ALLOWED_COMMS",
    "SELF_TEST",
    "ENFORCEMENT_COUNTERS",
    "ENFORCEMENT_EVENTS",
];

/// eBPF manager for the standalone enforce agent.
pub struct EnforceEbpf {
    bpf: Bpf,
    pin_path: PathBuf,
}

impl EnforceEbpf {
    /// Load and attach eBPF programs.
    pub fn load(ebpf_obj: Option<&Path>) -> anyhow::Result<Self> {
        let obj_path = match ebpf_obj {
            Some(p) => p.to_path_buf(),
            None => find_ebpf_object()?,
        };

        let pin_path = PathBuf::from(BPF_PIN_PATH);

        // Check for mutual exclusion — if maps are already pinned, another
        // syva instance may be running.
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

        let btf = Btf::from_sys_fs()
            .map_err(|e| anyhow::anyhow!("failed to load BTF: {e} — kernel needs CONFIG_DEBUG_INFO_BTF=y"))?;

        // Resolve kernel struct offsets via pahole.
        let offsets = resolve_offsets();

        let obj_data = fs::read(&obj_path)
            .map_err(|e| anyhow::anyhow!("failed to read eBPF object {}: {e}", obj_path.display()))?;

        let mut loader = BpfLoader::new();
        loader.btf(Some(&btf)).map_pin_path(&pin_path);

        for (name, val) in &offsets {
            loader.set_global(name.as_str(), val, true);
        }

        let mut bpf = loader
            .load(&obj_data)
            .map_err(|e| anyhow::anyhow!("failed to load eBPF: {e} — check CONFIG_BPF_LSM=y and lsm=bpf"))?;

        // Phase 1: Load all LSM programs (validates with kernel verifier).
        // Programs are NOT attached yet — no enforcement until attach_programs().
        for &name in LSM_PROGRAMS {
            let prog: &mut Lsm = bpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("LSM program '{name}' not found"))?
                .try_into()?;
            prog.load(name, &btf)?;
            tracing::debug!(program = name, "loaded LSM program");
        }

        tracing::info!(programs = LSM_PROGRAMS.len(), "eBPF programs loaded (not yet attached)");

        Ok(Self { bpf, pin_path })
    }

    /// Attach all loaded LSM programs. Call this AFTER zone membership is
    /// populated to eliminate the startup race window where hooks are active
    /// but ZONE_MEMBERSHIP is empty (all containers would appear unzoned).
    pub fn attach_programs(&mut self) -> anyhow::Result<()> {
        for &name in LSM_PROGRAMS {
            let prog: &mut Lsm = self.bpf
                .program_mut(name)
                .ok_or_else(|| anyhow::anyhow!("LSM program '{name}' not found"))?
                .try_into()?;
            prog.attach()?;
            tracing::info!(program = name, "attached LSM program");
        }
        tracing::info!(programs = LSM_PROGRAMS.len(), "all LSM programs attached — enforcement active");
        Ok(())
    }

    /// Take ownership of the ring buffer for event streaming.
    pub fn take_event_ring_buf(&mut self) -> Option<RingBuf<aya::maps::MapData>> {
        let map = self.bpf.take_map("ENFORCEMENT_EVENTS")?;
        RingBuf::try_from(map).ok()
    }

    /// Register a cgroup as belonging to a zone.
    pub fn add_zone_member(
        &mut self,
        cgroup_id: u64,
        zone_id: u32,
        zone_type: ZoneType,
    ) -> anyhow::Result<()> {
        let mut flags = 0u32;
        match zone_type {
            ZoneType::Global => flags |= ZONE_FLAG_GLOBAL,
            ZoneType::Privileged => flags |= ZONE_FLAG_PRIVILEGED,
            ZoneType::NonGlobal => {}
        }

        let info = ZoneInfoKernel { zone_id, flags };

        let mut map: AyaHashMap<_, u64, ZoneInfoKernel> = AyaHashMap::try_from(
            self.bpf.map_mut("ZONE_MEMBERSHIP")
                .ok_or_else(|| anyhow::anyhow!("ZONE_MEMBERSHIP map not found"))?,
        )?;

        map.insert(cgroup_id, info, 0)?;
        Ok(())
    }

    /// Remove a cgroup from zone membership.
    pub fn remove_zone_member(&mut self, cgroup_id: u64) -> anyhow::Result<()> {
        let mut map: AyaHashMap<_, u64, ZoneInfoKernel> = AyaHashMap::try_from(
            self.bpf.map_mut("ZONE_MEMBERSHIP")
                .ok_or_else(|| anyhow::anyhow!("ZONE_MEMBERSHIP map not found"))?,
        )?;
        let _ = map.remove(&cgroup_id);
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
        let kernel_policy = ZonePolicyKernel::from_caps(
            &policy.capabilities.allowed,
            allow_ptrace,
            allow_host_net,
        );

        let mut map = Array::<_, ZonePolicyKernel>::try_from(
            self.bpf.map_mut("ZONE_POLICY")
                .ok_or_else(|| anyhow::anyhow!("ZONE_POLICY map not found"))?,
        )?;

        map.set(zone_id, kernel_policy, 0)?;
        Ok(())
    }

    /// Read enforcement counters, summed across all CPUs.
    pub fn read_counters(&self) -> anyhow::Result<Vec<(String, EnforcementCounters)>> {
        use aya::maps::PerCpuArray;

        let map = PerCpuArray::<_, EnforcementCounters>::try_from(
            self.bpf.map("ENFORCEMENT_COUNTERS")
                .ok_or_else(|| anyhow::anyhow!("ENFORCEMENT_COUNTERS map not found"))?,
        )?;

        let mut results = Vec::new();
        for (idx, &name) in LSM_PROGRAMS.iter().enumerate() {
            let per_cpu = map.get(&(idx as u32), 0)?;
            let mut total = EnforcementCounters { allow: 0, deny: 0, error: 0, lost: 0 };
            for cpu_val in per_cpu.iter() {
                total.allow += cpu_val.allow;
                total.deny += cpu_val.deny;
                total.error += cpu_val.error;
                total.lost += cpu_val.lost;
            }
            results.push((name.to_string(), total));
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
                    self.bpf.map("SELF_TEST")
                        .ok_or_else(|| anyhow::anyhow!("SELF_TEST map not found"))?,
                )?;
                anyhow::Ok(map.get(&0, 0)?)
            })?;

            if result.helper_cgroup_id != 0 {
                if result.helper_cgroup_id == result.offset_cgroup_id {
                    tracing::info!(
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

    /// Allow cross-zone communication between two zones.
    ///
    /// Writes both directions (src→dst and dst→src) into ZONE_ALLOWED_COMMS.
    pub fn set_zone_allowed_comms(&mut self, src_zone_id: u32, dst_zone_id: u32) -> anyhow::Result<()> {
        let mut map: AyaHashMap<_, ZoneCommKey, u8> = AyaHashMap::try_from(
            self.bpf.map_mut("ZONE_ALLOWED_COMMS")
                .ok_or_else(|| anyhow::anyhow!("ZONE_ALLOWED_COMMS map not found"))?,
        )?;

        let fwd = ZoneCommKey { src_zone: src_zone_id, dst_zone: dst_zone_id };
        let rev = ZoneCommKey { src_zone: dst_zone_id, dst_zone: src_zone_id };
        map.insert(fwd, 1u8, 0)?;
        map.insert(rev, 1u8, 0)?;
        Ok(())
    }

    /// Clear a zone's enforcement policy (zeroed entry — Array can't remove).
    pub fn remove_zone_policy(&mut self, zone_id: u32) -> anyhow::Result<()> {
        use aya::maps::Array;

        let mut map = Array::<_, ZonePolicyKernel>::try_from(
            self.bpf.map_mut("ZONE_POLICY")
                .ok_or_else(|| anyhow::anyhow!("ZONE_POLICY map not found"))?,
        )?;
        let zeroed = ZonePolicyKernel { caps_mask: 0, flags: 0, _pad: 0 };
        map.set(zone_id, zeroed, 0)?;
        Ok(())
    }

    /// Remove all ZONE_ALLOWED_COMMS entries involving a zone.
    pub fn remove_zone_comms(&mut self, zone_id: u32) -> anyhow::Result<()> {
        let map: AyaHashMap<_, ZoneCommKey, u8> = AyaHashMap::try_from(
            self.bpf.map_mut("ZONE_ALLOWED_COMMS")
                .ok_or_else(|| anyhow::anyhow!("ZONE_ALLOWED_COMMS map not found"))?,
        )?;

        // Collect keys to remove (can't mutate while iterating).
        let keys_to_remove: Vec<ZoneCommKey> = map
            .keys()
            .filter_map(|k| k.ok())
            .filter(|k| k.src_zone == zone_id || k.dst_zone == zone_id)
            .collect();

        drop(map);

        let mut map: AyaHashMap<_, ZoneCommKey, u8> = AyaHashMap::try_from(
            self.bpf.map_mut("ZONE_ALLOWED_COMMS")
                .ok_or_else(|| anyhow::anyhow!("ZONE_ALLOWED_COMMS map not found"))?,
        )?;

        for key in keys_to_remove {
            let _ = map.remove(&key);
        }
        Ok(())
    }

    /// Remove all INODE_ZONE_MAP entries for a given zone.
    pub fn remove_zone_inodes(&mut self, zone_id: u32) -> anyhow::Result<()> {
        let map: AyaHashMap<_, u64, u32> = AyaHashMap::try_from(
            self.bpf.map_mut("INODE_ZONE_MAP")
                .ok_or_else(|| anyhow::anyhow!("INODE_ZONE_MAP map not found"))?,
        )?;

        let keys_to_remove: Vec<u64> = map
            .iter()
            .filter_map(|r| r.ok())
            .filter(|(_, &v)| v == zone_id)
            .map(|(k, _)| k)
            .collect();

        drop(map);

        let mut map: AyaHashMap<_, u64, u32> = AyaHashMap::try_from(
            self.bpf.map_mut("INODE_ZONE_MAP")
                .ok_or_else(|| anyhow::anyhow!("INODE_ZONE_MAP map not found"))?,
        )?;

        for key in keys_to_remove {
            let _ = map.remove(&key);
        }
        Ok(())
    }

    /// Register file inodes as belonging to a zone.
    ///
    /// Scans the given filesystem paths and registers every inode found
    /// in the INODE_ZONE_MAP BPF map. This enables the file_open and
    /// bprm_check hooks to detect cross-zone file access.
    ///
    /// Assumption: the paths are host-visible (e.g. container rootfs mounts
    /// or host paths listed in the zone's writable_paths policy). Inodes
    /// must be on the same filesystem visible to the kernel LSM hooks.
    ///
    /// Limitation: INODE_ZONE_MAP is keyed by inode number alone. Inode numbers
    /// are only unique within a filesystem — different filesystems can share the
    /// same i_ino. This matches the kernel-side eBPF map definition. Changing to
    /// (dev, ino) would require updating the BPF map type and all kernel hooks.
    pub fn populate_inode_zone_map(&mut self, zone_id: u32, paths: &[String]) -> anyhow::Result<usize> {
        let mut map: AyaHashMap<_, u64, u32> = AyaHashMap::try_from(
            self.bpf.map_mut("INODE_ZONE_MAP")
                .ok_or_else(|| anyhow::anyhow!("INODE_ZONE_MAP map not found"))?,
        )?;

        let mut count = 0usize;
        for path_str in paths {
            let path = Path::new(path_str);
            if !path.exists() {
                continue;
            }
            if let Ok(meta) = fs::metadata(path) {
                let ino = meta.ino();
                map.insert(ino, zone_id, 0)?;
                count += 1;
            }
            // Scan directory contents one level deep.
            if path.is_dir() {
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        if let Ok(meta) = entry.metadata() {
                            let ino = meta.ino();
                            map.insert(ino, zone_id, 0)?;
                            count += 1;
                        }
                    }
                }
            }
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

fn find_ebpf_object() -> anyhow::Result<PathBuf> {
    let candidates = [
        PathBuf::from("/usr/lib/syva/syva-ebpf"),
        PathBuf::from("/var/lib/syva/syva-ebpf"),
        // Development build paths.
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or(Path::new("."))
            .join("syva-ebpf/target/bpfel-unknown-none/debug/syva-ebpf"),
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap_or(Path::new("."))
            .join("syva-ebpf/target/bpfel-unknown-none/release/syva-ebpf"),
    ];

    for path in &candidates {
        if path.exists() {
            return Ok(path.clone());
        }
    }

    anyhow::bail!(
        "eBPF object not found — run `cargo xtask build-ebpf` or pass --ebpf-obj"
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
    ("linux_binprm", "file", "BPRM_FILE_OFFSET", 168),
];

fn resolve_offsets() -> Vec<(String, u64)> {
    let pahole = ["/usr/bin/pahole", "/usr/local/bin/pahole"]
        .iter()
        .find(|p| Path::new(p).exists())
        .map(|p| PathBuf::from(p));

    let pahole = match pahole {
        Some(p) => p,
        None => {
            tracing::warn!("pahole not found — using default struct offsets");
            return OFFSET_DEFS
                .iter()
                .map(|&(_, _, name, default)| (name.to_string(), default))
                .collect();
        }
    };

    OFFSET_DEFS
        .iter()
        .map(|&(type_name, field_name, global_name, default)| {
            let offset = pahole_field_offset(&pahole, type_name, field_name)
                .map(|v| v as u64)
                .unwrap_or_else(|_| {
                    tracing::debug!(r#type = type_name, field = field_name, "using default offset");
                    default
                });

            if offset != default {
                tracing::info!(
                    r#type = type_name, field = field_name, default, resolved = offset,
                    "kernel offset differs — using resolved value"
                );
            }

            (global_name.to_string(), offset)
        })
        .collect()
}

fn pahole_field_offset(pahole: &Path, type_name: &str, field_name: &str) -> Result<usize, String> {
    let output = std::process::Command::new(pahole)
        .args(["-C", type_name, "/sys/kernel/btf/vmlinux"])
        .output()
        .map_err(|e| format!("failed to run pahole: {e}"))?;

    if !output.status.success() {
        return Err(format!("pahole failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !is_field_match(trimmed, field_name) {
            continue;
        }
        if let Some(comment_start) = trimmed.rfind("/*") {
            let comment = &trimmed[comment_start + 2..];
            if let Some(comment_end) = comment.find("*/") {
                let nums = &comment[..comment_end].trim();
                if let Some(offset_str) = nums.split_whitespace().next() {
                    if let Ok(offset) = offset_str.parse::<usize>() {
                        return Ok(offset);
                    }
                }
            }
        }
    }

    Err(format!("field '{field_name}' not found in pahole output for '{type_name}'"))
}

/// Match a pahole output line against a field name using word boundaries.
///
/// The field name must be followed by whitespace, `;`, `[`, or end-of-string
/// to avoid substring matches (e.g. "file" matching "file_lock").
fn is_field_match(line: &str, field_name: &str) -> bool {
    let bytes = line.as_bytes();
    let mut start = 0;
    while let Some(pos) = line[start..].find(field_name) {
        let abs_pos = start + pos;
        let after = abs_pos + field_name.len();

        // Check left boundary: must be preceded by whitespace or `*` (pointer decl)
        // or be at the start of the line.
        let left_ok = abs_pos == 0 || {
            let prev = bytes[abs_pos - 1];
            prev == b' ' || prev == b'\t' || prev == b'*'
        };

        // Check right boundary: must be followed by whitespace, `;`, `[`, or end.
        let right_ok = after >= line.len() || {
            let next = bytes[after];
            next == b' ' || next == b'\t' || next == b';' || next == b'['
        };

        if left_ok && right_ok {
            return true;
        }
        start = abs_pos + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::is_field_match;

    #[test]
    fn field_match_exact() {
        let line = "    struct file *              file;                 /* 168     8 */";
        assert!(is_field_match(line, "file"));
    }

    #[test]
    fn field_match_rejects_substring() {
        let line = "    struct file_lock *          file_lock;            /* 200     8 */";
        assert!(!is_field_match(line, "file"));
    }

    #[test]
    fn field_match_with_array() {
        let line = "    unsigned long               flags[2];             /* 32    16 */";
        assert!(is_field_match(line, "flags"));
    }

    #[test]
    fn field_match_rejects_similar_prefix() {
        let line = "    struct file_ra_state        f_ra;                 /* 144    56 */";
        assert!(!is_field_match(line, "file"));
    }

    #[test]
    fn field_match_rejects_left_substring() {
        // "id" should not match "pid" — left boundary check.
        let line = "    pid_t                       pid;                  /* 100     4 */";
        assert!(!is_field_match(line, "id"));
    }

    #[test]
    fn field_match_accepts_pointer_field() {
        // Field after `*` pointer declaration.
        let line = "    struct cgroup *             dfl_cgrp;             /* 48     8 */";
        assert!(is_field_match(line, "dfl_cgrp"));
    }
}
