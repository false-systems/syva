//! Policy hot-reload — detects policy file changes and reconciles BPF maps.
//!
//! Polls the policy directory every 5 seconds. Detects changes via:
//! 1. ConfigMap symlink rotation (`..data` target changes)
//! 2. File fingerprint (sorted filenames + mtimes + sizes)
//!
//! On change: full reload → diff → apply additions/modifications/removals.
//! Never leaves BPF maps empty. Draining zones keep enforcement until
//! all containers leave.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::ebpf::EnforceEbpf;
use crate::policy;
use crate::types::ZonePolicy;
use crate::zone::ZoneRegistry;

/// Watches a policy directory for changes via polling.
pub struct PolicyDirWatcher {
    dir: PathBuf,
    last_symlink_target: Option<PathBuf>,
    last_fingerprint: u64,
}

impl PolicyDirWatcher {
    pub fn new(dir: PathBuf) -> Self {
        let symlink_target = std::fs::read_link(dir.join("..data")).ok();
        let fingerprint = compute_fingerprint(&dir);
        Self {
            dir,
            last_symlink_target: symlink_target,
            last_fingerprint: fingerprint,
        }
    }

    /// Returns true if the policy directory has changed since the last check.
    pub fn check_changed(&mut self) -> bool {
        // Check ConfigMap symlink rotation first (atomic, reliable).
        if let Ok(target) = std::fs::read_link(self.dir.join("..data")) {
            if self.last_symlink_target.as_ref() != Some(&target) {
                self.last_symlink_target = Some(target);
                self.last_fingerprint = compute_fingerprint(&self.dir);
                return true;
            }
            return false;
        }

        // Fallback: compare file fingerprint (non-Kubernetes direct edits).
        let fingerprint = compute_fingerprint(&self.dir);
        if fingerprint != self.last_fingerprint {
            self.last_fingerprint = fingerprint;
            return true;
        }
        false
    }
}

/// Compute a fingerprint from the policy directory's file metadata.
fn compute_fingerprint(dir: &Path) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut entries: Vec<(String, u64, u64)> = Vec::new();

    if let Ok(read_dir) = std::fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.ends_with(".toml") {
                continue;
            }
            if let Ok(meta) = entry.metadata() {
                use std::time::UNIX_EPOCH;
                let mtime = meta.modified()
                    .ok()
                    .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                    .map(|d| d.as_nanos() as u64)
                    .unwrap_or(0);
                entries.push((name, mtime, meta.len()));
            }
        }
    }
    entries.sort();
    entries.hash(&mut hasher);
    hasher.finish()
}

/// A single policy change detected by diff.
#[derive(Debug)]
pub enum PolicyChange {
    Added(String, ZonePolicy),
    Modified(String, ZonePolicy),
    Removed(String),
}

/// Diff two policy sets. Returns the changes needed to go from old → new.
pub fn diff_policies(
    old: &HashMap<String, ZonePolicy>,
    new: &HashMap<String, ZonePolicy>,
) -> Vec<PolicyChange> {
    let mut changes = Vec::new();

    for (name, new_policy) in new {
        match old.get(name) {
            None => changes.push(PolicyChange::Added(name.clone(), new_policy.clone())),
            Some(old_policy) if old_policy != new_policy => {
                changes.push(PolicyChange::Modified(name.clone(), new_policy.clone()));
            }
            Some(_) => {} // Unchanged.
        }
    }

    for name in old.keys() {
        if !new.contains_key(name) {
            changes.push(PolicyChange::Removed(name.clone()));
        }
    }

    changes
}

/// Reload policies from disk and apply changes to BPF maps.
///
/// Returns the number of changes applied, or Err if the reload should
/// be aborted (caller keeps current policies).
pub fn try_reload(
    dir: &Path,
    registry: &mut ZoneRegistry,
    ebpf: &mut EnforceEbpf,
    current_policies: &mut HashMap<String, ZonePolicy>,
) -> anyhow::Result<usize> {
    let new_policies = policy::load_policies(dir)?;

    // Guard: if new set is empty but current is not, this is likely a
    // transient state during ConfigMap rotation. Don't wipe enforcement.
    if new_policies.is_empty() && !current_policies.is_empty() {
        tracing::debug!("policy reload returned empty set — skipping (possible ConfigMap rotation)");
        return Ok(0);
    }

    let changes = diff_policies(current_policies, &new_policies);
    if changes.is_empty() {
        return Ok(0);
    }

    // Apply in order: additions first, modifications second, removals last.
    // This ensures new zones exist before cross-zone comms reference them.
    let mut applied = 0;

    // Additions.
    for change in &changes {
        if let PolicyChange::Added(name, policy) = change {
            if let Err(e) = apply_addition(name, policy, registry, ebpf, &new_policies) {
                tracing::error!(zone = name.as_str(), %e, "failed to add zone during reload");
                continue;
            }
            current_policies.insert(name.clone(), policy.clone());
            applied += 1;
            tracing::info!(zone = name.as_str(), "reload: zone added");
        }
    }

    // Modifications.
    for change in &changes {
        if let PolicyChange::Modified(name, new_policy) = change {
            let old_policy = match current_policies.get(name) {
                Some(p) => p.clone(),
                None => continue,
            };
            if let Err(e) = apply_modification(name, &old_policy, new_policy, registry, ebpf, &new_policies) {
                tracing::error!(zone = name.as_str(), %e, "failed to modify zone during reload");
                continue;
            }
            current_policies.insert(name.clone(), new_policy.clone());
            applied += 1;
            tracing::info!(zone = name.as_str(), "reload: zone policy updated");
        }
    }

    // Removals.
    for change in &changes {
        if let PolicyChange::Removed(name) = change {
            apply_removal(name, registry, ebpf);
            current_policies.remove(name);
            applied += 1;
        }
    }

    Ok(applied)
}

fn apply_addition(
    zone_name: &str,
    policy: &ZonePolicy,
    registry: &mut ZoneRegistry,
    ebpf: &mut EnforceEbpf,
    all_policies: &HashMap<String, ZonePolicy>,
) -> anyhow::Result<()> {
    let zone_id = registry.register_zone(zone_name)?;
    ebpf.set_zone_policy(zone_id, policy)?;

    if !policy.filesystem.host_paths.is_empty() {
        match ebpf.populate_inode_zone_map(zone_id, &policy.filesystem.host_paths) {
            Ok(n) if n > 0 => tracing::info!(zone = zone_name, inodes = n, "reload: inode map populated"),
            Ok(_) => {}
            Err(e) => tracing::warn!(zone = zone_name, %e, "reload: inode map population failed"),
        }
    }

    // Set up bilateral comms.
    for peer_name in &policy.network.allowed_zones {
        if let Some(peer_id) = registry.zone_id(peer_name) {
            let bilateral = all_policies
                .get(peer_name)
                .map(|p| p.network.allowed_zones.contains(&zone_name.to_string()))
                .unwrap_or(false);
            if bilateral {
                let _ = ebpf.set_zone_allowed_comms(zone_id, peer_id);
            }
        }
    }

    Ok(())
}

fn apply_modification(
    zone_name: &str,
    old_policy: &ZonePolicy,
    new_policy: &ZonePolicy,
    registry: &mut ZoneRegistry,
    ebpf: &mut EnforceEbpf,
    all_policies: &HashMap<String, ZonePolicy>,
) -> anyhow::Result<()> {
    let zone_id = registry.zone_id(zone_name)
        .ok_or_else(|| anyhow::anyhow!("zone '{zone_name}' not in registry"))?;

    // Always update ZONE_POLICY (Array set is idempotent).
    ebpf.set_zone_policy(zone_id, new_policy)?;

    // Rebuild comms if allowed_zones changed.
    if old_policy.network.allowed_zones != new_policy.network.allowed_zones {
        let _ = ebpf.remove_zone_comms(zone_id);
        for peer_name in &new_policy.network.allowed_zones {
            if let Some(peer_id) = registry.zone_id(peer_name) {
                let bilateral = all_policies
                    .get(peer_name)
                    .map(|p| p.network.allowed_zones.contains(&zone_name.to_string()))
                    .unwrap_or(false);
                if bilateral {
                    let _ = ebpf.set_zone_allowed_comms(zone_id, peer_id);
                }
            }
        }
    }

    // Rebuild inodes if host_paths changed.
    if old_policy.filesystem.host_paths != new_policy.filesystem.host_paths {
        let _ = ebpf.remove_zone_inodes(zone_id);
        if !new_policy.filesystem.host_paths.is_empty() {
            match ebpf.populate_inode_zone_map(zone_id, &new_policy.filesystem.host_paths) {
                Ok(n) => tracing::info!(zone = zone_name, inodes = n, "reload: inode map rebuilt"),
                Err(e) => tracing::warn!(zone = zone_name, %e, "reload: inode map rebuild failed"),
            }
        }
    }

    Ok(())
}

fn apply_removal(
    zone_name: &str,
    registry: &mut ZoneRegistry,
    ebpf: &mut EnforceEbpf,
) {
    let refcount = registry.refcount(zone_name);
    let zone_id = match registry.zone_id(zone_name) {
        Some(id) => id,
        None => return,
    };

    if refcount == 0 {
        // No containers — clean up immediately.
        let _ = ebpf.remove_zone_policy(zone_id);
        let _ = ebpf.remove_zone_comms(zone_id);
        let _ = ebpf.remove_zone_inodes(zone_id);
        let _ = registry.unregister_zone(zone_name);
        tracing::info!(zone = zone_name, zone_id, "reload: zone removed (was empty)");
    } else {
        // Containers still running — mark draining.
        let _ = registry.mark_draining(zone_name);
        tracing::warn!(
            zone = zone_name, zone_id, containers = refcount,
            "reload: zone removed from policy but has active containers — \
             draining (enforcement continues, new containers rejected)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ZonePolicy;

    fn make_policy() -> ZonePolicy {
        ZonePolicy::default()
    }

    fn make_policy_with_zones(zones: Vec<&str>) -> ZonePolicy {
        let mut p = ZonePolicy::default();
        p.network.allowed_zones = zones.into_iter().map(String::from).collect();
        p
    }

    #[test]
    fn diff_empty_to_one_zone_is_added() {
        let old = HashMap::new();
        let mut new = HashMap::new();
        new.insert("frontend".to_string(), make_policy());

        let changes = diff_policies(&old, &new);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], PolicyChange::Added(name, _) if name == "frontend"));
    }

    #[test]
    fn diff_removed_zone_detected() {
        let mut old = HashMap::new();
        old.insert("frontend".to_string(), make_policy());
        let new = HashMap::new();

        let changes = diff_policies(&old, &new);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], PolicyChange::Removed(name) if name == "frontend"));
    }

    #[test]
    fn diff_modified_zone_detected() {
        let mut old = HashMap::new();
        old.insert("frontend".to_string(), make_policy());

        let mut new = HashMap::new();
        new.insert("frontend".to_string(), make_policy_with_zones(vec!["database"]));

        let changes = diff_policies(&old, &new);
        assert_eq!(changes.len(), 1);
        assert!(matches!(&changes[0], PolicyChange::Modified(name, _) if name == "frontend"));
    }

    #[test]
    fn diff_no_changes_returns_empty() {
        let mut policies = HashMap::new();
        policies.insert("frontend".to_string(), make_policy());

        let changes = diff_policies(&policies, &policies);
        assert!(changes.is_empty());
    }

    #[test]
    fn diff_mixed_changes() {
        let mut old = HashMap::new();
        old.insert("frontend".to_string(), make_policy());
        old.insert("database".to_string(), make_policy());

        let mut new = HashMap::new();
        new.insert("frontend".to_string(), make_policy_with_zones(vec!["api"])); // modified
        new.insert("api".to_string(), make_policy()); // added
        // database removed

        let changes = diff_policies(&old, &new);
        assert_eq!(changes.len(), 3);
    }
}
