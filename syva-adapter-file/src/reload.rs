//! Policy hot-reload — detects policy file changes and produces diffs.
//!
//! Polls the policy directory every 5 seconds. Detects changes via:
//! 1. ConfigMap symlink rotation (`..data` target changes)
//! 2. File fingerprint (sorted filenames + mtimes + sizes)
//!
//! On change: full reload -> diff -> emit PolicyChange events.
//! The caller (main.rs) translates these into gRPC calls to syva-core.

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

use crate::types::ZonePolicy;

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
            // Symlink unchanged — still check fingerprint in case files were
            // edited in place (e.g. `..data` exists but isn't a true ConfigMap).
        } else {
            self.last_symlink_target = None;
        }

        // Compare file fingerprint to detect direct edits.
        let fingerprint = compute_fingerprint(&self.dir);
        if fingerprint != self.last_fingerprint {
            self.last_fingerprint = fingerprint;
            return true;
        }
        false
    }

    /// Returns the watched directory path.
    pub fn dir(&self) -> &Path {
        &self.dir
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

/// Diff two policy sets. Returns the changes needed to go from old -> new.
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
