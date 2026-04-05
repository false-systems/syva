//! Zone lifecycle registry — the single source of truth for zone state.
//!
//! A zone moves through two states:
//!
//!   Pending → Active → Pending (on last container leave)
//!
//! - **Pending**: policy loaded, zone_id assigned, BPF maps configured.
//!   No containers yet. The zone is fully configured in the kernel,
//!   waiting for containers. Re-activation is free.
//!
//! - **Active**: one or more containers are members. refcount > 0.
//!
//! Policy-defined zones are never removed during the agent lifetime.
//! Zone IDs are stable — once assigned, the same name always maps to the
//! same zone_id.

use std::collections::HashMap;

/// Zone lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneState {
    /// Policy written to kernel, no active containers.
    Pending,
    /// At least one container is a member.
    Active,
}

/// Per-zone metadata.
#[derive(Debug)]
pub struct ZoneEntry {
    pub zone_id: u32,
    pub state: ZoneState,
    pub refcount: usize,
}

/// Owns all zone lifecycle state. Replaces the scattered HashMaps that
/// previously lived in cmd_run.
///
/// Invariants:
/// - zone_id 0 is never assigned (reserved for ZONE_ID_HOST).
/// - A zone_id, once assigned to a name, is never reused for a different name.
/// - remove_container on an unknown container_id is a no-op.
/// - refcount never goes below 0.
pub struct ZoneRegistry {
    /// zone_name → ZoneEntry
    zones: HashMap<String, ZoneEntry>,
    /// cgroup_id → (container_id, zone_name) — enables hint-based removal
    cgroup_to_info: HashMap<u64, (String, String)>,
    /// container_id → (zone_name, cgroup_id)
    container_to_info: HashMap<String, (String, u64)>,
    /// Monotonic zone ID counter. Starts at 1. 0 is reserved for ZONE_ID_HOST.
    next_id: u32,
}

impl ZoneRegistry {
    pub fn new() -> Self {
        Self {
            zones: HashMap::new(),
            cgroup_to_info: HashMap::new(),
            container_to_info: HashMap::new(),
            next_id: 1,
        }
    }

    /// Register a zone from a loaded policy. Assigns a zone_id.
    /// Idempotent: if zone_name already exists, returns existing zone_id.
    pub fn register_zone(&mut self, zone_name: &str) -> u32 {
        if let Some(entry) = self.zones.get(zone_name) {
            return entry.zone_id;
        }
        let zone_id = self.next_id;
        self.next_id += 1;
        self.zones.insert(zone_name.to_string(), ZoneEntry {
            zone_id,
            state: ZoneState::Pending,
            refcount: 0,
        });
        zone_id
    }

    /// Record that a container has joined a zone.
    /// Transitions zone from Pending → Active.
    /// Returns Err if zone_name is not registered.
    pub fn add_container(
        &mut self,
        container_id: &str,
        zone_name: &str,
        cgroup_id: u64,
    ) -> anyhow::Result<u32> {
        let entry = self.zones.get_mut(zone_name)
            .ok_or_else(|| anyhow::anyhow!("zone '{zone_name}' is not registered"))?;

        entry.refcount += 1;
        entry.state = ZoneState::Active;
        let zone_id = entry.zone_id;

        self.cgroup_to_info.insert(cgroup_id, (container_id.to_string(), zone_name.to_string()));
        self.container_to_info.insert(
            container_id.to_string(),
            (zone_name.to_string(), cgroup_id),
        );

        Ok(zone_id)
    }

    /// Record that a container has left.
    /// Decrements refcount. If refcount hits 0: Active → Pending.
    /// Returns Some((zone_id, cgroup_id, went_to_pending)) if the container was tracked.
    /// Returns None if the container_id is unknown (no-op for Delete-before-Start).
    pub fn remove_container(
        &mut self,
        container_id: &str,
        cgroup_id_hint: Option<u64>,
    ) -> Option<(u32, u64, bool)> {
        // Look up container info. If not found, try the cgroup_id hint.
        let (zone_name, cgroup_id) = if let Some(info) = self.container_to_info.remove(container_id) {
            info
        } else if let Some(cid) = cgroup_id_hint {
            if let Some((cont_id, zone_name)) = self.cgroup_to_info.remove(&cid) {
                // Clean up the forward map too.
                self.container_to_info.remove(&cont_id);
                (zone_name, cid)
            } else {
                return None;
            }
        } else {
            return None;
        };

        self.cgroup_to_info.remove(&cgroup_id);

        let entry = self.zones.get_mut(&zone_name)?;
        entry.refcount = entry.refcount.saturating_sub(1);

        let went_to_pending = entry.refcount == 0;
        if went_to_pending {
            entry.state = ZoneState::Pending;
        }

        Some((entry.zone_id, cgroup_id, went_to_pending))
    }

    /// Look up zone_id by name.
    pub fn zone_id(&self, zone_name: &str) -> Option<u32> {
        self.zones.get(zone_name).map(|e| e.zone_id)
    }

    /// All registered zone names and their IDs.
    pub fn all_zones(&self) -> impl Iterator<Item = (&str, u32)> {
        self.zones.iter().map(|(name, entry)| (name.as_str(), entry.zone_id))
    }

    /// Active container count for a zone.
    pub fn refcount(&self, zone_name: &str) -> usize {
        self.zones.get(zone_name).map(|e| e.refcount).unwrap_or(0)
    }

    /// Total number of registered zones.
    pub fn zone_count(&self) -> usize {
        self.zones.len()
    }

    /// Total number of tracked containers.
    pub fn container_count(&self) -> usize {
        self.container_to_info.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_zone_assigns_nonzero_id() {
        let mut reg = ZoneRegistry::new();
        let id = reg.register_zone("frontend");
        assert!(id > 0, "zone_id 0 is reserved for ZONE_ID_HOST");
    }

    #[test]
    fn register_zone_is_idempotent() {
        let mut reg = ZoneRegistry::new();
        let id1 = reg.register_zone("frontend");
        let id2 = reg.register_zone("frontend");
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_zones_get_different_ids() {
        let mut reg = ZoneRegistry::new();
        let id1 = reg.register_zone("frontend");
        let id2 = reg.register_zone("database");
        assert_ne!(id1, id2);
    }

    #[test]
    fn add_container_transitions_to_active() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend");

        let zone_id = reg.add_container("c1", "frontend", 1000).unwrap();
        assert!(zone_id > 0);
        assert_eq!(reg.refcount("frontend"), 1);
        assert_eq!(reg.zones["frontend"].state, ZoneState::Active);
    }

    #[test]
    fn add_container_to_unregistered_zone_fails() {
        let mut reg = ZoneRegistry::new();
        assert!(reg.add_container("c1", "unknown", 1000).is_err());
    }

    #[test]
    fn remove_container_transitions_to_pending() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend");
        reg.add_container("c1", "frontend", 1000).unwrap();

        let result = reg.remove_container("c1", None);
        assert!(result.is_some());
        let (_, _, went_to_pending) = result.unwrap();
        assert!(went_to_pending);
        assert_eq!(reg.zones["frontend"].state, ZoneState::Pending);
        assert_eq!(reg.refcount("frontend"), 0);
    }

    #[test]
    fn remove_container_with_multiple_keeps_active() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend");
        reg.add_container("c1", "frontend", 1000).unwrap();
        reg.add_container("c2", "frontend", 2000).unwrap();

        let (_, _, went_to_pending) = reg.remove_container("c1", None).unwrap();
        assert!(!went_to_pending);
        assert_eq!(reg.zones["frontend"].state, ZoneState::Active);
        assert_eq!(reg.refcount("frontend"), 1);
    }

    #[test]
    fn delete_before_start_is_noop() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend");
        let result = reg.remove_container("unknown-container", None);
        assert!(result.is_none());
    }

    #[test]
    fn reactivation_after_pending() {
        let mut reg = ZoneRegistry::new();
        let id1 = reg.register_zone("frontend");
        reg.add_container("c1", "frontend", 1000).unwrap();
        reg.remove_container("c1", None);

        // Zone is Pending. Add a new container — same zone_id.
        let id2 = reg.add_container("c2", "frontend", 2000).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(reg.zones["frontend"].state, ZoneState::Active);
    }

    #[test]
    fn remove_with_cgroup_hint() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend");
        reg.add_container("c1", "frontend", 1000).unwrap();

        // Remove by cgroup_id hint when container_id is unknown.
        let result = reg.remove_container("wrong-id", Some(1000));
        assert!(result.is_some());
        assert_eq!(reg.refcount("frontend"), 0);
    }
}
