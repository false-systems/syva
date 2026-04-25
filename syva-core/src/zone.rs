//! Zone lifecycle registry — the single source of truth for zone state.
//!
//! A zone moves through three states:
//!
//!   Pending → Active → Pending (on last container leave)
//!   Active → Draining → (cleanup at refcount=0)
//!
//! - **Pending**: policy loaded, zone_id assigned, BPF maps configured.
//!   No containers yet. Re-activation is free.
//!
//! - **Active**: one or more containers are members. refcount > 0.
//!
//! - **Draining**: policy removed from disk, but containers still running.
//!   Enforcement continues. New containers rejected. BPF maps cleaned up
//!   when the last container leaves.
//!
//! Zone IDs are stable while a zone is registered. After `unregister_zone()`,
//! a re-registration of the same name will allocate a new ID.

use std::collections::{HashMap, HashSet};

/// Zone lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneState {
    /// Policy written to kernel, no active containers.
    Pending,
    /// At least one container is a member.
    Active,
    /// Policy removed from disk, containers still running.
    /// Enforcement continues. New containers rejected.
    Draining,
}

/// Result of a container removal — what happened to the zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub enum ZoneTransition {
    /// Zone still has containers.
    StillActive,
    /// Last container left, zone returned to Pending (policy still exists).
    WentToPending,
    /// Last container left a draining zone — caller must clean up BPF maps.
    DrainingComplete,
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
    #[cfg_attr(not(test), allow(dead_code))]
    cgroup_to_info: HashMap<u64, (String, String)>,
    /// container_id → (zone_name, cgroup_id)
    #[cfg_attr(not(test), allow(dead_code))]
    container_to_info: HashMap<String, (String, u64)>,
    /// Canonicalised allowed cross-zone comm pairs — the two names are
    /// stored in lexicographic order so the set is symmetric by construction.
    /// Mirror of BPF ZONE_ALLOWED_COMMS at the name level; purely for ListComms.
    allowed_comms: HashSet<(String, String)>,
    /// Monotonic zone ID counter. Starts at 1. 0 is reserved for ZONE_ID_HOST.
    next_id: u32,
}

impl ZoneRegistry {
    pub fn new() -> Self {
        Self {
            zones: HashMap::new(),
            cgroup_to_info: HashMap::new(),
            container_to_info: HashMap::new(),
            allowed_comms: HashSet::new(),
            next_id: 1,
        }
    }

    /// Register a zone from a loaded policy. Assigns a zone_id.
    /// Idempotent: if zone_name already exists, returns existing zone_id.
    /// Returns Err if zone ID space is exhausted (u32::MAX zones registered).
    pub fn register_zone(&mut self, zone_name: &str) -> anyhow::Result<u32> {
        if let Some(entry) = self.zones.get(zone_name) {
            return Ok(entry.zone_id);
        }
        // Zone ID 0 is reserved for ZONE_ID_HOST. Reject if we've wrapped.
        if self.next_id == 0 {
            anyhow::bail!("zone ID space exhausted");
        }
        // Cap at MAX_ZONES — the ZONE_POLICY BPF Array has this many entries.
        if self.next_id >= syva_ebpf_common::MAX_ZONES {
            anyhow::bail!(
                "zone ID {} exceeds BPF map limit (MAX_ZONES={})",
                self.next_id, syva_ebpf_common::MAX_ZONES
            );
        }
        let zone_id = self.next_id;
        // Advance. If this was u32::MAX, next call will see next_id=0 and fail.
        self.next_id = self.next_id.wrapping_add(1);
        self.zones.insert(zone_name.to_string(), ZoneEntry {
            zone_id,
            state: ZoneState::Pending,
            refcount: 0,
        });
        Ok(zone_id)
    }

    /// Record that a container has joined a zone.
    /// Transitions zone from Pending → Active.
    /// Returns Err if zone_name is not registered or container_id is already tracked.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn add_container(
        &mut self,
        container_id: &str,
        zone_name: &str,
        cgroup_id: u64,
    ) -> anyhow::Result<u32> {
        // Reject duplicate container_id — a second add without remove would
        // corrupt refcounts and orphan the old cgroup_to_info entry.
        if let Some((existing_zone, _)) = self.container_to_info.get(container_id) {
            anyhow::bail!(
                "container '{container_id}' is already tracked in zone '{existing_zone}'"
            );
        }

        let entry = self.zones.get_mut(zone_name)
            .ok_or_else(|| anyhow::anyhow!("zone '{zone_name}' is not registered"))?;

        if entry.state == ZoneState::Draining {
            anyhow::bail!("zone '{zone_name}' is draining — cannot add new containers");
        }

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
    /// Decrements refcount. Returns the zone transition that occurred.
    /// Returns None if the container_id is unknown (no-op for Delete-before-Start).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn remove_container(
        &mut self,
        container_id: &str,
        cgroup_id_hint: Option<u64>,
    ) -> Option<(u32, u64, ZoneTransition)> {
        // Look up container info. If not found, try the cgroup_id hint.
        let (zone_name, cgroup_id) = if let Some(info) = self.container_to_info.remove(container_id) {
            info
        } else if let Some(cid) = cgroup_id_hint {
            if let Some((cont_id, zone_name)) = self.cgroup_to_info.remove(&cid) {
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

        let transition = if entry.refcount == 0 {
            if entry.state == ZoneState::Draining {
                // Draining zone emptied — caller must clean BPF maps.
                ZoneTransition::DrainingComplete
            } else {
                entry.state = ZoneState::Pending;
                ZoneTransition::WentToPending
            }
        } else {
            ZoneTransition::StillActive
        };

        Some((entry.zone_id, cgroup_id, transition))
    }

    /// Mark a zone as draining. Policy was removed but containers remain.
    /// Returns Err if the zone is not registered.
    pub fn mark_draining(&mut self, zone_name: &str) -> anyhow::Result<()> {
        let entry = self.zones.get_mut(zone_name)
            .ok_or_else(|| anyhow::anyhow!("zone '{zone_name}' is not registered"))?;
        entry.state = ZoneState::Draining;
        Ok(())
    }

    /// Transition a Draining zone back to Pending so it accepts containers again.
    /// Used when a removed policy reappears during hot-reload.
    /// No-op if the zone is already Pending or Active.
    pub fn revive_draining(&mut self, zone_name: &str) -> anyhow::Result<u32> {
        let entry = self.zones.get_mut(zone_name)
            .ok_or_else(|| anyhow::anyhow!("zone '{zone_name}' is not registered"))?;
        if entry.state == ZoneState::Draining {
            entry.state = if entry.refcount > 0 { ZoneState::Active } else { ZoneState::Pending };
        }
        Ok(entry.zone_id)
    }

    /// Remove a zone entry entirely. Only valid for zones with refcount 0.
    /// Also wipes any allowed_comms entries involving this zone so the
    /// mirror stays in sync with the BPF map (core clears those at the same
    /// time via `remove_zone_comms`).
    /// Returns the zone_id that was removed (it will never be reused).
    pub fn unregister_zone(&mut self, zone_name: &str) -> anyhow::Result<u32> {
        let entry = self.zones.get(zone_name)
            .ok_or_else(|| anyhow::anyhow!("zone '{zone_name}' is not registered"))?;
        if entry.refcount > 0 {
            anyhow::bail!("zone '{zone_name}' still has {} active containers", entry.refcount);
        }
        let zone_id = entry.zone_id;
        self.zones.remove(zone_name);
        self.allowed_comms.retain(|(a, b)| a != zone_name && b != zone_name);
        Ok(zone_id)
    }

    /// Remove a zone entry by ID. Reverse-lookup by scanning zones.
    /// Only valid for zones with refcount 0.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn unregister_zone_by_id(&mut self, zone_id: u32) -> anyhow::Result<()> {
        let zone_name = self.zones.iter()
            .find(|(_, e)| e.zone_id == zone_id)
            .map(|(name, _)| name.clone());
        match zone_name {
            Some(name) => { self.unregister_zone(&name)?; Ok(()) }
            None => anyhow::bail!("no zone with id {zone_id}"),
        }
    }

    /// Look up zone_id by name.
    pub fn zone_id(&self, zone_name: &str) -> Option<u32> {
        self.zones.get(zone_name).map(|e| e.zone_id)
    }

    /// All registered zone names and their IDs.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn all_zones(&self) -> impl Iterator<Item = (&str, u32)> {
        self.zones.iter().map(|(name, entry)| (name.as_str(), entry.zone_id))
    }

    /// Full snapshot for ListZones — (name, zone_id, state, refcount).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn zones_summary(&self) -> impl Iterator<Item = (&str, u32, ZoneState, usize)> {
        self.zones.iter().map(|(name, e)| (name.as_str(), e.zone_id, e.state, e.refcount))
    }

    /// Record an allowed cross-zone comm pair. Idempotent.
    /// Names are stored canonically (lexicographic) so pairs are symmetric.
    pub fn record_allow_comm(&mut self, zone_a: &str, zone_b: &str) {
        self.allowed_comms.insert(canon_pair(zone_a, zone_b));
    }

    /// Remove an allowed comm pair. No-op if not recorded.
    pub fn record_deny_comm(&mut self, zone_a: &str, zone_b: &str) {
        self.allowed_comms.remove(&canon_pair(zone_a, zone_b));
    }

    /// Iterate allowed comm pairs, optionally filtered to those involving
    /// a specific zone name. Yields canonicalised (a, b) tuples.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn list_allowed_comms<'a>(
        &'a self,
        filter_zone: Option<&'a str>,
    ) -> impl Iterator<Item = (&'a str, &'a str)> + 'a {
        self.allowed_comms.iter().filter_map(move |(a, b)| {
            match filter_zone {
                Some(z) if a != z && b != z => None,
                _ => Some((a.as_str(), b.as_str())),
            }
        })
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
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn container_count(&self) -> usize {
        self.container_to_info.len()
    }
}

/// Canonicalise a pair of zone names for symmetric storage.
fn canon_pair(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.to_string(), b.to_string())
    } else {
        (b.to_string(), a.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_zone_assigns_nonzero_id() {
        let mut reg = ZoneRegistry::new();
        let id = reg.register_zone("frontend").unwrap();
        assert!(id > 0, "zone_id 0 is reserved for ZONE_ID_HOST");
    }

    #[test]
    fn register_zone_is_idempotent() {
        let mut reg = ZoneRegistry::new();
        let id1 = reg.register_zone("frontend").unwrap();
        let id2 = reg.register_zone("frontend").unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_zones_get_different_ids() {
        let mut reg = ZoneRegistry::new();
        let id1 = reg.register_zone("frontend").unwrap();
        let id2 = reg.register_zone("database").unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn add_container_transitions_to_active() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend").unwrap();

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
        reg.register_zone("frontend").unwrap();
        reg.add_container("c1", "frontend", 1000).unwrap();

        let result = reg.remove_container("c1", None);
        assert!(result.is_some());
        let (_, _, transition) = result.unwrap();
        assert_eq!(transition, ZoneTransition::WentToPending);
        assert_eq!(reg.zones["frontend"].state, ZoneState::Pending);
        assert_eq!(reg.refcount("frontend"), 0);
    }

    #[test]
    fn remove_container_with_multiple_keeps_active() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend").unwrap();
        reg.add_container("c1", "frontend", 1000).unwrap();
        reg.add_container("c2", "frontend", 2000).unwrap();

        let (_, _, transition) = reg.remove_container("c1", None).unwrap();
        assert_eq!(transition, ZoneTransition::StillActive);
        assert_eq!(reg.zones["frontend"].state, ZoneState::Active);
        assert_eq!(reg.refcount("frontend"), 1);
    }

    #[test]
    fn delete_before_start_is_noop() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend").unwrap();
        let result = reg.remove_container("unknown-container", None);
        assert!(result.is_none());
    }

    #[test]
    fn reactivation_after_pending() {
        let mut reg = ZoneRegistry::new();
        let id1 = reg.register_zone("frontend").unwrap();
        reg.add_container("c1", "frontend", 1000).unwrap();
        reg.remove_container("c1", None);

        // Zone is Pending. Add a new container — same zone_id.
        let id2 = reg.add_container("c2", "frontend", 2000).unwrap();
        assert_eq!(id1, id2);
        assert_eq!(reg.zones["frontend"].state, ZoneState::Active);
    }

    #[test]
    fn duplicate_container_id_returns_error() {
        let mut reg = ZoneRegistry::new();
        let _ = reg.register_zone("frontend");
        reg.add_container("c1", "frontend", 1000).unwrap();

        // Second add with same container_id must fail.
        let result = reg.add_container("c1", "frontend", 1000);
        assert!(result.is_err());

        // Refcount must still be 1 — not corrupted by the failed add.
        assert_eq!(reg.refcount("frontend"), 1);
    }

    #[test]
    fn duplicate_container_id_different_zone_returns_error() {
        let mut reg = ZoneRegistry::new();
        let _ = reg.register_zone("frontend");
        let _ = reg.register_zone("database");
        reg.add_container("c1", "frontend", 1000).unwrap();

        // Same container_id in a different zone must also fail.
        let result = reg.add_container("c1", "database", 2000);
        assert!(result.is_err());

        // Both zones' refcounts must be unaffected.
        assert_eq!(reg.refcount("frontend"), 1);
        assert_eq!(reg.refcount("database"), 0);
    }

    #[test]
    fn remove_with_cgroup_hint() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend").unwrap();
        reg.add_container("c1", "frontend", 1000).unwrap();

        // Remove by cgroup_id hint when container_id is unknown.
        let result = reg.remove_container("wrong-id", Some(1000));
        assert!(result.is_some());
        assert_eq!(reg.refcount("frontend"), 0);
    }

    #[test]
    fn draining_zone_rejects_new_containers() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend").unwrap();
        reg.add_container("c1", "frontend", 1000).unwrap();
        reg.mark_draining("frontend").unwrap();

        let result = reg.add_container("c2", "frontend", 2000);
        assert!(result.is_err());
        assert_eq!(reg.refcount("frontend"), 1);
    }

    #[test]
    fn remove_container_from_draining_returns_draining_complete() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend").unwrap();
        reg.add_container("c1", "frontend", 1000).unwrap();
        reg.mark_draining("frontend").unwrap();

        let (_, _, transition) = reg.remove_container("c1", None).unwrap();
        assert_eq!(transition, ZoneTransition::DrainingComplete);
    }

    #[test]
    fn unregister_zone_with_active_containers_fails() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend").unwrap();
        reg.add_container("c1", "frontend", 1000).unwrap();

        let result = reg.unregister_zone("frontend");
        assert!(result.is_err());
    }

    #[test]
    fn unregister_empty_zone_succeeds() {
        let mut reg = ZoneRegistry::new();
        let id = reg.register_zone("frontend").unwrap();
        let removed_id = reg.unregister_zone("frontend").unwrap();
        assert_eq!(id, removed_id);
        assert!(reg.zone_id("frontend").is_none());
    }

    #[test]
    fn revive_draining_allows_new_containers() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend").unwrap();
        reg.add_container("c1", "frontend", 1000).unwrap();
        reg.mark_draining("frontend").unwrap();

        // Revive the draining zone — should transition to Active (has containers).
        let id = reg.revive_draining("frontend").unwrap();
        assert!(id > 0);

        // Now new containers should be accepted.
        reg.add_container("c2", "frontend", 2000).unwrap();
        assert_eq!(reg.refcount("frontend"), 2);
    }

    #[test]
    fn revive_draining_empty_goes_to_pending() {
        let mut reg = ZoneRegistry::new();
        reg.register_zone("frontend").unwrap();
        reg.mark_draining("frontend").unwrap();

        reg.revive_draining("frontend").unwrap();
        assert_eq!(reg.zones["frontend"].state, ZoneState::Pending);
    }

    #[test]
    fn register_zone_capped_at_max_zones() {
        // Registration must fail once next_id reaches MAX_ZONES, because
        // ZONE_POLICY is a BPF Array whose index range is [0, MAX_ZONES).
        let mut reg = ZoneRegistry::new();
        reg.next_id = syva_ebpf_common::MAX_ZONES - 1;

        // The last slot below MAX_ZONES is still usable.
        let id = reg.register_zone("last-zone").unwrap();
        assert_eq!(id, syva_ebpf_common::MAX_ZONES - 1);

        // next_id is now == MAX_ZONES → next registration must fail.
        let result = reg.register_zone("one-too-many");
        assert!(result.is_err(), "expected registration past MAX_ZONES to fail");
    }
}
