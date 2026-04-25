//! Zone mapper — maps container labels to zone assignments.
//!
//! Containers with a `syva.dev/zone` label are assigned to the named zone.
//! Containers without this label are treated as global (no enforcement).

/// Label keys for zone assignment.
pub const LABEL_ZONE: &str = "syva.dev/zone";
#[allow(dead_code)]
pub const LABEL_POLICY: &str = "syva.dev/policy";

/// Determine the zone name from container labels.
///
/// Returns None if the container has no `syva.dev/zone` label (global/unzoned).
#[allow(dead_code)]
pub fn zone_from_labels(labels: &std::collections::HashMap<String, String>) -> Option<String> {
    labels.get(LABEL_ZONE).cloned()
}
