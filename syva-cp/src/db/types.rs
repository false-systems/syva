//! Rust mirrors of the persisted row shapes.
//!
//! These are the "current state" projections — the same structs are used
//! by read paths and by write paths (where the writer returns the freshly
//! inserted row). Historical/immutable tables (events, audit_log) don't
//! need Rust mirrors at this stage; we read them via ad-hoc queries in
//! structural tests and dashboards.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Map as JsonMap;
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use sqlx::Row;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Team {
    pub id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: i64,
    pub caused_by_event_id: Option<Uuid>,
}

/// Who performed the operation. Populated from the gRPC metadata in a
/// later session (auth/RBAC). For now every call uses a `dev` actor.
#[derive(Debug, Clone)]
pub struct Actor {
    /// One of `"user"`, `"service_account"`, `"node"`, `"system"`.
    pub actor_type: String,
    pub actor_id: String,
    /// Team the actor is acting as. `None` means "no team context yet".
    pub team_id: Option<Uuid>,
    /// `subject_*` is the identity the event/audit records should cite;
    /// usually matches `actor_*` but can differ for `on-behalf-of` flows.
    pub subject_type: String,
    pub subject_id: String,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Zone {
    pub id: Uuid,
    pub team_id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub status: String,
    pub current_policy_id: Option<Uuid>,
    pub selector_json: Option<JsonValue>,
    pub metadata_json: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    pub version: i64,
    pub caused_by_event_id: Option<Uuid>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub zone_id: Uuid,
    pub version: i64,
    pub checksum: String,
    pub policy_json: JsonValue,
    pub summary_json: JsonValue,
    pub created_at: DateTime<Utc>,
    pub created_by_subject: Option<String>,
    pub caused_by_event_id: Uuid,
}

/// Input for creating or updating a zone's policy.
///
/// The policy content itself is opaque JSON at the control plane level —
/// the schema is enforced by validators at the adapter layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInput {
    pub policy_json: JsonValue,
    pub summary_json: Option<JsonValue>,
}

impl PolicyInput {
    fn canonicalize_json(value: &JsonValue) -> JsonValue {
        match value {
            JsonValue::Object(map) => {
                let sorted = map
                    .iter()
                    .map(|(key, value)| (key.clone(), Self::canonicalize_json(value)))
                    .collect::<BTreeMap<_, _>>();

                let mut canonical = JsonMap::with_capacity(sorted.len());
                for (key, value) in sorted {
                    canonical.insert(key, value);
                }

                JsonValue::Object(canonical)
            }
            JsonValue::Array(values) => JsonValue::Array(
                values.iter().map(Self::canonicalize_json).collect(),
            ),
            _ => value.clone(),
        }
    }

    /// Compute a stable checksum for deduplication and idempotency.
    /// SHA-256 of the canonical JSON form.
    pub fn checksum(&self) -> String {
        use sha2::{Digest, Sha256};
        let canonical_json = Self::canonicalize_json(&self.policy_json);
        let canonical = serde_json::to_string(&canonical_json).unwrap_or_default();
        let hash = Sha256::digest(canonical.as_bytes());
        format!("sha256:{}", hex::encode(hash))
    }
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Node {
    pub id: Uuid,
    pub node_name: String,
    pub cluster_id: Option<String>,
    pub status: String,
    pub fingerprint: Option<String>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub last_heartbeat_event_id: Option<Uuid>,
    pub current_token_expires_at: Option<DateTime<Utc>>,
    pub capabilities_json: JsonValue,
    pub metadata_json: JsonValue,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: i64,
    pub caused_by_event_id: Option<Uuid>,
}

pub fn node_from_row(row: &sqlx::postgres::PgRow) -> Node {
    Node {
        id: row.get("id"),
        node_name: row.get("node_name"),
        cluster_id: row.get("cluster_id"),
        status: row.get("status"),
        fingerprint: row.get("fingerprint"),
        last_seen_at: row.get("last_seen_at"),
        last_heartbeat_event_id: row.get("last_heartbeat_event_id"),
        current_token_expires_at: row.get("current_token_expires_at"),
        capabilities_json: row.get("capabilities_json"),
        metadata_json: row.get("metadata_json"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        version: row.get("version"),
        caused_by_event_id: row.get("caused_by_event_id"),
    }
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Assignment {
    pub id: Uuid,
    pub zone_id: Uuid,
    pub node_id: Uuid,
    pub status: String,
    pub desired_policy_id: Uuid,
    pub desired_zone_version: i64,
    pub actual_policy_id: Option<Uuid>,
    pub actual_zone_version: Option<i64>,
    pub last_reported_at: Option<DateTime<Utc>>,
    pub error_json: Option<JsonValue>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: i64,
    pub caused_by_event_id: Uuid,
}

/// Node label set, keyed for deterministic selector matching.
pub type NodeLabels = BTreeMap<String, String>;

/// NodeSelector — how a zone chooses its nodes.
///
/// Stored in `zones.selector_json` and matched in Rust.
///
/// If all three fields are empty/default, the selector matches nothing.
/// Use `all_nodes: true` to target every node.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeSelector {
    #[serde(default)]
    pub all_nodes: bool,

    #[serde(default)]
    pub node_names: Vec<String>,

    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
}

impl NodeSelector {
    pub fn from_json(value: &JsonValue) -> Result<Self, serde_json::Error> {
        if value.is_null() {
            return Ok(Self::default());
        }

        serde_json::from_value(value.clone())
    }

    pub fn matches(&self, node_name: &str, labels: &NodeLabels) -> bool {
        if self.all_nodes {
            return true;
        }

        if !self.node_names.is_empty() && self.node_names.iter().any(|n| n == node_name) {
            return true;
        }

        if !self.match_labels.is_empty() {
            return self
                .match_labels
                .iter()
                .all(|(k, v)| labels.get(k).map(|x| x == v).unwrap_or(false));
        }

        false
    }
}
