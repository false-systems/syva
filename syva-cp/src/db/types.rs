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
