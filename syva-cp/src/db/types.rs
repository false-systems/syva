//! Rust mirrors of the persisted row shapes.
//!
//! These are the "current state" projections — the same structs are used
//! by read paths and by write paths (where the writer returns the freshly
//! inserted row). Historical/immutable tables (events, audit_log) don't
//! need Rust mirrors at this stage; we read them via ad-hoc queries in
//! structural tests and dashboards.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
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
