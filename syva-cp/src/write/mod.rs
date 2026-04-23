//! TransactionalWriter — the single entry point for all mutating operations.
//!
//! Every mutating operation in syva-cp follows the rules in
//! `docs/adr/0003-transactional-write-discipline.md`:
//!
//! 1. Single transaction per operation.
//! 2. Canonical write order: event → resource → history → audit.
//! 3. No external I/O inside the transaction — gather all external data
//!    first, validate it, then BEGIN.
//! 4. Optimistic locking on versioned resources via a `version` column
//!    in the WHERE clause of UPDATE.
//! 5. Advisory locks for zone-scoped serialization (lands with zones).
//! 6. All mutations go through this module. No `sqlx::query!(... INSERT/
//!    UPDATE/DELETE ...)` anywhere else in the crate — enforced by the
//!    `check-write-discipline` xtask in CI.
//! 7. Every event carries a causal predecessor via `caused_by_event_id`.
//!    The one exception is origin events (a CreateTeam has no parent).
//! 8. Audit is structural: a row lands for every accepted write, every
//!    rejected write (with `result = 'denied' | 'failed'`), and every
//!    read of sensitive resources.
//! 9. Append-only enforcement at the database layer — see the triggers
//!    migration.
//! 10. Transaction duration is a monitored SLO via
//!     `crate::metrics::record_transaction_duration`.
//!
//! **Do not add mutating code outside this module.** The
//! `check-write-discipline` xtask and the CI job that runs it exist to
//! catch regressions.

use crate::db::types::Actor;
use crate::error::CpError;
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::postgres::PgPool;
use uuid::Uuid;

pub mod assignment;
pub mod team;
pub mod node;
pub mod zone;

pub struct TransactionalWriter<'a> {
    pub(crate) pool: &'a PgPool,
}

impl<'a> TransactionalWriter<'a> {
    pub fn new(pool: &'a PgPool) -> Self {
        Self { pool }
    }

    pub(crate) async fn record_rejected_audit<T: Serialize>(
        &self,
        operation: &'static str,
        actor: &Actor,
        input: &T,
        err: &CpError,
    ) {
        let request_json = match serde_json::to_value(input) {
            Ok(value) => value,
            Err(e) => {
                tracing::warn!(%e, operation, "failed to serialize rejected audit request");
                json!({})
            }
        };

        let resource_id = audit_resource_id(&request_json);
        let team_id = audit_team_id(self.pool, actor, &request_json).await;
        let response_json = json!({ "error": err.to_string() });
        let result = match err {
            CpError::Database(_) | CpError::Serialization(_) | CpError::Internal(_) => "failed",
            _ => "denied",
        };
        let resource_type = operation
            .split_once('.')
            .map(|(resource_type, _)| resource_type)
            .unwrap_or("unknown");
        let action = operation;

        if let Err(e) = sqlx::query(
            r#"INSERT INTO audit_log
               (id, occurred_at, actor_type, actor_id, team_id, action,
                resource_type, resource_id, result, request_json, response_json,
                control_plane_event_id)
               VALUES ($1, NOW(), $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL)"#,
        )
        .bind(Uuid::new_v4())
        .bind(&actor.actor_type)
        .bind(&actor.actor_id)
        .bind(team_id)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(result)
        .bind(request_json)
        .bind(response_json)
        .execute(self.pool)
        .await
        {
            tracing::warn!(%e, operation, %resource_id, "failed to record rejected audit row");
        }
    }
}

fn audit_resource_id(request_json: &Value) -> Uuid {
    parse_uuid_field(request_json, &["zone_id", "team_id", "id"]).unwrap_or_else(Uuid::new_v4)
}

async fn audit_team_id(pool: &PgPool, actor: &Actor, request_json: &Value) -> Option<Uuid> {
    let candidate = actor
        .team_id
        .or_else(|| parse_uuid_field(request_json, &["team_id"]))?;

    match sqlx::query_scalar::<_, i64>("SELECT 1 FROM teams WHERE id = $1")
        .bind(candidate)
        .fetch_optional(pool)
        .await
    {
        Ok(Some(_)) => Some(candidate),
        Ok(None) => None,
        Err(e) => {
            tracing::warn!(%e, team_id = %candidate, "failed to verify audit team_id");
            None
        }
    }
}

fn parse_uuid_field(request_json: &Value, keys: &[&str]) -> Option<Uuid> {
    let obj = request_json.as_object()?;
    keys.iter()
        .filter_map(|key| obj.get(*key))
        .filter_map(Value::as_str)
        .find_map(|s| Uuid::parse_str(s).ok())
}
