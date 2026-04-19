//! `create_team` — the reference implementation for ADR 0003.
//!
//! Every subsequent mutating operation copies this shape: validate
//! inputs before BEGIN, take the transaction, write the causal rows in
//! canonical order (event → resource → audit), record metrics, commit.

use crate::db::types::{Actor, Team};
use crate::error::CpError;
use crate::metrics;
use crate::write::TransactionalWriter;
use chrono::Utc;
use serde_json::json;
use serde_json::Value;
use sqlx::Row;
use std::time::Instant;
use uuid::Uuid;

pub struct CreateTeamInput {
    pub name: String,
    pub display_name: Option<String>,
}

impl<'a> TransactionalWriter<'a> {
    /// Create a team.
    ///
    /// Writes, in canonical order (ADR 0003 Rule 2):
    ///
    /// 1. `control_plane_events` row (`team.created`).
    /// 2. `teams` row with `caused_by_event_id` pointing at step 1.
    /// 3. `audit_log` row with `control_plane_event_id` pointing at step 1.
    ///
    /// Teams don't get a history table at this stage — schema evolution
    /// is slow for teams and adding one later is cheap. Zones and
    /// policies do get a history path, landing in Session 2.
    pub async fn create_team(
        &self,
        input: CreateTeamInput,
        actor: &Actor,
    ) -> Result<Team, CpError> {
        const OPERATION: &str = "team.create";
        let start = Instant::now();

        // Rule 3: validate everything we don't need the DB for before BEGIN.
        // If we bail here, no transaction has opened and no metric is
        // wasted on a rollback.
        if input.name.is_empty() || input.name.len() > 63 {
            return Err(CpError::InvalidArgument(
                "team name must be 1..=63 characters".into(),
            ));
        }
        if !input
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(CpError::InvalidArgument(
                "team name must be ASCII alphanumeric, dash, or underscore".into(),
            ));
        }

        let team_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        let audit_id = Uuid::new_v4();
        let now = Utc::now();
        let request_json = json!({
            "name": &input.name,
            "display_name": &input.display_name,
        });

        // Rule 1: one transaction per operation.
        let mut tx = self.pool.begin().await.map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "begin_failed");
            CpError::Database(e)
        })?;

        // Rule 2, step 1: event first.
        // CreateTeam is an origin event — no `caused_by_event_id` predecessor
        // because creating a team is the first causal step for that team.
        let event_result = sqlx::query(
            r#"INSERT INTO control_plane_events
               (id, event_type, source, subject_type, subject_id, team_id,
                resource_type, resource_id, occurred_at, payload_json)
               VALUES ($1, 'team.created', 'api', $2, $3, $4, 'team', $5, $6, $7)"#,
        )
        .bind(event_id)
        .bind(&actor.subject_type)
        .bind(&actor.subject_id)
        // `team_id` on the event is the *actor's* current team, not the
        // team being created. For a CreateTeam request from a user not
        // yet inside any team this is NULL.
        .bind(actor.team_id)
        .bind(team_id)
        .bind(now)
        .bind(request_json.clone())
        .execute(&mut *tx)
        .await;

        if let Err(e) = event_result {
            metrics::record_transaction_rollback(OPERATION, "event_insert_failed");
            let _ = tx.rollback().await;
            record_rejected_audit(
                self.pool,
                actor,
                team_id,
                now,
                request_json.clone(),
                "failed",
                &format!("event insert failed: {e}"),
            )
            .await;
            return Err(CpError::Database(e));
        }

        // Rule 2, step 2: current state, pointing back at the event.
        let team_result = sqlx::query(
            r#"INSERT INTO teams
               (id, name, display_name, status, created_at, updated_at,
                version, caused_by_event_id)
               VALUES ($1, $2, $3, 'active', $4, $4, 1, $5)
               RETURNING id, name, display_name, status, created_at,
                         updated_at, version, caused_by_event_id"#,
        )
        .bind(team_id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(now)
        .bind(event_id)
        .fetch_one(&mut *tx)
        .await;

        let team_row = match team_result {
            Ok(row) => row,
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                metrics::record_transaction_rollback(OPERATION, "name_conflict");
                let _ = tx.rollback().await;
                record_rejected_audit(
                    self.pool,
                    actor,
                    team_id,
                    now,
                    request_json.clone(),
                    "denied",
                    &format!("team name '{}' already exists", input.name),
                )
                .await;
                return Err(CpError::Conflict {
                    message: format!("team name '{}' already exists", input.name),
                });
            }
            Err(e) => {
                metrics::record_transaction_rollback(OPERATION, "team_insert_failed");
                let _ = tx.rollback().await;
                record_rejected_audit(
                    self.pool,
                    actor,
                    team_id,
                    now,
                    request_json.clone(),
                    "failed",
                    &format!("team insert failed: {e}"),
                )
                .await;
                return Err(CpError::Database(e));
            }
        };

        let team = Team {
            id: team_row.get("id"),
            name: team_row.get("name"),
            display_name: team_row.get("display_name"),
            status: team_row.get("status"),
            created_at: team_row.get("created_at"),
            updated_at: team_row.get("updated_at"),
            version: team_row.get("version"),
            caused_by_event_id: team_row.get("caused_by_event_id"),
        };

        // Rule 2, step 5 + Rule 8: audit row, always.
        let audit_result = sqlx::query(
            r#"INSERT INTO audit_log
               (id, occurred_at, actor_type, actor_id, team_id, action,
                resource_type, resource_id, result, request_json,
                control_plane_event_id)
               VALUES ($1, $2, $3, $4, $5, 'team.create', 'team', $6,
                       'success', $7, $8)"#,
        )
        .bind(audit_id)
        .bind(now)
        .bind(&actor.actor_type)
        .bind(&actor.actor_id)
        .bind(actor.team_id)
        .bind(team_id)
        .bind(request_json)
        .bind(event_id)
        .execute(&mut *tx)
        .await;

        if let Err(e) = audit_result {
            metrics::record_transaction_rollback(OPERATION, "audit_insert_failed");
            let _ = tx.rollback().await;
            return Err(CpError::Database(e));
        }

        tx.commit().await.map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "commit_failed");
            CpError::Database(e)
        })?;

        // Rule 10: duration is a monitored SLO.
        metrics::record_transaction_duration(OPERATION, start.elapsed());

        tracing::debug!(
            team_id = %team.id,
            event_id = %event_id,
            duration_ms = start.elapsed().as_millis(),
            "team created",
        );

        Ok(team)
    }
}

async fn record_rejected_audit(
    pool: &sqlx::postgres::PgPool,
    actor: &Actor,
    resource_id: Uuid,
    occurred_at: chrono::DateTime<Utc>,
    request_json: Value,
    result: &'static str,
    message: &str,
) {
    let response_json = json!({ "error": message });

    if let Err(e) = sqlx::query(
        r#"INSERT INTO audit_log
           (id, occurred_at, actor_type, actor_id, team_id, action,
            resource_type, resource_id, result, request_json, response_json,
            control_plane_event_id)
           VALUES ($1, $2, $3, $4, $5, 'team.create', 'team', $6,
                   $7, $8, $9, NULL)"#,
    )
    .bind(Uuid::new_v4())
    .bind(occurred_at)
    .bind(&actor.actor_type)
    .bind(&actor.actor_id)
    .bind(actor.team_id)
    .bind(resource_id)
    .bind(result)
    .bind(request_json)
    .bind(response_json)
    .execute(pool)
    .await
    {
        tracing::warn!(%e, %resource_id, "failed to record rejected team.create audit row");
    }
}
