use crate::db::types::Actor;
use crate::error::CpError;
use crate::metrics;
use crate::write::TransactionalWriter;
use chrono::Utc;
use serde_json::{json, Value as JsonValue};
use sqlx::Row;
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize)]
pub struct AppliedReport {
    pub assignment_id: Uuid,
    pub actual_zone_version: i64,
    pub actual_policy_id: Uuid,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FailedReport {
    pub assignment_id: Uuid,
    pub error_json: JsonValue,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ReportAssignmentStateInput {
    pub node_id: Uuid,
    pub applied: Vec<AppliedReport>,
    pub failed: Vec<FailedReport>,
}

pub struct ReportAssignmentStateOutput {
    pub accepted: usize,
    pub rejected: usize,
}

impl<'a> TransactionalWriter<'a> {
    pub async fn report_assignment_state(
        &self,
        input: ReportAssignmentStateInput,
        actor: &Actor,
    ) -> Result<ReportAssignmentStateOutput, CpError> {
        const OPERATION: &str = "assignment.report";

        match self.try_report_assignment_state(input.clone(), actor).await {
            Ok(out) => Ok(out),
            Err(err) => {
                self.record_rejected_audit(OPERATION, actor, &input, &err).await;
                Err(err)
            }
        }
    }

    async fn try_report_assignment_state(
        &self,
        input: ReportAssignmentStateInput,
        actor: &Actor,
    ) -> Result<ReportAssignmentStateOutput, CpError> {
        const OPERATION: &str = "assignment.report";
        let start = Instant::now();
        let event_id = Uuid::new_v4();
        let audit_id = Uuid::new_v4();
        let now = Utc::now();

        let mut tx = self.pool.begin().await.map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "begin_failed");
            CpError::Database(e)
        })?;

        sqlx::query(
            r#"INSERT INTO control_plane_events
               (id, event_type, source, subject_type, subject_id,
                resource_type, resource_id, occurred_at, payload_json)
               VALUES ($1, 'assignment.reported', 'node-agent', $2, $3,
                       'node', $4, $5, $6)"#,
        )
        .bind(event_id)
        .bind(&actor.subject_type)
        .bind(&actor.subject_id)
        .bind(input.node_id)
        .bind(now)
        .bind(json!({
            "applied_count": input.applied.len(),
            "failed_count": input.failed.len(),
        }))
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "event_insert_failed");
            CpError::Database(e)
        })?;

        let mut accepted = 0usize;
        let mut rejected = 0usize;

        for applied in &input.applied {
            let row = sqlx::query(
                r#"UPDATE assignments
                      SET actual_policy_id = $1,
                          actual_zone_version = $2,
                          last_reported_at = $3,
                          status = CASE
                            WHEN $1 = desired_policy_id
                             AND $2 = desired_zone_version
                            THEN 'applied'
                            ELSE 'drifted'
                          END,
                          updated_at = $3,
                          version = version + 1,
                          caused_by_event_id = $4,
                          error_json = NULL
                    WHERE id = $5 AND node_id = $6
                    RETURNING *"#,
            )
            .bind(applied.actual_policy_id)
            .bind(applied.actual_zone_version)
            .bind(now)
            .bind(event_id)
            .bind(applied.assignment_id)
            .bind(input.node_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                metrics::record_transaction_rollback(OPERATION, "applied_update_failed");
                CpError::Database(e)
            })?;

            if let Some(row) = row {
                accepted += 1;
                insert_assignment_version(
                    &mut tx,
                    row.get("id"),
                    row.get("version"),
                    assignment_snapshot_json(&row),
                    now,
                    event_id,
                )
                .await?;
            } else {
                rejected += 1;
            }
        }

        for failed in &input.failed {
            let row = sqlx::query(
                r#"UPDATE assignments
                      SET status = 'failed',
                          error_json = $1,
                          last_reported_at = $2,
                          updated_at = $2,
                          version = version + 1,
                          caused_by_event_id = $3
                    WHERE id = $4 AND node_id = $5
                    RETURNING *"#,
            )
            .bind(&failed.error_json)
            .bind(now)
            .bind(event_id)
            .bind(failed.assignment_id)
            .bind(input.node_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                metrics::record_transaction_rollback(OPERATION, "failed_update_failed");
                CpError::Database(e)
            })?;

            if let Some(row) = row {
                accepted += 1;
                insert_assignment_version(
                    &mut tx,
                    row.get("id"),
                    row.get("version"),
                    assignment_snapshot_json(&row),
                    now,
                    event_id,
                )
                .await?;
            } else {
                rejected += 1;
            }
        }

        let request_json = serde_json::to_value(&input).unwrap_or_else(|_| json!({}));
        sqlx::query(
            r#"INSERT INTO audit_log
               (id, occurred_at, actor_type, actor_id, action,
                resource_type, resource_id, result, request_json,
                control_plane_event_id)
               VALUES ($1, $2, $3, $4, 'assignment.report', 'node', $5,
                       'success', $6, $7)"#,
        )
        .bind(audit_id)
        .bind(now)
        .bind(&actor.actor_type)
        .bind(&actor.actor_id)
        .bind(input.node_id)
        .bind(&request_json)
        .bind(event_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "audit_insert_failed");
            CpError::Database(e)
        })?;

        tx.commit().await.map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "commit_failed");
            CpError::Database(e)
        })?;

        metrics::record_transaction_duration(OPERATION, start.elapsed());

        Ok(ReportAssignmentStateOutput { accepted, rejected })
    }
}

async fn insert_assignment_version(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    assignment_id: Uuid,
    version: i64,
    snapshot_json: JsonValue,
    now: chrono::DateTime<Utc>,
    event_id: Uuid,
) -> Result<(), CpError> {
    sqlx::query(
        r#"INSERT INTO assignment_versions
           (id, assignment_id, version, snapshot_json,
            created_at, caused_by_event_id)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(Uuid::new_v4())
    .bind(assignment_id)
    .bind(version)
    .bind(&snapshot_json)
    .bind(now)
    .bind(event_id)
    .execute(&mut **tx)
    .await
    .map_err(|e| {
        metrics::record_transaction_rollback("assignment.report", "version_insert_failed");
        CpError::Database(e)
    })?;

    Ok(())
}

fn assignment_snapshot_json(row: &sqlx::postgres::PgRow) -> JsonValue {
    json!({
        "id": row.get::<Uuid, _>("id").to_string(),
        "zone_id": row.get::<Uuid, _>("zone_id").to_string(),
        "node_id": row.get::<Uuid, _>("node_id").to_string(),
        "status": row.get::<String, _>("status"),
        "version": row.get::<i64, _>("version"),
        "desired_policy_id": row.get::<Uuid, _>("desired_policy_id").to_string(),
        "desired_zone_version": row.get::<i64, _>("desired_zone_version"),
        "actual_policy_id": row.get::<Option<Uuid>, _>("actual_policy_id").map(|id| id.to_string()),
        "actual_zone_version": row.get::<Option<i64>, _>("actual_zone_version"),
        "error_json": row.get::<Option<JsonValue>, _>("error_json"),
    })
}
