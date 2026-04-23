use crate::db::types::{Actor, Node, NodeLabels};
use crate::engine::assignment::{
    compute_node_assignments, diff_assignments, DesiredAssignment, ExistingAssignment,
    NodeForAssignment, ZoneForAssignment,
};
use crate::error::CpError;
use crate::metrics;
use crate::write::TransactionalWriter;
use chrono::Utc;
use serde_json::{json, Value as JsonValue};
use sqlx::Row;
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize)]
pub struct RegisterNodeInput {
    pub node_name: String,
    pub fingerprint: Option<String>,
    pub cluster_id: Option<String>,
    pub labels: NodeLabels,
    pub capabilities_json: JsonValue,
    pub proposed_id: Uuid,
}

pub struct RegisterNodeOutput {
    pub node: Node,
    pub labels: NodeLabels,
    pub is_new: bool,
    pub assignments_upserted: usize,
    pub assignments_removed: usize,
}

impl<'a> TransactionalWriter<'a> {
    pub async fn register_node(
        &self,
        input: RegisterNodeInput,
        actor: &Actor,
    ) -> Result<RegisterNodeOutput, CpError> {
        const OPERATION: &str = "node.register";

        if let Err(err) = validate_register_node(&input) {
            self.record_rejected_audit(OPERATION, actor, &input, &err).await;
            return Err(err);
        }

        match self.try_register_node(input.clone(), actor).await {
            Ok(out) => Ok(out),
            Err(err) => {
                self.record_rejected_audit(OPERATION, actor, &input, &err).await;
                Err(err)
            }
        }
    }

    async fn try_register_node(
        &self,
        input: RegisterNodeInput,
        actor: &Actor,
    ) -> Result<RegisterNodeOutput, CpError> {
        const OPERATION: &str = "node.register";
        let start = Instant::now();
        let event_id = Uuid::new_v4();
        let audit_id = Uuid::new_v4();
        let now = Utc::now();

        let mut tx = self.pool.begin().await.map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "begin_failed");
            CpError::Database(e)
        })?;

        let existing: Option<(Uuid, i64)> = if let Some(fingerprint) = input.fingerprint.as_deref()
        {
            sqlx::query_as("SELECT id, version FROM nodes WHERE fingerprint = $1 FOR UPDATE")
                .bind(fingerprint)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| {
                    metrics::record_transaction_rollback(OPERATION, "node_lookup_failed");
                    CpError::Database(e)
                })?
        } else {
            sqlx::query_as("SELECT id, version FROM nodes WHERE node_name = $1 FOR UPDATE")
                .bind(&input.node_name)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| {
                    metrics::record_transaction_rollback(OPERATION, "node_lookup_failed");
                    CpError::Database(e)
                })?
        };

        let resource_id = existing.map(|(id, _)| id).unwrap_or(input.proposed_id);

        sqlx::query(
            r#"INSERT INTO control_plane_events
               (id, event_type, source, subject_type, subject_id,
                resource_type, resource_id, occurred_at, payload_json)
               VALUES ($1, 'node.registered', 'node-agent', $2, $3,
                       'node', $4, $5, $6)"#,
        )
        .bind(event_id)
        .bind(&actor.subject_type)
        .bind(&actor.subject_id)
        .bind(resource_id)
        .bind(now)
        .bind(json!({
            "node_name": &input.node_name,
            "is_new": existing.is_none(),
        }))
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "event_insert_failed");
            CpError::Database(e)
        })?;

        let (node_row, is_new) = match existing {
            Some((node_id, current_version)) => {
                let row = sqlx::query(
                    r#"UPDATE nodes
                          SET node_name = $1,
                              cluster_id = $2,
                              fingerprint = $3,
                              status = 'online',
                              capabilities_json = $4,
                              last_seen_at = $5,
                              updated_at = $5,
                              version = version + 1,
                              caused_by_event_id = $6
                        WHERE id = $7 AND version = $8
                        RETURNING *"#,
                )
                .bind(&input.node_name)
                .bind(&input.cluster_id)
                .bind(&input.fingerprint)
                .bind(&input.capabilities_json)
                .bind(now)
                .bind(event_id)
                .bind(node_id)
                .bind(current_version)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| {
                    metrics::record_transaction_rollback(OPERATION, "node_update_failed");
                    CpError::Database(e)
                })?
                .ok_or_else(|| {
                    metrics::record_transaction_rollback(OPERATION, "version_race");
                    CpError::Internal("node version race during re-registration".into())
                })?;

                (row, false)
            }
            None => {
                let row = match sqlx::query(
                    r#"INSERT INTO nodes
                       (id, node_name, cluster_id, fingerprint, status,
                        capabilities_json, last_seen_at, created_at, updated_at,
                        version, caused_by_event_id)
                       VALUES ($1, $2, $3, $4, 'online', $5, $6, $6, $6, 1, $7)
                       RETURNING *"#,
                )
                .bind(input.proposed_id)
                .bind(&input.node_name)
                .bind(&input.cluster_id)
                .bind(&input.fingerprint)
                .bind(&input.capabilities_json)
                .bind(now)
                .bind(event_id)
                .fetch_one(&mut *tx)
                .await
                {
                    Ok(row) => row,
                    Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                        metrics::record_transaction_rollback(OPERATION, "name_or_id_conflict");
                        return Err(CpError::Conflict {
                            message: format!(
                                "node_name '{}' or id is already taken",
                                input.node_name
                            ),
                        });
                    }
                    Err(e) => {
                        metrics::record_transaction_rollback(OPERATION, "node_insert_failed");
                        return Err(CpError::Database(e));
                    }
                };

                (row, true)
            }
        };

        let node = node_from_row(&node_row);

        sqlx::query("DELETE FROM node_labels WHERE node_id = $1")
            .bind(node.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                metrics::record_transaction_rollback(OPERATION, "label_delete_failed");
                CpError::Database(e)
            })?;

        for (key, value) in &input.labels {
            sqlx::query("INSERT INTO node_labels (node_id, key, value) VALUES ($1, $2, $3)")
                .bind(node.id)
                .bind(key)
                .bind(value)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    metrics::record_transaction_rollback(OPERATION, "label_insert_failed");
                    CpError::Database(e)
                })?;
        }

        let (upserted, removed) =
            recompute_node_assignments_in_tx(&mut tx, &node, &input.labels, event_id, now).await?;

        let request_json = serde_json::to_value(&input).unwrap_or_else(|_| json!({}));
        sqlx::query(
            r#"INSERT INTO audit_log
               (id, occurred_at, actor_type, actor_id, action,
                resource_type, resource_id, result, request_json,
                control_plane_event_id)
               VALUES ($1, $2, $3, $4, 'node.register', 'node', $5,
                       'success', $6, $7)"#,
        )
        .bind(audit_id)
        .bind(now)
        .bind(&actor.actor_type)
        .bind(&actor.actor_id)
        .bind(node.id)
        .bind(&request_json)
        .bind(event_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "audit_insert_failed");
            CpError::Database(e)
        })?;

        sqlx::query("SELECT pg_notify('syva_cp_assignments', $1)")
            .bind(node.id.to_string())
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                metrics::record_transaction_rollback(OPERATION, "notify_failed");
                CpError::Database(e)
            })?;

        tx.commit().await.map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "commit_failed");
            CpError::Database(e)
        })?;

        metrics::record_transaction_duration(OPERATION, start.elapsed());

        Ok(RegisterNodeOutput {
            node,
            labels: input.labels,
            is_new,
            assignments_upserted: upserted,
            assignments_removed: removed,
        })
    }
}

fn validate_register_node(input: &RegisterNodeInput) -> Result<(), CpError> {
    if input.node_name.is_empty() || input.node_name.len() > 253 {
        return Err(CpError::InvalidArgument(
            "node_name must be 1..=253 chars".into(),
        ));
    }

    if input.capabilities_json.is_null() {
        return Err(CpError::InvalidArgument(
            "capabilities_json must be valid non-null JSON".into(),
        ));
    }

    for key in input.labels.keys() {
        if key.is_empty() || key.len() > 253 {
            return Err(CpError::InvalidArgument(
                "label keys must be 1..=253 chars".into(),
            ));
        }
    }

    Ok(())
}

pub(crate) fn node_from_row(row: &sqlx::postgres::PgRow) -> Node {
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

#[allow(dead_code)]
pub(crate) fn node_advisory_lock_key(node_id: Uuid) -> i64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in node_id.as_bytes() {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash as i64
}

pub(crate) async fn recompute_node_assignments_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    node: &Node,
    labels: &NodeLabels,
    event_id: Uuid,
    now: chrono::DateTime<Utc>,
) -> Result<(usize, usize), CpError> {
    let zone_rows = sqlx::query(
        r#"SELECT id, selector_json, current_policy_id, version
           FROM zones
           WHERE deleted_at IS NULL
             AND status = 'active'
             AND current_policy_id IS NOT NULL"#,
    )
    .fetch_all(&mut **tx)
    .await
    .map_err(CpError::Database)?;

    let zones = zone_rows
        .iter()
        .map(|row| ZoneForAssignment {
            zone_id: row.get("id"),
            selector_json: row
                .get::<Option<JsonValue>, _>("selector_json")
                .unwrap_or(JsonValue::Null),
            current_policy_id: row.get("current_policy_id"),
            zone_version: row.get("version"),
        })
        .collect::<Vec<_>>();

    let node_input = NodeForAssignment {
        node_id: node.id,
        node_name: node.node_name.clone(),
        status: node.status.clone(),
        labels: labels.clone(),
    };

    let desired = compute_node_assignments(&node_input, &zones);

    let current_rows = sqlx::query(
        r#"SELECT id, zone_id, node_id, desired_policy_id, desired_zone_version
           FROM assignments
           WHERE node_id = $1 AND status NOT IN ('removed', 'failed')"#,
    )
    .bind(node.id)
    .fetch_all(&mut **tx)
    .await
    .map_err(CpError::Database)?;

    let current = current_rows
        .iter()
        .map(|row| ExistingAssignment {
            id: row.get("id"),
            zone_id: row.get("zone_id"),
            node_id: row.get("node_id"),
            desired_policy_id: row.get("desired_policy_id"),
            desired_zone_version: row.get("desired_zone_version"),
        })
        .collect::<Vec<_>>();

    let (upserts, removes) = diff_assignments(&current, &desired);

    for assignment in &upserts {
        apply_assignment_upsert(tx, assignment, event_id, now).await?;
    }

    for assignment_id in &removes {
        let _ = apply_assignment_remove_and_return_node(tx, *assignment_id, event_id, now).await?;
    }

    Ok((upserts.len(), removes.len()))
}

#[allow(dead_code)]
pub(crate) async fn apply_assignment_upsert_exposed(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    desired: &DesiredAssignment,
    event_id: Uuid,
    now: chrono::DateTime<Utc>,
) -> Result<(), CpError> {
    apply_assignment_upsert(tx, desired, event_id, now).await
}

#[allow(dead_code)]
pub(crate) async fn apply_assignment_remove_exposed(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    assignment_id: Uuid,
    event_id: Uuid,
    now: chrono::DateTime<Utc>,
) -> Result<Option<Uuid>, CpError> {
    apply_assignment_remove_and_return_node(tx, assignment_id, event_id, now).await
}

async fn apply_assignment_upsert(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    desired: &DesiredAssignment,
    event_id: Uuid,
    now: chrono::DateTime<Utc>,
) -> Result<(), CpError> {
    let assignment_id = Uuid::new_v4();

    let row = sqlx::query(
        r#"INSERT INTO assignments
           (id, zone_id, node_id, status, desired_policy_id,
            desired_zone_version, created_at, updated_at,
            version, caused_by_event_id)
           VALUES ($1, $2, $3, 'desired', $4, $5, $6, $6, 1, $7)
           ON CONFLICT (zone_id, node_id) DO UPDATE SET
             desired_policy_id = EXCLUDED.desired_policy_id,
             desired_zone_version = EXCLUDED.desired_zone_version,
             status = CASE
               WHEN assignments.actual_policy_id = EXCLUDED.desired_policy_id
                    AND assignments.actual_zone_version = EXCLUDED.desired_zone_version
               THEN 'applied'
               ELSE 'desired'
             END,
             updated_at = EXCLUDED.updated_at,
             version = assignments.version + 1,
             caused_by_event_id = EXCLUDED.caused_by_event_id
           RETURNING *"#,
    )
    .bind(assignment_id)
    .bind(desired.zone_id)
    .bind(desired.node_id)
    .bind(desired.desired_policy_id)
    .bind(desired.desired_zone_version)
    .bind(now)
    .bind(event_id)
    .fetch_one(&mut **tx)
    .await
    .map_err(CpError::Database)?;

    let resulting_id: Uuid = row.get("id");
    let resulting_version: i64 = row.get("version");
    let snapshot = assignment_snapshot_json(&row);

    sqlx::query(
        r#"INSERT INTO assignment_versions
           (id, assignment_id, version, snapshot_json, created_at,
            caused_by_event_id)
           VALUES ($1, $2, $3, $4, $5, $6)"#,
    )
    .bind(Uuid::new_v4())
    .bind(resulting_id)
    .bind(resulting_version)
    .bind(&snapshot)
    .bind(now)
    .bind(event_id)
    .execute(&mut **tx)
    .await
    .map_err(CpError::Database)?;

    Ok(())
}

async fn apply_assignment_remove_and_return_node(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    assignment_id: Uuid,
    event_id: Uuid,
    now: chrono::DateTime<Utc>,
) -> Result<Option<Uuid>, CpError> {
    let row = sqlx::query(
        r#"UPDATE assignments
              SET status = 'removing',
                  updated_at = $1,
                  version = version + 1,
                  caused_by_event_id = $2
            WHERE id = $3 AND status NOT IN ('removed', 'failed')
           RETURNING *"#,
    )
    .bind(now)
    .bind(event_id)
    .bind(assignment_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(CpError::Database)?;

    Ok(match row {
        Some(row) => {
            let node_id: Uuid = row.get("node_id");
            let version: i64 = row.get("version");
            let snapshot = assignment_snapshot_json(&row);

            sqlx::query(
                r#"INSERT INTO assignment_versions
                   (id, assignment_id, version, snapshot_json, created_at,
                    caused_by_event_id)
                   VALUES ($1, $2, $3, $4, $5, $6)"#,
            )
            .bind(Uuid::new_v4())
            .bind(assignment_id)
            .bind(version)
            .bind(&snapshot)
            .bind(now)
            .bind(event_id)
            .execute(&mut **tx)
            .await
            .map_err(CpError::Database)?;

            Some(node_id)
        }
        None => None,
    })
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
