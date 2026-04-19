use crate::db::types::{Actor, Policy, PolicyInput, Zone};
use crate::error::CpError;
use crate::metrics;
use crate::write::TransactionalWriter;
use chrono::Utc;
use serde_json::{json, Value as JsonValue};
use sqlx::Row;
use std::time::Instant;
use uuid::Uuid;

#[derive(Debug, Clone, serde::Serialize)]
pub struct CreateZoneInput {
    pub team_id: Uuid,
    pub name: String,
    pub display_name: Option<String>,
    pub policy: PolicyInput,
    pub selector_json: Option<JsonValue>,
    pub metadata_json: Option<JsonValue>,
}

pub struct CreateZoneOutput {
    pub zone: Zone,
    pub policy: Policy,
}

impl<'a> TransactionalWriter<'a> {
    pub async fn create_zone(
        &self,
        input: CreateZoneInput,
        actor: &Actor,
    ) -> Result<CreateZoneOutput, CpError> {
        const OPERATION: &str = "zone.create";

        if let Err(e) = validate_create_zone(&input) {
            self.record_rejected_audit(OPERATION, actor, &input, &e).await;
            return Err(e);
        }

        match self.try_create_zone(input.clone(), actor).await {
            Ok(out) => Ok(out),
            Err(e) => {
                self.record_rejected_audit(OPERATION, actor, &input, &e).await;
                Err(e)
            }
        }
    }

    async fn try_create_zone(
        &self,
        input: CreateZoneInput,
        actor: &Actor,
    ) -> Result<CreateZoneOutput, CpError> {
        const OPERATION: &str = "zone.create";
        let start = Instant::now();

        let zone_id = Uuid::new_v4();
        let policy_id = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        let version_row_id = Uuid::new_v4();
        let audit_id = Uuid::new_v4();
        let now = Utc::now();
        let checksum = input.policy.checksum();
        let selector = input.selector_json.clone().unwrap_or(JsonValue::Null);
        let metadata = input.metadata_json.clone().unwrap_or_else(|| json!({}));
        let summary = input.policy.summary_json.clone().unwrap_or_else(|| json!({}));

        let mut tx = self.pool.begin().await.map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "begin_failed");
            CpError::Database(e)
        })?;

        let name_lock_key = hash_name_lock(input.team_id, &input.name);
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(name_lock_key)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                metrics::record_transaction_rollback(OPERATION, "advisory_lock_failed");
                CpError::Database(e)
            })?;

        let team_status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM teams WHERE id = $1 FOR SHARE",
        )
        .bind(input.team_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "team_lookup_failed");
            CpError::Database(e)
        })?;

        match team_status.as_deref() {
            Some("active") => {}
            Some(_) => {
                metrics::record_transaction_rollback(OPERATION, "team_inactive");
                return Err(CpError::FailedPrecondition(format!(
                    "team {} is not active",
                    input.team_id
                )));
            }
            None => {
                metrics::record_transaction_rollback(OPERATION, "team_not_found");
                return Err(CpError::NotFound {
                    resource: "team",
                    identifier: input.team_id.to_string(),
                });
            }
        }

        sqlx::query(
            r#"INSERT INTO control_plane_events
               (id, event_type, source, subject_type, subject_id, team_id,
                resource_type, resource_id, occurred_at, payload_json)
               VALUES ($1, 'zone.created', 'api', $2, $3, $4, 'zone', $5, $6, $7)"#,
        )
        .bind(event_id)
        .bind(&actor.subject_type)
        .bind(&actor.subject_id)
        .bind(input.team_id)
        .bind(zone_id)
        .bind(now)
        .bind(json!({
            "name": &input.name,
            "checksum": &checksum,
        }))
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "event_insert_failed");
            CpError::Database(e)
        })?;

        let policy_row = sqlx::query(
            r#"INSERT INTO policies
               (id, zone_id, version, checksum, policy_json, summary_json,
                created_at, created_by_subject, caused_by_event_id)
               VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8)
               RETURNING id, zone_id, version, checksum, policy_json,
                         summary_json, created_at, created_by_subject,
                         caused_by_event_id"#,
        )
        .bind(policy_id)
        .bind(zone_id)
        .bind(&checksum)
        .bind(&input.policy.policy_json)
        .bind(&summary)
        .bind(now)
        .bind(&actor.subject_id)
        .bind(event_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "policy_insert_failed");
            CpError::Database(e)
        })?;

        let policy = Policy {
            id: policy_row.get("id"),
            zone_id: policy_row.get("zone_id"),
            version: policy_row.get("version"),
            checksum: policy_row.get("checksum"),
            policy_json: policy_row.get("policy_json"),
            summary_json: policy_row.get("summary_json"),
            created_at: policy_row.get("created_at"),
            created_by_subject: policy_row.get("created_by_subject"),
            caused_by_event_id: policy_row.get("caused_by_event_id"),
        };

        let zone_row = match sqlx::query(
            r#"INSERT INTO zones
               (id, team_id, name, display_name, status, current_policy_id,
                selector_json, metadata_json, created_at, updated_at,
                version, caused_by_event_id)
               VALUES ($1, $2, $3, $4, 'active', $5, $6, $7, $8, $8, 1, $9)
               RETURNING id, team_id, name, display_name, status,
                         current_policy_id, selector_json, metadata_json,
                         created_at, updated_at, deleted_at, version,
                         caused_by_event_id"#,
        )
        .bind(zone_id)
        .bind(input.team_id)
        .bind(&input.name)
        .bind(&input.display_name)
        .bind(policy_id)
        .bind(&selector)
        .bind(&metadata)
        .bind(now)
        .bind(event_id)
        .fetch_one(&mut *tx)
        .await
        {
            Ok(row) => row,
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                metrics::record_transaction_rollback(OPERATION, "name_conflict");
                return Err(CpError::Conflict {
                    message: format!(
                        "zone name '{}' already exists in team",
                        input.name
                    ),
                });
            }
            Err(e) => {
                metrics::record_transaction_rollback(OPERATION, "zone_insert_failed");
                return Err(CpError::Database(e));
            }
        };

        let zone = Zone {
            id: zone_row.get("id"),
            team_id: zone_row.get("team_id"),
            name: zone_row.get("name"),
            display_name: zone_row.get("display_name"),
            status: zone_row.get("status"),
            current_policy_id: zone_row.get("current_policy_id"),
            selector_json: zone_row.get("selector_json"),
            metadata_json: zone_row.get("metadata_json"),
            created_at: zone_row.get("created_at"),
            updated_at: zone_row.get("updated_at"),
            deleted_at: zone_row.get("deleted_at"),
            version: zone_row.get("version"),
            caused_by_event_id: zone_row.get("caused_by_event_id"),
        };

        let snapshot = serde_json::to_value(&zone).map_err(CpError::Serialization)?;
        sqlx::query(
            r#"INSERT INTO zone_versions
               (id, zone_id, version, snapshot_json, created_at,
                caused_by_event_id)
               VALUES ($1, $2, $3, $4, $5, $6)"#,
        )
        .bind(version_row_id)
        .bind(zone_id)
        .bind(zone.version)
        .bind(&snapshot)
        .bind(now)
        .bind(event_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            metrics::record_transaction_rollback(OPERATION, "version_insert_failed");
            CpError::Database(e)
        })?;

        let request_json = serde_json::to_value(&input).map_err(CpError::Serialization)?;
        sqlx::query(
            r#"INSERT INTO audit_log
               (id, occurred_at, actor_type, actor_id, team_id, action,
                resource_type, resource_id, result, request_json,
                control_plane_event_id)
               VALUES ($1, $2, $3, $4, $5, 'zone.create', 'zone', $6,
                       'success', $7, $8)"#,
        )
        .bind(audit_id)
        .bind(now)
        .bind(&actor.actor_type)
        .bind(&actor.actor_id)
        .bind(input.team_id)
        .bind(zone_id)
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

        tracing::debug!(
            zone_id = %zone.id,
            policy_id = %policy.id,
            event_id = %event_id,
            duration_ms = start.elapsed().as_millis(),
            "zone created"
        );

        Ok(CreateZoneOutput { zone, policy })
    }
}

fn validate_create_zone(input: &CreateZoneInput) -> Result<(), CpError> {
    if input.name.is_empty() || input.name.len() > 63 {
        return Err(CpError::InvalidArgument(
            "zone name must be 1..=63 characters".into(),
        ));
    }
    if !input
        .name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CpError::InvalidArgument(
            "zone name must be ASCII alphanumeric, dash, or underscore".into(),
        ));
    }
    if input.policy.policy_json.is_null() {
        return Err(CpError::InvalidArgument(
            "policy_json must be a non-null JSON object".into(),
        ));
    }
    Ok(())
}

fn hash_name_lock(team_id: Uuid, name: &str) -> i64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    team_id.hash(&mut hasher);
    name.hash(&mut hasher);
    hasher.finish() as i64
}

#[allow(dead_code)]
pub(crate) fn zone_advisory_lock_key(zone_id: Uuid) -> i64 {
    let bytes = zone_id.as_bytes();
    let mut key: i64 = 0;
    for (i, b) in bytes.iter().take(8).enumerate() {
        key |= (*b as i64) << (i * 8);
    }
    key
}
