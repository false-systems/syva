use crate::db::types::Assignment;
use crate::error::CpError;
use serde_json::Value as JsonValue;
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

pub async fn get_assignment(pool: &PgPool, id: Uuid) -> Result<Assignment, CpError> {
    let row = sqlx::query("SELECT * FROM assignments WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or(CpError::NotFound {
            resource: "assignment",
            identifier: id.to_string(),
        })?;

    Ok(assignment_from_row(&row))
}

pub async fn list_for_node(pool: &PgPool, node_id: Uuid) -> Result<Vec<Assignment>, CpError> {
    let rows = sqlx::query(
        r#"SELECT * FROM assignments
           WHERE node_id = $1 AND status NOT IN ('removed', 'failed')
           ORDER BY created_at ASC"#,
    )
    .bind(node_id)
    .fetch_all(pool)
    .await?;

    Ok(rows.iter().map(assignment_from_row).collect())
}

pub async fn list_filtered(
    pool: &PgPool,
    zone_id: Option<Uuid>,
    node_id: Option<Uuid>,
    status: Option<&str>,
    limit: i64,
) -> Result<Vec<Assignment>, CpError> {
    let limit = limit.clamp(1, 500);
    let rows = match (zone_id, node_id, status) {
        (Some(zone_id), Some(node_id), Some(status)) => sqlx::query(
            "SELECT * FROM assignments WHERE zone_id=$1 AND node_id=$2 AND status=$3 ORDER BY updated_at DESC LIMIT $4",
        )
        .bind(zone_id)
        .bind(node_id)
        .bind(status)
        .bind(limit)
        .fetch_all(pool)
        .await?,
        (Some(zone_id), Some(node_id), None) => sqlx::query(
            "SELECT * FROM assignments WHERE zone_id=$1 AND node_id=$2 ORDER BY updated_at DESC LIMIT $3",
        )
        .bind(zone_id)
        .bind(node_id)
        .bind(limit)
        .fetch_all(pool)
        .await?,
        (Some(zone_id), None, Some(status)) => sqlx::query(
            "SELECT * FROM assignments WHERE zone_id=$1 AND status=$2 ORDER BY updated_at DESC LIMIT $3",
        )
        .bind(zone_id)
        .bind(status)
        .bind(limit)
        .fetch_all(pool)
        .await?,
        (None, Some(node_id), Some(status)) => sqlx::query(
            "SELECT * FROM assignments WHERE node_id=$1 AND status=$2 ORDER BY updated_at DESC LIMIT $3",
        )
        .bind(node_id)
        .bind(status)
        .bind(limit)
        .fetch_all(pool)
        .await?,
        (Some(zone_id), None, None) => sqlx::query(
            "SELECT * FROM assignments WHERE zone_id=$1 ORDER BY updated_at DESC LIMIT $2",
        )
        .bind(zone_id)
        .bind(limit)
        .fetch_all(pool)
        .await?,
        (None, Some(node_id), None) => sqlx::query(
            "SELECT * FROM assignments WHERE node_id=$1 ORDER BY updated_at DESC LIMIT $2",
        )
        .bind(node_id)
        .bind(limit)
        .fetch_all(pool)
        .await?,
        (None, None, Some(status)) => sqlx::query(
            "SELECT * FROM assignments WHERE status=$1 ORDER BY updated_at DESC LIMIT $2",
        )
        .bind(status)
        .bind(limit)
        .fetch_all(pool)
        .await?,
        (None, None, None) => sqlx::query(
            "SELECT * FROM assignments ORDER BY updated_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(pool)
        .await?,
    };

    Ok(rows.iter().map(assignment_from_row).collect())
}

pub(crate) fn assignment_from_row(row: &sqlx::postgres::PgRow) -> Assignment {
    Assignment {
        id: row.get("id"),
        zone_id: row.get("zone_id"),
        node_id: row.get("node_id"),
        status: row.get("status"),
        desired_policy_id: row.get("desired_policy_id"),
        desired_zone_version: row.get("desired_zone_version"),
        actual_policy_id: row.get("actual_policy_id"),
        actual_zone_version: row.get("actual_zone_version"),
        last_reported_at: row.get("last_reported_at"),
        error_json: row.get::<Option<JsonValue>, _>("error_json"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        version: row.get("version"),
        caused_by_event_id: row.get("caused_by_event_id"),
    }
}
