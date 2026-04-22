use crate::db::types::{Policy, Zone};
use crate::error::CpError;
use chrono::{DateTime, Utc};
use serde_json::Value as JsonValue;
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

pub async fn get_zone(pool: &PgPool, zone_id: Uuid) -> Result<Zone, CpError> {
    let row = sqlx::query(
        r#"SELECT id, team_id, name, display_name, status, current_policy_id,
                  selector_json, metadata_json, created_at, updated_at,
                  deleted_at, version, caused_by_event_id
           FROM zones WHERE id = $1 AND deleted_at IS NULL"#,
    )
    .bind(zone_id)
    .fetch_optional(pool)
    .await?
    .ok_or(CpError::NotFound {
        resource: "zone",
        identifier: zone_id.to_string(),
    })?;

    Ok(zone_from_row(&row))
}

pub async fn get_zone_by_name(
    pool: &PgPool,
    team_id: Uuid,
    name: &str,
) -> Result<Zone, CpError> {
    let row = sqlx::query(
        r#"SELECT id, team_id, name, display_name, status, current_policy_id,
                  selector_json, metadata_json, created_at, updated_at,
                  deleted_at, version, caused_by_event_id
           FROM zones
           WHERE team_id = $1 AND name = $2 AND deleted_at IS NULL"#,
    )
    .bind(team_id)
    .bind(name)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| CpError::NotFound {
        resource: "zone",
        identifier: format!("{team_id}/{name}"),
    })?;

    Ok(zone_from_row(&row))
}

pub async fn list_zones(
    pool: &PgPool,
    team_id: Uuid,
    status_filter: Option<&str>,
    limit: i64,
) -> Result<Vec<Zone>, CpError> {
    let limit = limit.clamp(1, 500);
    let rows = match status_filter {
        Some(status) => sqlx::query(
            r#"SELECT id, team_id, name, display_name, status, current_policy_id,
                      selector_json, metadata_json, created_at, updated_at,
                      deleted_at, version, caused_by_event_id
               FROM zones
               WHERE team_id = $1 AND status = $2 AND deleted_at IS NULL
               ORDER BY updated_at DESC LIMIT $3"#,
        )
        .bind(team_id)
        .bind(status)
        .bind(limit)
        .fetch_all(pool)
        .await?,
        None => sqlx::query(
            r#"SELECT id, team_id, name, display_name, status, current_policy_id,
                      selector_json, metadata_json, created_at, updated_at,
                      deleted_at, version, caused_by_event_id
               FROM zones
               WHERE team_id = $1 AND deleted_at IS NULL
               ORDER BY updated_at DESC LIMIT $2"#,
        )
        .bind(team_id)
        .bind(limit)
        .fetch_all(pool)
        .await?,
    };

    Ok(rows.iter().map(zone_from_row).collect())
}

pub async fn get_current_policy(
    pool: &PgPool,
    zone_id: Uuid,
) -> Result<Option<Policy>, CpError> {
    let row = sqlx::query(
        r#"SELECT p.id, p.zone_id, p.version, p.checksum, p.policy_json,
                  p.summary_json, p.created_at, p.created_by_subject,
                  p.caused_by_event_id
           FROM policies p
           INNER JOIN zones z ON z.current_policy_id = p.id
           WHERE z.id = $1 AND z.deleted_at IS NULL"#,
    )
    .bind(zone_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(|r| Policy {
        id: r.get("id"),
        zone_id: r.get("zone_id"),
        version: r.get("version"),
        checksum: r.get("checksum"),
        policy_json: r.get("policy_json"),
        summary_json: r.get("summary_json"),
        created_at: r.get("created_at"),
        created_by_subject: r.get("created_by_subject"),
        caused_by_event_id: r.get("caused_by_event_id"),
    }))
}

pub struct ZoneHistoryEntry {
    pub version: i64,
    pub snapshot_json: JsonValue,
    pub created_at: DateTime<Utc>,
    pub caused_by_event_id: Uuid,
}

pub async fn get_zone_history(
    pool: &PgPool,
    zone_id: Uuid,
    limit: i64,
) -> Result<Vec<ZoneHistoryEntry>, CpError> {
    let limit = limit.clamp(1, 500);
    let rows = sqlx::query(
        r#"SELECT version, snapshot_json, created_at, caused_by_event_id
           FROM zone_versions
           WHERE zone_id = $1
           ORDER BY version DESC LIMIT $2"#,
    )
    .bind(zone_id)
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|r| ZoneHistoryEntry {
            version: r.get("version"),
            snapshot_json: r.get("snapshot_json"),
            created_at: r.get("created_at"),
            caused_by_event_id: r.get("caused_by_event_id"),
        })
        .collect())
}

fn zone_from_row(row: &sqlx::postgres::PgRow) -> Zone {
    Zone {
        id: row.get("id"),
        team_id: row.get("team_id"),
        name: row.get("name"),
        display_name: row.get("display_name"),
        status: row.get("status"),
        current_policy_id: row.get("current_policy_id"),
        selector_json: row.get("selector_json"),
        metadata_json: row.get("metadata_json"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        deleted_at: row.get("deleted_at"),
        version: row.get("version"),
        caused_by_event_id: row.get("caused_by_event_id"),
    }
}
