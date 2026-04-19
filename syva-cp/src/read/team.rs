//! Team read paths. Each query runs against the pool directly; there's
//! no transaction because reads are consistent-enough under REPEATABLE
//! READ defaults for team lookups. When we need cross-table consistency
//! (zone + policy, for example), read transactions will land in a
//! helper alongside these.

use crate::db::types::Team;
use crate::error::CpError;
use sqlx::postgres::PgPool;
use sqlx::Row;
use uuid::Uuid;

pub async fn get_team(pool: &PgPool, team_id: Uuid) -> Result<Team, CpError> {
    let row = sqlx::query(
        r#"SELECT id, name, display_name, status, created_at, updated_at,
                  version, caused_by_event_id
             FROM teams
            WHERE id = $1"#,
    )
    .bind(team_id)
    .fetch_optional(pool)
    .await?
    .ok_or(CpError::NotFound {
        resource: "team",
        identifier: team_id.to_string(),
    })?;

    Ok(row_to_team(&row))
}

pub async fn get_team_by_name(pool: &PgPool, name: &str) -> Result<Team, CpError> {
    let row = sqlx::query(
        r#"SELECT id, name, display_name, status, created_at, updated_at,
                  version, caused_by_event_id
             FROM teams
            WHERE name = $1"#,
    )
    .bind(name)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| CpError::NotFound {
        resource: "team",
        identifier: name.to_string(),
    })?;

    Ok(row_to_team(&row))
}

pub async fn list_teams(pool: &PgPool, limit: i64) -> Result<Vec<Team>, CpError> {
    let limit = limit.clamp(1, 500);
    let rows = sqlx::query(
        r#"SELECT id, name, display_name, status, created_at, updated_at,
                  version, caused_by_event_id
             FROM teams
            WHERE status = 'active'
         ORDER BY created_at DESC
            LIMIT $1"#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(rows.iter().map(row_to_team).collect())
}

fn row_to_team(row: &sqlx::postgres::PgRow) -> Team {
    Team {
        id: row.get("id"),
        name: row.get("name"),
        display_name: row.get("display_name"),
        status: row.get("status"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        version: row.get("version"),
        caused_by_event_id: row.get("caused_by_event_id"),
    }
}
