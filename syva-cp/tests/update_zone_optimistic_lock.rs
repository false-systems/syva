use serde_json::json;
use sqlx::postgres::PgPool;
use syva_cp::db::types::{Actor, PolicyInput};
use syva_cp::error::CpError;
use syva_cp::write::team::CreateTeamInput;
use syva_cp::write::zone::{CreateZoneInput, UpdateZoneInput};
use syva_cp::write::TransactionalWriter;
use uuid::Uuid;

fn actor() -> Actor {
    Actor {
        actor_type: "user".into(),
        actor_id: "test".into(),
        team_id: None,
        subject_type: "user".into(),
        subject_id: "test".into(),
    }
}

async fn seed_zone(pool: &PgPool) -> (Uuid, i64) {
    let writer = TransactionalWriter::new(pool);
    let team = writer
        .create_team(
            CreateTeamInput {
                name: "payments".into(),
                display_name: None,
            },
            &actor(),
        )
        .await
        .unwrap();
    let out = writer
        .create_zone(
            CreateZoneInput {
                team_id: team.id,
                name: "api".into(),
                display_name: None,
                policy: PolicyInput {
                    policy_json: json!({}),
                    summary_json: None,
                },
                selector_json: None,
                metadata_json: None,
            },
            &actor(),
        )
        .await
        .unwrap();
    (out.zone.id, out.zone.version)
}

#[sqlx::test]
async fn update_zone_increments_version_and_writes_history(pool: PgPool) {
    let (zone_id, v) = seed_zone(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    let out = writer
        .update_zone(
            UpdateZoneInput {
                zone_id,
                if_version: v,
                policy: Some(PolicyInput {
                    policy_json: json!({"changed": true}),
                    summary_json: None,
                }),
                selector_json: None,
                metadata_json: None,
            },
            &actor(),
        )
        .await
        .unwrap();

    assert_eq!(out.zone.version, v + 1);
    assert!(out.new_policy.is_some());
    assert_eq!(out.new_policy.unwrap().version, 2);

    let versions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM zone_versions WHERE zone_id = $1")
            .bind(zone_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(versions, 2, "initial snapshot + update snapshot");
}

#[sqlx::test]
async fn update_zone_with_stale_version_returns_conflict(pool: PgPool) {
    let (zone_id, v) = seed_zone(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    let err = writer
        .update_zone(
            UpdateZoneInput {
                zone_id,
                if_version: v + 99,
                policy: Some(PolicyInput {
                    policy_json: json!({"x": 1}),
                    summary_json: None,
                }),
                selector_json: None,
                metadata_json: None,
            },
            &actor(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, CpError::VersionConflict { .. }));

    let current_version: i64 = sqlx::query_scalar("SELECT version FROM zones WHERE id = $1")
        .bind(zone_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(current_version, v);

    let audit = sqlx::query(
        "SELECT result, control_plane_event_id FROM audit_log
          WHERE action = 'zone.update' AND resource_id = $1",
    )
    .bind(zone_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let result: String = sqlx::Row::get(&audit, "result");
    let link: Option<Uuid> = sqlx::Row::get(&audit, "control_plane_event_id");
    assert_eq!(result, "denied");
    assert!(link.is_none());
}

#[sqlx::test]
async fn update_zone_with_identical_policy_content_returns_conflict(pool: PgPool) {
    let (zone_id, v) = seed_zone(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    let err = writer
        .update_zone(
            UpdateZoneInput {
                zone_id,
                if_version: v,
                policy: Some(PolicyInput {
                    policy_json: json!({}),
                    summary_json: None,
                }),
                selector_json: None,
                metadata_json: None,
            },
            &actor(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, CpError::Conflict { .. }));
}
