use serde_json::json;
use sqlx::postgres::PgPool;
use syva_cp::db::types::{Actor, PolicyInput};
use syva_cp::error::CpError;
use syva_cp::write::team::CreateTeamInput;
use syva_cp::write::zone::{CreateZoneInput, DeleteZoneInput};
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

async fn seed(pool: &PgPool) -> (Uuid, i64) {
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
async fn delete_zone_drain_sets_status_draining(pool: PgPool) {
    let (zone_id, v) = seed(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    let zone = writer
        .delete_zone(
            DeleteZoneInput {
                zone_id,
                if_version: v,
                drain: true,
            },
            &actor(),
        )
        .await
        .unwrap();

    assert_eq!(zone.status, "draining");
    assert!(zone.deleted_at.is_none());
    assert_eq!(zone.version, v + 1);
}

#[sqlx::test]
async fn delete_zone_immediate_sets_deleted_at_and_hides(pool: PgPool) {
    let (zone_id, v) = seed(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    let zone = writer
        .delete_zone(
            DeleteZoneInput {
                zone_id,
                if_version: v,
                drain: false,
            },
            &actor(),
        )
        .await
        .unwrap();

    assert_eq!(zone.status, "deleted");
    assert!(zone.deleted_at.is_some());

    let err = syva_cp::read::zone::get_zone(&pool, zone_id).await.unwrap_err();
    assert!(matches!(err, CpError::NotFound { .. }));
}

#[sqlx::test]
async fn delete_zone_with_stale_version_returns_conflict(pool: PgPool) {
    let (zone_id, v) = seed(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    let err = writer
        .delete_zone(
            DeleteZoneInput {
                zone_id,
                if_version: v + 99,
                drain: true,
            },
            &actor(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, CpError::VersionConflict { .. }));
}
