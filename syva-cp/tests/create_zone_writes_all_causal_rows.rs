use serde_json::json;
use sqlx::postgres::PgPool;
use syva_cp::db::types::{Actor, PolicyInput};
use syva_cp::error::CpError;
use syva_cp::write::team::CreateTeamInput;
use syva_cp::write::zone::CreateZoneInput;
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

async fn seed_team(pool: &PgPool) -> Uuid {
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
    team.id
}

fn sample_policy() -> PolicyInput {
    PolicyInput {
        policy_json: json!({"allowed_zones": []}),
        summary_json: None,
    }
}

#[sqlx::test]
async fn create_zone_writes_all_causal_rows(pool: PgPool) {
    let team_id = seed_team(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    let out = writer
        .create_zone(
            CreateZoneInput {
                team_id,
                name: "api-prod".into(),
                display_name: Some("API Prod".into()),
                policy: sample_policy(),
                selector_json: None,
                metadata_json: None,
            },
            &actor(),
        )
        .await
        .unwrap();

    let ec: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM control_plane_events WHERE resource_id = $1",
    )
    .bind(out.zone.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(ec, 1);

    assert!(out.zone.caused_by_event_id.is_some());
    assert_eq!(out.zone.version, 1);
    assert_eq!(out.zone.status, "active");

    let pc: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies WHERE zone_id = $1")
        .bind(out.zone.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pc, 1);
    assert_eq!(out.policy.version, 1);

    let zc: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM zone_versions WHERE zone_id = $1")
        .bind(out.zone.id)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(zc, 1);

    let audit = sqlx::query(
        "SELECT result, control_plane_event_id FROM audit_log WHERE resource_id = $1",
    )
    .bind(out.zone.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let result: String = sqlx::Row::get(&audit, "result");
    let event_link: Option<Uuid> = sqlx::Row::get(&audit, "control_plane_event_id");
    assert_eq!(result, "success");
    assert_eq!(event_link, out.zone.caused_by_event_id);
}

#[sqlx::test]
async fn create_zone_with_duplicate_name_writes_denial_audit(pool: PgPool) {
    let team_id = seed_team(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    writer
        .create_zone(
            CreateZoneInput {
                team_id,
                name: "api-prod".into(),
                display_name: None,
                policy: sample_policy(),
                selector_json: None,
                metadata_json: None,
            },
            &actor(),
        )
        .await
        .unwrap();

    let err = writer
        .create_zone(
            CreateZoneInput {
                team_id,
                name: "api-prod".into(),
                display_name: None,
                policy: sample_policy(),
                selector_json: None,
                metadata_json: None,
            },
            &actor(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, CpError::Conflict { .. }));

    let audits = sqlx::query(
        "SELECT result, control_plane_event_id FROM audit_log
          WHERE resource_type = 'zone' ORDER BY occurred_at",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(audits.len(), 2);
    let first_result: String = sqlx::Row::get(&audits[0], "result");
    let first_link: Option<Uuid> = sqlx::Row::get(&audits[0], "control_plane_event_id");
    let second_result: String = sqlx::Row::get(&audits[1], "result");
    let second_link: Option<Uuid> = sqlx::Row::get(&audits[1], "control_plane_event_id");
    assert_eq!(first_result, "success");
    assert!(first_link.is_some());
    assert_eq!(second_result, "denied");
    assert!(second_link.is_none(), "denied audit must not link to event");
}

#[sqlx::test]
async fn create_zone_rejects_nonexistent_team(pool: PgPool) {
    let writer = TransactionalWriter::new(&pool);

    let err = writer
        .create_zone(
            CreateZoneInput {
                team_id: Uuid::new_v4(),
                name: "api".into(),
                display_name: None,
                policy: sample_policy(),
                selector_json: None,
                metadata_json: None,
            },
            &actor(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, CpError::NotFound { resource: "team", .. }));

    let audits: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE result = 'denied'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audits, 1);
}
