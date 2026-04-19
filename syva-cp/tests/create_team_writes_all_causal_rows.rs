//! Structural test per ADR 0003.
//!
//! Every mutating operation must ship with a test asserting the full
//! causal write set lands atomically. For CreateTeam that set is:
//!
//! - exactly one `control_plane_events` row
//! - exactly one `teams` row
//! - exactly one `audit_log` row
//! - all three share the event id: `teams.caused_by_event_id` and
//!   `audit_log.control_plane_event_id` both equal
//!   `control_plane_events.id`
//!
//! Plus two negative-path tests:
//!
//! - duplicate name triggers `Conflict`, and neither the event nor the
//!   audit row from the failed attempt is persisted — the transaction
//!   is Rule 1 atomic
//! - append-only triggers reject UPDATE / DELETE on `audit_log` and
//!   `control_plane_events` (ADR 0003 Rule 9)
//!
//! These run with `#[sqlx::test]`, which gives each test its own
//! freshly-migrated database so ordering and state bleed are impossible.

use sqlx::postgres::PgPool;
use sqlx::Row;
use syva_cp::db::types::Actor;
use syva_cp::write::{team::CreateTeamInput, TransactionalWriter};
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

#[sqlx::test]
async fn create_team_writes_all_causal_rows(pool: PgPool) {
    let writer = TransactionalWriter::new(&pool);

    let team = writer
        .create_team(
            CreateTeamInput {
                name: "payments".into(),
                display_name: Some("Payments Team".into()),
            },
            &actor(),
        )
        .await
        .expect("create_team should succeed");

    // 1. Exactly one event for this team.
    let event_count: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM control_plane_events WHERE resource_id = $1",
    )
    .bind(team.id)
    .fetch_one(&pool)
    .await
    .unwrap()
    .get("c");
    assert_eq!(event_count, 1, "exactly one event must be written");

    let event_row = sqlx::query(
        "SELECT id, event_type, resource_type
           FROM control_plane_events WHERE resource_id = $1",
    )
    .bind(team.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let event_id: Uuid = event_row.get("id");
    let event_type: String = event_row.get("event_type");
    let resource_type: String = event_row.get("resource_type");
    assert_eq!(event_type, "team.created");
    assert_eq!(resource_type, "team");

    // 2. Team row references the event, version 1, active.
    assert_eq!(team.caused_by_event_id, Some(event_id));
    assert_eq!(team.version, 1);
    assert_eq!(team.status, "active");

    // 3. Exactly one audit row referencing the same event.
    let audit_count: i64 = sqlx::query(
        "SELECT COUNT(*) AS c FROM audit_log
          WHERE resource_id = $1 AND action = 'team.create'",
    )
    .bind(team.id)
    .fetch_one(&pool)
    .await
    .unwrap()
    .get("c");
    assert_eq!(audit_count, 1, "exactly one audit row per mutation");

    let audit_row = sqlx::query(
        "SELECT control_plane_event_id, result
           FROM audit_log WHERE resource_id = $1",
    )
    .bind(team.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let audit_event_id: Uuid = audit_row.get("control_plane_event_id");
    let audit_result: String = audit_row.get("result");
    assert_eq!(audit_event_id, event_id, "audit points at the same event");
    assert_eq!(audit_result, "success");
}

#[sqlx::test]
async fn create_team_rejects_duplicate_name(pool: PgPool) {
    let writer = TransactionalWriter::new(&pool);

    writer
        .create_team(
            CreateTeamInput {
                name: "payments".into(),
                display_name: None,
            },
            &actor(),
        )
        .await
        .expect("first create should succeed");

    let err = writer
        .create_team(
            CreateTeamInput {
                name: "payments".into(),
                display_name: None,
            },
            &actor(),
        )
        .await
        .expect_err("second create must fail");

    match err {
        syva_cp::error::CpError::Conflict { .. } => {}
        other => panic!("expected Conflict, got {other:?}"),
    }

    // Rule 1: the failed transaction must not leave orphan event rows.
    let event_count: i64 = sqlx::query("SELECT COUNT(*) AS c FROM control_plane_events")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("c");
    assert_eq!(event_count, 1, "only the successful insert writes an event");

    // Rule 8: rejected mutations still emit an audit row outside the
    // rolled-back write transaction.
    let audit_count: i64 = sqlx::query("SELECT COUNT(*) AS c FROM audit_log")
        .fetch_one(&pool)
        .await
        .unwrap()
        .get("c");
    assert_eq!(audit_count, 2, "success + rejected attempt both write audit");

    let rejected_audit = sqlx::query(
        "SELECT result, control_plane_event_id, response_json
           FROM audit_log
          WHERE action = 'team.create'
       ORDER BY occurred_at DESC
          LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let result: String = rejected_audit.get("result");
    let control_plane_event_id: Option<Uuid> = rejected_audit.get("control_plane_event_id");
    let response_json: serde_json::Value = rejected_audit.get("response_json");
    assert_eq!(result, "denied");
    assert!(control_plane_event_id.is_none(), "rejected audit should not point at a rolled-back event");
    assert_eq!(response_json["error"], "team name 'payments' already exists");
}

#[sqlx::test]
async fn audit_log_is_append_only(pool: PgPool) {
    let writer = TransactionalWriter::new(&pool);
    let team = writer
        .create_team(
            CreateTeamInput {
                name: "test".into(),
                display_name: None,
            },
            &actor(),
        )
        .await
        .unwrap();

    let update =
        sqlx::query("UPDATE audit_log SET result = 'failed' WHERE resource_id = $1")
            .bind(team.id)
            .execute(&pool)
            .await;
    assert!(update.is_err(), "audit_log UPDATE must be rejected");

    let delete = sqlx::query("DELETE FROM audit_log WHERE resource_id = $1")
        .bind(team.id)
        .execute(&pool)
        .await;
    assert!(delete.is_err(), "audit_log DELETE must be rejected");
}

#[sqlx::test]
async fn control_plane_events_is_append_only(pool: PgPool) {
    let writer = TransactionalWriter::new(&pool);
    let team = writer
        .create_team(
            CreateTeamInput {
                name: "test".into(),
                display_name: None,
            },
            &actor(),
        )
        .await
        .unwrap();

    let update = sqlx::query(
        "UPDATE control_plane_events SET event_type = 'hacked'
          WHERE resource_id = $1",
    )
    .bind(team.id)
    .execute(&pool)
    .await;
    assert!(
        update.is_err(),
        "control_plane_events UPDATE must be rejected"
    );

    let delete =
        sqlx::query("DELETE FROM control_plane_events WHERE resource_id = $1")
            .bind(team.id)
            .execute(&pool)
            .await;
    assert!(
        delete.is_err(),
        "control_plane_events DELETE must be rejected"
    );
}
