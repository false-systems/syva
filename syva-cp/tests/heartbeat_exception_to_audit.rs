use serde_json::json;
use sqlx::postgres::PgPool;
use syva_cp::db::types::Actor;
use syva_cp::write::node::{HeartbeatInput, RegisterNodeInput};
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

async fn seed_node(pool: &PgPool) -> Uuid {
    let writer = TransactionalWriter::new(pool);
    writer
        .register_node(
            RegisterNodeInput {
                node_name: "n01".into(),
                fingerprint: Some("fp-01".into()),
                cluster_id: None,
                labels: Default::default(),
                capabilities_json: json!({}),
                proposed_id: Uuid::new_v4(),
            },
            &actor(),
        )
        .await
        .unwrap()
        .node
        .id
}

#[sqlx::test]
async fn heartbeat_exception_to_audit(pool: PgPool) {
    let node_id = seed_node(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    let before_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM control_plane_events WHERE resource_id = $1",
    )
    .bind(node_id)
    .fetch_one(&pool)
    .await
    .unwrap();

    writer
        .heartbeat_node(
            HeartbeatInput {
                node_id,
                status_hint: Some("online".into()),
            },
            &actor(),
        )
        .await
        .unwrap();

    let after_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM control_plane_events WHERE resource_id = $1",
    )
    .bind(node_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(after_events, before_events + 1);

    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'node.heartbeat' AND resource_id = $1",
    )
    .bind(node_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 0);

    let last_seen = sqlx::query("SELECT last_seen_at, last_heartbeat_event_id FROM nodes WHERE id = $1")
        .bind(node_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let last_seen_at: Option<chrono::DateTime<chrono::Utc>> = sqlx::Row::get(&last_seen, "last_seen_at");
    let heartbeat_event_id: Option<Uuid> = sqlx::Row::get(&last_seen, "last_heartbeat_event_id");
    assert!(last_seen_at.is_some());
    assert!(heartbeat_event_id.is_some());
}
