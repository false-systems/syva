use serde_json::json;
use sqlx::postgres::PgPool;
use syva_cp::db::types::{Actor, PolicyInput};
use syva_cp::write::node::RegisterNodeInput;
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

async fn seed_team_with_zone(pool: &PgPool) -> Uuid {
    let writer = TransactionalWriter::new(pool);
    let team = writer
        .create_team(
            CreateTeamInput {
                name: "platform".into(),
                display_name: None,
            },
            &actor(),
        )
        .await
        .unwrap();

    writer
        .create_zone(
            CreateZoneInput {
                team_id: team.id,
                name: "agents".into(),
                display_name: None,
                policy: PolicyInput {
                    policy_json: json!({"allowed_zones": []}),
                    summary_json: None,
                },
                selector_json: Some(json!({"match_labels": {"tier": "prod"}})),
                metadata_json: None,
            },
            &actor(),
        )
        .await
        .unwrap();

    team.id
}

#[sqlx::test]
async fn register_node_writes_all_causal_rows(pool: PgPool) {
    let _team_id = seed_team_with_zone(&pool).await;
    let writer = TransactionalWriter::new(&pool);
    let node_id = Uuid::new_v4();

    let out = writer
        .register_node(
            RegisterNodeInput {
                node_name: "n01".into(),
                fingerprint: Some("fp-01".into()),
                cluster_id: Some("cluster-a".into()),
                labels: [("tier".to_string(), "prod".to_string())]
                    .into_iter()
                    .collect(),
                capabilities_json: json!({"runtime": "linux"}),
                proposed_id: node_id,
            },
            &actor(),
        )
        .await
        .unwrap();

    assert!(out.is_new);
    assert_eq!(out.node.id, node_id);
    assert_eq!(out.assignments_upserted, 1);
    assert_eq!(out.assignments_removed, 0);

    let event_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM control_plane_events WHERE resource_id = $1")
            .bind(node_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(event_count, 1);

    let label_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM node_labels WHERE node_id = $1")
            .bind(node_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(label_count, 1);

    let assignment_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM assignments WHERE node_id = $1")
            .bind(node_id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(assignment_count, 1);

    let assignment_version_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM assignment_versions av
           INNER JOIN assignments a ON a.id = av.assignment_id
           WHERE a.node_id = $1"#,
    )
    .bind(node_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(assignment_version_count, 1);

    let audit = sqlx::query(
        "SELECT result, control_plane_event_id FROM audit_log WHERE resource_id = $1 AND action = 'node.register'",
    )
    .bind(node_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let result: String = sqlx::Row::get(&audit, "result");
    let event_link: Option<Uuid> = sqlx::Row::get(&audit, "control_plane_event_id");
    assert_eq!(result, "success");
    assert_eq!(event_link, out.node.caused_by_event_id);
}
