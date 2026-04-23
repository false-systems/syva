use serde_json::json;
use sqlx::postgres::PgPool;
use syva_cp::db::types::{Actor, PolicyInput};
use syva_cp::error::CpError;
use syva_cp::write::node::{RegisterNodeInput, SetNodeLabelsInput};
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

async fn seed_node_and_zone(pool: &PgPool) -> (Uuid, i64) {
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

    let node = writer
        .register_node(
            RegisterNodeInput {
                node_name: "n01".into(),
                fingerprint: Some("fp-01".into()),
                cluster_id: None,
                labels: [("tier".to_string(), "dev".to_string())]
                    .into_iter()
                    .collect(),
                capabilities_json: json!({}),
                proposed_id: Uuid::new_v4(),
            },
            &actor(),
        )
        .await
        .unwrap();

    (node.node.id, node.node.version)
}

#[sqlx::test]
async fn set_node_labels_recomputes_assignments(pool: PgPool) {
    let (node_id, version) = seed_node_and_zone(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    let out = writer
        .set_node_labels(
            SetNodeLabelsInput {
                node_id,
                if_version: version,
                labels: [("tier".to_string(), "prod".to_string())]
                    .into_iter()
                    .collect(),
            },
            &actor(),
        )
        .await
        .unwrap();

    assert_eq!(out.assignments_upserted, 1);
    assert_eq!(out.assignments_removed, 0);
    assert_eq!(out.node.version, version + 1);

    let desired_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assignments WHERE node_id = $1 AND status = 'desired'",
    )
    .bind(node_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(desired_count, 1);

    let out = writer
        .set_node_labels(
            SetNodeLabelsInput {
                node_id,
                if_version: out.node.version,
                labels: [("tier".to_string(), "dev".to_string())]
                    .into_iter()
                    .collect(),
            },
            &actor(),
        )
        .await
        .unwrap();

    assert_eq!(out.assignments_upserted, 0);
    assert_eq!(out.assignments_removed, 1);

    let removing_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assignments WHERE node_id = $1 AND status = 'removing'",
    )
    .bind(node_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(removing_count, 1);

    let versions: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM assignment_versions av
           INNER JOIN assignments a ON a.id = av.assignment_id
           WHERE a.node_id = $1"#,
    )
    .bind(node_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(versions, 2);
}

#[sqlx::test]
async fn set_node_labels_with_stale_version_returns_conflict(pool: PgPool) {
    let (node_id, version) = seed_node_and_zone(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    let err = match writer
        .set_node_labels(
            SetNodeLabelsInput {
                node_id,
                if_version: version + 99,
                labels: [("tier".to_string(), "prod".to_string())]
                    .into_iter()
                    .collect(),
            },
            &actor(),
        )
        .await
    {
        Ok(_) => panic!("expected stale version conflict"),
        Err(err) => err,
    };

    assert!(matches!(err, CpError::VersionConflict { .. }));

    let audit = sqlx::query(
        "SELECT result, control_plane_event_id FROM audit_log WHERE action = 'node.set_labels' ORDER BY occurred_at DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let result: String = sqlx::Row::get(&audit, "result");
    let event_link: Option<Uuid> = sqlx::Row::get(&audit, "control_plane_event_id");
    assert_eq!(result, "denied");
    assert!(event_link.is_none());
}
