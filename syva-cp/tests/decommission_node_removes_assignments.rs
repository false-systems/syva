use serde_json::json;
use sqlx::postgres::PgPool;
use syva_cp::db::types::{Actor, PolicyInput};
use syva_cp::error::CpError;
use syva_cp::write::node::{DecommissionNodeInput, RegisterNodeInput};
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

async fn seed_node_with_assignments(pool: &PgPool) -> (Uuid, i64) {
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

    for zone_name in ["agents-a", "agents-b"] {
        writer
            .create_zone(
                CreateZoneInput {
                    team_id: team.id,
                    name: zone_name.into(),
                    display_name: None,
                    policy: PolicyInput {
                        policy_json: json!({"allowed_zones": []}),
                        summary_json: None,
                    },
                    selector_json: Some(json!({"all_nodes": true})),
                    metadata_json: None,
                },
                &actor(),
            )
            .await
            .unwrap();
    }

    let node = writer
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
        .unwrap();

    (node.node.id, node.node.version)
}

#[sqlx::test]
async fn decommission_node_removes_assignments(pool: PgPool) {
    let (node_id, version) = seed_node_with_assignments(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    let node = writer
        .decommission_node(
            DecommissionNodeInput {
                node_id,
                if_version: version,
            },
            &actor(),
        )
        .await
        .unwrap();

    assert_eq!(node.status, "decommissioned");
    assert_eq!(node.version, version + 1);

    let removing_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assignments WHERE node_id = $1 AND status = 'removing'",
    )
    .bind(node_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(removing_count, 2);

    let version_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM assignment_versions av
           INNER JOIN assignments a ON a.id = av.assignment_id
           WHERE a.node_id = $1"#,
    )
    .bind(node_id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(version_count, 4);

    let audit = sqlx::query(
        "SELECT result, control_plane_event_id FROM audit_log WHERE action = 'node.decommission' ORDER BY occurred_at DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let result: String = sqlx::Row::get(&audit, "result");
    let event_link: Option<Uuid> = sqlx::Row::get(&audit, "control_plane_event_id");
    assert_eq!(result, "success");
    assert_eq!(event_link, node.caused_by_event_id);
}

#[sqlx::test]
async fn decommission_node_with_stale_version_returns_conflict(pool: PgPool) {
    let (node_id, version) = seed_node_with_assignments(&pool).await;
    let writer = TransactionalWriter::new(&pool);

    let err = writer
        .decommission_node(
            DecommissionNodeInput {
                node_id,
                if_version: version + 99,
            },
            &actor(),
        )
        .await
        .unwrap_err();

    assert!(matches!(err, CpError::VersionConflict { .. }));

    let audit = sqlx::query(
        "SELECT result, control_plane_event_id FROM audit_log WHERE action = 'node.decommission' ORDER BY occurred_at DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let result: String = sqlx::Row::get(&audit, "result");
    let event_link: Option<Uuid> = sqlx::Row::get(&audit, "control_plane_event_id");
    assert_eq!(result, "denied");
    assert!(event_link.is_none());
}
