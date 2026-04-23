use serde_json::json;
use sqlx::postgres::PgPool;
use syva_cp::db::types::{Actor, PolicyInput};
use syva_cp::write::node::{DecommissionNodeInput, RegisterNodeInput};
use syva_cp::write::team::CreateTeamInput;
use syva_cp::write::zone::{CreateZoneInput, DeleteZoneInput, UpdateZoneInput};
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

struct SeededNode {
    id: Uuid,
    version: i64,
    name: &'static str,
}

async fn register_node(
    pool: &PgPool,
    name: &'static str,
    labels: &[(&str, &str)],
) -> SeededNode {
    let writer = TransactionalWriter::new(pool);
    let node = writer
        .register_node(
            RegisterNodeInput {
                node_name: name.into(),
                fingerprint: Some(format!("fp-{name}")),
                cluster_id: None,
                labels: labels
                    .iter()
                    .map(|(key, value)| (key.to_string(), value.to_string()))
                    .collect(),
                capabilities_json: json!({}),
                proposed_id: Uuid::new_v4(),
            },
            &actor(),
        )
        .await
        .unwrap();

    SeededNode {
        id: node.node.id,
        version: node.node.version,
        name,
    }
}

#[sqlx::test]
async fn zone_write_recomputes_assignments(pool: PgPool) {
    let writer = TransactionalWriter::new(&pool);
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

    let n1 = register_node(&pool, "n1", &[("tier", "prod"), ("region", "eu")]).await;
    let n2 = register_node(&pool, "n2", &[("tier", "prod"), ("region", "us")]).await;
    let n3 = register_node(&pool, "n3", &[("tier", "dev"), ("region", "eu")]).await;
    let n4 = register_node(&pool, "n4", &[("tier", "dev"), ("region", "us")]).await;
    let n5 = register_node(&pool, "n5", &[("tier", "dev"), ("region", "eu")]).await;

    let zone1 = writer
        .create_zone(
            CreateZoneInput {
                team_id: team.id,
                name: "all-nodes".into(),
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

    let zone1_assignment_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM assignments WHERE zone_id = $1")
            .bind(zone1.zone.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(zone1_assignment_count, 5);

    let zone1 = writer
        .update_zone(
            UpdateZoneInput {
                zone_id: zone1.zone.id,
                if_version: zone1.zone.version,
                policy: None,
                selector_json: Some(json!({"match_labels": {"tier": "prod"}})),
                metadata_json: None,
            },
            &actor(),
        )
        .await
        .unwrap();

    let zone1_desired_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assignments WHERE zone_id = $1 AND status = 'desired'",
    )
    .bind(zone1.zone.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    let zone1_removing_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assignments WHERE zone_id = $1 AND status = 'removing'",
    )
    .bind(zone1.zone.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(zone1_desired_count, 2);
    assert_eq!(zone1_removing_count, 3);

    let zone2 = writer
        .create_zone(
            CreateZoneInput {
                team_id: team.id,
                name: "named".into(),
                display_name: None,
                policy: PolicyInput {
                    policy_json: json!({"allowed_zones": ["db"]}),
                    summary_json: None,
                },
                selector_json: Some(json!({"node_names": [n1.name, n3.name]})),
                metadata_json: None,
            },
            &actor(),
        )
        .await
        .unwrap();

    let zone2_assignment_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM assignments WHERE zone_id = $1")
            .bind(zone2.zone.id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(zone2_assignment_count, 2);

    let zone2 = writer
        .delete_zone(
            DeleteZoneInput {
                zone_id: zone2.zone.id,
                if_version: zone2.zone.version,
                drain: true,
            },
            &actor(),
        )
        .await
        .unwrap();
    assert_eq!(zone2.status, "draining");

    let zone2_removing_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assignments WHERE zone_id = $1 AND status = 'removing'",
    )
    .bind(zone2.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(zone2_removing_count, 2);

    let zone1 = writer
        .delete_zone(
            DeleteZoneInput {
                zone_id: zone1.zone.id,
                if_version: zone1.zone.version,
                drain: false,
            },
            &actor(),
        )
        .await
        .unwrap();
    assert_eq!(zone1.status, "deleted");

    let zone1_after_delete: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assignments WHERE zone_id = $1 AND status = 'removing'",
    )
    .bind(zone1.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(zone1_after_delete, 5);

    let zone3 = writer
        .create_zone(
            CreateZoneInput {
                team_id: team.id,
                name: "survivors".into(),
                display_name: None,
                policy: PolicyInput {
                    policy_json: json!({"allowed_zones": ["cache"]}),
                    summary_json: None,
                },
                selector_json: Some(json!({"all_nodes": true})),
                metadata_json: None,
            },
            &actor(),
        )
        .await
        .unwrap();

    let zone3_assignment_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assignments WHERE zone_id = $1 AND status = 'desired'",
    )
    .bind(zone3.zone.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(zone3_assignment_count, 5);

    let node = writer
        .decommission_node(
            DecommissionNodeInput {
                node_id: n1.id,
                if_version: n1.version,
            },
            &actor(),
        )
        .await
        .unwrap();
    assert_eq!(node.status, "decommissioned");

    let n1_active_assignments: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assignments WHERE node_id = $1 AND status = 'desired'",
    )
    .bind(n1.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(n1_active_assignments, 0);

    let n1_removing_assignments: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assignments WHERE node_id = $1 AND status = 'removing'",
    )
    .bind(n1.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(n1_removing_assignments >= 3);

    let assignment_versions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM assignment_versions")
            .fetch_one(&pool)
            .await
            .unwrap();
    let assignments: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM assignments")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(assignment_versions >= assignments);

    let orphan_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*)
           FROM assignments a
           LEFT JOIN zones z ON z.id = a.zone_id
           LEFT JOIN nodes n ON n.id = a.node_id
           WHERE z.id IS NULL OR n.id IS NULL"#,
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(orphan_count, 0);

    let event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_plane_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(event_count >= 10);

    let surviving_zone3_assignments: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM assignments WHERE zone_id = $1 AND status = 'desired'",
    )
    .bind(zone3.zone.id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(surviving_zone3_assignments, 4);

    let _ = (n2, n3, n4, n5);
}
