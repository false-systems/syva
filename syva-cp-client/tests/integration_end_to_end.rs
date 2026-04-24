use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use sqlx::Connection;
use syva_cp::config::Config as CpConfig;
use syva_cp_client::{AppliedReport, CpClient, CpClientConfig};
use syva_proto::syva_control::v1::assignment_service_client::AssignmentServiceClient;
use syva_proto::syva_control::v1::team_service_client::TeamServiceClient;
use syva_proto::syva_control::v1::zone_service_client::ZoneServiceClient;
use syva_proto::syva_control::v1::{
    node_assignment_update::Kind as UpdateKind, CreateTeamRequest, CreateZoneRequest,
    ListAssignmentsRequest,
};
use tempfile::TempDir;
use tokio::net::TcpListener;
use uuid::Uuid;

async fn free_local_addr() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral listener");
    let addr = listener.local_addr().expect("read local addr");
    drop(listener);
    addr
}

async fn wait_for_grpc(endpoint: &str) {
    let target = endpoint.trim_start_matches("http://");

    for _ in 0..50 {
        if tokio::net::TcpStream::connect(target).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("timed out waiting for syva-cp at {endpoint}");
}

fn split_database_url(database_url: &str) -> (&str, &str, String) {
    let (prefix, database_and_suffix) = database_url
        .rsplit_once('/')
        .expect("database url must contain a database name");
    match database_and_suffix.split_once('?') {
        Some((database_name, query)) => (prefix, database_name, format!("?{query}")),
        None => (prefix, database_and_suffix, String::new()),
    }
}

fn replace_database_name(database_url: &str, database_name: &str) -> String {
    let (prefix, _, suffix) = split_database_url(database_url);
    format!("{prefix}/{database_name}{suffix}")
}

async fn create_isolated_database(base_database_url: &str) -> (String, String) {
    let isolated_name = format!("syva_cp_client_{}", Uuid::new_v4().simple());
    let admin_url = replace_database_name(base_database_url, "postgres");

    let mut connection = sqlx::PgConnection::connect(&admin_url)
        .await
        .expect("connect postgres admin database");
    sqlx::query(&format!("CREATE DATABASE {isolated_name}"))
        .execute(&mut connection)
        .await
        .expect("create isolated database");

    (
        replace_database_name(base_database_url, &isolated_name),
        isolated_name,
    )
}

async fn drop_isolated_database(base_database_url: &str, isolated_name: &str) {
    let admin_url = replace_database_name(base_database_url, "postgres");
    let mut connection = match sqlx::PgConnection::connect(&admin_url).await {
        Ok(connection) => connection,
        Err(_) => return,
    };

    let terminate = format!(
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{isolated_name}'"
    );
    let _ = sqlx::query(&terminate).execute(&mut connection).await;
    let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS {isolated_name}"))
        .execute(&mut connection)
        .await;
}

#[tokio::test]
#[ignore = "requires postgres; run with --ignored"]
async fn end_to_end_register_subscribe_report() {
    let base_database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let (database_url, isolated_name) = create_isolated_database(&base_database_url).await;
    let grpc_addr = free_local_addr().await;
    let health_addr = free_local_addr().await;
    let endpoint = format!("http://{grpc_addr}");

    let cp_handle = tokio::spawn(async move {
        syva_cp::run(CpConfig {
            database_url,
            grpc_addr,
            health_addr,
            db_max_connections: 16,
            db_timeout_secs: 5,
        })
        .await
    });

    wait_for_grpc(&endpoint).await;

    let test_result = async {
        let tmp = TempDir::new().expect("tempdir");
        let node_id_path = tmp.path().join("node-id");

        let suffix = Uuid::new_v4().simple().to_string();
        let mut labels = BTreeMap::new();
        labels.insert("session".to_string(), suffix.clone());
        let node_name = format!("test-node-{suffix}");
        let fingerprint = format!("fingerprint-{suffix}");

        let cp = CpClient::connect(CpClientConfig {
            endpoint: endpoint.clone(),
            node_name,
            fingerprint: Some(fingerprint),
            labels,
            node_id_path,
            heartbeat_interval: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(2),
            ..Default::default()
        })
        .await?;

        let registration = cp.register().await?;
        assert_ne!(registration.node_id, Uuid::nil());

        cp.heartbeat("online").await?;

        let mut stream = cp.subscribe_assignments().await?;
        let first = tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("subscribe timeout")?
            .expect("stream closed");
        assert_eq!(first.kind, UpdateKind::FullSnapshot as i32);

        let team_name = format!("platform-{suffix}");
        let zone_name = format!("agents-{suffix}");

        let mut team_client = TeamServiceClient::connect(endpoint.clone()).await?;
        let team = team_client
            .create_team(CreateTeamRequest {
                name: team_name,
                display_name: "Platform".to_string(),
            })
            .await?
            .into_inner()
            .team
            .expect("team response");

        let mut zone_client = ZoneServiceClient::connect(endpoint.clone()).await?;
        let create_zone = zone_client
            .create_zone(CreateZoneRequest {
                team_id: team.id.clone(),
                name: zone_name.clone(),
                display_name: "Agents".to_string(),
                policy_json: "{\"allowed_zones\":[]}".to_string(),
                summary_json: String::new(),
                selector_json: format!("{{\"match_labels\":{{\"session\":\"{suffix}\"}}}}"),
                metadata_json: String::new(),
            })
            .await?
            .into_inner();
        let created_zone = create_zone.zone.expect("zone response");
        assert_eq!(created_zone.name, zone_name);

        let update = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let Some(message) = stream.message().await.expect("stream error") else {
                    panic!("assignment stream closed");
                };
                if message.kind == UpdateKind::Upsert as i32 {
                    break message;
                }
            }
        })
        .await
        .expect("waiting for upsert");

        assert_eq!(update.assignments.len(), 1);
        let assignment = &update.assignments[0];
        assert_eq!(assignment.zone_name, zone_name);

        let (accepted, rejected) = cp
            .report_assignment_state(
                vec![AppliedReport {
                    assignment_id: Uuid::from_str(&assignment.assignment_id)
                        .expect("assignment uuid"),
                    actual_zone_version: assignment.desired_zone_version,
                    actual_policy_id: Uuid::from_str(&assignment.desired_policy_id)
                        .expect("policy uuid"),
                }],
                Vec::new(),
            )
            .await?;
        assert_eq!(accepted, 1);
        assert_eq!(rejected, 0);

        let mut assignment_client = AssignmentServiceClient::connect(endpoint.clone()).await?;
        let list = assignment_client
            .list_assignments(ListAssignmentsRequest {
                zone_id: String::new(),
                node_id: registration.node_id.to_string(),
                status: String::new(),
                limit: 10,
            })
            .await?
            .into_inner();

        assert_eq!(list.assignments.len(), 1);
        let reported = &list.assignments[0];
        assert_eq!(reported.status, "applied");
        assert_eq!(reported.actual_policy_id, assignment.desired_policy_id);
        assert_eq!(reported.actual_zone_version, assignment.desired_zone_version);

        Ok::<(), anyhow::Error>(())
    }
    .await;

    cp_handle.abort();
    let _ = cp_handle.await;
    drop_isolated_database(&base_database_url, &isolated_name).await;

    test_result.expect("end-to-end assertion failure");
}
