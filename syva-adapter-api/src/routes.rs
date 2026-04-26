use anyhow::{Context, Result};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;
use syva_core_client::syva_core::{
    ListZonesRequest, RegisterZoneRequest, RemoveZoneRequest, ZonePolicy, ZoneSummary,
};
use syva_cp_client::{CpClient, CpClientConfig, CreateZoneArgs, DeleteZoneArgs, UpdateZoneArgs};
use tracing::warn;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    mode: ClientMode,
}

#[derive(Clone)]
enum ClientMode {
    Cp {
        client: CpClient,
        team_id: Uuid,
    },
    Core {
        client: syva_core_client::SyvaCoreClient,
    },
}

pub struct Config {
    pub listen: SocketAddr,
    pub cp_endpoint: Option<String>,
    pub core_socket: Option<PathBuf>,
    pub team_id: Option<Uuid>,
}

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Deserialize)]
pub struct CreateZoneBody {
    pub name: String,
    pub display_name: Option<String>,
    pub policy_json: JsonValue,
    pub selector_json: Option<JsonValue>,
}

#[derive(Deserialize)]
pub struct UpdateZoneBody {
    pub if_version: i64,
    pub policy_json: Option<JsonValue>,
    pub selector_json: Option<JsonValue>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CorePolicyJson {
    host_paths: Vec<String>,
    allowed_zones: Vec<String>,
    allow_ptrace: bool,
    zone_type: CoreZoneType,
}

impl Default for CorePolicyJson {
    fn default() -> Self {
        Self {
            host_paths: Vec::new(),
            allowed_zones: Vec::new(),
            allow_ptrace: false,
            zone_type: CoreZoneType::Standard,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum CoreZoneType {
    Standard,
    Privileged,
    Isolated,
}

#[derive(Deserialize)]
pub struct ListZonesQuery {
    pub status: Option<String>,
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct CreateZoneOut {
    pub zone_id: String,
    pub policy_id: String,
    pub version: i64,
}

#[derive(Serialize)]
pub struct ZoneOut {
    pub zone_id: String,
    pub team_id: String,
    pub name: String,
    pub display_name: Option<String>,
    pub status: String,
    pub version: i64,
    pub current_policy_id: Option<String>,
    pub current_policy_json: Option<JsonValue>,
    pub selector_json: Option<JsonValue>,
    pub metadata_json: Option<JsonValue>,
}

#[derive(Serialize)]
pub struct HealthOut {
    pub ok: bool,
}

pub async fn serve(config: Config) -> Result<()> {
    let state = match (&config.cp_endpoint, &config.core_socket) {
        (Some(_), Some(_)) => {
            anyhow::bail!("--cp-endpoint and --core-socket are mutually exclusive")
        }
        (None, None) => anyhow::bail!("exactly one of --cp-endpoint or --core-socket is required"),
        (Some(endpoint), None) => {
            let team_id = config
                .team_id
                .context("--team-id is required when using --cp-endpoint")?;
            AppState {
                mode: ClientMode::Cp {
                    client: connect_with_retry(endpoint).await,
                    team_id,
                },
            }
        }
        (None, Some(socket_path)) => AppState {
            mode: ClientMode::Core {
                client: syva_core_client::connect_unix_socket_with_retry(socket_path.clone()).await,
            },
        },
    };
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("bind {}", config.listen))?;
    tracing::info!(listen = %config.listen, "syva-api listening");

    axum::serve(listener, app).await?;
    Ok(())
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/zones", post(create_zone).get(list_zones))
        .route(
            "/v1/zones/{name}",
            get(get_zone).put(update_zone).delete(delete_zone),
        )
        .route("/healthz", get(healthz))
        .with_state(state)
}

async fn connect_with_retry(endpoint: &str) -> CpClient {
    let mut backoff = Duration::from_millis(250);
    let max_backoff = Duration::from_secs(30);

    loop {
        match CpClient::connect(CpClientConfig {
            endpoint: endpoint.to_string(),
            ..Default::default()
        })
        .await
        {
            Ok(client) => return client,
            Err(error) => {
                warn!(
                    endpoint,
                    error = %error,
                    backoff_ms = backoff.as_millis(),
                    "could not connect to syva-cp; retrying"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

pub async fn create_zone(
    State(state): State<AppState>,
    Json(body): Json<CreateZoneBody>,
) -> Result<(StatusCode, Json<CreateZoneOut>), ApiError> {
    match state.mode {
        ClientMode::Cp { client, team_id } => {
            let output = client
                .create_zone(CreateZoneArgs {
                    team_id,
                    name: body.name,
                    display_name: body.display_name,
                    policy_json: body.policy_json,
                    summary_json: None,
                    selector_json: body.selector_json,
                    metadata_json: None,
                })
                .await
                .map_err(ApiError::from_cp)?;

            Ok((
                StatusCode::CREATED,
                Json(CreateZoneOut {
                    zone_id: output.zone_id.to_string(),
                    policy_id: output.policy_id.to_string(),
                    version: output.version,
                }),
            ))
        }
        ClientMode::Core { mut client } => {
            let response = client
                .register_zone(core_register_request(&body.name, body.policy_json)?)
                .await
                .map_err(ApiError::from_core)?
                .into_inner();

            Ok((
                StatusCode::CREATED,
                Json(CreateZoneOut {
                    zone_id: response.zone_id.to_string(),
                    policy_id: String::new(),
                    version: 0,
                }),
            ))
        }
    }
}

pub async fn list_zones(
    State(state): State<AppState>,
    Query(query): Query<ListZonesQuery>,
) -> Result<Json<Vec<ZoneOut>>, ApiError> {
    match state.mode {
        ClientMode::Cp { client, team_id } => {
            let zones = client
                .list_zones(team_id, query.status.as_deref(), query.limit.unwrap_or(100))
                .await
                .map_err(ApiError::from_cp)?;
            Ok(Json(zones.into_iter().map(zone_to_out).collect()))
        }
        ClientMode::Core { mut client } => {
            let mut zones = client
                .list_zones(ListZonesRequest {})
                .await
                .map_err(ApiError::from_core)?
                .into_inner()
                .zones;
            if let Some(status) = query.status {
                zones.retain(|zone| zone.state == status);
            }
            zones.truncate(query.limit.unwrap_or(100).max(0) as usize);
            Ok(Json(zones.into_iter().map(core_zone_to_out).collect()))
        }
    }
}

pub async fn get_zone(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<ZoneOut>, ApiError> {
    match state.mode {
        ClientMode::Cp { client, team_id } => {
            let zone = client
                .get_zone_by_name(team_id, &name)
                .await
                .map_err(ApiError::from_cp)?
                .ok_or_else(|| ApiError::not_found(format!("zone '{name}' not found")))?;
            Ok(Json(zone_to_out(zone)))
        }
        ClientMode::Core { mut client } => {
            let zones = client
                .list_zones(ListZonesRequest {})
                .await
                .map_err(ApiError::from_core)?
                .into_inner()
                .zones;
            let zone = zones
                .into_iter()
                .find(|zone| zone.name == name)
                .ok_or_else(|| ApiError::not_found(format!("zone '{name}' not found")))?;
            Ok(Json(core_zone_to_out(zone)))
        }
    }
}

pub async fn update_zone(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<UpdateZoneBody>,
) -> Result<Json<ZoneOut>, ApiError> {
    match state.mode {
        ClientMode::Cp { client, team_id } => {
            let snapshot = client
                .get_zone_by_name(team_id, &name)
                .await
                .map_err(ApiError::from_cp)?
                .ok_or_else(|| ApiError::not_found(format!("zone '{name}' not found")))?;

            client
                .update_zone(UpdateZoneArgs {
                    zone_id: snapshot.zone_id,
                    if_version: body.if_version,
                    policy_json: body.policy_json,
                    selector_json: body.selector_json,
                    metadata_json: None,
                })
                .await
                .map_err(ApiError::from_cp)?;

            let refreshed = client
                .get_zone_by_name(team_id, &name)
                .await
                .map_err(ApiError::from_cp)?
                .ok_or_else(|| {
                    ApiError::not_found(format!("zone '{name}' not found after update"))
                })?;
            Ok(Json(zone_to_out(refreshed)))
        }
        ClientMode::Core { mut client } => {
            if let Some(policy_json) = body.policy_json {
                client
                    .register_zone(core_register_request(&name, policy_json)?)
                    .await
                    .map_err(ApiError::from_core)?;
            }
            let zones = client
                .list_zones(ListZonesRequest {})
                .await
                .map_err(ApiError::from_core)?
                .into_inner()
                .zones;
            let zone = zones
                .into_iter()
                .find(|zone| zone.name == name)
                .ok_or_else(|| {
                    ApiError::not_found(format!("zone '{name}' not found after update"))
                })?;
            Ok(Json(core_zone_to_out(zone)))
        }
    }
}

pub async fn delete_zone(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    match state.mode {
        ClientMode::Cp { client, team_id } => {
            let snapshot = client
                .get_zone_by_name(team_id, &name)
                .await
                .map_err(ApiError::from_cp)?
                .ok_or_else(|| ApiError::not_found(format!("zone '{name}' not found")))?;

            client
                .delete_zone(DeleteZoneArgs {
                    zone_id: snapshot.zone_id,
                    if_version: snapshot.version,
                    drain: true,
                })
                .await
                .map_err(ApiError::from_cp)?;
            Ok(StatusCode::NO_CONTENT)
        }
        ClientMode::Core { mut client } => {
            client
                .remove_zone(RemoveZoneRequest {
                    zone_name: name,
                    drain: true,
                })
                .await
                .map_err(ApiError::from_core)?;
            Ok(StatusCode::NO_CONTENT)
        }
    }
}

pub async fn healthz() -> Json<HealthOut> {
    Json(HealthOut { ok: true })
}

fn zone_to_out(zone: syva_cp_client::ZoneSnapshot) -> ZoneOut {
    ZoneOut {
        zone_id: zone.zone_id.to_string(),
        team_id: zone.team_id.to_string(),
        name: zone.name,
        display_name: zone.display_name,
        status: zone.status,
        version: zone.version,
        current_policy_id: zone.current_policy_id.map(|id| id.to_string()),
        current_policy_json: zone.current_policy_json,
        selector_json: zone.selector_json,
        metadata_json: zone.metadata_json,
    }
}

fn core_zone_to_out(zone: ZoneSummary) -> ZoneOut {
    ZoneOut {
        zone_id: zone.zone_id.to_string(),
        team_id: String::new(),
        name: zone.name,
        display_name: None,
        status: zone.state,
        version: 0,
        current_policy_id: None,
        current_policy_json: None,
        selector_json: None,
        metadata_json: None,
    }
}

fn core_register_request(
    name: &str,
    policy_json: JsonValue,
) -> Result<RegisterZoneRequest, ApiError> {
    // Local-core mode intentionally accepts only the fields represented by
    // syva.core.v1.ZonePolicy; CP-only request fields are ignored by handlers.
    let policy: CorePolicyJson = serde_json::from_value(policy_json).map_err(|error| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: format!(
            "local-core mode expects policy_json with host_paths, allowed_zones, allow_ptrace, and zone_type only: {error}"
        ),
    })?;

    Ok(RegisterZoneRequest {
        zone_name: name.to_string(),
        policy: Some(ZonePolicy {
            host_paths: policy.host_paths,
            allowed_zones: policy.allowed_zones,
            allow_ptrace: policy.allow_ptrace,
            zone_type: match policy.zone_type {
                CoreZoneType::Privileged => 1,
                CoreZoneType::Standard | CoreZoneType::Isolated => 0,
            },
        }),
    })
}

impl ApiError {
    fn not_found(message: String) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message,
        }
    }

    fn from_cp(error: syva_cp_client::CpClientError) -> Self {
        let status = match &error {
            syva_cp_client::CpClientError::Grpc(grpc) => match grpc.code() {
                tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
                tonic::Code::NotFound => StatusCode::NOT_FOUND,
                tonic::Code::AlreadyExists
                | tonic::Code::FailedPrecondition
                | tonic::Code::Aborted => StatusCode::CONFLICT,
                tonic::Code::Unavailable | tonic::Code::DeadlineExceeded => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                _ => StatusCode::BAD_GATEWAY,
            },
            syva_cp_client::CpClientError::InvalidEndpoint(_)
            | syva_cp_client::CpClientError::Serde(_)
            | syva_cp_client::CpClientError::Internal(_) => StatusCode::BAD_GATEWAY,
            syva_cp_client::CpClientError::Connection(_) => StatusCode::SERVICE_UNAVAILABLE,
            syva_cp_client::CpClientError::NotRegistered => StatusCode::INTERNAL_SERVER_ERROR,
        };

        Self {
            status,
            message: error.to_string(),
        }
    }

    fn from_core(error: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_zone_body_deserializes() {
        let json = r#"{
            "name":"web",
            "display_name":"Web",
            "policy_json":{"host_paths":["/data"]},
            "selector_json":{"all_nodes":true}
        }"#;
        let body: CreateZoneBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.name, "web");
        assert_eq!(body.display_name.as_deref(), Some("Web"));
        assert_eq!(body.policy_json["host_paths"], serde_json::json!(["/data"]));
        assert_eq!(
            body.selector_json.unwrap()["all_nodes"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn update_zone_body_deserializes() {
        let json = r#"{"if_version":7,"policy_json":{"allow_ptrace":true}}"#;
        let body: UpdateZoneBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.if_version, 7);
        assert_eq!(
            body.policy_json.unwrap()["allow_ptrace"],
            serde_json::json!(true)
        );
    }

    #[test]
    fn core_register_request_maps_narrow_local_policy_json() {
        let request = core_register_request(
            "web",
            serde_json::json!({
                "host_paths": ["/data"],
                "allowed_zones": ["db"],
                "allow_ptrace": true,
                "zone_type": "privileged"
            }),
        )
        .expect("request");

        let policy = request.policy.expect("policy");
        assert_eq!(request.zone_name, "web");
        assert_eq!(policy.host_paths, vec!["/data"]);
        assert_eq!(policy.allowed_zones, vec!["db"]);
        assert!(policy.allow_ptrace);
        assert_eq!(policy.zone_type, 1);
    }

    #[test]
    fn core_register_request_rejects_cp_only_policy_json_fields() {
        let error = core_register_request(
            "web",
            serde_json::json!({
                "host_paths": [],
                "selector_json": {"all_nodes": true}
            }),
        )
        .expect_err("unknown fields should be rejected in local mode");

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }
}
