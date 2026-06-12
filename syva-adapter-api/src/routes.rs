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
use syva_core_client::syva_core::{
    ListZonesRequest, RegisterZoneRequest, RemoveZoneRequest, ZonePolicy, ZoneSummary,
};

#[derive(Clone)]
pub struct AppState {
    client: syva_core_client::SyvaCoreClient,
}

pub struct Config {
    pub listen: SocketAddr,
    pub core_socket: PathBuf,
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
    pub policy_json: JsonValue,
}

#[derive(Deserialize)]
pub struct UpdateZoneBody {
    pub policy_json: Option<JsonValue>,
}

#[derive(Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CorePolicyJson {
    host_paths: Vec<String>,
    allow_ptrace: bool,
    zone_type: CoreZoneType,
}

impl Default for CorePolicyJson {
    fn default() -> Self {
        Self {
            host_paths: Vec::new(),
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
    let state = AppState {
        client: syva_core_client::connect_unix_socket_with_retry(config.core_socket.clone()).await,
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

pub async fn create_zone(
    State(state): State<AppState>,
    Json(body): Json<CreateZoneBody>,
) -> Result<(StatusCode, Json<CreateZoneOut>), ApiError> {
    let mut client = state.client;
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

pub async fn list_zones(
    State(state): State<AppState>,
    Query(query): Query<ListZonesQuery>,
) -> Result<Json<Vec<ZoneOut>>, ApiError> {
    let mut client = state.client;
    let mut zones = client
        .list_zones(ListZonesRequest {})
        .await
        .map_err(ApiError::from_core)?
        .into_inner()
        .zones;
    if let Some(status) = query.status {
        zones.retain(|zone| zone.state == status);
    }
    let limit = query.limit.unwrap_or(100).max(0);
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    zones.truncate(limit);
    Ok(Json(zones.into_iter().map(core_zone_to_out).collect()))
}

pub async fn get_zone(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<ZoneOut>, ApiError> {
    let mut client = state.client;
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

pub async fn update_zone(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<UpdateZoneBody>,
) -> Result<Json<ZoneOut>, ApiError> {
    let mut client = state.client;
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
        .ok_or_else(|| ApiError::not_found(format!("zone '{name}' not found after update")))?;
    Ok(Json(core_zone_to_out(zone)))
}

pub async fn delete_zone(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let mut client = state.client;
    client
        .remove_zone(RemoveZoneRequest {
            zone_name: name,
            drain: true,
        })
        .await
        .map_err(ApiError::from_core)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn healthz() -> Json<HealthOut> {
    Json(HealthOut { ok: true })
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
    // Local-core API calls have no global policy view, so cross-zone comms must
    // come from reconciling adapters that can derive mutual allow pairs.
    let policy: CorePolicyJson = serde_json::from_value(policy_json).map_err(|error| ApiError {
        status: StatusCode::BAD_REQUEST,
        message: format!(
            "local-core mode expects policy_json with host_paths, allow_ptrace, and zone_type only: {error}"
        ),
    })?;

    Ok(RegisterZoneRequest {
        zone_name: name.to_string(),
        policy: Some(ZonePolicy {
            host_paths: policy.host_paths,
            allowed_zones: Vec::new(),
            allow_ptrace: policy.allow_ptrace,
            zone_type: match policy.zone_type {
                CoreZoneType::Privileged => 1,
                CoreZoneType::Standard | CoreZoneType::Isolated => 0,
            },
            // The partial REST surface does not expose the network mode; zones
            // registered through it default to ISOLATED (network-locked).
            network_mode: 0,
            allowed_egress_cidrs: Vec::new(),
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
            "policy_json":{"host_paths":["/data"]}
        }"#;
        let body: CreateZoneBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.name, "web");
        assert_eq!(body.policy_json["host_paths"], serde_json::json!(["/data"]));
    }

    #[test]
    fn update_zone_body_deserializes() {
        let json = r#"{"policy_json":{"allow_ptrace":true}}"#;
        let body: UpdateZoneBody = serde_json::from_str(json).unwrap();
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
                "allow_ptrace": true,
                "zone_type": "privileged"
            }),
        )
        .expect("request");

        let policy = request.policy.expect("policy");
        assert_eq!(request.zone_name, "web");
        assert_eq!(policy.host_paths, vec!["/data"]);
        assert!(policy.allowed_zones.is_empty());
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

    #[test]
    fn core_register_request_rejects_allowed_zones_without_global_reconcile() {
        let error = core_register_request(
            "web",
            serde_json::json!({
                "host_paths": [],
                "allowed_zones": ["db"]
            }),
        )
        .expect_err("API local mode should not accept comm policy");

        assert_eq!(error.status, StatusCode::BAD_REQUEST);
    }
}
