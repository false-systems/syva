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
use std::time::Duration;
use syva_cp_client::{CpClient, CpClientConfig, CreateZoneArgs, DeleteZoneArgs, UpdateZoneArgs};
use tracing::warn;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    cp: CpClient,
    team_id: Uuid,
}

pub struct Config {
    pub listen: SocketAddr,
    pub cp_endpoint: String,
    pub team_id: Uuid,
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
    let cp = connect_with_retry(&config.cp_endpoint).await;
    let app = router(AppState {
        cp,
        team_id: config.team_id,
    });

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
        .route("/v1/zones/{name}", get(get_zone).put(update_zone).delete(delete_zone))
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
    let output = state
        .cp
        .create_zone(CreateZoneArgs {
            team_id: state.team_id,
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

pub async fn list_zones(
    State(state): State<AppState>,
    Query(query): Query<ListZonesQuery>,
) -> Result<Json<Vec<ZoneOut>>, ApiError> {
    let zones = state
        .cp
        .list_zones(
            state.team_id,
            query.status.as_deref(),
            query.limit.unwrap_or(100),
        )
        .await
        .map_err(ApiError::from_cp)?;

    Ok(Json(zones.into_iter().map(zone_to_out).collect()))
}

pub async fn get_zone(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<ZoneOut>, ApiError> {
    let zone = state
        .cp
        .get_zone_by_name(state.team_id, &name)
        .await
        .map_err(ApiError::from_cp)?
        .ok_or_else(|| ApiError::not_found(format!("zone '{name}' not found")))?;

    Ok(Json(zone_to_out(zone)))
}

pub async fn update_zone(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Json(body): Json<UpdateZoneBody>,
) -> Result<Json<ZoneOut>, ApiError> {
    let snapshot = state
        .cp
        .get_zone_by_name(state.team_id, &name)
        .await
        .map_err(ApiError::from_cp)?
        .ok_or_else(|| ApiError::not_found(format!("zone '{name}' not found")))?;

    state
        .cp
        .update_zone(UpdateZoneArgs {
            zone_id: snapshot.zone_id,
            if_version: body.if_version,
            policy_json: body.policy_json,
            selector_json: body.selector_json,
            metadata_json: None,
        })
        .await
        .map_err(ApiError::from_cp)?;

    let refreshed = state
        .cp
        .get_zone_by_name(state.team_id, &name)
        .await
        .map_err(ApiError::from_cp)?
        .ok_or_else(|| ApiError::not_found(format!("zone '{name}' not found after update")))?;

    Ok(Json(zone_to_out(refreshed)))
}

pub async fn delete_zone(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let snapshot = state
        .cp
        .get_zone_by_name(state.team_id, &name)
        .await
        .map_err(ApiError::from_cp)?
        .ok_or_else(|| ApiError::not_found(format!("zone '{name}' not found")))?;

    state
        .cp
        .delete_zone(DeleteZoneArgs {
            zone_id: snapshot.zone_id,
            if_version: snapshot.version,
            drain: true,
        })
        .await
        .map_err(ApiError::from_cp)?;

    Ok(StatusCode::NO_CONTENT)
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

impl ApiError {
    fn not_found(message: String) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message,
        }
    }

    fn from_cp(error: syva_cp_client::CpClientError) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(ErrorBody { error: self.message })).into_response()
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
        assert_eq!(body.selector_json.unwrap()["all_nodes"], serde_json::json!(true));
    }

    #[test]
    fn update_zone_body_deserializes() {
        let json = r#"{"if_version":7,"policy_json":{"allow_ptrace":true}}"#;
        let body: UpdateZoneBody = serde_json::from_str(json).unwrap();
        assert_eq!(body.if_version, 7);
        assert_eq!(body.policy_json.unwrap()["allow_ptrace"], serde_json::json!(true));
    }
}
