//! REST API route handlers that proxy to syva-core gRPC.

use std::convert::Infallible;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{
        sse::{Event, KeepAlive},
        IntoResponse, Response, Sse,
    },
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::*;
use tokio::sync::Mutex;
use tokio_stream::StreamExt;
use tonic::transport::Channel;

pub type SharedClient = Arc<Mutex<SyvaCoreClient<Channel>>>;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
pub struct RegisterZoneBody {
    pub zone_name: String,
    pub policy: PolicyBody,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PolicyBody {
    #[serde(default)]
    pub host_paths: Vec<String>,
    #[serde(default)]
    pub allowed_zones: Vec<String>,
    #[serde(default)]
    pub allow_ptrace: bool,
}

#[derive(Debug, Serialize)]
pub struct ZoneIdResponse {
    pub zone_id: u32,
}

#[derive(Debug, Serialize)]
pub struct OkResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RemoveZoneQuery {
    #[serde(default)]
    pub drain: bool,
}

#[derive(Debug, Deserialize)]
pub struct AttachContainerBody {
    pub container_id: String,
    pub cgroup_id: u64,
}

#[derive(Debug, Deserialize)]
pub struct AllowCommBody {
    pub peer_zone: String,
}

#[derive(Debug, Serialize)]
pub struct StatusJson {
    pub attached: bool,
    pub zones_active: u32,
    pub containers_active: u32,
    pub uptime_secs: u64,
    pub hooks: Vec<HookStatusJson>,
}

#[derive(Debug, Serialize)]
pub struct HookStatusJson {
    pub hook: String,
    pub allow: u64,
    pub deny: u64,
    pub error: u64,
    pub lost: u64,
}

#[derive(Debug, Deserialize)]
pub struct WatchEventsQuery {
    #[serde(default)]
    pub follow: bool,
}

#[derive(Debug, Serialize)]
pub struct DenyEventJson {
    pub timestamp_ns: u64,
    pub hook: String,
    pub zone_id: u32,
    pub target_zone_id: u32,
    pub pid: u32,
    pub comm: String,
    pub inode: u64,
    pub context: String,
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn router(client: SharedClient) -> Router {
    Router::new()
        .route("/zones", post(register_zone))
        .route("/zones/{name}", delete(remove_zone))
        .route("/zones/{name}/containers", post(attach_container))
        .route("/containers/{id}", delete(detach_container))
        .route("/zones/{name}/comms", post(allow_comm))
        .route("/status", get(status))
        .route("/events", get(watch_events))
        .with_state(client)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn register_zone(
    State(client): State<SharedClient>,
    Json(body): Json<RegisterZoneBody>,
) -> Response {
    let policy = ZonePolicy {
        host_paths: body.policy.host_paths,
        allowed_zones: body.policy.allowed_zones,
        allow_ptrace: body.policy.allow_ptrace,
        zone_type: ZoneType::Standard.into(),
    };

    let req = RegisterZoneRequest {
        zone_name: body.zone_name,
        policy: Some(policy),
    };

    let mut c = client.lock().await;
    match c.register_zone(req).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            (
                StatusCode::CREATED,
                Json(ZoneIdResponse {
                    zone_id: inner.zone_id,
                }),
            )
                .into_response()
        }
        Err(e) => grpc_error_to_response(e),
    }
}

async fn remove_zone(
    State(client): State<SharedClient>,
    Path(name): Path<String>,
    Query(q): Query<RemoveZoneQuery>,
) -> Response {
    let req = RemoveZoneRequest {
        zone_name: name,
        drain: q.drain,
    };

    let mut c = client.lock().await;
    match c.remove_zone(req).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            Json(OkResponse {
                ok: inner.ok,
                message: if inner.message.is_empty() {
                    None
                } else {
                    Some(inner.message)
                },
            })
            .into_response()
        }
        Err(e) => grpc_error_to_response(e),
    }
}

async fn attach_container(
    State(client): State<SharedClient>,
    Path(name): Path<String>,
    Json(body): Json<AttachContainerBody>,
) -> Response {
    let req = AttachContainerRequest {
        container_id: body.container_id,
        zone_name: name,
        cgroup_id: body.cgroup_id,
    };

    let mut c = client.lock().await;
    match c.attach_container(req).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            (
                StatusCode::CREATED,
                Json(OkResponse {
                    ok: inner.ok,
                    message: if inner.message.is_empty() {
                        None
                    } else {
                        Some(inner.message)
                    },
                }),
            )
                .into_response()
        }
        Err(e) => grpc_error_to_response(e),
    }
}

async fn detach_container(
    State(client): State<SharedClient>,
    Path(id): Path<String>,
) -> Response {
    let req = DetachContainerRequest { container_id: id };

    let mut c = client.lock().await;
    match c.detach_container(req).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            Json(OkResponse {
                ok: inner.ok,
                message: None,
            })
            .into_response()
        }
        Err(e) => grpc_error_to_response(e),
    }
}

async fn allow_comm(
    State(client): State<SharedClient>,
    Path(name): Path<String>,
    Json(body): Json<AllowCommBody>,
) -> Response {
    let req = AllowCommRequest {
        zone_a: name,
        zone_b: body.peer_zone,
    };

    let mut c = client.lock().await;
    match c.allow_comm(req).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            Json(OkResponse {
                ok: inner.ok,
                message: None,
            })
            .into_response()
        }
        Err(e) => grpc_error_to_response(e),
    }
}

async fn status(State(client): State<SharedClient>) -> Response {
    let mut c = client.lock().await;
    match c.status(StatusRequest {}).await {
        Ok(resp) => {
            let inner = resp.into_inner();
            let hooks = inner
                .hooks
                .into_iter()
                .map(|h| HookStatusJson {
                    hook: h.hook,
                    allow: h.allow,
                    deny: h.deny,
                    error: h.error,
                    lost: h.lost,
                })
                .collect();

            Json(StatusJson {
                attached: inner.attached,
                zones_active: inner.zones_active,
                containers_active: inner.containers_active,
                uptime_secs: inner.uptime_secs,
                hooks,
            })
            .into_response()
        }
        Err(e) => grpc_error_to_response(e),
    }
}

async fn watch_events(
    State(client): State<SharedClient>,
    Query(q): Query<WatchEventsQuery>,
) -> Response {
    let req = WatchEventsRequest { follow: q.follow };

    let mut c = client.lock().await;
    let stream = match c.watch_events(req).await {
        Ok(resp) => resp.into_inner(),
        Err(e) => return grpc_error_to_response(e),
    };
    // Release the lock before streaming.
    drop(c);

    let sse_stream = stream.map(|result| -> Result<Event, Infallible> {
        match result {
            Ok(event) => {
                let json = DenyEventJson {
                    timestamp_ns: event.timestamp_ns,
                    hook: event.hook,
                    zone_id: event.zone_id,
                    target_zone_id: event.target_zone_id,
                    pid: event.pid,
                    comm: event.comm,
                    inode: event.inode,
                    context: event.context,
                };
                // Best-effort JSON serialization; on failure send raw debug.
                let data = serde_json::to_string(&json)
                    .unwrap_or_else(|_| format!("{json:?}"));
                Ok(Event::default().event("deny").data(data))
            }
            Err(e) => Ok(Event::default()
                .event("error")
                .data(format!("gRPC stream error: {e}"))),
        }
    });

    Sse::new(sse_stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn grpc_error_to_response(e: tonic::Status) -> Response {
    let status = match e.code() {
        tonic::Code::NotFound => StatusCode::NOT_FOUND,
        tonic::Code::InvalidArgument => StatusCode::BAD_REQUEST,
        tonic::Code::AlreadyExists => StatusCode::CONFLICT,
        tonic::Code::FailedPrecondition => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };

    (
        status,
        Json(OkResponse {
            ok: false,
            message: Some(e.message().to_string()),
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_zone_body_deserializes() {
        let json = r#"{
            "zone_name": "web",
            "policy": {
                "host_paths": ["/data"],
                "allowed_zones": ["db"],
                "allow_ptrace": false
            }
        }"#;
        let body: RegisterZoneBody = serde_json::from_str(json).expect("deserialize");
        assert_eq!(body.zone_name, "web");
        assert_eq!(body.policy.host_paths, vec!["/data"]);
        assert_eq!(body.policy.allowed_zones, vec!["db"]);
        assert!(!body.policy.allow_ptrace);
    }

    #[test]
    fn register_zone_body_defaults() {
        let json = r#"{"zone_name": "minimal", "policy": {}}"#;
        let body: RegisterZoneBody = serde_json::from_str(json).expect("deserialize");
        assert_eq!(body.zone_name, "minimal");
        assert!(body.policy.host_paths.is_empty());
        assert!(body.policy.allowed_zones.is_empty());
        assert!(!body.policy.allow_ptrace);
    }

    #[test]
    fn zone_id_response_serializes() {
        let resp = ZoneIdResponse { zone_id: 42 };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert_eq!(json, r#"{"zone_id":42}"#);
    }

    #[test]
    fn ok_response_skips_none_message() {
        let resp = OkResponse {
            ok: true,
            message: None,
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert_eq!(json, r#"{"ok":true}"#);
    }

    #[test]
    fn ok_response_includes_message() {
        let resp = OkResponse {
            ok: false,
            message: Some("zone not found".into()),
        };
        let json = serde_json::to_string(&resp).expect("serialize");
        assert!(json.contains("zone not found"));
    }

    #[test]
    fn attach_container_body_deserializes() {
        let json = r#"{"container_id": "abc123", "cgroup_id": 99999}"#;
        let body: AttachContainerBody = serde_json::from_str(json).expect("deserialize");
        assert_eq!(body.container_id, "abc123");
        assert_eq!(body.cgroup_id, 99999);
    }

    #[test]
    fn allow_comm_body_deserializes() {
        let json = r#"{"peer_zone": "backend"}"#;
        let body: AllowCommBody = serde_json::from_str(json).expect("deserialize");
        assert_eq!(body.peer_zone, "backend");
    }

    #[test]
    fn status_json_serializes() {
        let status = StatusJson {
            attached: true,
            zones_active: 3,
            containers_active: 7,
            uptime_secs: 3600,
            hooks: vec![HookStatusJson {
                hook: "file_open".into(),
                allow: 100,
                deny: 5,
                error: 0,
                lost: 0,
            }],
        };
        let json = serde_json::to_string(&status).expect("serialize");
        assert!(json.contains("\"attached\":true"));
        assert!(json.contains("\"file_open\""));
    }

    #[test]
    fn deny_event_json_serializes() {
        let event = DenyEventJson {
            timestamp_ns: 1234567890,
            hook: "exec_guard".into(),
            zone_id: 1,
            target_zone_id: 2,
            pid: 42,
            comm: "cat".into(),
            inode: 12345,
            context: "cross-zone exec".into(),
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("exec_guard"));
        assert!(json.contains("cross-zone exec"));
    }

    #[test]
    fn remove_zone_query_defaults() {
        let q: RemoveZoneQuery = serde_json::from_str("{}").expect("deserialize");
        assert!(!q.drain);
    }

    #[test]
    fn watch_events_query_defaults() {
        let q: WatchEventsQuery = serde_json::from_str("{}").expect("deserialize");
        assert!(!q.follow);
    }
}
