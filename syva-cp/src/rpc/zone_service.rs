use crate::db::types::{Actor, PolicyInput};
use crate::read;
use crate::write::zone::{CreateZoneInput, DeleteZoneInput, UpdateZoneInput};
use crate::write::TransactionalWriter;
use serde_json::Value as JsonValue;
use sqlx::postgres::PgPool;
use syva_proto::syva_control::v1::zone_service_server::ZoneService;
use syva_proto::syva_control::v1::{
    get_zone_request::Identifier, CreateZoneRequest, CreateZoneResponse, DeleteZoneRequest,
    DeleteZoneResponse, GetZoneContextRequest, GetZoneContextResponse, GetZoneHistoryRequest,
    GetZoneHistoryResponse, GetZoneRequest, GetZoneResponse, ListZonesRequest, ListZonesResponse,
    Policy as PolicyProto, PreviewZoneAssignmentRequest, PreviewZoneAssignmentResponse,
    UpdateZoneRequest, UpdateZoneResponse, WatchZonesRequest, Zone as ZoneProto, ZoneEvent,
    ZoneHistoryEntry as ZoneHistoryEntryProto,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct ZoneServiceImpl {
    pub pool: PgPool,
}

#[tonic::async_trait]
impl ZoneService for ZoneServiceImpl {
    async fn create_zone(
        &self,
        request: Request<CreateZoneRequest>,
    ) -> Result<Response<CreateZoneResponse>, Status> {
        grpc_request_counter("CreateZone");
        let req = request.into_inner();
        let team_id = parse_uuid(&req.team_id, "team_id")?;

        let policy_json = parse_json(&req.policy_json, "policy_json")?;
        let summary_json = parse_optional_json(&req.summary_json)?;
        let selector_json = parse_optional_json(&req.selector_json)?;
        let metadata_json = parse_optional_json(&req.metadata_json)?;

        let actor = dev_actor();

        let writer = TransactionalWriter::new(&self.pool);
        let out = writer
            .create_zone(
                CreateZoneInput {
                    team_id,
                    name: req.name,
                    display_name: if req.display_name.is_empty() {
                        None
                    } else {
                        Some(req.display_name)
                    },
                    policy: PolicyInput {
                        policy_json,
                        summary_json,
                    },
                    selector_json,
                    metadata_json,
                },
                &actor,
            )
            .await?;

        Ok(Response::new(CreateZoneResponse {
            zone: Some(zone_to_proto(out.zone)),
            policy: Some(policy_to_proto(out.policy)),
        }))
    }

    async fn update_zone(
        &self,
        request: Request<UpdateZoneRequest>,
    ) -> Result<Response<UpdateZoneResponse>, Status> {
        grpc_request_counter("UpdateZone");
        let req = request.into_inner();
        let zone_id = parse_uuid(&req.zone_id, "zone_id")?;

        let policy = if req.policy_json.is_empty() {
            None
        } else {
            Some(PolicyInput {
                policy_json: parse_json(&req.policy_json, "policy_json")?,
                summary_json: None,
            })
        };

        let actor = dev_actor();
        let writer = TransactionalWriter::new(&self.pool);

        let out = writer
            .update_zone(
                UpdateZoneInput {
                    zone_id,
                    if_version: req.if_version,
                    policy,
                    selector_json: parse_optional_json(&req.selector_json)?,
                    metadata_json: parse_optional_json(&req.metadata_json)?,
                },
                &actor,
            )
            .await?;

        Ok(Response::new(UpdateZoneResponse {
            zone: Some(zone_to_proto(out.zone)),
            new_policy: out.new_policy.map(policy_to_proto),
        }))
    }

    async fn delete_zone(
        &self,
        request: Request<DeleteZoneRequest>,
    ) -> Result<Response<DeleteZoneResponse>, Status> {
        grpc_request_counter("DeleteZone");
        let req = request.into_inner();
        let zone_id = parse_uuid(&req.zone_id, "zone_id")?;

        let actor = dev_actor();
        let writer = TransactionalWriter::new(&self.pool);

        let zone = writer
            .delete_zone(
                DeleteZoneInput {
                    zone_id,
                    if_version: req.if_version,
                    drain: req.drain,
                },
                &actor,
            )
            .await?;

        Ok(Response::new(DeleteZoneResponse {
            zone: Some(zone_to_proto(zone)),
        }))
    }

    async fn get_zone(
        &self,
        request: Request<GetZoneRequest>,
    ) -> Result<Response<GetZoneResponse>, Status> {
        grpc_request_counter("GetZone");
        let req = request.into_inner();
        let zone = match req.identifier {
            Some(Identifier::Id(id)) => read::zone::get_zone(&self.pool, parse_uuid(&id, "id")?).await?,
            Some(Identifier::NameRef(name_ref)) => {
                read::zone::get_zone_by_name(
                    &self.pool,
                    parse_uuid(&name_ref.team_id, "team_id")?,
                    &name_ref.name,
                )
                .await?
            }
            None => return Err(Status::invalid_argument("identifier required")),
        };

        let current_policy = read::zone::get_current_policy(&self.pool, zone.id).await?;

        Ok(Response::new(GetZoneResponse {
            zone: Some(zone_to_proto(zone)),
            current_policy: current_policy.map(policy_to_proto),
        }))
    }

    async fn list_zones(
        &self,
        request: Request<ListZonesRequest>,
    ) -> Result<Response<ListZonesResponse>, Status> {
        grpc_request_counter("ListZones");
        let req = request.into_inner();
        let team_id = parse_uuid(&req.team_id, "team_id")?;
        let status = if req.status.is_empty() {
            None
        } else {
            Some(req.status.as_str())
        };
        let limit = if req.limit == 0 { 50 } else { req.limit };

        let zones = read::zone::list_zones(&self.pool, team_id, status, limit).await?;

        Ok(Response::new(ListZonesResponse {
            zones: zones.into_iter().map(zone_to_proto).collect(),
        }))
    }

    async fn get_zone_history(
        &self,
        request: Request<GetZoneHistoryRequest>,
    ) -> Result<Response<GetZoneHistoryResponse>, Status> {
        grpc_request_counter("GetZoneHistory");
        let req = request.into_inner();
        let zone_id = parse_uuid(&req.zone_id, "zone_id")?;
        let limit = if req.limit == 0 { 50 } else { req.limit };

        let entries = read::zone::get_zone_history(&self.pool, zone_id, limit).await?;

        Ok(Response::new(GetZoneHistoryResponse {
            entries: entries
                .into_iter()
                .map(|e| ZoneHistoryEntryProto {
                    version: e.version,
                    snapshot_json: e.snapshot_json.to_string(),
                    created_at: Some(to_ts(e.created_at)),
                    caused_by_event_id: e.caused_by_event_id.to_string(),
                })
                .collect(),
        }))
    }

    type WatchZonesStream = tokio_stream::wrappers::ReceiverStream<Result<ZoneEvent, Status>>;

    async fn watch_zones(
        &self,
        _request: Request<WatchZonesRequest>,
    ) -> Result<Response<Self::WatchZonesStream>, Status> {
        Err(Status::unimplemented("WatchZones — deferred to session 4"))
    }

    async fn preview_zone_assignment(
        &self,
        _request: Request<PreviewZoneAssignmentRequest>,
    ) -> Result<Response<PreviewZoneAssignmentResponse>, Status> {
        Err(Status::unimplemented(
            "PreviewZoneAssignment — deferred to session 3",
        ))
    }

    async fn get_zone_context(
        &self,
        _request: Request<GetZoneContextRequest>,
    ) -> Result<Response<GetZoneContextResponse>, Status> {
        Err(Status::unimplemented("GetZoneContext — deferred to session 4"))
    }
}

fn grpc_request_counter(method: &'static str) {
    ::metrics::counter!(
        "syva_cp_grpc_requests_total",
        "service" => "ZoneService",
        "method" => method
    )
    .increment(1);
}

#[allow(clippy::result_large_err)]
fn parse_uuid(s: &str, field: &'static str) -> Result<Uuid, Status> {
    Uuid::parse_str(s).map_err(|_| Status::invalid_argument(format!("invalid {field}")))
}

#[allow(clippy::result_large_err)]
fn parse_json(s: &str, field: &'static str) -> Result<JsonValue, Status> {
    serde_json::from_str(s)
        .map_err(|_| Status::invalid_argument(format!("{field} must be valid JSON")))
}

#[allow(clippy::result_large_err)]
fn parse_optional_json(s: &str) -> Result<Option<JsonValue>, Status> {
    if s.is_empty() {
        Ok(None)
    } else {
        serde_json::from_str(s)
            .map(Some)
            .map_err(|_| Status::invalid_argument("json field must be valid JSON"))
    }
}

fn dev_actor() -> Actor {
    Actor {
        actor_type: "user".into(),
        actor_id: "dev".into(),
        team_id: None,
        subject_type: "user".into(),
        subject_id: "dev".into(),
    }
}

fn zone_to_proto(zone: crate::db::types::Zone) -> ZoneProto {
    ZoneProto {
        id: zone.id.to_string(),
        team_id: zone.team_id.to_string(),
        name: zone.name,
        display_name: zone.display_name.unwrap_or_default(),
        status: zone.status,
        current_policy_id: zone
            .current_policy_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        selector_json: zone
            .selector_json
            .map(|j| j.to_string())
            .unwrap_or_default(),
        metadata_json: zone.metadata_json.to_string(),
        created_at: Some(to_ts(zone.created_at)),
        updated_at: Some(to_ts(zone.updated_at)),
        deleted_at: zone.deleted_at.map(to_ts),
        version: zone.version,
        caused_by_event_id: zone
            .caused_by_event_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
    }
}

fn policy_to_proto(policy: crate::db::types::Policy) -> PolicyProto {
    PolicyProto {
        id: policy.id.to_string(),
        zone_id: policy.zone_id.to_string(),
        version: policy.version,
        checksum: policy.checksum,
        policy_json: policy.policy_json.to_string(),
        summary_json: policy.summary_json.to_string(),
        created_at: Some(to_ts(policy.created_at)),
        created_by_subject: policy.created_by_subject.unwrap_or_default(),
        caused_by_event_id: policy.caused_by_event_id.to_string(),
    }
}

fn to_ts(ts: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: ts.timestamp(),
        nanos: ts.timestamp_subsec_nanos() as i32,
    }
}
