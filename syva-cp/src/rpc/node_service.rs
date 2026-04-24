use crate::db::types::Actor;
use crate::read;
use crate::write::node::{
    DecommissionNodeInput, HeartbeatInput, RegisterNodeInput, SetNodeLabelsInput,
};
use crate::write::TransactionalWriter;
use serde_json::Value as JsonValue;
use sqlx::postgres::PgPool;
use std::collections::BTreeMap;
use syva_proto::syva_control::v1::node_service_server::NodeService;
use syva_proto::syva_control::v1::{
    get_node_request::Identifier, DecommissionNodeRequest, DecommissionNodeResponse,
    GetNodeRequest, GetNodeResponse, HeartbeatRequest, HeartbeatResponse, ListNodesRequest,
    ListNodesResponse, Node as NodeProto, RegisterNodeRequest, RegisterNodeResponse,
    SetNodeLabelsRequest, SetNodeLabelsResponse,
};
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct NodeServiceImpl {
    pub pool: PgPool,
}

#[tonic::async_trait]
impl NodeService for NodeServiceImpl {
    async fn register_node(
        &self,
        request: Request<RegisterNodeRequest>,
    ) -> Result<Response<RegisterNodeResponse>, Status> {
        grpc_request_counter("RegisterNode");
        let req = request.into_inner();
        let proposed_id = parse_uuid(&req.proposed_id, "proposed_id")?;
        let capabilities_json = parse_optional_json(&req.capabilities_json, "capabilities_json")?
            .unwrap_or_else(|| JsonValue::Object(serde_json::Map::new()));

        let writer = TransactionalWriter::new(&self.pool);
        let out = writer
            .register_node(
                RegisterNodeInput {
                    node_name: req.node_name,
                    fingerprint: non_empty(req.fingerprint),
                    cluster_id: non_empty(req.cluster_id),
                    labels: map_to_labels(req.labels),
                    capabilities_json,
                    proposed_id,
                },
                &dev_actor(),
            )
            .await?;

        let assigned_id = out.node.id.to_string();

        Ok(Response::new(RegisterNodeResponse {
            node: Some(node_to_proto(out.node, out.labels)),
            assigned_id,
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        grpc_request_counter("Heartbeat");
        let req = request.into_inner();
        let node_id = parse_uuid(&req.node_id, "node_id")?;

        let writer = TransactionalWriter::new(&self.pool);
        writer
            .heartbeat_node(
                HeartbeatInput {
                    node_id,
                    status_hint: non_empty(req.status_hint),
                },
                &dev_actor(),
            )
            .await?;

        Ok(Response::new(HeartbeatResponse {
            server_time: Some(to_ts(chrono::Utc::now())),
        }))
    }

    async fn decommission_node(
        &self,
        request: Request<DecommissionNodeRequest>,
    ) -> Result<Response<DecommissionNodeResponse>, Status> {
        grpc_request_counter("DecommissionNode");
        let req = request.into_inner();
        let node_id = parse_uuid(&req.node_id, "node_id")?;

        let writer = TransactionalWriter::new(&self.pool);
        let node = writer
            .decommission_node(
                DecommissionNodeInput {
                    node_id,
                    if_version: req.if_version,
                },
                &dev_actor(),
            )
            .await?;

        let labels = read::node::load_labels(&self.pool, node.id).await?;

        Ok(Response::new(DecommissionNodeResponse {
            node: Some(node_to_proto(node, labels)),
        }))
    }

    async fn set_node_labels(
        &self,
        request: Request<SetNodeLabelsRequest>,
    ) -> Result<Response<SetNodeLabelsResponse>, Status> {
        grpc_request_counter("SetNodeLabels");
        let req = request.into_inner();
        let node_id = parse_uuid(&req.node_id, "node_id")?;

        let writer = TransactionalWriter::new(&self.pool);
        let out = writer
            .set_node_labels(
                SetNodeLabelsInput {
                    node_id,
                    if_version: req.if_version,
                    labels: map_to_labels(req.labels),
                },
                &dev_actor(),
            )
            .await?;

        Ok(Response::new(SetNodeLabelsResponse {
            node: Some(node_to_proto(out.node, out.labels)),
        }))
    }

    async fn get_node(
        &self,
        request: Request<GetNodeRequest>,
    ) -> Result<Response<GetNodeResponse>, Status> {
        grpc_request_counter("GetNode");
        let req = request.into_inner();

        let (node, labels) = match req.identifier {
            Some(Identifier::Id(id)) => read::node::get_node(&self.pool, parse_uuid(&id, "id")?).await?,
            Some(Identifier::NodeName(node_name)) => {
                read::node::get_node_by_name(&self.pool, &node_name).await?
            }
            None => return Err(Status::invalid_argument("identifier required")),
        };

        Ok(Response::new(GetNodeResponse {
            node: Some(node_to_proto(node, labels)),
        }))
    }

    async fn list_nodes(
        &self,
        request: Request<ListNodesRequest>,
    ) -> Result<Response<ListNodesResponse>, Status> {
        grpc_request_counter("ListNodes");
        let req = request.into_inner();
        let status = if req.status.is_empty() {
            None
        } else {
            Some(req.status.as_str())
        };
        let limit = if req.limit <= 0 { 50 } else { req.limit };

        let nodes = read::node::list_nodes(&self.pool, status, limit).await?;

        Ok(Response::new(ListNodesResponse {
            nodes: nodes
                .into_iter()
                .map(|(node, labels)| node_to_proto(node, labels))
                .collect(),
        }))
    }
}

fn grpc_request_counter(method: &'static str) {
    ::metrics::counter!(
        "syva_cp_grpc_requests_total",
        "service" => "NodeService",
        "method" => method
    )
    .increment(1);
}

#[allow(clippy::result_large_err)]
fn parse_uuid(s: &str, field: &'static str) -> Result<Uuid, Status> {
    Uuid::parse_str(s).map_err(|_| Status::invalid_argument(format!("invalid {field}")))
}

#[allow(clippy::result_large_err)]
fn parse_optional_json(s: &str, field: &'static str) -> Result<Option<JsonValue>, Status> {
    if s.is_empty() {
        Ok(None)
    } else {
        serde_json::from_str(s)
            .map(Some)
            .map_err(|_| Status::invalid_argument(format!("{field} must be valid JSON")))
    }
}

fn map_to_labels(labels: std::collections::HashMap<String, String>) -> BTreeMap<String, String> {
    labels.into_iter().collect()
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s)
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

fn node_to_proto(node: crate::db::types::Node, labels: BTreeMap<String, String>) -> NodeProto {
    NodeProto {
        id: node.id.to_string(),
        node_name: node.node_name,
        cluster_id: node.cluster_id.unwrap_or_default(),
        status: node.status,
        fingerprint: node.fingerprint.unwrap_or_default(),
        last_seen_at: node.last_seen_at.map(to_ts),
        created_at: Some(to_ts(node.created_at)),
        updated_at: Some(to_ts(node.updated_at)),
        version: node.version,
        labels: labels.into_iter().collect(),
        capabilities_json: node.capabilities_json.to_string(),
        metadata_json: node.metadata_json.to_string(),
    }
}

fn to_ts(ts: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: ts.timestamp(),
        nanos: ts.timestamp_subsec_nanos() as i32,
    }
}
