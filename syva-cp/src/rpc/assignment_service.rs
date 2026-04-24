use crate::bus::AssignmentBus;
use crate::db::types::Actor;
use crate::read;
use crate::write::assignment::{
    AppliedReport, FailedReport, ReportAssignmentStateInput,
};
use crate::write::TransactionalWriter;
use serde_json::json;
use sqlx::postgres::PgPool;
use sqlx::Row;
use std::collections::HashMap;
use syva_proto::syva_control::v1::assignment_service_server::AssignmentService;
use syva_proto::syva_control::v1::node_assignment_update::Kind as UpdateKind;
use syva_proto::syva_control::v1::{
    Assignment as AssignmentProto, GetAssignmentRequest, GetAssignmentResponse,
    ListAssignmentsRequest, ListAssignmentsResponse, NodeAssignmentUpdate,
    ReportAssignmentStateRequest, ReportAssignmentStateResponse,
    SubscribeAssignmentsRequest, ZoneAssignment,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use uuid::Uuid;

pub struct AssignmentServiceImpl {
    pub pool: PgPool,
    pub bus: AssignmentBus,
}

#[tonic::async_trait]
impl AssignmentService for AssignmentServiceImpl {
    type SubscribeAssignmentsStream = ReceiverStream<Result<NodeAssignmentUpdate, Status>>;

    async fn subscribe_assignments(
        &self,
        request: Request<SubscribeAssignmentsRequest>,
    ) -> Result<Response<Self::SubscribeAssignmentsStream>, Status> {
        grpc_request_counter("SubscribeAssignments");
        let node_id = parse_uuid(&request.into_inner().node_id, "node_id")?;

        let (tx, rx) = mpsc::channel::<Result<NodeAssignmentUpdate, Status>>(32);
        let pool = self.pool.clone();
        let bus = self.bus.clone();

        tokio::spawn(async move {
            let initial = match build_assignments_for_node(&pool, node_id).await {
                Ok(assignments) => assignments,
                Err(err) => {
                    let _ = tx.send(Err(Status::from(err))).await;
                    return;
                }
            };

            let mut last_sent: HashMap<Uuid, (Uuid, i64)> = initial
                .iter()
                .filter_map(|assignment| {
                    let zone_id = Uuid::parse_str(&assignment.zone_id).ok()?;
                    let policy_id = Uuid::parse_str(&assignment.desired_policy_id).ok()?;
                    Some((zone_id, (policy_id, assignment.desired_zone_version)))
                })
                .collect();

            if tx
                .send(Ok(NodeAssignmentUpdate {
                    kind: UpdateKind::FullSnapshot as i32,
                    assignments: initial,
                    removed_zone_id: String::new(),
                    server_revision: 1,
                }))
                .await
                .is_err()
            {
                return;
            }

            let mut bus_rx = bus.subscribe(node_id).await;
            let mut server_revision = 2_i64;

            loop {
                match bus_rx.recv().await {
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }

                let current = match build_assignments_for_node(&pool, node_id).await {
                    Ok(assignments) => assignments,
                    Err(err) => {
                        let _ = tx.send(Err(Status::from(err))).await;
                        return;
                    }
                };

                let current_map: HashMap<Uuid, (Uuid, i64, ZoneAssignment)> = current
                    .into_iter()
                    .filter_map(|assignment| {
                        let zone_id = Uuid::parse_str(&assignment.zone_id).ok()?;
                        let policy_id =
                            Uuid::parse_str(&assignment.desired_policy_id).ok()?;
                        Some((
                            zone_id,
                            (policy_id, assignment.desired_zone_version, assignment),
                        ))
                    })
                    .collect();

                for (zone_id, (policy_id, zone_version, assignment)) in &current_map {
                    let changed = last_sent
                        .get(zone_id)
                        .map(|(old_policy_id, old_zone_version)| {
                            old_policy_id != policy_id || old_zone_version != zone_version
                        })
                        .unwrap_or(true);

                    if changed
                        && tx
                            .send(Ok(NodeAssignmentUpdate {
                                kind: UpdateKind::Upsert as i32,
                                assignments: vec![assignment.clone()],
                                removed_zone_id: String::new(),
                                server_revision,
                            }))
                            .await
                            .is_err()
                    {
                        return;
                    }

                    if changed {
                        server_revision += 1;
                    }
                }

                for zone_id in last_sent.keys() {
                    if current_map.contains_key(zone_id) {
                        continue;
                    }

                    if tx
                        .send(Ok(NodeAssignmentUpdate {
                            kind: UpdateKind::Remove as i32,
                            assignments: Vec::new(),
                            removed_zone_id: zone_id.to_string(),
                            server_revision,
                        }))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    server_revision += 1;
                }

                last_sent = current_map
                    .into_iter()
                    .map(|(zone_id, (policy_id, zone_version, _))| {
                        (zone_id, (policy_id, zone_version))
                    })
                    .collect();
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn report_assignment_state(
        &self,
        request: Request<ReportAssignmentStateRequest>,
    ) -> Result<Response<ReportAssignmentStateResponse>, Status> {
        grpc_request_counter("ReportAssignmentState");
        let req = request.into_inner();
        let node_id = parse_uuid(&req.node_id, "node_id")?;

        let mut applied = Vec::with_capacity(req.applied.len());
        for report in req.applied {
            applied.push(AppliedReport {
                assignment_id: parse_uuid(&report.assignment_id, "assignment_id")?,
                actual_zone_version: report.actual_zone_version,
                actual_policy_id: parse_uuid(&report.actual_policy_id, "actual_policy_id")?,
            });
        }

        let mut failed = Vec::with_capacity(req.failed.len());
        for report in req.failed {
            let error_json = serde_json::from_str(&report.error_json)
                .unwrap_or_else(|_| json!({ "raw": report.error_json }));
            failed.push(FailedReport {
                assignment_id: parse_uuid(&report.assignment_id, "assignment_id")?,
                error_json,
            });
        }

        let writer = TransactionalWriter::new(&self.pool);
        let out = writer
            .report_assignment_state(
                ReportAssignmentStateInput {
                    node_id,
                    applied,
                    failed,
                },
                &dev_actor(),
            )
            .await?;

        Ok(Response::new(ReportAssignmentStateResponse {
            accepted_count: out.accepted as i32,
            rejected_count: out.rejected as i32,
        }))
    }

    async fn get_assignment(
        &self,
        request: Request<GetAssignmentRequest>,
    ) -> Result<Response<GetAssignmentResponse>, Status> {
        grpc_request_counter("GetAssignment");
        let assignment_id = parse_uuid(&request.into_inner().assignment_id, "assignment_id")?;
        let assignment = read::assignment::get_assignment(&self.pool, assignment_id).await?;

        Ok(Response::new(GetAssignmentResponse {
            assignment: Some(assignment_to_proto(assignment)),
        }))
    }

    async fn list_assignments(
        &self,
        request: Request<ListAssignmentsRequest>,
    ) -> Result<Response<ListAssignmentsResponse>, Status> {
        grpc_request_counter("ListAssignments");
        let req = request.into_inner();
        let zone_id = parse_optional_uuid(&req.zone_id, "zone_id")?;
        let node_id = parse_optional_uuid(&req.node_id, "node_id")?;
        let status = if req.status.is_empty() {
            None
        } else {
            Some(req.status.as_str())
        };
        let limit = if req.limit <= 0 { 50 } else { req.limit };

        let assignments =
            read::assignment::list_filtered(&self.pool, zone_id, node_id, status, limit).await?;

        Ok(Response::new(ListAssignmentsResponse {
            assignments: assignments.into_iter().map(assignment_to_proto).collect(),
        }))
    }
}

async fn build_assignments_for_node(
    pool: &PgPool,
    node_id: Uuid,
) -> Result<Vec<ZoneAssignment>, crate::error::CpError> {
    let rows = sqlx::query(
        r#"SELECT a.id AS assignment_id,
                  a.zone_id,
                  a.desired_policy_id,
                  a.desired_zone_version,
                  z.name AS zone_name,
                  z.team_id,
                  p.version AS desired_policy_version,
                  p.policy_json
           FROM assignments a
           INNER JOIN zones z ON z.id = a.zone_id AND z.deleted_at IS NULL
           INNER JOIN policies p ON p.id = a.desired_policy_id
           WHERE a.node_id = $1 AND a.status NOT IN ('removing', 'removed', 'failed')"#,
    )
    .bind(node_id)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| ZoneAssignment {
            assignment_id: row.get::<Uuid, _>("assignment_id").to_string(),
            zone_id: row.get::<Uuid, _>("zone_id").to_string(),
            zone_name: row.get("zone_name"),
            desired_zone_version: row.get("desired_zone_version"),
            desired_policy_id: row.get::<Uuid, _>("desired_policy_id").to_string(),
            desired_policy_version: row.get("desired_policy_version"),
            policy_json: row.get::<serde_json::Value, _>("policy_json").to_string(),
            team_id: row.get::<Uuid, _>("team_id").to_string(),
        })
        .collect())
}

fn grpc_request_counter(method: &'static str) {
    ::metrics::counter!(
        "syva_cp_grpc_requests_total",
        "service" => "AssignmentService",
        "method" => method
    )
    .increment(1);
}

#[allow(clippy::result_large_err)]
fn parse_uuid(s: &str, field: &'static str) -> Result<Uuid, Status> {
    Uuid::parse_str(s).map_err(|_| Status::invalid_argument(format!("invalid {field}")))
}

#[allow(clippy::result_large_err)]
fn parse_optional_uuid(s: &str, field: &'static str) -> Result<Option<Uuid>, Status> {
    if s.is_empty() {
        Ok(None)
    } else {
        parse_uuid(s, field).map(Some)
    }
}

fn dev_actor() -> Actor {
    Actor {
        actor_type: "node".into(),
        actor_id: "agent".into(),
        team_id: None,
        subject_type: "node".into(),
        subject_id: "agent".into(),
    }
}

fn assignment_to_proto(assignment: crate::db::types::Assignment) -> AssignmentProto {
    AssignmentProto {
        id: assignment.id.to_string(),
        zone_id: assignment.zone_id.to_string(),
        node_id: assignment.node_id.to_string(),
        status: assignment.status,
        desired_policy_id: assignment.desired_policy_id.to_string(),
        desired_zone_version: assignment.desired_zone_version,
        actual_policy_id: assignment
            .actual_policy_id
            .map(|id| id.to_string())
            .unwrap_or_default(),
        actual_zone_version: assignment.actual_zone_version.unwrap_or_default(),
        last_reported_at: assignment.last_reported_at.map(to_ts),
        error_json: assignment
            .error_json
            .map(|value| value.to_string())
            .unwrap_or_default(),
        created_at: Some(to_ts(assignment.created_at)),
        updated_at: Some(to_ts(assignment.updated_at)),
        version: assignment.version,
        caused_by_event_id: assignment.caused_by_event_id.to_string(),
    }
}

fn to_ts(ts: chrono::DateTime<chrono::Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: ts.timestamp(),
        nanos: ts.timestamp_subsec_nanos() as i32,
    }
}
