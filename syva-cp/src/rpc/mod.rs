//! gRPC server. Only wires services to the underlying TransactionalWriter
//! and read module — no business logic here, no direct DB writes.

use crate::bus::AssignmentBus;
use anyhow::Result;
use sqlx::postgres::PgPool;
use std::net::SocketAddr;
use tokio::task::JoinHandle;
use tonic::transport::Server;

pub mod assignment_service;
pub mod node_service;
pub mod team_service;
pub mod zone_service;

pub async fn spawn(pool: PgPool, bus: AssignmentBus, addr: SocketAddr) -> Result<JoinHandle<()>> {
    let assignment_svc = assignment_service::AssignmentServiceImpl {
        pool: pool.clone(),
        bus,
    };
    let node_svc = node_service::NodeServiceImpl { pool: pool.clone() };
    let team_svc = team_service::TeamServiceImpl { pool: pool.clone() };
    let zone_svc = zone_service::ZoneServiceImpl { pool: pool.clone() };

    let handle = tokio::spawn(async move {
        let result = Server::builder()
            .add_service(
                syva_proto::syva_control::v1::assignment_service_server::AssignmentServiceServer::new(
                    assignment_svc,
                ),
            )
            .add_service(
                syva_proto::syva_control::v1::node_service_server::NodeServiceServer::new(
                    node_svc,
                ),
            )
            .add_service(
                syva_proto::syva_control::v1::team_service_server::TeamServiceServer::new(
                    team_svc,
                ),
            )
            .add_service(
                syva_proto::syva_control::v1::zone_service_server::ZoneServiceServer::new(
                    zone_svc,
                ),
            )
            .serve(addr)
            .await;
        if let Err(e) = result {
            tracing::error!("grpc server error: {e}");
        }
    });

    tracing::info!("grpc listening on {addr}");
    Ok(handle)
}
