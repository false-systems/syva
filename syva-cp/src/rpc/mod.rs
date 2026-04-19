//! gRPC server. Only wires services to the underlying TransactionalWriter
//! and read module — no business logic here, no direct DB writes.

use anyhow::Result;
use sqlx::postgres::PgPool;
use std::net::SocketAddr;
use tokio::task::JoinHandle;
use tonic::transport::Server;

pub mod team_service;

pub async fn spawn(pool: PgPool, addr: SocketAddr) -> Result<JoinHandle<()>> {
    let team_svc = team_service::TeamServiceImpl { pool: pool.clone() };

    let handle = tokio::spawn(async move {
        let result = Server::builder()
            .add_service(
                syva_proto::syva_control::v1::team_service_server::TeamServiceServer::new(
                    team_svc,
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
