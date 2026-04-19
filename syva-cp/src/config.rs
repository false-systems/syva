use clap::Parser;
use std::net::SocketAddr;

#[derive(Parser, Debug, Clone)]
#[command(name = "syva-cp", version)]
pub struct Config {
    /// PostgreSQL connection URL.
    #[arg(long, env = "SYVA_CP_DATABASE_URL")]
    pub database_url: String,

    /// gRPC server address.
    #[arg(long, env = "SYVA_CP_GRPC_ADDR", default_value = "0.0.0.0:50051")]
    pub grpc_addr: SocketAddr,

    /// Health/metrics HTTP address.
    #[arg(long, env = "SYVA_CP_HEALTH_ADDR", default_value = "0.0.0.0:9092")]
    pub health_addr: SocketAddr,

    /// Max database connections.
    #[arg(long, env = "SYVA_CP_DB_MAX_CONN", default_value = "16")]
    pub db_max_connections: u32,

    /// Database connection timeout in seconds.
    #[arg(long, env = "SYVA_CP_DB_TIMEOUT", default_value = "5")]
    pub db_timeout_secs: u64,
}
