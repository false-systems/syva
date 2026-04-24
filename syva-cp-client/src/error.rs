use thiserror::Error;

#[derive(Debug, Error)]
pub enum CpClientError {
    #[error("connection failed: {0}")]
    Connection(#[from] tonic::transport::Error),

    #[error("grpc error: {0}")]
    Grpc(#[from] tonic::Status),

    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),

    #[error("not registered: call register() before this operation")]
    NotRegistered,

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("internal: {0}")]
    Internal(String),
}

