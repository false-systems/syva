use thiserror::Error;

#[derive(Debug, Error)]
pub enum CpClientError {
    #[error("connection failed: {0}")]
    Connection(#[from] Box<tonic::transport::Error>),

    #[error("grpc error: {0}")]
    Grpc(#[from] Box<tonic::Status>),

    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),

    #[error("not registered: call register() before this operation")]
    NotRegistered,

    #[error("serialization error: {0}")]
    Serde(#[from] Box<serde_json::Error>),

    #[error("internal: {0}")]
    Internal(String),
}

impl From<tonic::transport::Error> for CpClientError {
    fn from(value: tonic::transport::Error) -> Self {
        Self::Connection(Box::new(value))
    }
}

impl From<tonic::Status> for CpClientError {
    fn from(value: tonic::Status) -> Self {
        Self::Grpc(Box::new(value))
    }
}

impl From<serde_json::Error> for CpClientError {
    fn from(value: serde_json::Error) -> Self {
        Self::Serde(Box::new(value))
    }
}
