//! Typed error surface for the control plane.
//!
//! Every caller — gRPC handlers, REST gateway, CLI — must be able to
//! distinguish "conflict" from "not found" from "permission denied"
//! without parsing strings. `From<CpError> for tonic::Status` maps each
//! variant to the right gRPC code.

use thiserror::Error;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum CpError {
    #[error("resource not found: {resource} {resource_id}")]
    NotFound {
        resource: &'static str,
        resource_id: Uuid,
    },

    #[error("version conflict on {resource} {resource_id}: expected {expected}, current changed")]
    VersionConflict {
        resource: &'static str,
        resource_id: Uuid,
        expected: i64,
    },

    #[error("conflict: {message}")]
    Conflict { message: String },

    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("failed precondition: {0}")]
    FailedPrecondition(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("internal error: {0}")]
    Internal(String),
}

impl From<CpError> for tonic::Status {
    fn from(err: CpError) -> Self {
        use tonic::{Code, Status};
        let code = match &err {
            CpError::NotFound { .. } => Code::NotFound,
            CpError::VersionConflict { .. } => Code::FailedPrecondition,
            CpError::Conflict { .. } => Code::AlreadyExists,
            CpError::InvalidArgument(_) => Code::InvalidArgument,
            CpError::PermissionDenied(_) => Code::PermissionDenied,
            CpError::FailedPrecondition(_) => Code::FailedPrecondition,
            CpError::Database(_) | CpError::Serialization(_) | CpError::Internal(_) => {
                Code::Internal
            }
        };
        Status::new(code, err.to_string())
    }
}
