//! Unix-socket client for the node-local `syva.core.v1` API.

use std::path::{Path, PathBuf};
use std::time::Duration;

use syva_proto::syva_core::syva_core_client::SyvaCoreClient as ProtoSyvaCoreClient;
use tonic::transport::{Channel, Endpoint};

pub use syva_proto::syva_core;

#[derive(Debug, thiserror::Error)]
pub enum CoreClientError {
    #[error("invalid endpoint: {0}")]
    InvalidEndpoint(String),

    #[error("connection failed: {0}")]
    Connection(#[from] tonic::transport::Error),

    #[error("grpc error: {0}")]
    Grpc(#[from] tonic::Status),
}

pub type SyvaCoreClient = ProtoSyvaCoreClient<Channel>;

pub async fn connect_unix_socket(
    socket_path: impl AsRef<Path>,
) -> Result<SyvaCoreClient, CoreClientError> {
    let path = socket_path.as_ref().to_path_buf();
    let endpoint = Endpoint::try_from("http://[::]:50051")
        .map_err(|error| CoreClientError::InvalidEndpoint(error.to_string()))?;

    let channel = endpoint
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await?;

    Ok(ProtoSyvaCoreClient::new(channel))
}

pub async fn connect_unix_socket_with_retry(socket_path: PathBuf) -> SyvaCoreClient {
    let mut backoff = Duration::from_millis(250);
    let max_backoff = Duration::from_secs(30);

    loop {
        match connect_unix_socket(&socket_path).await {
            Ok(client) => return client,
            Err(error) => {
                tracing::warn!(
                    socket = %socket_path.display(),
                    error = %error,
                    backoff_ms = backoff.as_millis(),
                    "could not connect to syva-core; retrying"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}
