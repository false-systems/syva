//! gRPC connection to syva-core over Unix domain socket.

use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use tonic::transport::Channel;

/// Connect to syva-core over Unix socket.
pub async fn connect_to_core(socket_path: &str) -> anyhow::Result<SyvaCoreClient<Channel>> {
    let path = socket_path.to_string();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await?;
    Ok(SyvaCoreClient::new(channel))
}

/// Connect with exponential backoff retry.
pub async fn connect_with_retry(
    socket_path: &str,
    max_attempts: usize,
) -> anyhow::Result<SyvaCoreClient<Channel>> {
    let mut backoff = std::time::Duration::from_millis(100);
    for attempt in 1..=max_attempts {
        match connect_to_core(socket_path).await {
            Ok(client) => return Ok(client),
            Err(e) => {
                if attempt == max_attempts {
                    return Err(anyhow::anyhow!(
                        "failed to connect to syva-core after {max_attempts} attempts: {e}"
                    ));
                }
                tracing::warn!(attempt, %e, "failed to connect to syva-core — retrying");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(5));
            }
        }
    }
    unreachable!()
}
