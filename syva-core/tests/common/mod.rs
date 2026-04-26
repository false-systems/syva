use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use tonic::transport::Channel;

pub(crate) struct CoreProcess {
    child: Child,
}

impl Drop for CoreProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) fn spawn_core(socket_path: &std::path::Path) -> anyhow::Result<CoreProcess> {
    let bin = std::env::var("CARGO_BIN_EXE_syva-core")
        .unwrap_or_else(|_| "target/debug/syva-core".to_string());
    let child = Command::new(bin)
        .arg("--policy-source")
        .arg("local")
        .arg("--socket-path")
        .arg(socket_path)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(CoreProcess { child })
}

pub(crate) async fn connect(
    socket_path: &std::path::Path,
) -> anyhow::Result<SyvaCoreClient<Channel>> {
    let path = socket_path.to_path_buf();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await?;
    Ok(SyvaCoreClient::new(channel))
}

pub(crate) async fn wait_for_core(
    socket_path: &std::path::Path,
) -> anyhow::Result<SyvaCoreClient<Channel>> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last_error = None;
    while Instant::now() < deadline {
        match connect(socket_path).await {
            Ok(client) => return Ok(client),
            Err(error) => {
                last_error = Some(error);
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }

    match last_error {
        Some(error) => Err(error),
        None => anyhow::bail!("timed out waiting for syva-core"),
    }
}
