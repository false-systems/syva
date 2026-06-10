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

// Each integration-test binary compiles its own copy of this module, so any
// helper unused by one binary would otherwise trip dead_code.
#[allow(dead_code)]
pub(crate) fn spawn_core(socket_path: &std::path::Path) -> anyhow::Result<CoreProcess> {
    spawn_core_with_args(socket_path, &[])
}

#[allow(dead_code)]
pub(crate) fn spawn_core_with_args(
    socket_path: &std::path::Path,
    extra_args: &[&str],
) -> anyhow::Result<CoreProcess> {
    let bin = std::env::var("CARGO_BIN_EXE_syva-core")
        .unwrap_or_else(|_| "target/debug/syva-core".to_string());
    let mut command = Command::new(bin);
    command.arg("--socket-path").arg(socket_path);
    // Pin the eBPF object to THIS workspace's release build. Object discovery
    // prefers system paths (/usr/lib/syva) first, so on a host with a deployed
    // Syva the gates would otherwise test the installed object, not the tree.
    if let Some(obj) = workspace_release_ebpf_object() {
        command.arg("--ebpf-obj").arg(obj);
    }
    let child = command
        .args(extra_args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;
    Ok(CoreProcess { child })
}

fn workspace_release_ebpf_object() -> Option<std::path::PathBuf> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok()?;
    let path = std::path::Path::new(&manifest_dir)
        .parent()?
        .join("syva-ebpf/target/bpfel-unknown-none/release/syva-ebpf");
    path.exists().then_some(path)
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
