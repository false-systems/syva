//! Manual integration test for local-mode startup.
//!
//! Run on Linux as root with a `syva` group present:
//!
//! ```text
//! sudo -E cargo test -p syva-core --test local_mode_starts_server -- --ignored --nocapture
//! ```

mod common;

use syva_proto::syva_core::StatusRequest;

#[tokio::test]
#[ignore = "requires Linux, root privileges, BPF LSM support, and group 'syva'"]
async fn local_mode_starts_server() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let socket_path = dir.path().join("syva-core.sock");
    let _core = common::spawn_core(&socket_path)?;

    let mut client = common::wait_for_core(&socket_path).await?;
    let status = client.status(StatusRequest {}).await?.into_inner();

    assert!(status.attached);
    assert!(socket_path.exists());
    Ok(())
}
