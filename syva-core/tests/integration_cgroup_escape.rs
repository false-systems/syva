//! Privileged Linux / BPF-LSM integration test: prove the cgroup-escape
//! detector observes a zoned task migrating out of its zone.
//!
//! Run via the dedicated target (requires Linux, root, BPF LSM, group `syva`):
//!
//! ```text
//! sudo -E make verify-cgroup-escape
//! ```
//!
//! ## Detection, not prevention
//!
//! BPF-LSM has no hook that can DENY a cgroup migration on supported kernels,
//! so this is honestly a detector: an fentry on `cgroup_attach_task` reads the
//! migrating task's source cgroup (before the move) and its destination, and
//! records an escape when a zoned task leaves for an unzoned/other-zone cgroup.
//! The move itself is NOT blocked. The test asserts the escape is detected and
//! surfaced (counter + degraded health), never that it was prevented.

mod common;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::{AttachContainerRequest, RegisterZoneRequest, ZonePolicy};
use tonic::transport::Channel;

const ZONE: &str = "syva-it-zone-escape";
const HEALTH_PORT: u16 = 19296;

fn empty_policy() -> ZonePolicy {
    ZonePolicy {
        host_paths: Vec::new(),
        allowed_zones: Vec::new(),
        allow_ptrace: false,
        zone_type: 0,
    }
}

/// Cleans up both cgroup leaves and the parked workload even on panic.
struct Cleanup {
    src: PathBuf,
    dst: PathBuf,
    child: Option<Child>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = fs::remove_dir(&self.src);
        let _ = fs::remove_dir(&self.dst);
    }
}

async fn fetch_metrics(port: u16) -> anyhow::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    stream
        .write_all(b"GET /metrics HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut body = String::new();
    stream.read_to_string(&mut body).await?;
    Ok(body)
}

/// Poll /metrics until `needle` appears or the deadline passes.
async fn wait_for_metric(port: u16, needle: &str, secs: u64) -> anyhow::Result<String> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut last = String::new();
    while Instant::now() < deadline {
        if let Ok(body) = fetch_metrics(port).await {
            if body.contains(needle) {
                return Ok(body);
            }
            last = body;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("timed out waiting for metric '{needle}'; last scrape:\n{last}")
}

#[tokio::test]
#[ignore = "requires Linux, root privileges, BPF LSM support, and group 'syva'"]
async fn zoned_task_leaving_its_cgroup_is_detected() -> anyhow::Result<()> {
    let pid = std::process::id();
    let src = PathBuf::from(format!("/sys/fs/cgroup/syva-escape-src-{pid}"));
    let dst = PathBuf::from(format!("/sys/fs/cgroup/syva-escape-dst-{pid}"));

    // 1. Start the core with a known health port.
    let sock_dir = tempfile::tempdir()?;
    let socket_path = sock_dir.path().join("syva-core.sock");
    let health = HEALTH_PORT.to_string();
    let _core = common::spawn_core_with_args(&socket_path, &["--health-port", &health])?;
    let mut client: SyvaCoreClient<Channel> = common::wait_for_core(&socket_path).await?;

    // The escape detector must be present for this test to be meaningful.
    let initial_metrics = fetch_metrics(HEALTH_PORT).await?;
    assert!(
        initial_metrics.contains("syva_escape_detector_attached 1"),
        "escape detector is not attached; cannot test detection:\n{initial_metrics}"
    );
    assert!(
        initial_metrics.contains("syva_cgroup_escape_detected_total 0"),
        "expected zero escapes at start:\n{initial_metrics}"
    );

    // 2. Register a zone and two cgroup leaves: src (zoned) and dst (unzoned).
    client
        .register_zone(RegisterZoneRequest {
            zone_name: ZONE.to_string(),
            policy: Some(empty_policy()),
        })
        .await?;
    fs::create_dir_all(&src)?;
    fs::create_dir_all(&dst)?;

    // 3. Park a long-lived workload in the src cgroup, then attach src to zone.
    let child = Command::new("/bin/sh")
        .arg("-c")
        .arg("exec sleep 300")
        .spawn()?;
    let child_pid = child.id();
    let mut cleanup = Cleanup {
        src: src.clone(),
        dst: dst.clone(),
        child: Some(child),
    };
    fs::write(src.join("cgroup.procs"), child_pid.to_string())?;

    let cgroup_id = fs::metadata(&src)?.ino();
    let attach = client
        .attach_container(AttachContainerRequest {
            container_id: format!("e5ca-{pid:08x}"),
            zone_name: ZONE.to_string(),
            cgroup_id,
            source: "integration".to_string(),
            ..Default::default()
        })
        .await?
        .into_inner();
    assert!(attach.ok, "AttachContainer failed: {}", attach.message);

    // 4. ESCAPE: move the zoned workload to the unzoned dst cgroup. This fires
    //    cgroup_attach_task; the fentry reads src (zoned) and dst (unzoned).
    fs::write(dst.join("cgroup.procs"), child_pid.to_string())?;

    // 5. The detector must record exactly the escape and degrade health. The
    //    monitor snapshots escapes on its interval, so poll with patience.
    let metrics = wait_for_metric(HEALTH_PORT, "syva_cgroup_escape_detected_total 1", 60).await?;
    assert!(
        metrics.contains("syva_security_status{status=\"degraded\"} 1"),
        "a detected escape must degrade security status:\n{metrics}"
    );

    // Tidy: stop the parked workload now that the move is observed.
    if let Some(mut c) = cleanup.child.take() {
        let _ = c.kill();
        let _ = c.wait();
    }

    println!("=== syva integration evidence: cgroup-escape detection ===");
    println!("zoned src cgroup_id={cgroup_id}; workload pid={child_pid} moved src -> unzoned dst");
    println!("syva_cgroup_escape_detected_total = 1 (detected; migration NOT prevented)");
    println!("security status degraded by the detected escape");
    Ok(())
}
