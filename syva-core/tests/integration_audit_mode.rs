//! Privileged Linux / BPF-LSM integration test: prove **audit mode** records a
//! cross-zone violation as a would-deny decision WITHOUT blocking it.
//!
//! This is NOT a normal `cargo test`. It loads and attaches real eBPF LSM
//! programs and therefore requires Linux with BPF LSM enabled, root, and a
//! `syva` group. Run it through the dedicated target:
//!
//! ```text
//! sudo -E make verify-audit-mode
//! ```
//!
//! ## What this proves (and why it cannot be faked)
//!
//! The setup is identical to the enforcement gate: same zones, same files,
//! same cgroup attach. The only difference is `--mode audit`. The assertions
//! invert the negative control:
//!
//! - the zone-a workload READS the zone-b secret successfully (no EPERM), and
//! - the `file_open` deny counter still increments by exactly 1 (the decision
//!   was made and recorded), and
//! - `/healthz` reports `enforcement_mode: "audit"` while remaining `healthy`.
//!
//! If audit mode silently failed open everywhere, the deny counter would not
//! move. If it failed closed (still enforcing), the read would fail. Only a
//! genuine record-but-allow path satisfies both.

mod common;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::{
    AttachContainerRequest, RegisterHostPathRequest, RegisterZoneRequest, StatusRequest, ZonePolicy,
};
use tonic::transport::Channel;

const ZONE_A: &str = "syva-it-zone-a";
const ZONE_B: &str = "syva-it-zone-b";
const ALLOWED_MARKER: &str = "ZONE_A_PUBLIC_OK";
const SECRET_MARKER: &str = "ZONE_B_SECRET_DENYME";
const HEALTH_PORT: u16 = 19295;

fn empty_policy() -> ZonePolicy {
    ZonePolicy {
        host_paths: Vec::new(),
        allowed_zones: Vec::new(),
        allow_ptrace: false,
        zone_type: 0, // NonGlobal — enforced (audit mode is the only relaxation).
    }
}

struct Cleanup {
    cgroup: PathBuf,
    workdir: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.cgroup);
        let _ = fs::remove_dir_all(&self.workdir);
    }
}

async fn file_open_deny(client: &mut SyvaCoreClient<Channel>) -> anyhow::Result<u64> {
    let status = client.status(StatusRequest {}).await?.into_inner();
    Ok(status
        .hooks
        .iter()
        .find(|hook| hook.hook == "file_open")
        .map(|hook| hook.deny)
        .unwrap_or(0))
}

fn workload_open(cgroup_procs: &Path, file: &Path) -> Output {
    let script = format!(
        "echo $$ > '{}' && exec cat '{}'",
        cgroup_procs.display(),
        file.display()
    );
    Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .output()
        .expect("failed to spawn workload shell")
}

/// Minimal raw-HTTP GET against the core's health server. Avoids pulling an
/// HTTP client into dev-dependencies for one assertion.
async fn fetch_healthz(port: u16) -> anyhow::Result<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    stream
        .write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

#[tokio::test]
#[ignore = "requires Linux, root privileges, BPF LSM support, and group 'syva'"]
async fn audit_mode_records_would_deny_without_blocking() -> anyhow::Result<()> {
    let pid = std::process::id();
    let workdir = PathBuf::from(format!("/tmp/syva-audit-it-{pid}"));
    let cgroup = PathBuf::from(format!("/sys/fs/cgroup/syva-audit-it-{pid}-a"));
    let cgroup_procs = cgroup.join("cgroup.procs");
    let _cleanup = Cleanup {
        cgroup: cgroup.clone(),
        workdir: workdir.clone(),
    };

    // 1. Start the local core in AUDIT mode.
    let sock_dir = tempfile::tempdir()?;
    let socket_path = sock_dir.path().join("syva-core.sock");
    let health_port = HEALTH_PORT.to_string();
    let _core = common::spawn_core_with_args(
        &socket_path,
        &["--mode", "audit", "--health-port", &health_port],
    )?;
    let mut client = common::wait_for_core(&socket_path).await?;

    // 2. Same zone/file/cgroup setup as the enforcement gate.
    for zone in [ZONE_A, ZONE_B] {
        client
            .register_zone(RegisterZoneRequest {
                zone_name: zone.to_string(),
                policy: Some(empty_policy()),
            })
            .await?;
    }

    fs::create_dir_all(&workdir)?;
    let allowed_file = workdir.join("zone-a-allowed.txt");
    let secret_file = workdir.join("zone-b-secret.txt");
    fs::write(&allowed_file, format!("{ALLOWED_MARKER}\n"))?;
    fs::write(&secret_file, format!("{SECRET_MARKER}\n"))?;

    client
        .register_host_path(RegisterHostPathRequest {
            zone_name: ZONE_A.to_string(),
            path: allowed_file.to_string_lossy().into_owned(),
            recursive: false,
        })
        .await?;
    client
        .register_host_path(RegisterHostPathRequest {
            zone_name: ZONE_B.to_string(),
            path: secret_file.to_string_lossy().into_owned(),
            recursive: false,
        })
        .await?;

    fs::create_dir_all(&cgroup)?;
    let cgroup_id = fs::metadata(&cgroup)?.ino();
    let attach = client
        .attach_container(AttachContainerRequest {
            container_id: format!("a0d1-{pid:08x}"),
            zone_name: ZONE_A.to_string(),
            cgroup_id,
            source: "integration".to_string(),
            ..Default::default()
        })
        .await?
        .into_inner();
    assert!(
        attach.ok,
        "AttachContainer failed (cgroup_id={cgroup_id}): {}",
        attach.message
    );

    // 3. The health endpoint must report audit mode and stay healthy —
    //    audit is an operator choice, not a degradation.
    let healthz = fetch_healthz(HEALTH_PORT).await?;
    assert!(
        healthz.contains("\"enforcement_mode\":\"audit\""),
        "healthz does not report audit mode: {healthz}"
    );
    assert!(
        healthz.contains("\"status\":\"healthy\""),
        "audit mode must not degrade health: {healthz}"
    );

    // 4. POSITIVE control — zone-a workload reads its own zone-a file.
    let positive = workload_open(&cgroup_procs, &allowed_file);
    let pos_stdout = String::from_utf8_lossy(&positive.stdout);
    assert!(
        positive.status.success() && pos_stdout.contains(ALLOWED_MARKER),
        "POSITIVE CONTROL FAILED: zone-a workload could not read its own zone-a file. \
         status={:?} stdout={pos_stdout:?} stderr={:?}",
        positive.status.code(),
        String::from_utf8_lossy(&positive.stderr),
    );

    // 5. AUDIT control — the cross-zone read must SUCCEED (no EPERM) while
    //    the deny counter records exactly one would-deny decision.
    let deny_before = file_open_deny(&mut client).await?;

    let audited = workload_open(&cgroup_procs, &secret_file);
    let audited_exit = audited.status.code();
    let audited_stdout = String::from_utf8_lossy(&audited.stdout);
    let audited_stderr = String::from_utf8_lossy(&audited.stderr);

    let deny_after = file_open_deny(&mut client).await?;
    let deny_delta = deny_after.saturating_sub(deny_before);

    assert!(
        audited.status.success(),
        "AUDIT FAILURE: cross-zone read was BLOCKED in audit mode \
         (exit={audited_exit:?}, stderr={audited_stderr:?}); audit must not enforce"
    );
    assert!(
        audited_stdout.contains(SECRET_MARKER),
        "AUDIT FAILURE: cross-zone read returned no content in audit mode. \
         stdout={audited_stdout:?}"
    );
    assert_eq!(
        deny_delta, 1,
        "expected exactly one would-deny decision recorded for the audited read, \
         got delta={deny_delta} (before={deny_before}, after={deny_after})"
    );

    // --- Release evidence (printed under --nocapture). ---
    println!("=== syva integration evidence: audit mode (observe-only) ===");
    println!("core started with --mode audit; healthz enforcement_mode=audit, status=healthy");
    println!("host cgroup attached to zone-a: cgroup_id={cgroup_id}");
    println!("positive (zone-a -> zone-a file): exit=0, content read -> ALLOWED");
    println!(
        "audited (zone-a -> zone-b file): exit={audited_exit:?} -> NOT BLOCKED, content read \
         (audit mode)"
    );
    println!(
        "file_open deny decisions: before={deny_before} after={deny_after} delta={deny_delta} \
         (recorded as would-deny; operation proceeded)"
    );
    Ok(())
}
