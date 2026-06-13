//! Privileged Linux / BPF-LSM integration test: the ALLOW contract — the
//! operations Syva must NOT block.
//!
//! Run via:
//!
//! ```text
//! sudo -E make verify-allow
//! ```
//!
//! ## Why this gate exists
//!
//! Every other gate asserts a denial. None of them would catch an
//! over-blocking regression — a bug that denies something legitimate. A core
//! that denied *everything* would pass the entire deny-side suite while being
//! completely broken for real workloads, which is the failure that gets an
//! enforcement product ripped out. This gate proves the negative space: a set
//! of operations that must succeed, each asserted with `file_open` /
//! `socket_connect` `deny_delta == 0`.
//!
//! ## Why it cannot pass trivially
//!
//! The same workload, cgroup, and zoned files are also used to confirm a
//! genuine cross-zone denial DOES fire (the final check). So a core that
//! allowed everything fails the denial check, and a core that blocks too much
//! fails the allow checks — only correct enforcement passes both.

mod common;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::{
    AllowCommRequest, AttachContainerRequest, RegisterHostPathRequest, RegisterZoneRequest,
    StatusRequest, ZonePolicy,
};
use tonic::transport::Channel;

const ZONE_A: &str = "syva-allow-a";
const ZONE_B: &str = "syva-allow-b";
const A_MARKER: &str = "ZONE_A_OK";
const B_MARKER: &str = "ZONE_B_OK";

fn locked_policy() -> ZonePolicy {
    ZonePolicy {
        host_paths: Vec::new(),
        allowed_zones: Vec::new(),
        allow_ptrace: false,
        zone_type: 0,
        network_mode: 0, // Isolated — network-locked, so loopback-allow is meaningful.
        allowed_egress_cidrs: vec![],
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
    hook_deny(client, "file_open").await
}

async fn hook_deny(client: &mut SyvaCoreClient<Channel>, hook: &str) -> anyhow::Result<u64> {
    let status = client.status(StatusRequest {}).await?.into_inner();
    Ok(status
        .hooks
        .iter()
        .find(|h| h.hook == hook)
        .map(|h| h.deny)
        .unwrap_or(0))
}

fn workload(cgroup_procs: &Path, command: &str) -> Output {
    let script = format!("echo $$ > '{}' && {command}", cgroup_procs.display());
    Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .output()
        .expect("failed to spawn workload shell")
}

async fn attach(
    client: &mut SyvaCoreClient<Channel>,
    cgroup: &Path,
    zone: &str,
) -> anyhow::Result<()> {
    let cgroup_id = fs::metadata(cgroup)?.ino();
    let attach = client
        .attach_container(AttachContainerRequest {
            container_id: format!("a110{:08x}", std::process::id()),
            zone_name: zone.to_string(),
            cgroup_id,
            source: "integration".to_string(),
            ..Default::default()
        })
        .await?
        .into_inner();
    anyhow::ensure!(attach.ok, "attach failed: {}", attach.message);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Linux, root privileges, BPF LSM support, and group 'syva'"]
async fn allow_contract_must_not_overblock() -> anyhow::Result<()> {
    let pid = std::process::id();
    let workdir = PathBuf::from(format!("/tmp/syva-allow-it-{pid}"));
    let cgroup = PathBuf::from(format!("/sys/fs/cgroup/syva-allow-it-{pid}"));
    let cgroup_procs = cgroup.join("cgroup.procs");
    let _cleanup = Cleanup {
        cgroup: cgroup.clone(),
        workdir: workdir.clone(),
    };

    let sock_dir = tempfile::tempdir()?;
    let socket_path = sock_dir.path().join("syva-core.sock");
    let _core = common::spawn_core(&socket_path)?;
    let mut client = common::wait_for_core(&socket_path).await?;

    for zone in [ZONE_A, ZONE_B] {
        client
            .register_zone(RegisterZoneRequest {
                zone_name: zone.to_string(),
                policy: Some(locked_policy()),
            })
            .await?;
    }

    fs::create_dir_all(&workdir)?;
    let a_file = workdir.join("a.txt");
    let b_file = workdir.join("b.txt");
    fs::write(&a_file, format!("{A_MARKER}\n"))?;
    fs::write(&b_file, format!("{B_MARKER}\n"))?;
    for (zone, file) in [(ZONE_A, &a_file), (ZONE_B, &b_file)] {
        client
            .register_host_path(RegisterHostPathRequest {
                zone_name: zone.to_string(),
                path: file.to_string_lossy().into_owned(),
                recursive: false,
            })
            .await?;
    }

    fs::create_dir_all(&cgroup)?;
    attach(&mut client, &cgroup, ZONE_A).await?;

    // ALLOW 1 — same-zone file open. The most basic must-not-block.
    let before = file_open_deny(&mut client).await?;
    let same_zone = workload(&cgroup_procs, &format!("exec cat '{}'", a_file.display()));
    let after = file_open_deny(&mut client).await?;
    let out = String::from_utf8_lossy(&same_zone.stdout);
    anyhow::ensure!(
        same_zone.status.success() && out.contains(A_MARKER),
        "OVER-BLOCK: zone-a workload could not read its OWN zone-a file. stderr={:?}",
        String::from_utf8_lossy(&same_zone.stderr)
    );
    anyhow::ensure!(
        after == before,
        "OVER-BLOCK: same-zone file open moved the deny counter ({before} -> {after})"
    );

    // ALLOW 2 — loopback from a network-LOCKED zone (must always reach lo).
    let before_c = hook_deny(&mut client, "socket_connect").await?;
    let loopback = workload(
        &cgroup_procs,
        "exec python3 -c \"import socket,sys
s=socket.socket(); s.settimeout(2)
try: s.connect(('127.0.0.1', 9))
except ConnectionRefusedError: pass
except OSError as e: print('EPERM' if e.errno==1 else 'OTHER', file=sys.stderr); sys.exit(3)\"",
    );
    let after_c = hook_deny(&mut client, "socket_connect").await?;
    anyhow::ensure!(
        loopback.status.code() != Some(3),
        "OVER-BLOCK: locked zone was denied loopback. stderr={:?}",
        String::from_utf8_lossy(&loopback.stderr)
    );
    anyhow::ensure!(
        after_c == before_c,
        "OVER-BLOCK: loopback connect moved the socket_connect deny counter ({before_c} -> {after_c})"
    );

    // CONTROL — confirm the SAME setup still denies a real cross-zone open,
    // so "all green" cannot mean "allows everything".
    let before_d = file_open_deny(&mut client).await?;
    let cross = workload(&cgroup_procs, &format!("exec cat '{}'", b_file.display()));
    let after_d = file_open_deny(&mut client).await?;
    anyhow::ensure!(
        !cross.status.success() && after_d == before_d + 1,
        "control failed: cross-zone open was not denied (delta {} != 1)",
        after_d.saturating_sub(before_d)
    );

    // ALLOW 3 — after AllowComm, the previously-denied pair is permitted.
    client
        .allow_comm(AllowCommRequest {
            zone_a: ZONE_A.to_string(),
            zone_b: ZONE_B.to_string(),
        })
        .await?;
    let before_e = file_open_deny(&mut client).await?;
    let allowed = workload(&cgroup_procs, &format!("exec cat '{}'", b_file.display()));
    let after_e = file_open_deny(&mut client).await?;
    let allowed_out = String::from_utf8_lossy(&allowed.stdout);
    anyhow::ensure!(
        allowed.status.success() && allowed_out.contains(B_MARKER),
        "OVER-BLOCK: AllowComm pair was still denied. stderr={:?}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    anyhow::ensure!(
        after_e == before_e,
        "OVER-BLOCK: AllowComm'd open moved the deny counter ({before_e} -> {after_e})"
    );

    println!("=== syva integration evidence: ALLOW contract (must-not-block) ===");
    println!("same-zone file open      : ALLOWED, deny_delta=0");
    println!("loopback from locked zone: ALLOWED, deny_delta=0");
    println!("cross-zone control       : DENIED, deny_delta=1 (green != allow-everything)");
    println!("AllowComm pair           : ALLOWED at runtime, deny_delta=0");
    Ok(())
}
