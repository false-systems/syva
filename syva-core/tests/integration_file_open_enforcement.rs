//! Privileged Linux / BPF-LSM integration test: prove the `file_open` hook
//! actually blocks a cross-zone file read in the kernel.
//!
//! This is NOT a normal `cargo test`. It loads and attaches real eBPF LSM
//! programs and therefore requires Linux with BPF LSM enabled, root, and a
//! `syva` group. Run it through the dedicated target:
//!
//! ```text
//! sudo -E make verify-integration
//! ```
//!
//! ## Why processes, not containers
//!
//! The supported enforcement key is the cgroup id (`bpf_get_current_cgroup_id`
//! → `ZONE_MEMBERSHIP`). A container runtime would give us that id via a
//! container's cgroup; this host has no container runtime, so the test creates
//! its own cgroup-v2 leaf, moves a workload process into it, and attaches that
//! cgroup to a zone through the exact same `AttachContainer` gRPC the adapters
//! use. It proves kernel enforcement for cgroup/workload membership — container
//! *runtime* integration (containerd/k8s adapters) is a separate follow-up.
//!
//! ## Why this cannot be faked
//!
//! If anything in the setup is wrong (wrong cgroup id, attach failed, hook not
//! firing) the workload's cgroup is simply not in `ZONE_MEMBERSHIP`, so
//! `file_open` treats the caller as unzoned and ALLOWS the read — which makes
//! the negative control FAIL. A green run is only possible if the kernel
//! genuinely denied the cross-zone open.

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

fn empty_policy() -> ZonePolicy {
    ZonePolicy {
        host_paths: Vec::new(),
        allowed_zones: Vec::new(),
        allow_ptrace: false,
        zone_type: 0, // NonGlobal — enforced.
    }
}

/// Best-effort cleanup of the cgroup leaf and work directory, run even on panic
/// so the test is safe to rerun.
struct Cleanup {
    cgroup: PathBuf,
    workdir: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        // The cgroup is empty once the synchronous workloads have exited.
        let _ = fs::remove_dir(&self.cgroup);
        let _ = fs::remove_dir_all(&self.workdir);
    }
}

/// Live (allow, deny) counters for the `file_open` hook, read over gRPC.
///
/// Note: `allow` is a GLOBAL counter. The `file_open` hook runs on every
/// `open()` by every process; unzoned/system callers return allow, so `allow`
/// reflects system-wide activity and is NOT workload-specific. Only `deny` is
/// attributable here, because the workload is the only zoned process and
/// unzoned callers can never be denied.
async fn file_open_allow_deny(client: &mut SyvaCoreClient<Channel>) -> anyhow::Result<(u64, u64)> {
    let status = client.status(StatusRequest {}).await?.into_inner();
    Ok(status
        .hooks
        .iter()
        .find(|hook| hook.hook == "file_open")
        .map(|hook| (hook.allow, hook.deny))
        .unwrap_or((0, 0)))
}

/// Run a one-shot workload that joins `cgroup` and then opens `file` via
/// `cat`. The cgroup move happens in the shell before `exec`, so by the time
/// `cat` issues `open()` the process is a member of the zone-attached cgroup.
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

#[tokio::test]
#[ignore = "requires Linux, root privileges, BPF LSM support, and group 'syva'"]
async fn file_open_cross_zone_read_is_blocked() -> anyhow::Result<()> {
    let pid = std::process::id();
    let workdir = PathBuf::from(format!("/tmp/syva-integration-{pid}"));
    let cgroup = PathBuf::from(format!("/sys/fs/cgroup/syva-it-{pid}-a"));
    let cgroup_procs = cgroup.join("cgroup.procs");
    let _cleanup = Cleanup {
        cgroup: cgroup.clone(),
        workdir: workdir.clone(),
    };

    // 1. Start the local core (loads + attaches eBPF, runs self-tests).
    let sock_dir = tempfile::tempdir()?;
    let socket_path = sock_dir.path().join("syva-core.sock");
    let _core = common::spawn_core(&socket_path)?;
    let mut client = common::wait_for_core(&socket_path).await?;

    // 2. Register two zones.
    for zone in [ZONE_A, ZONE_B] {
        client
            .register_zone(RegisterZoneRequest {
                zone_name: zone.to_string(),
                policy: Some(empty_policy()),
            })
            .await?;
    }

    // 3. Create one file per zone. Both are root-owned and world-readable, so
    //    a denial can only come from Syvä, not from filesystem permissions.
    fs::create_dir_all(&workdir)?;
    let allowed_file = workdir.join("zone-a-allowed.txt");
    let secret_file = workdir.join("zone-b-secret.txt");
    fs::write(&allowed_file, format!("{ALLOWED_MARKER}\n"))?;
    fs::write(&secret_file, format!("{SECRET_MARKER}\n"))?;

    // Control C0: an UNZONED reader (this test process) can read the secret.
    // This proves the file is intrinsically readable; any later block is Syvä's.
    let intrinsic = fs::read_to_string(&secret_file)?;
    assert!(
        intrinsic.contains(SECRET_MARKER),
        "precondition failed: secret file is not intrinsically readable"
    );

    // Map each file's inode to its owning zone.
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

    // 4. Create the workload cgroup and attach it to zone-a. The cgroup id the
    //    kernel reports via bpf_get_current_cgroup_id() is the cgroup-v2
    //    directory inode on this kernel.
    fs::create_dir_all(&cgroup)?;
    let cgroup_id = fs::metadata(&cgroup)?.ino();
    let attach = client
        .attach_container(AttachContainerRequest {
            // container_id must be hex/dash/underscore only (core validation).
            container_id: format!("5a4a-{pid:08x}"),
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

    // 5. POSITIVE control — zone-a workload reads its own zone-a file: allowed.
    let positive = workload_open(&cgroup_procs, &allowed_file);
    let pos_stdout = String::from_utf8_lossy(&positive.stdout);
    assert!(
        positive.status.success() && pos_stdout.contains(ALLOWED_MARKER),
        "POSITIVE CONTROL FAILED: zone-a workload could not read its own zone-a file. \
         status={:?} stdout={pos_stdout:?} stderr={:?}",
        positive.status.code(),
        String::from_utf8_lossy(&positive.stderr),
    );

    // 6. NEGATIVE control — zone-a workload reads the zone-b file: must block.
    //    Snapshot the deny counter immediately before so the delta is
    //    attributable to this single workload open.
    let (_, deny_before) = file_open_allow_deny(&mut client).await?;

    let negative = workload_open(&cgroup_procs, &secret_file);
    let neg_exit = negative.status.code();
    let neg_stdout = String::from_utf8_lossy(&negative.stdout);
    let neg_stderr = String::from_utf8_lossy(&negative.stderr);

    let (allow_after, deny_after) = file_open_allow_deny(&mut client).await?;
    let deny_delta = deny_after.saturating_sub(deny_before);

    // --- Hard assertions: the kernel actually blocked the cross-zone open. ---
    assert!(
        !neg_stdout.contains(SECRET_MARKER),
        "ENFORCEMENT FAILURE: zone-a workload READ zone-b secret content. stdout={neg_stdout:?}"
    );
    assert!(
        !negative.status.success(),
        "ENFORCEMENT FAILURE: zone-a workload opened the zone-b file (exit 0); \
         the kernel did not block the cross-zone read"
    );
    // The hook denies by returning -1, which the kernel surfaces as EPERM
    // ("Operation not permitted") — not EACCES ("Permission denied").
    assert!(
        neg_stderr.contains("Operation not permitted"),
        "expected EPERM ('Operation not permitted') from the blocked open, got stderr={neg_stderr:?}"
    );
    // Exactly one new deny is attributable to the workload (it is the only
    // zoned process; unzoned callers are always allowed, never denied).
    assert_eq!(
        deny_delta, 1,
        "expected exactly one new file_open deny from the workload, got delta={deny_delta} \
         (before={deny_before}, after={deny_after})"
    );

    // --- Release evidence (printed under --nocapture for the PR/release log). ---
    println!("=== syva integration evidence: file_open cross-zone enforcement ===");
    println!("host cgroup attached to zone-a: cgroup_id={cgroup_id}");
    println!("positive (zone-a -> zone-a file): exit=0, content read -> ALLOWED");
    println!(
        "negative (zone-a -> zone-b file): exit={neg_exit:?} stderr={:?}",
        neg_stderr.trim()
    );
    println!("  -> kernel DENIED the open with EPERM (Operation not permitted); no content read");
    println!(
        "file_open deny: before={deny_before} after={deny_after} deny_delta={deny_delta} (workload-attributable)"
    );
    println!(
        "file_open allow: {allow_after} (GLOBAL counter: every allowed open system-wide, \
         including unzoned/system processes; NOT workload-specific)"
    );
    Ok(())
}
