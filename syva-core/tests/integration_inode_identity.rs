//! Privileged Linux / BPF-LSM integration test: prove the composite
//! `(dev, ino)` file identity — an inode-number collision across two
//! filesystems must NOT cause cross-zone confusion.
//!
//! This is NOT a normal `cargo test`. It loads and attaches real eBPF LSM
//! programs and therefore requires Linux with BPF LSM enabled, root, and a
//! `syva` group. Run it through the dedicated target:
//!
//! ```text
//! sudo -E make verify-inode-identity
//! ```
//!
//! ## What it proves
//!
//! Two fresh tmpfs mounts hand out the same low inode numbers (per-superblock
//! allocation since Linux 5.9), so the test constructs a real collision: a
//! zoned `secret.txt` on filesystem A and an unrelated file on filesystem B
//! with the SAME inode number but a different device. Under the old
//! ino-only map key the fs-B file would inherit the secret's zone and a
//! zoned workload would be wrongly denied (zone confusion). With the
//! composite key the fs-B open is allowed, while the genuinely zoned fs-A
//! secret is still denied with EPERM.
//!
//! ## Why this cannot be faked
//!
//! The collision precondition (same ino, different st_dev) is asserted
//! before any enforcement runs. If the map key ignored the dev dimension,
//! the cross-fs control would be denied and the test would fail; if
//! enforcement were not working at all, the same-fs control would be allowed
//! and the test would fail. Only a kernel that distinguishes the two files
//! by (dev, ino) passes both.

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

const ZONE_A: &str = "syva-it-devino-a";
const ZONE_B: &str = "syva-it-devino-b";
const SECRET_MARKER: &str = "FS_A_SECRET_DENYME";
const COLLISION_MARKER: &str = "FS_B_COLLISION_OK";

/// Bound on the collision search. In practice the first file on a fresh
/// tmpfs collides because both superblocks start their ino counters equal.
const COLLISION_SEARCH_CAP: usize = 65_536;

fn empty_policy() -> ZonePolicy {
    ZonePolicy {
        host_paths: Vec::new(),
        allowed_zones: Vec::new(),
        allow_ptrace: false,
        zone_type: 0,    // NonGlobal — enforced.
        network_mode: 0, // Isolated (network-locked)
    }
}

/// Best-effort cleanup of the tmpfs mounts and cgroup leaf, run even on panic
/// so the test is safe to rerun.
struct Cleanup {
    mounts: Vec<PathBuf>,
    cgroup: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for mount in &self.mounts {
            let _ = Command::new("umount").arg("-l").arg(mount).status();
            let _ = fs::remove_dir(mount);
        }
        let _ = fs::remove_dir(&self.cgroup);
    }
}

/// Mount a fresh tmpfs at `dir` (created if needed).
fn mount_tmpfs(dir: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(dir)?;
    let status = Command::new("mount")
        .args(["-t", "tmpfs", "-o", "size=16m", "tmpfs"])
        .arg(dir)
        .status()?;
    anyhow::ensure!(
        status.success(),
        "failed to mount tmpfs at {}",
        dir.display()
    );
    Ok(())
}

/// Live (allow, deny) counters for the `file_open` hook, read over gRPC.
/// Only `deny` is workload-attributable (the workload is the only zoned
/// process; unzoned callers are never denied).
async fn file_open_deny(client: &mut SyvaCoreClient<Channel>) -> anyhow::Result<u64> {
    let status = client.status(StatusRequest {}).await?.into_inner();
    Ok(status
        .hooks
        .iter()
        .find(|hook| hook.hook == "file_open")
        .map(|hook| hook.deny)
        .unwrap_or(0))
}

/// Run a one-shot workload that joins `cgroup` and then opens `file` via
/// `cat`. The cgroup move happens in the shell before `exec`.
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
async fn inode_collision_across_filesystems_is_not_zone_confused() -> anyhow::Result<()> {
    let pid = std::process::id();
    let fs_a = PathBuf::from(format!("/tmp/syva-devino-a-{pid}"));
    let fs_b = PathBuf::from(format!("/tmp/syva-devino-b-{pid}"));
    let cgroup = PathBuf::from(format!("/sys/fs/cgroup/syva-it-devino-{pid}"));
    let cgroup_procs = cgroup.join("cgroup.procs");
    let _cleanup = Cleanup {
        mounts: vec![fs_a.clone(), fs_b.clone()],
        cgroup: cgroup.clone(),
    };

    // 1. Two distinct filesystems.
    mount_tmpfs(&fs_a)?;
    mount_tmpfs(&fs_b)?;
    let dev_a = fs::metadata(&fs_a)?.dev();
    let dev_b = fs::metadata(&fs_b)?.dev();
    anyhow::ensure!(
        dev_a != dev_b,
        "precondition failed: the two tmpfs mounts share st_dev {dev_a}"
    );

    // 2. The zoned secret on fs A, then a same-ino file on fs B.
    let secret_file = fs_a.join("secret.txt");
    fs::write(&secret_file, format!("{SECRET_MARKER}\n"))?;
    let secret_ino = fs::metadata(&secret_file)?.ino();

    let mut collision_file = None;
    for i in 0..COLLISION_SEARCH_CAP {
        let candidate = fs_b.join(format!("decoy-{i}.txt"));
        fs::write(&candidate, format!("{COLLISION_MARKER}\n"))?;
        if fs::metadata(&candidate)?.ino() == secret_ino {
            collision_file = Some(candidate);
            break;
        }
    }
    let collision_file = collision_file.ok_or_else(|| {
        anyhow::anyhow!(
            "could not construct an ino collision in {COLLISION_SEARCH_CAP} files — \
             this kernel's tmpfs may not use per-superblock inode allocation (expected on >= 5.9)"
        )
    })?;
    let collision_meta = fs::metadata(&collision_file)?;
    // The precondition that makes this test unfakeable: same ino, different fs.
    assert_eq!(collision_meta.ino(), secret_ino);
    assert_ne!(collision_meta.dev(), fs::metadata(&secret_file)?.dev());

    // 3. Start the local core (loads + attaches eBPF, runs self-tests).
    let sock_dir = tempfile::tempdir()?;
    let socket_path = sock_dir.path().join("syva-core.sock");
    let _core = common::spawn_core(&socket_path)?;
    let mut client = common::wait_for_core(&socket_path).await?;

    // 4. Zones: the secret belongs to zone-b; the workload runs in zone-a.
    //    The fs-B collision file is registered to NO zone.
    for zone in [ZONE_A, ZONE_B] {
        client
            .register_zone(RegisterZoneRequest {
                zone_name: zone.to_string(),
                policy: Some(empty_policy()),
            })
            .await?;
    }
    client
        .register_host_path(RegisterHostPathRequest {
            zone_name: ZONE_B.to_string(),
            path: secret_file.to_string_lossy().into_owned(),
            recursive: false,
        })
        .await?;

    // 5. Attach the workload cgroup to zone-a.
    fs::create_dir_all(&cgroup)?;
    let cgroup_id = fs::metadata(&cgroup)?.ino();
    let attach = client
        .attach_container(AttachContainerRequest {
            container_id: format!("de51-{pid:08x}"),
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

    // 6. CROSS-FS CONTROL — the zone-a workload opens the UNZONED fs-B file
    //    whose ino collides with the zoned secret: must be ALLOWED. Under an
    //    ino-only key this open would be zone-confused and denied.
    let deny_before = file_open_deny(&mut client).await?;
    let cross_fs = workload_open(&cgroup_procs, &collision_file);
    let cross_stdout = String::from_utf8_lossy(&cross_fs.stdout);
    let cross_stderr = String::from_utf8_lossy(&cross_fs.stderr);
    let deny_after_cross = file_open_deny(&mut client).await?;

    assert!(
        cross_fs.status.success() && cross_stdout.contains(COLLISION_MARKER),
        "ZONE CONFUSION: the unzoned fs-B file with a colliding ino was blocked \
         (the map key is not distinguishing filesystems). status={:?} stderr={cross_stderr:?}",
        cross_fs.status.code(),
    );
    assert_eq!(
        deny_after_cross.saturating_sub(deny_before),
        0,
        "ZONE CONFUSION: a file_open deny was recorded for the unzoned fs-B file"
    );

    // 7. ENFORCEMENT CONTROL — the same workload opens the genuinely zoned
    //    fs-A secret: must be DENIED with EPERM, exactly one deny.
    let secret_attempt = workload_open(&cgroup_procs, &secret_file);
    let secret_stdout = String::from_utf8_lossy(&secret_attempt.stdout);
    let secret_stderr = String::from_utf8_lossy(&secret_attempt.stderr);
    let deny_after_secret = file_open_deny(&mut client).await?;
    let deny_delta = deny_after_secret.saturating_sub(deny_after_cross);

    assert!(
        !secret_stdout.contains(SECRET_MARKER),
        "ENFORCEMENT FAILURE: zone-a workload READ the zone-b secret. stdout={secret_stdout:?}"
    );
    assert!(
        !secret_attempt.status.success(),
        "ENFORCEMENT FAILURE: zone-a workload opened the zone-b secret (exit 0)"
    );
    assert!(
        secret_stderr.contains("Operation not permitted"),
        "expected EPERM ('Operation not permitted'), got stderr={secret_stderr:?}"
    );
    assert_eq!(
        deny_delta, 1,
        "expected exactly one new file_open deny from the workload, got delta={deny_delta}"
    );

    // --- Release evidence (printed under --nocapture). ---
    println!("=== syva integration evidence: (dev, ino) inode identity ===");
    println!(
        "ino collision constructed: ino={secret_ino} on st_dev {dev_a} (zoned, fs A) \
         and st_dev {dev_b} (unzoned, fs B)"
    );
    println!(
        "cross-fs control (zone-a -> unzoned same-ino fs-B file): exit=0, content read, \
         deny_delta=0 -> ALLOWED (no zone confusion)"
    );
    println!(
        "enforcement control (zone-a -> zoned fs-A secret): exit={:?} stderr={:?}",
        secret_attempt.status.code(),
        secret_stderr.trim()
    );
    println!("  -> kernel DENIED the open with EPERM; file_open deny_delta=1");
    Ok(())
}
