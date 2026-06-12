//! Privileged Linux / BPF-LSM **container** integration test.
//!
//! Proves Syvä blocks a forbidden cross-zone `file_open` performed by a process
//! inside a real container, using the live kernel enforcement path. This is not
//! a unit test, not a mock, and not merely an API-success check.
//!
//! Run it through the dedicated target (it loads/attaches real BPF-LSM programs,
//! starts a container, and needs root + a container runtime):
//!
//! ```text
//! sudo -E make verify-container-integration
//! ```
//!
//! Set `SYVA_SOCKET=/path/to/syva-core.sock` to verify an already-deployed
//! core instead of spawning a managed test core. That mode is used by
//! `verify-deployment` / `lima-verify-deployment`.
//!
//! ## Why the container's main process (not `podman exec`)
//!
//! Enforcement keys on `bpf_get_current_cgroup_id()` (the host cgroup). A
//! container has its own cgroup namespace, so `exec` processes report `0::/`
//! from inside and their host cgroup is awkward to attribute. The container's
//! **main** process has a stable host cgroup (`.../libpod-<id>.scope/container`)
//! that we read from `/proc/<pid>/cgroup` and attach via the real
//! `AttachContainer` gRPC — exactly what an adapter does. The workload runs as
//! that main process (and its `cat` children inherit the cgroup), so the open is
//! performed by the zoned cgroup.
//!
//! ## Why this cannot be faked
//!
//! The allowed and forbidden files live in the same bind mount with identical
//! permissions and identical AppArmor treatment; the only difference is the
//! Syvä zone registration. A host (unzoned) read of the secret succeeds first,
//! proving intrinsic readability. If anything in the setup is wrong the workload
//! is simply unzoned, which `file_open` ALLOWS — which fails the negative
//! control. A green run is only possible on a genuine kernel denial.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::{
    AttachContainerRequest, DetachContainerRequest, RegisterHostPathRequest, RegisterZoneRequest,
    RemoveZoneRequest, StatusRequest, ZonePolicy,
};
use tonic::transport::Channel;

const ZONE_A_PREFIX: &str = "syva-it-zone-a";
const ZONE_B_PREFIX: &str = "syva-it-zone-b";
const ALLOWED_MARKER: &str = "ZONE_A_PUBLIC_OK";
const SECRET_MARKER: &str = "ZONE_B_SECRET_DENYME";
const DEFAULT_IMAGE: &str = "docker.io/library/busybox";

fn empty_policy() -> ZonePolicy {
    ZonePolicy {
        host_paths: Vec::new(),
        allowed_zones: Vec::new(),
        allow_ptrace: false,
        zone_type: 0, // NonGlobal — enforced.
        network_mode: 0,
        allowed_egress_cidrs: vec![],
    }
}

fn have(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Detect a Docker-CLI-compatible runtime: `SYVA_CONTAINER_RUNTIME` override,
/// else docker → nerdctl → podman. `ctr` is intentionally not used here (its CLI
/// is not compatible with the `run/inspect/rm` calls below); the target fails
/// clearly rather than silently falling back to a non-container test.
fn detect_runtime() -> anyhow::Result<String> {
    if let Ok(r) = std::env::var("SYVA_CONTAINER_RUNTIME") {
        if have(&r) {
            return Ok(r);
        }
        anyhow::bail!("SYVA_CONTAINER_RUNTIME={r} was set but '{r}' is not on PATH");
    }
    for r in ["docker", "nerdctl", "podman"] {
        if have(r) {
            return Ok(r.to_string());
        }
    }
    anyhow::bail!(
        "verify-container-integration requires docker, nerdctl, podman, or another \
         supported container runtime"
    )
}

fn run_capture(bin: &str, args: &[&str]) -> anyhow::Result<String> {
    let out = Command::new(bin).args(args).output()?;
    if !out.status.success() {
        anyhow::bail!(
            "`{bin} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Host cgroup-v2 id of the container's main process — the value the kernel
/// reports via `bpf_get_current_cgroup_id()` for that cgroup (the directory
/// inode on cgroup v2).
fn container_cgroup_id(runtime: &str, name: &str) -> anyhow::Result<(u64, String)> {
    let pid = run_capture(runtime, &["inspect", "-f", "{{.State.Pid}}", name])?
        .trim()
        .to_string();
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup"))?;
    let rel = cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))
        .ok_or_else(|| anyhow::anyhow!("no cgroup-v2 line in /proc/{pid}/cgroup"))?
        .trim()
        .to_string();
    let dir = format!("/sys/fs/cgroup{rel}");
    let ino = std::os::unix::fs::MetadataExt::ino(&std::fs::metadata(&dir)?);
    Ok((ino, rel))
}

async fn file_open_allow_deny(client: &mut SyvaCoreClient<Channel>) -> anyhow::Result<(u64, u64)> {
    let status = client.status(StatusRequest {}).await?.into_inner();
    Ok(status
        .hooks
        .iter()
        .find(|hook| hook.hook == "file_open")
        .map(|hook| (hook.allow, hook.deny))
        .unwrap_or((0, 0)))
}

fn wait_for_file(path: &Path, timeout: Duration) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if path.exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    anyhow::bail!("timed out waiting for {}", path.display())
}

/// Removes the container and work directory even on panic, so reruns are clean.
struct Cleanup {
    runtime: String,
    container: String,
    workdir: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = Command::new(&self.runtime)
            .args(["rm", "-f", &self.container])
            .output();
        let _ = std::fs::remove_dir_all(&self.workdir);
    }
}

#[tokio::test]
#[ignore = "requires Linux, root, BPF LSM, group 'syva', and a container runtime"]
async fn container_file_open_cross_zone_is_blocked() -> anyhow::Result<()> {
    let pid = std::process::id();
    let runtime = detect_runtime()?;
    let image = std::env::var("SYVA_TEST_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
    let version = run_capture(&runtime, &["--version"])
        .unwrap_or_default()
        .trim()
        .to_string();
    let zone_a = format!("{ZONE_A_PREFIX}-{pid}");
    let zone_b = format!("{ZONE_B_PREFIX}-{pid}");
    let container = format!("syva-it-container-a-{pid}");
    let workdir = PathBuf::from(format!("/tmp/syva-container-it-{pid}"));
    let _cleanup = Cleanup {
        runtime: runtime.clone(),
        container: container.clone(),
        workdir: workdir.clone(),
    };

    // Target Syvä: an already-deployed core (SYVA_SOCKET) for deployment
    // verification, or a managed core for the standalone container test.
    let deployed_socket = std::env::var_os("SYVA_SOCKET").map(PathBuf::from);
    let deployment_mode = deployed_socket.is_some();

    // --- Declared contract: printed BEFORE running the workload. ---
    if deployment_mode {
        println!("=== syva deployment verification contract ===");
        println!("PASS:  deployed Syvä allows a container in zone-a to read its zone-a file.");
        println!("BLOCK: deployed Syvä blocks a container in zone-a from reading the zone-b file.");
    } else {
        println!("=== syva container integration contract ===");
        println!("PASS:  container in zone-a can read its own zone-a file.");
        println!("BLOCK: container in zone-a cannot read protected zone-b file.");
    }
    println!("HOOK:  file_open");
    println!("EXPECTED DENIAL: EPERM / Operation not permitted");
    println!("EXPECTED KERNEL EVIDENCE: file_open deny_delta=1");

    // Ensure the image is present (pull once if needed).
    if run_capture(&runtime, &["image", "inspect", &image]).is_err() {
        run_capture(&runtime, &["pull", &image])
            .map_err(|e| anyhow::anyhow!("image '{image}' unavailable and pull failed: {e}"))?;
    }

    // Files: one per zone, root-owned and world-readable so any denial is Syvä's.
    let zone_a_dir = workdir.join("zone-a");
    let zone_b_dir = workdir.join("zone-b");
    let ctl = workdir.join("ctl");
    for d in [&zone_a_dir, &zone_b_dir, &ctl] {
        std::fs::create_dir_all(d)?;
    }
    let allowed_file = zone_a_dir.join("allowed.txt");
    let secret_file = zone_b_dir.join("secret.txt");
    std::fs::write(&allowed_file, format!("{ALLOWED_MARKER}\n"))?;
    std::fs::write(&secret_file, format!("{SECRET_MARKER}\n"))?;

    // Control C0: an unzoned host reader can read the secret (proves the file is
    // intrinsically readable; the later block is Syvä's, not Unix permissions).
    let intrinsic = std::fs::read_to_string(&secret_file)?;
    assert!(
        intrinsic.contains(SECRET_MARKER),
        "precondition failed: secret file is not intrinsically readable"
    );

    // --- Obtain a Syvä client: connect to the deployed core, or spawn a
    //     managed one for the standalone test. In deployment mode we do NOT
    //     start a core — the point is to verify the already-deployed instance. ---
    let managed: Option<(tempfile::TempDir, common::CoreProcess)>;
    let socket_path = match deployed_socket {
        Some(path) => {
            if !path.exists() {
                anyhow::bail!(
                    "SYVA_SOCKET={} does not exist — is syva-core deployed and running? \
                     (run `make lima-deploy` first)",
                    path.display()
                );
            }
            println!(
                "mode: existing-core (deployment), socket={}",
                path.display()
            );
            managed = None;
            path
        }
        None => {
            println!("mode: managed-core (standalone container test)");
            let dir = tempfile::tempdir()?;
            let sp = dir.path().join("syva-core.sock");
            let core = common::spawn_core(&sp)?;
            managed = Some((dir, core));
            sp
        }
    };
    // Keep the tempdir and child core alive for the whole standalone test.
    let _managed = managed;
    let mut client = common::wait_for_core(&socket_path).await?;

    for zone in [&zone_a, &zone_b] {
        client
            .register_zone(RegisterZoneRequest {
                zone_name: zone.clone(),
                policy: Some(empty_policy()),
            })
            .await?;
    }
    for (zone, file) in [(&zone_a, &allowed_file), (&zone_b, &secret_file)] {
        client
            .register_host_path(RegisterHostPathRequest {
                zone_name: zone.clone(),
                path: file.to_string_lossy().into_owned(),
                recursive: false,
            })
            .await?;
    }

    // --- Start the real container. Its main process waits for trigger files,
    //     then opens the zone files; results land in the bind-mounted ctl dir. ---
    let script = "\
        touch /work/ctl/up; \
        while [ ! -e /work/ctl/go ]; do sleep 0.1; done; \
        cat /work/zone-a/allowed.txt > /work/ctl/allowed.out 2> /work/ctl/allowed.err; \
        echo $? > /work/ctl/allowed.code; touch /work/ctl/allowed.done; \
        while [ ! -e /work/ctl/go2 ]; do sleep 0.1; done; \
        cat /work/zone-b/secret.txt > /work/ctl/secret.out 2> /work/ctl/secret.err; \
        echo $? > /work/ctl/secret.code; touch /work/ctl/secret.done; \
        sleep 3";
    let mount = format!("{}:/work", workdir.display());
    let cid = run_capture(
        &runtime,
        &[
            "run", "-d", "--name", &container, "-v", &mount, &image, "sh", "-c", script,
        ],
    )?
    .trim()
    .chars()
    .take(12)
    .collect::<String>();

    wait_for_file(&ctl.join("up"), Duration::from_secs(20))?;

    // Resolve the container's host cgroup and attach it to zone-a.
    let (cgroup_id, cgroup_rel) = container_cgroup_id(&runtime, &container)?;
    let attach_container_id = format!("c0a-{pid:08x}");
    let attach = client
        .attach_container(AttachContainerRequest {
            container_id: attach_container_id.clone(),
            zone_name: zone_a.clone(),
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

    println!("--- container setup ---");
    println!("runtime: {runtime} ({version})");
    println!("image:   {image}");
    println!("container: name={container} id={cid}");
    println!("cgroup:  host_path={cgroup_rel} cgroup_id={cgroup_id} -> zone={zone_a}");

    // --- POSITIVE: zone-a workload reads its own zone-a file. ---
    std::fs::write(ctl.join("go"), b"")?;
    wait_for_file(&ctl.join("allowed.done"), Duration::from_secs(20))?;
    let allowed_code = std::fs::read_to_string(ctl.join("allowed.code"))?
        .trim()
        .to_string();
    let allowed_out = std::fs::read_to_string(ctl.join("allowed.out")).unwrap_or_default();
    assert!(
        allowed_code == "0" && allowed_out.contains(ALLOWED_MARKER),
        "POSITIVE CONTROL FAILED: zone-a container could not read its own zone-a file. \
         code={allowed_code} out={allowed_out:?} err={:?}",
        std::fs::read_to_string(ctl.join("allowed.err")).unwrap_or_default()
    );

    // --- NEGATIVE: same container reads the zone-b file. Snapshot deny first. ---
    let (_, deny_before) = file_open_allow_deny(&mut client).await?;
    std::fs::write(ctl.join("go2"), b"")?;
    wait_for_file(&ctl.join("secret.done"), Duration::from_secs(20))?;
    let (allow_after, deny_after) = file_open_allow_deny(&mut client).await?;
    let deny_delta = deny_after.saturating_sub(deny_before);

    let secret_code = std::fs::read_to_string(ctl.join("secret.code"))?
        .trim()
        .to_string();
    let secret_out = std::fs::read_to_string(ctl.join("secret.out")).unwrap_or_default();
    let secret_err = std::fs::read_to_string(ctl.join("secret.err")).unwrap_or_default();

    // --- Hard assertions: the kernel blocked the cross-zone open. ---
    assert!(
        !secret_out.contains(SECRET_MARKER),
        "ENFORCEMENT FAILURE: container READ zone-b secret content. out={secret_out:?}"
    );
    assert!(
        secret_code != "0",
        "ENFORCEMENT FAILURE: container read of zone-b file exited 0; not blocked. \
         out={secret_out:?} err={secret_err:?}"
    );
    // The hook denies by returning -1, surfaced as EPERM ("Operation not
    // permitted") — not EACCES ("Permission denied").
    assert!(
        secret_err.contains("Operation not permitted"),
        "expected EPERM ('Operation not permitted') from the blocked open, got err={secret_err:?}"
    );
    assert_eq!(
        deny_delta, 1,
        "expected exactly one new file_open deny from the container, got delta={deny_delta} \
         (before={deny_before}, after={deny_after})"
    );

    // --- Release evidence. ---
    println!("--- allowed operation (zone-a -> zone-a file) ---");
    println!("cmd: cat /work/zone-a/allowed.txt (in container)");
    println!("exit={allowed_code} -> ALLOWED, content present");
    println!("--- blocked operation (zone-a -> zone-b file) ---");
    println!("cmd: cat /work/zone-b/secret.txt (in container)");
    println!("exit={secret_code} stderr={:?}", secret_err.trim());
    println!("  -> kernel DENIED the open with EPERM (Operation not permitted); no secret read");
    println!(
        "file_open deny: before={deny_before} after={deny_after} deny_delta={deny_delta} (container-workload attributable)"
    );
    println!(
        "file_open allow: {allow_after} (GLOBAL counter: allowed opens system-wide, \
         including unzoned/system processes; NOT workload-specific)"
    );

    // In deployment mode the core outlives this test, so remove all persistent
    // state we created. Detach first so RemoveZone can clear zone policy,
    // communication, and inode maps for the two pid-suffixed test zones.
    if deployment_mode {
        let _ = client
            .detach_container(DetachContainerRequest {
                container_id: attach_container_id.clone(),
                ..Default::default()
            })
            .await;
        for zone in [&zone_a, &zone_b] {
            let _ = client
                .remove_zone(RemoveZoneRequest {
                    zone_name: zone.clone(),
                    drain: false,
                })
                .await;
        }
        println!("deployment: removed test container membership and zones");
    }
    Ok(())
}
