//! Privileged proof that a core crash/restart never opens an enforcement gap.

mod common;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::{
    ActivateGenerationRequest, AttachContainerRequest, DisableEnforcementRequest,
    RegisterHostPathRequest, RegisterZoneRequest, StatusRequest, ZonePolicy,
};
use tonic::transport::Channel;

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

fn workload_open(cgroup: &Path, file: &Path) -> Output {
    Command::new("/bin/sh")
        .arg("-c")
        .arg(format!(
            "echo $$ > '{}' && exec cat '{}'",
            cgroup.join("cgroup.procs").display(),
            file.display()
        ))
        .output()
        .expect("failed to run workload")
}

async fn replay_and_activate(
    client: &mut SyvaCoreClient<Channel>,
    cgroup_id: u64,
    secret: &Path,
) -> anyhow::Result<u64> {
    for zone in ["restart-a", "restart-b"] {
        client
            .register_zone(RegisterZoneRequest {
                zone_name: zone.into(),
                policy: Some(ZonePolicy::default()),
            })
            .await?;
    }
    client
        .register_host_path(RegisterHostPathRequest {
            zone_name: "restart-b".into(),
            path: secret.to_string_lossy().into_owned(),
            recursive: false,
        })
        .await?;
    let attached = client
        .attach_container(AttachContainerRequest {
            container_id: format!("5e57a47-{:x}", std::process::id()),
            zone_name: "restart-a".into(),
            cgroup_id,
            source: "restart-test".into(),
            ..Default::default()
        })
        .await?
        .into_inner();
    anyhow::ensure!(attached.ok, "attach failed: {}", attached.message);

    let generation = client
        .status(StatusRequest {})
        .await?
        .into_inner()
        .staging_generation;
    anyhow::ensure!(generation != 0, "core has no staging generation");
    client
        .activate_generation(ActivateGenerationRequest { generation })
        .await?;
    Ok(generation)
}

fn assert_denied(cgroup: &Path, secret: &Path, phase: &str) {
    let output = workload_open(cgroup, secret);
    assert!(
        !output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains("Operation not permitted"),
        "enforcement gap during {phase}: status={:?} stdout={:?} stderr={:?}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[tokio::test]
#[ignore = "requires Linux, root privileges, BPF LSM support, and group 'syva'"]
async fn crash_restart_preserves_enforcement_until_replay_activation() -> anyhow::Result<()> {
    let pid = std::process::id();
    let workdir = PathBuf::from(format!("/tmp/syva-restart-{pid}"));
    let cgroup = PathBuf::from(format!("/sys/fs/cgroup/syva-restart-{pid}"));
    let _cleanup = Cleanup {
        cgroup: cgroup.clone(),
        workdir: workdir.clone(),
    };
    fs::create_dir_all(&workdir)?;
    fs::create_dir_all(&cgroup)?;
    let secret = workdir.join("secret");
    fs::write(&secret, "must stay blocked\n")?;
    let cgroup_id = fs::metadata(&cgroup)?.ino();
    let socket_dir = tempfile::tempdir()?;
    let socket = socket_dir.path().join("core.sock");

    let first = common::spawn_core(&socket)?;
    let mut client = common::wait_for_core_without_activation(&socket).await?;
    let first_generation = replay_and_activate(&mut client, cgroup_id, &secret).await?;
    assert_denied(&cgroup, &secret, "initial generation");

    let running = Arc::new(AtomicBool::new(true));
    let attempts = Arc::new(AtomicU64::new(0));
    let successes = Arc::new(AtomicU64::new(0));
    let probe = {
        let running = running.clone();
        let attempts = attempts.clone();
        let successes = successes.clone();
        let cgroup = cgroup.clone();
        let secret = secret.clone();
        std::thread::spawn(move || {
            while running.load(Ordering::Relaxed) {
                if workload_open(&cgroup, &secret).status.success() {
                    successes.fetch_add(1, Ordering::Relaxed);
                }
                attempts.fetch_add(1, Ordering::Relaxed);
            }
        })
    };

    drop(client);
    first.crash()?;
    assert_denied(&cgroup, &secret, "core crash");

    let _second = common::spawn_core(&socket)?;
    let mut client = common::wait_for_core_without_activation(&socket).await?;
    let status = client.status(StatusRequest {}).await?.into_inner();
    assert_eq!(status.active_generation, first_generation);
    assert_ne!(status.staging_generation, 0);
    assert_denied(&cgroup, &secret, "disabled staging replay");

    let second_generation = replay_and_activate(&mut client, cgroup_id, &secret).await?;
    assert!(second_generation > first_generation);
    assert_denied(&cgroup, &secret, "generation switch");

    running.store(false, Ordering::Relaxed);
    probe.join().expect("continuity probe panicked");
    assert!(attempts.load(Ordering::Relaxed) > 0);
    assert_eq!(
        successes.load(Ordering::Relaxed),
        0,
        "background probe crossed the generation handoff"
    );

    client
        .disable_enforcement(DisableEnforcementRequest {})
        .await?;
    println!(
        "restart continuity: generation {first_generation} enforced through crash and replay, then generation {second_generation} activated"
    );
    Ok(())
}
