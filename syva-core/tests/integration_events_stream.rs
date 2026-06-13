//! Privileged Linux / BPF-LSM integration test: prove the enriched
//! enforcement event stream — the operator-facing answer to "why was my
//! workload blocked?".
//!
//! This is NOT a normal `cargo test`. Run it through the dedicated target:
//!
//! ```text
//! sudo -E make verify-events
//! ```
//!
//! ## What it proves
//!
//! A zoned workload triggers one file denial (`cat` on another zone's file)
//! and one network denial (`connect` to a non-loopback TEST-NET-1 address).
//! The `WatchEvents` stream must deliver both events fully enriched: zone
//! NAMES (not ids), the denied process `comm`, the registered host `path`
//! and inode for the file denial, the destination `ip:port` for the network
//! denial, a `decision` label, and non-empty templated reason fields.
//!
//! ## Why this cannot be faked
//!
//! Every asserted field travels a different path: comm is captured by the
//! kernel hook, the path comes from the registration-time index, zone names
//! from the registry reverse index, and the destination from the socket
//! hook's sockaddr read. A regression in any layer (kernel struct, pump
//! enrichment, registration indexing) fails a specific assertion.

mod common;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::{
    AttachContainerRequest, DenyEvent, RegisterHostPathRequest, RegisterZoneRequest,
    WatchEventsRequest, ZonePolicy,
};
use tonic::transport::Channel;

const ZONE_A: &str = "payments";
const ZONE_B: &str = "database";
/// TEST-NET-1: guaranteed not to be this host; the lock denies before routing.
const BLOCKED_DST: &str = "192.0.2.1";
const BLOCKED_PORT: u16 = 5432;

fn empty_policy() -> ZonePolicy {
    ZonePolicy {
        host_paths: Vec::new(),
        allowed_zones: Vec::new(),
        allow_ptrace: false,
        zone_type: 0,    // NonGlobal — enforced.
        network_mode: 0, // Isolated (network-locked)
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

fn workload(cgroup_procs: &Path, command: &str) -> Output {
    let script = format!("echo $$ > '{}' && {command}", cgroup_procs.display());
    Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .output()
        .expect("failed to spawn workload shell")
}

async fn attach_zone_a(client: &mut SyvaCoreClient<Channel>, cgroup: &Path) -> anyhow::Result<()> {
    let cgroup_id = fs::metadata(cgroup)?.ino();
    let attach = client
        .attach_container(AttachContainerRequest {
            container_id: format!("e7e9{:08x}", std::process::id()),
            zone_name: ZONE_A.to_string(),
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
async fn deny_events_stream_fully_enriched() -> anyhow::Result<()> {
    let pid = std::process::id();
    let workdir = PathBuf::from(format!("/tmp/syva-events-it-{pid}"));
    let cgroup = PathBuf::from(format!("/sys/fs/cgroup/syva-events-it-{pid}"));
    let cgroup_procs = cgroup.join("cgroup.procs");
    let _cleanup = Cleanup {
        cgroup: cgroup.clone(),
        workdir: workdir.clone(),
    };

    // 1. Core + zones + one protected file in zone "database".
    let sock_dir = tempfile::tempdir()?;
    let socket_path = sock_dir.path().join("syva-core.sock");
    let _core = common::spawn_core(&socket_path)?;
    let mut client = common::wait_for_core(&socket_path).await?;

    for zone in [ZONE_A, ZONE_B] {
        client
            .register_zone(RegisterZoneRequest {
                zone_name: zone.to_string(),
                policy: Some(empty_policy()),
            })
            .await?;
    }
    fs::create_dir_all(&workdir)?;
    let secret_file = workdir.join("db-credentials.txt");
    fs::write(&secret_file, "TOP SECRET\n")?;
    client
        .register_host_path(RegisterHostPathRequest {
            zone_name: ZONE_B.to_string(),
            path: secret_file.to_string_lossy().into_owned(),
            recursive: false,
        })
        .await?;

    fs::create_dir_all(&cgroup)?;
    attach_zone_a(&mut client, &cgroup).await?;

    // 2. Subscribe to the enriched stream BEFORE triggering denials.
    let mut watcher = common::connect(&socket_path).await?;
    let mut stream = watcher
        .watch_events(WatchEventsRequest { follow: true })
        .await?
        .into_inner();

    // 3. Trigger one file denial and one network denial from zone-a.
    let denied_cat = workload(
        &cgroup_procs,
        &format!("exec cat '{}'", secret_file.display()),
    );
    anyhow::ensure!(
        !denied_cat.status.success(),
        "precondition failed: cross-zone cat was not denied"
    );
    let py = format!(
        "import socket\ns = socket.socket(); s.settimeout(3)\n\
         try: s.connect((\"{BLOCKED_DST}\", {BLOCKED_PORT}))\n\
         except OSError as e: print(e)"
    );
    let _ = workload(&cgroup_procs, &format!("exec python3 -c '{py}'"));

    // 4. Collect events from the stream (bounded wait).
    let mut file_event: Option<DenyEvent> = None;
    let mut net_event: Option<DenyEvent> = None;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while (file_event.is_none() || net_event.is_none()) && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(2), stream.message()).await {
            Ok(Ok(Some(event))) => match event.hook.as_str() {
                "file_open" if file_event.is_none() && event.comm == "cat" => {
                    file_event = Some(event)
                }
                "socket_connect" if net_event.is_none() => net_event = Some(event),
                _ => {}
            },
            Ok(Ok(None)) | Ok(Err(_)) => break,
            Err(_) => {} // timeout tick — keep waiting until deadline
        }
    }

    // --- File denial: every enrichment layer asserted. ---
    let file_event = file_event
        .ok_or_else(|| anyhow::anyhow!("no enriched file_open deny event arrived within 10s"))?;
    assert_eq!(file_event.decision, "deny");
    assert_eq!(file_event.zone, ZONE_A, "caller zone NAME expected");
    assert_eq!(file_event.target_zone, ZONE_B, "target zone NAME expected");
    assert_eq!(file_event.comm, "cat", "kernel-captured comm expected");
    assert_ne!(
        file_event.inode, 0,
        "real inode expected (issue #67 closed)"
    );
    assert_eq!(
        file_event.path,
        secret_file.to_string_lossy(),
        "registered host path expected from the (zone, ino) index"
    );
    assert!(!file_event.what_failed.is_empty());
    assert!(!file_event.why_it_matters.is_empty());
    assert!(!file_event.possible_causes.is_empty());

    // --- Network denial: destination enrichment asserted. ---
    let net_event = net_event.ok_or_else(|| {
        anyhow::anyhow!("no enriched socket_connect deny event arrived within 10s")
    })?;
    assert_eq!(net_event.decision, "deny");
    assert_eq!(net_event.zone, ZONE_A);
    assert_eq!(net_event.dst_ip, BLOCKED_DST, "destination IP expected");
    assert_eq!(net_event.dst_port, u32::from(BLOCKED_PORT));
    assert!(
        !net_event.comm.is_empty(),
        "comm expected on network denials"
    );
    assert!(!net_event.what_failed.is_empty());

    // --- Release evidence (printed under --nocapture). ---
    println!("=== syva integration evidence: enriched deny events ===");
    println!(
        "file deny : {} {} {} \u{2192} {} pid={} comm={} path={} inode={}",
        file_event.decision,
        file_event.hook,
        file_event.zone,
        file_event.target_zone,
        file_event.pid,
        file_event.comm,
        file_event.path,
        file_event.inode
    );
    println!(
        "            why: {} \u{2014} {}",
        file_event.what_failed, file_event.why_it_matters
    );
    println!(
        "net deny  : {} {} {} pid={} comm={} dst={}:{}",
        net_event.decision,
        net_event.hook,
        net_event.zone,
        net_event.pid,
        net_event.comm,
        net_event.dst_ip,
        net_event.dst_port
    );
    println!(
        "            why: {} \u{2014} {}",
        net_event.what_failed, net_event.why_it_matters
    );
    Ok(())
}
