//! Privileged Linux / BPF-LSM integration test: prove the `socket_connect`
//! egress lock blocks an Isolated zone's outbound non-loopback connection
//! while allowing loopback.
//!
//! Run via the dedicated target (requires Linux, root, BPF LSM, group `syva`):
//!
//! ```text
//! sudo -E make verify-socket-egress
//! ```
//!
//! ## What this proves (and why it cannot be faked)
//!
//! A workload cgroup is attached to an Isolated-network zone (the default), so
//! its policy carries no egress permission. Two controls, same workload cgroup:
//!
//! - POSITIVE: a connect to `127.0.0.1` (a real listener) SUCCEEDS — the hook's
//!   loopback carve-out returns allow, proving it is attached and discriminates.
//! - NEGATIVE: a connect to a non-loopback host IP fails with `EPERM` at
//!   `connect()` and `socket_connect deny_delta == 1`.
//!
//! If the hook were not attached, the negative connect would reach the network
//! and fail with `ECONNREFUSED`/timeout, never `EPERM`, and the counter would
//! not move. If it denied everything, the loopback positive would fail.

mod common;

use std::fs;
use std::net::{TcpListener, UdpSocket};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::{
    AttachContainerRequest, RegisterZoneRequest, StatusRequest, ZonePolicy,
};
use tonic::transport::Channel;

const ZONE_ISO: &str = "syva-it-zone-iso";

fn isolated_policy() -> ZonePolicy {
    // No network field on the proto policy → core defaults to Isolated, which
    // sets no egress permission. That default is exactly what we are testing.
    ZonePolicy {
        host_paths: Vec::new(),
        allowed_zones: Vec::new(),
        allow_ptrace: false,
        zone_type: 0, // NonGlobal — enforced.
    }
}

struct Cleanup {
    cgroup: PathBuf,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.cgroup);
    }
}

async fn socket_connect_deny(client: &mut SyvaCoreClient<Channel>) -> anyhow::Result<u64> {
    let status = client.status(StatusRequest {}).await?.into_inner();
    Ok(status
        .hooks
        .iter()
        .find(|hook| hook.hook == "socket_connect")
        .map(|hook| hook.deny)
        .unwrap_or(0))
}

/// The source IP the kernel would use for off-host traffic — a non-loopback
/// address. `connect` on a UDP socket only sets the default destination; no
/// packet is sent.
fn host_egress_ip() -> Option<std::net::IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip())
}

/// Join `cgroup` then exec a Python TCP connect to `addr`. Prints `CONNECTED`
/// on success or `ERRNO <NAME> <strerror>` on failure, so the caller can tell
/// an `EPERM` denial from an `ECONNREFUSED`/timeout that means "allowed".
fn workload_connect(cgroup_procs: &Path, ip: &str, port: u16) -> Output {
    let py = format!(
        "import socket,errno,sys\n\
         s=socket.socket(); s.settimeout(5)\n\
         try:\n  s.connect(({ip:?},{port})); print('CONNECTED')\n\
         except OSError as e:\n  print('ERRNO', errno.errorcode.get(e.errno, e.errno), e.strerror)\n"
    );
    let script = format!(
        "echo $$ > '{}' && exec python3 -c \"$0\" ",
        cgroup_procs.display()
    );
    Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .arg(py)
        .output()
        .expect("failed to spawn workload shell")
}

#[tokio::test]
#[ignore = "requires Linux, root privileges, BPF LSM support, and group 'syva'"]
async fn isolated_zone_egress_is_blocked_but_loopback_allowed() -> anyhow::Result<()> {
    let pid = std::process::id();
    let cgroup = PathBuf::from(format!("/sys/fs/cgroup/syva-egress-it-{pid}"));
    let cgroup_procs = cgroup.join("cgroup.procs");
    let _cleanup = Cleanup {
        cgroup: cgroup.clone(),
    };

    // 1. Start the local core (loads + attaches the seven LSM hooks).
    let sock_dir = tempfile::tempdir()?;
    let socket_path = sock_dir.path().join("syva-core.sock");
    let _core = common::spawn_core(&socket_path)?;
    let mut client = common::wait_for_core(&socket_path).await?;

    // 2. Register one Isolated zone (default network mode = no egress).
    client
        .register_zone(RegisterZoneRequest {
            zone_name: ZONE_ISO.to_string(),
            policy: Some(isolated_policy()),
        })
        .await?;

    // 3. A loopback TCP listener so the positive control can actually connect.
    let loopback_listener = TcpListener::bind("127.0.0.1:0")?;
    let loopback_port = loopback_listener.local_addr()?.port();

    // 4. Attach the workload cgroup to the isolated zone.
    fs::create_dir_all(&cgroup)?;
    let cgroup_id = fs::metadata(&cgroup)?.ino();
    let attach = client
        .attach_container(AttachContainerRequest {
            container_id: format!("e6e5-{pid:08x}"),
            zone_name: ZONE_ISO.to_string(),
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

    // 5. POSITIVE control — loopback connect must succeed (allow carve-out).
    let positive = workload_connect(&cgroup_procs, "127.0.0.1", loopback_port);
    let pos_stdout = String::from_utf8_lossy(&positive.stdout);
    assert!(
        pos_stdout.contains("CONNECTED"),
        "POSITIVE CONTROL FAILED: isolated zone could not connect to loopback. \
         stdout={pos_stdout:?} stderr={:?}",
        String::from_utf8_lossy(&positive.stderr),
    );

    // 6. NEGATIVE control — non-loopback egress must be denied with EPERM.
    let egress_ip = host_egress_ip()
        .map(|ip| ip.to_string())
        .ok_or_else(|| anyhow::anyhow!("could not determine a non-loopback host IP"))?;
    assert!(
        egress_ip != "127.0.0.1" && !egress_ip.starts_with("127."),
        "resolved egress IP is loopback ({egress_ip}); cannot test egress denial"
    );

    let deny_before = socket_connect_deny(&mut client).await?;
    // Port 9 (discard) — closed on the host; only reached if NOT denied.
    let negative = workload_connect(&cgroup_procs, &egress_ip, 9);
    let neg_stdout = String::from_utf8_lossy(&negative.stdout);
    let deny_after = socket_connect_deny(&mut client).await?;
    let deny_delta = deny_after.saturating_sub(deny_before);

    assert!(
        neg_stdout.contains("EPERM"),
        "ENFORCEMENT FAILURE: outbound connect to {egress_ip}:9 was not denied with EPERM. \
         stdout={neg_stdout:?} stderr={:?}",
        String::from_utf8_lossy(&negative.stderr),
    );
    assert!(
        !neg_stdout.contains("CONNECTED"),
        "ENFORCEMENT FAILURE: isolated zone reached the network: {neg_stdout:?}"
    );
    assert_eq!(
        deny_delta, 1,
        "expected exactly one socket_connect deny from the workload, got delta={deny_delta} \
         (before={deny_before}, after={deny_after})"
    );

    // --- Release evidence (printed under --nocapture). ---
    println!("=== syva integration evidence: socket_connect egress lock ===");
    println!("host cgroup attached to isolated zone: cgroup_id={cgroup_id}");
    println!(
        "positive (loopback 127.0.0.1:{loopback_port}): CONNECTED -> ALLOWED (loopback carve-out)"
    );
    println!(
        "negative (egress {egress_ip}:9): {} -> DENIED with EPERM",
        neg_stdout.trim()
    );
    println!(
        "socket_connect deny: before={deny_before} after={deny_after} deny_delta={deny_delta} \
         (workload-attributable)"
    );
    Ok(())
}
