//! Privileged Linux / BPF-LSM integration test: prove the per-zone egress CIDR
//! allowlist. A network-locked zone with an allowlisted destination may reach
//! THAT destination while everything else non-loopback stays denied — and the
//! allowlist is egress-only (it never relaxes `bind`).
//!
//! Run via the dedicated target (Linux, root, BPF LSM, group `syva`):
//!
//! ```text
//! sudo -E make verify-egress-cidr
//! ```
//!
//! ## Why it cannot be faked
//!
//! The zone is locked (Isolated) but its policy allows exactly `<host-ip>/32`.
//! - connect/sendto to the allowed host IP: NOT `EPERM` (the CIDR carve-out).
//! - connect/sendto to a different non-loopback IP (TEST-NET 192.0.2.1):
//!   `EPERM`, and `socket_connect` / `socket_sendmsg` deny counters move.
//! - bind to the allowed host IP: still `EPERM` — the allowlist is for egress
//!   destinations, not local listeners.

mod common;

use std::fs;
use std::net::UdpSocket;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::{
    AttachContainerRequest, RegisterZoneRequest, StatusRequest, ZonePolicy,
};
use tonic::transport::Channel;

const ZONE: &str = "syva-it-zone-cidr";
// TEST-NET-1 (RFC 5737) — guaranteed not the host's address, never routed.
const BLOCKED_IP: &str = "192.0.2.1";

fn locked_policy_with_cidr(cidr: String) -> ZonePolicy {
    ZonePolicy {
        host_paths: Vec::new(),
        allowed_zones: Vec::new(),
        allow_ptrace: false,
        zone_type: 0,
        network_mode: 0, // Isolated — network-locked
        allowed_egress_cidrs: vec![cidr],
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

async fn hook_deny(client: &mut SyvaCoreClient<Channel>, hook: &str) -> anyhow::Result<u64> {
    let status = client.status(StatusRequest {}).await?.into_inner();
    Ok(status
        .hooks
        .iter()
        .find(|h| h.hook == hook)
        .map(|h| h.deny)
        .unwrap_or(0))
}

fn host_egress_ip() -> Option<std::net::IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    Some(sock.local_addr().ok()?.ip())
}

fn workload_op(cgroup_procs: &Path, op: &str, ip: &str, port: u16) -> Output {
    let py = r#"
import socket,errno,sys
op,ip,port=sys.argv[1],sys.argv[2],int(sys.argv[3])
try:
  if op=='connect':
    s=socket.socket(); s.settimeout(5); s.connect((ip,port)); print('OK connect')
  elif op=='sendto':
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b'x',(ip,port)); print('OK sendto')
  elif op=='bind':
    s=socket.socket(); s.bind((ip,port)); print('OK bind')
except OSError as e:
  print('ERRNO', errno.errorcode.get(e.errno,e.errno))
"#;
    let script = format!(
        "echo $$ > '{}' && exec python3 -c \"$0\" \"$1\" \"$2\" \"$3\"",
        cgroup_procs.display()
    );
    Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .arg(py)
        .arg(op)
        .arg(ip)
        .arg(port.to_string())
        .output()
        .expect("failed to spawn workload shell")
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

#[tokio::test]
#[ignore = "requires Linux, root privileges, BPF LSM support, and group 'syva'"]
async fn locked_zone_reaches_only_its_allowlisted_cidr() -> anyhow::Result<()> {
    let pid = std::process::id();
    let cgroup = PathBuf::from(format!("/sys/fs/cgroup/syva-cidr-it-{pid}"));
    let procs = cgroup.join("cgroup.procs");
    let _cleanup = Cleanup {
        cgroup: cgroup.clone(),
    };

    let allowed_ip = host_egress_ip()
        .map(|ip| ip.to_string())
        .ok_or_else(|| anyhow::anyhow!("could not determine a non-loopback host IP"))?;
    anyhow::ensure!(
        !allowed_ip.starts_with("127.") && allowed_ip != BLOCKED_IP,
        "resolved egress IP {allowed_ip} is unsuitable"
    );

    let sock_dir = tempfile::tempdir()?;
    let socket_path = sock_dir.path().join("syva-core.sock");
    let _core = common::spawn_core(&socket_path)?;
    let mut client = common::wait_for_core(&socket_path).await?;

    // Locked zone whose ONLY egress exception is the host IP (as a /32).
    client
        .register_zone(RegisterZoneRequest {
            zone_name: ZONE.to_string(),
            policy: Some(locked_policy_with_cidr(format!("{allowed_ip}/32"))),
        })
        .await?;

    fs::create_dir_all(&cgroup)?;
    let cgroup_id = fs::metadata(&cgroup)?.ino();
    let attach = client
        .attach_container(AttachContainerRequest {
            container_id: format!("c1d4-{pid:08x}"),
            zone_name: ZONE.to_string(),
            cgroup_id,
            source: "integration".to_string(),
            ..Default::default()
        })
        .await?
        .into_inner();
    anyhow::ensure!(attach.ok, "attach failed: {}", attach.message);

    // ALLOWED: connect + sendto to the allowlisted IP must NOT be EPERM.
    for op in ["connect", "sendto"] {
        let r = workload_op(&procs, op, &allowed_ip, 9);
        anyhow::ensure!(
            !out(&r).contains("EPERM"),
            "{op} to allowlisted {allowed_ip} was denied: {}",
            out(&r)
        );
        println!(
            "allowlisted {op} -> {allowed_ip}:9 : {} (NOT EPERM — CIDR allows)",
            out(&r)
        );
    }

    // BLOCKED: the same ops to a non-allowlisted IP must be EPERM, and the
    // matching per-hook deny counter must move by exactly one.
    for (op, hook) in [("connect", "socket_connect"), ("sendto", "socket_sendmsg")] {
        let before = hook_deny(&mut client, hook).await?;
        let r = workload_op(&procs, op, BLOCKED_IP, 9);
        let after = hook_deny(&mut client, hook).await?;
        anyhow::ensure!(
            out(&r).contains("EPERM"),
            "{op} to non-allowlisted {BLOCKED_IP} was not denied: {}",
            out(&r)
        );
        anyhow::ensure!(
            after.saturating_sub(before) == 1,
            "{hook} deny did not move by 1 (before={before}, after={after})"
        );
        println!("blocked {op} -> {BLOCKED_IP}:9 : DENIED EPERM, {hook} deny_delta=1");
    }

    // EGRESS-ONLY: bind to the allowlisted IP is STILL denied — the allowlist
    // governs egress destinations, never local listeners.
    let b = workload_op(&procs, "bind", &allowed_ip, 0);
    anyhow::ensure!(
        out(&b).contains("EPERM"),
        "bind to {allowed_ip} should remain denied (allowlist is egress-only): {}",
        out(&b)
    );
    println!("bind -> {allowed_ip}:0 : DENIED EPERM (allowlist does not relax bind)");

    println!("=== syva integration evidence: egress CIDR allowlist ===");
    println!("locked zone allowed {allowed_ip}/32: reaches it (connect+sendto), all else EPERM; bind still EPERM");
    Ok(())
}
