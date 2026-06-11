//! Privileged Linux / BPF-LSM integration test: prove the network lock.
//!
//! An Isolated (network-locked) zone is reachable on loopback only — the three
//! network hooks deny its non-loopback operations:
//!
//! - `socket_connect` — outbound TCP / connected UDP
//! - `socket_sendmsg` — outbound UNCONNECTED UDP (sendto), which never calls
//!   connect() and so bypasses socket_connect
//! - `socket_bind` — exposing a listener on the network
//!
//! A Bridged (network-open) zone — registered via the proto network mode — is
//! allowed out, proving the per-zone lock/open switch works end to end.
//!
//! Run via the dedicated target (Linux, root, BPF LSM, group `syva`):
//!
//! ```text
//! sudo -E make verify-network-lock
//! ```
//!
//! ## Why it cannot be faked
//!
//! Every file is the same workload cgroup pattern. A locked zone's non-loopback
//! op fails with `EPERM` at the syscall and bumps the matching per-hook deny
//! counter; loopback succeeds. The open zone's identical op does NOT get
//! `EPERM`. If a hook were unattached, the locked op would reach the network
//! (ECONNREFUSED/timeout, never EPERM) and the counter would not move.

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

const ZONE_LOCKED: &str = "syva-it-zone-locked";
const ZONE_OPEN: &str = "syva-it-zone-open";

fn policy(network_mode: i32) -> ZonePolicy {
    ZonePolicy {
        host_paths: Vec::new(),
        allowed_zones: Vec::new(),
        allow_ptrace: false,
        zone_type: 0,
        network_mode,
    }
}

struct Cleanup {
    cgroups: Vec<PathBuf>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for cg in &self.cgroups {
            let _ = fs::remove_dir(cg);
        }
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

/// Join `cgroup` then exec one Python network op against `ip:port`. Prints
/// `OK <op>` on success or `ERRNO <NAME>` so the caller can distinguish an
/// `EPERM` denial from a benign network error (which means "allowed").
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

async fn attach(
    client: &mut SyvaCoreClient<Channel>,
    cgroup: &Path,
    zone: &str,
    tag: &str,
) -> anyhow::Result<()> {
    let id = fs::metadata(cgroup)?.ino();
    let resp = client
        .attach_container(AttachContainerRequest {
            // container_id must be hex/dash/underscore only.
            container_id: format!("{tag}-{:08x}", std::process::id()),
            zone_name: zone.to_string(),
            cgroup_id: id,
            source: "integration".to_string(),
            ..Default::default()
        })
        .await?
        .into_inner();
    anyhow::ensure!(resp.ok, "attach {zone} failed: {}", resp.message);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Linux, root privileges, BPF LSM support, and group 'syva'"]
async fn isolated_zone_is_network_locked_open_zone_is_not() -> anyhow::Result<()> {
    let pid = std::process::id();
    let locked_cg = PathBuf::from(format!("/sys/fs/cgroup/syva-netlock-locked-{pid}"));
    let open_cg = PathBuf::from(format!("/sys/fs/cgroup/syva-netlock-open-{pid}"));
    let _cleanup = Cleanup {
        cgroups: vec![locked_cg.clone(), open_cg.clone()],
    };

    let sock_dir = tempfile::tempdir()?;
    let socket_path = sock_dir.path().join("syva-core.sock");
    let _core = common::spawn_core(&socket_path)?;
    let mut client = common::wait_for_core(&socket_path).await?;

    // Locked zone (Isolated, default) and open zone (Bridged, mode = 1).
    client
        .register_zone(RegisterZoneRequest {
            zone_name: ZONE_LOCKED.to_string(),
            policy: Some(policy(0)),
        })
        .await?;
    client
        .register_zone(RegisterZoneRequest {
            zone_name: ZONE_OPEN.to_string(),
            policy: Some(policy(1)),
        })
        .await?;

    fs::create_dir_all(&locked_cg)?;
    fs::create_dir_all(&open_cg)?;
    attach(&mut client, &locked_cg, ZONE_LOCKED, "10c4ed").await?;
    attach(&mut client, &open_cg, ZONE_OPEN, "0bee").await?;
    let locked_procs = locked_cg.join("cgroup.procs");
    let open_procs = open_cg.join("cgroup.procs");

    let egress_ip = host_egress_ip()
        .map(|ip| ip.to_string())
        .ok_or_else(|| anyhow::anyhow!("could not determine a non-loopback host IP"))?;
    anyhow::ensure!(
        !egress_ip.starts_with("127."),
        "resolved egress IP is loopback ({egress_ip})"
    );

    // POSITIVE: loopback connect from the locked zone is allowed.
    let lo = workload_op(&locked_procs, "connect", "127.0.0.1", 9);
    anyhow::ensure!(
        out(&lo).contains("OK") || out(&lo).contains("ECONNREFUSED"),
        "locked zone loopback connect was blocked: {}",
        out(&lo)
    );

    // NEGATIVE x3: locked zone non-loopback connect / sendto / bind → EPERM,
    // each on its own per-hook deny counter.
    for (op, hook) in [
        ("connect", "socket_connect"),
        ("sendto", "socket_sendmsg"),
        ("bind", "socket_bind"),
    ] {
        let before = hook_deny(&mut client, hook).await?;
        let res = workload_op(&locked_procs, op, &egress_ip, 9);
        let after = hook_deny(&mut client, hook).await?;
        let delta = after.saturating_sub(before);
        anyhow::ensure!(
            out(&res).contains("EPERM"),
            "locked zone {op} to {egress_ip} was not denied with EPERM: {} (stderr={})",
            out(&res),
            String::from_utf8_lossy(&res.stderr)
        );
        anyhow::ensure!(
            delta == 1,
            "expected exactly one {hook} deny for {op}, got delta={delta} (before={before}, after={after})"
        );
        println!("locked {op} -> {egress_ip}:9 : DENIED EPERM, {hook} deny_delta=1");
    }

    // OPEN zone: the same non-loopback connect must NOT be EPERM.
    let open_res = workload_op(&open_procs, "connect", &egress_ip, 9);
    anyhow::ensure!(
        !out(&open_res).contains("EPERM"),
        "open (bridged) zone connect was denied with EPERM: {}",
        out(&open_res)
    );
    println!(
        "open connect -> {egress_ip}:9 : {} (NOT EPERM — network open)",
        out(&open_res)
    );

    println!("=== syva integration evidence: network lock ===");
    println!(
        "locked zone: connect/sendmsg/bind to non-loopback all DENIED with EPERM; loopback allowed"
    );
    println!("open zone (network mode bridged): outbound connect allowed (lock/open switch works)");
    Ok(())
}
