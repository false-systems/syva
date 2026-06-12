//! Privileged Linux / BPF-LSM integration test: prove the per-zone egress
//! allowlist. A network-locked zone with an allowlisted destination may reach
//! THAT destination while everything else non-loopback stays denied. Entries
//! can be IPv4 or IPv6 CIDRs and may optionally pin one destination port; the
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
//! The zones are locked (Isolated) with narrow egress exceptions.
//! - connect/sendto to the allowed host IP: NOT `EPERM` (the CIDR carve-out).
//! - connect to an allowed `CIDR:port` on the allowed port: NOT `EPERM`.
//! - connect to the same allowed IP on a different port: `EPERM`, and
//!   `socket_connect` deny moves.
//! - connect to an allowed IPv6 CIDR: NOT `EPERM`; a different IPv6
//!   destination is `EPERM`, and `socket_connect` deny moves.
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

const ZONE_ANY: &str = "syva-it-zone-cidr-any";
const ZONE_PORT: &str = "syva-it-zone-cidr-port";
const ZONE_V6: &str = "syva-it-zone-cidr-v6";
// TEST-NET-1 (RFC 5737) — guaranteed not the host's address, never routed.
const BLOCKED_IP: &str = "192.0.2.1";
const ALLOWED_V6: &str = "fd7a:115c:a1e0::91";
const BLOCKED_V6: &str = "fd7a:115c:a1e0::92";

struct Cleanup {
    cgroups: Vec<PathBuf>,
    ipv6_addr: Option<String>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(addr) = &self.ipv6_addr {
            let _ = Command::new("ip")
                .args(["-6", "addr", "del", addr, "dev", "lo"])
                .status();
        }
        for cgroup in &self.cgroups {
            let _ = fs::remove_dir(cgroup);
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

fn workload_op(cgroup_procs: &Path, op: &str, ip: &str, port: u16) -> Output {
    let py = r#"
import socket,errno,sys
op,ip,port=sys.argv[1],sys.argv[2],int(sys.argv[3])
family=socket.AF_INET6 if ':' in ip else socket.AF_INET
try:
  if op=='connect':
    s=socket.socket(family); s.settimeout(5); s.connect((ip,port)); print('OK connect')
  elif op=='sendto':
    s=socket.socket(family,socket.SOCK_DGRAM); s.sendto(b'x',(ip,port)); print('OK sendto')
  elif op=='bind':
    s=socket.socket(family); s.bind((ip,port)); print('OK bind')
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

fn add_ipv6_addr(addr: &str) -> anyhow::Result<()> {
    let status = Command::new("ip")
        .args(["-6", "addr", "replace", addr, "dev", "lo"])
        .status()?;
    anyhow::ensure!(
        status.success(),
        "failed to configure IPv6 address {addr} on lo; IPv6 egress gate cannot run"
    );
    Ok(())
}

async fn attach_zone(
    client: &mut SyvaCoreClient<Channel>,
    zone_name: &str,
    cidrs: Vec<String>,
    cgroup: &Path,
    pid: u32,
) -> anyhow::Result<()> {
    client
        .register_zone(RegisterZoneRequest {
            zone_name: zone_name.to_string(),
            policy: Some(locked_policy_with_cidr_list(cidrs)),
        })
        .await?;

    fs::create_dir_all(cgroup)?;
    let cgroup_id = fs::metadata(cgroup)?.ino();
    let attach = client
        .attach_container(AttachContainerRequest {
            container_id: format!("{pid:08x}{cgroup_id:08x}"),
            zone_name: zone_name.to_string(),
            cgroup_id,
            source: "integration".to_string(),
            ..Default::default()
        })
        .await?
        .into_inner();
    anyhow::ensure!(attach.ok, "attach failed: {}", attach.message);
    Ok(())
}

fn locked_policy_with_cidr_list(cidrs: Vec<String>) -> ZonePolicy {
    ZonePolicy {
        host_paths: Vec::new(),
        allowed_zones: Vec::new(),
        allow_ptrace: false,
        zone_type: 0,
        network_mode: 0, // Isolated — network-locked
        allowed_egress_cidrs: cidrs,
    }
}

#[tokio::test]
#[ignore = "requires Linux, root privileges, BPF LSM support, and group 'syva'"]
async fn locked_zone_reaches_only_its_allowlisted_egress_policy() -> anyhow::Result<()> {
    let pid = std::process::id();
    let cgroup_any = PathBuf::from(format!("/sys/fs/cgroup/syva-cidr-any-it-{pid}"));
    let cgroup_port = PathBuf::from(format!("/sys/fs/cgroup/syva-cidr-port-it-{pid}"));
    let cgroup_v6 = PathBuf::from(format!("/sys/fs/cgroup/syva-cidr-v6-it-{pid}"));
    let procs_any = cgroup_any.join("cgroup.procs");
    let procs_port = cgroup_port.join("cgroup.procs");
    let procs_v6 = cgroup_v6.join("cgroup.procs");
    let _cleanup = Cleanup {
        cgroups: vec![cgroup_any.clone(), cgroup_port.clone(), cgroup_v6.clone()],
        ipv6_addr: Some(format!("{ALLOWED_V6}/128")),
    };
    add_ipv6_addr(&format!("{ALLOWED_V6}/128"))?;

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

    attach_zone(
        &mut client,
        ZONE_ANY,
        vec![format!("{allowed_ip}/32")],
        &cgroup_any,
        pid,
    )
    .await?;
    attach_zone(
        &mut client,
        ZONE_PORT,
        vec![format!("{allowed_ip}/32:9")],
        &cgroup_port,
        pid,
    )
    .await?;
    attach_zone(
        &mut client,
        ZONE_V6,
        vec![format!("[{ALLOWED_V6}/128]:9")],
        &cgroup_v6,
        pid,
    )
    .await?;

    // ALLOWED: connect + sendto to the allowlisted IP must NOT be EPERM.
    for op in ["connect", "sendto"] {
        let r = workload_op(&procs_any, op, &allowed_ip, 9);
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

    let port_allowed = workload_op(&procs_port, "connect", &allowed_ip, 9);
    anyhow::ensure!(
        !out(&port_allowed).contains("EPERM"),
        "connect to allowlisted {allowed_ip}:9 was denied: {}",
        out(&port_allowed)
    );
    println!(
        "allowlisted connect -> {allowed_ip}:9 : {} (NOT EPERM — CIDR:port allows)",
        out(&port_allowed)
    );

    let before = hook_deny(&mut client, "socket_connect").await?;
    let port_blocked = workload_op(&procs_port, "connect", &allowed_ip, 10);
    let after = hook_deny(&mut client, "socket_connect").await?;
    anyhow::ensure!(
        out(&port_blocked).contains("EPERM"),
        "connect to {allowed_ip}:10 should be denied by CIDR:port policy: {}",
        out(&port_blocked)
    );
    anyhow::ensure!(
        after.saturating_sub(before) == 1,
        "socket_connect deny did not move by 1 for port mismatch (before={before}, after={after})"
    );
    println!("blocked connect -> {allowed_ip}:10 : DENIED EPERM, socket_connect deny_delta=1");

    let v6_allowed = workload_op(&procs_v6, "connect", ALLOWED_V6, 9);
    anyhow::ensure!(
        !out(&v6_allowed).contains("EPERM"),
        "connect to allowlisted IPv6 {ALLOWED_V6}:9 was denied: {}",
        out(&v6_allowed)
    );
    println!(
        "allowlisted connect -> [{ALLOWED_V6}]:9 : {} (NOT EPERM — IPv6 CIDR:port allows)",
        out(&v6_allowed)
    );

    let before = hook_deny(&mut client, "socket_connect").await?;
    let v6_blocked = workload_op(&procs_v6, "connect", BLOCKED_V6, 9);
    let after = hook_deny(&mut client, "socket_connect").await?;
    anyhow::ensure!(
        out(&v6_blocked).contains("EPERM"),
        "connect to non-allowlisted IPv6 {BLOCKED_V6}:9 was not denied: {}",
        out(&v6_blocked)
    );
    anyhow::ensure!(
        after.saturating_sub(before) == 1,
        "socket_connect deny did not move by 1 for IPv6 miss (before={before}, after={after})"
    );
    println!("blocked connect -> [{BLOCKED_V6}]:9 : DENIED EPERM, socket_connect deny_delta=1");

    // BLOCKED: the same ops to a non-allowlisted IP must be EPERM, and the
    // matching per-hook deny counter must move by exactly one.
    for (op, hook) in [("connect", "socket_connect"), ("sendto", "socket_sendmsg")] {
        let before = hook_deny(&mut client, hook).await?;
        let r = workload_op(&procs_any, op, BLOCKED_IP, 9);
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
    let b = workload_op(&procs_any, "bind", &allowed_ip, 0);
    anyhow::ensure!(
        out(&b).contains("EPERM"),
        "bind to {allowed_ip} should remain denied (allowlist is egress-only): {}",
        out(&b)
    );
    println!("bind -> {allowed_ip}:0 : DENIED EPERM (allowlist does not relax bind)");

    println!("=== syva integration evidence: egress CIDR allowlist with port and IPv6 ===");
    println!("locked zone allowed {allowed_ip}/32: reaches it on any port; {allowed_ip}/32:9 reaches only port 9; [{ALLOWED_V6}/128]:9 reaches only that IPv6 destination/port; misses are EPERM; bind still EPERM");
    Ok(())
}
