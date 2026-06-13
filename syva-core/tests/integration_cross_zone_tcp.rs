//! Privileged Linux / BPF-LSM integration test: prove IPv4 IP-to-zone
//! cross-zone TCP enforcement.
//!
//! A zoned workload connects to local non-loopback dummy-interface IPs. The
//! core maps one IP to the caller's zone and one IP to another zone. The hook
//! must allow same-zone, deny cross-zone with EPERM, and then allow the
//! cross-zone connect after `AllowComm`.
//!
//! A second workload in a network-OPEN (Bridged) zone proves the headline
//! semantic: an unmapped destination is reachable (the zone really is open),
//! but a destination that maps to another zone still follows the zone-pair
//! rule — open network mode does not bypass `ZONE_ALLOWED_COMMS`.

mod common;

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::{
    AllowCommRequest, AttachContainerRequest, RegisterZoneRequest, SetIpZoneRequest, StatusRequest,
    ZonePolicy,
};
use tonic::transport::Channel;

const ZONE_A: &str = "syva-it-zone-ip-a";
const ZONE_B: &str = "syva-it-zone-ip-b";
const ZONE_C: &str = "syva-it-zone-ip-c";
const IP_A: &str = "10.123.91.2";
const IP_B: &str = "10.123.91.3";
/// On the dummy interface but never inserted into IP_ZONE_MAP.
const IP_UNMAPPED: &str = "10.123.91.4";

fn locked_policy() -> ZonePolicy {
    ZonePolicy {
        host_paths: Vec::new(),
        allowed_zones: Vec::new(),
        allow_ptrace: false,
        zone_type: 0,
        network_mode: 0,
        allowed_egress_cidrs: vec![],
    }
}

fn bridged_policy() -> ZonePolicy {
    ZonePolicy {
        network_mode: 1, // Bridged — network-open
        ..locked_policy()
    }
}

struct Cleanup {
    cgroups: Vec<PathBuf>,
    iface: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        remove_dummy_interface_silent(&self.iface);
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

fn setup_dummy_interface(iface: &str) -> anyhow::Result<()> {
    remove_dummy_interface_silent(iface);
    run_ip(&["link", "add", iface, "type", "dummy"])?;
    run_ip(&["addr", "add", &format!("{IP_A}/32"), "dev", iface])?;
    run_ip(&["addr", "add", &format!("{IP_B}/32"), "dev", iface])?;
    run_ip(&["addr", "add", &format!("{IP_UNMAPPED}/32"), "dev", iface])?;
    run_ip(&["link", "set", iface, "up"])?;
    Ok(())
}

fn remove_dummy_interface_silent(iface: &str) {
    let _ = Command::new("ip")
        .args(["link", "del", iface])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn run_ip(args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new("ip").args(args).status()?;
    anyhow::ensure!(status.success(), "ip {} failed", args.join(" "));
    Ok(())
}

fn workload_connect(cgroup_procs: &Path, ip: &str, port: u16) -> Output {
    let py = r#"
import socket,errno,sys
ip,port=sys.argv[1],int(sys.argv[2])
try:
  s=socket.socket(); s.settimeout(5); s.connect((ip,port)); print('OK connect')
except OSError as e:
  print('ERRNO', errno.errorcode.get(e.errno,e.errno))
"#;
    let script = format!(
        "echo $$ > '{}' && exec python3 -c \"$0\" \"$1\" \"$2\"",
        cgroup_procs.display()
    );
    Command::new("/bin/sh")
        .arg("-c")
        .arg(script)
        .arg(py)
        .arg(ip)
        .arg(port.to_string())
        .output()
        .expect("failed to spawn workload shell")
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

async fn attach_zone(
    client: &mut SyvaCoreClient<Channel>,
    cgroup: &Path,
    zone: &str,
) -> anyhow::Result<()> {
    let cgroup_id = fs::metadata(cgroup)?.ino();
    let attach = client
        .attach_container(AttachContainerRequest {
            container_id: format!("{:08x}{cgroup_id:08x}", std::process::id()),
            zone_name: zone.to_string(),
            cgroup_id,
            source: "integration".to_string(),
            ..Default::default()
        })
        .await?
        .into_inner();
    anyhow::ensure!(attach.ok, "attach to {zone} failed: {}", attach.message);
    Ok(())
}

#[tokio::test]
#[ignore = "requires Linux, root privileges, BPF LSM support, and group 'syva'"]
async fn ip_zone_map_enforces_zone_pair_for_tcp_connect() -> anyhow::Result<()> {
    let pid = std::process::id();
    let iface = format!("syvaxz{pid}");
    let cgroup = PathBuf::from(format!("/sys/fs/cgroup/syva-cross-zone-tcp-{pid}"));
    let bridged_cgroup = PathBuf::from(format!("/sys/fs/cgroup/syva-cross-zone-tcp-open-{pid}"));
    let procs = cgroup.join("cgroup.procs");
    let bridged_procs = bridged_cgroup.join("cgroup.procs");
    let _cleanup = Cleanup {
        cgroups: vec![cgroup.clone(), bridged_cgroup.clone()],
        iface: iface.clone(),
    };
    setup_dummy_interface(&iface)?;
    fs::create_dir_all(&cgroup)?;
    fs::create_dir_all(&bridged_cgroup)?;

    let sock_dir = tempfile::tempdir()?;
    let socket_path = sock_dir.path().join("syva-core.sock");
    let _core = common::spawn_core(&socket_path)?;
    let mut client = common::wait_for_core(&socket_path).await?;

    client
        .register_zone(RegisterZoneRequest {
            zone_name: ZONE_A.to_string(),
            policy: Some(locked_policy()),
        })
        .await?;
    client
        .register_zone(RegisterZoneRequest {
            zone_name: ZONE_B.to_string(),
            policy: Some(locked_policy()),
        })
        .await?;
    client
        .register_zone(RegisterZoneRequest {
            zone_name: ZONE_C.to_string(),
            policy: Some(bridged_policy()),
        })
        .await?;
    attach_zone(&mut client, &cgroup, ZONE_A).await?;
    attach_zone(&mut client, &bridged_cgroup, ZONE_C).await?;

    client
        .set_ip_zone(SetIpZoneRequest {
            ip: IP_A.to_string(),
            zone_name: ZONE_A.to_string(),
        })
        .await?;
    client
        .set_ip_zone(SetIpZoneRequest {
            ip: IP_B.to_string(),
            zone_name: ZONE_B.to_string(),
        })
        .await?;

    let same_zone = workload_connect(&procs, IP_A, 9);
    anyhow::ensure!(
        !out(&same_zone).contains("EPERM"),
        "same-zone connect to {IP_A}:9 was denied: {}",
        out(&same_zone)
    );
    println!(
        "same-zone connect -> {IP_A}:9 : {} (NOT EPERM — IP maps to caller zone)",
        out(&same_zone)
    );

    let before = hook_deny(&mut client, "socket_connect").await?;
    let blocked = workload_connect(&procs, IP_B, 9);
    let after = hook_deny(&mut client, "socket_connect").await?;
    anyhow::ensure!(
        out(&blocked).contains("EPERM"),
        "cross-zone connect to {IP_B}:9 was not denied: {}",
        out(&blocked)
    );
    anyhow::ensure!(
        after.saturating_sub(before) == 1,
        "socket_connect deny did not move by 1 (before={before}, after={after})"
    );
    println!("cross-zone connect -> {IP_B}:9 : DENIED EPERM, socket_connect deny_delta=1");

    client
        .allow_comm(AllowCommRequest {
            zone_a: ZONE_A.to_string(),
            zone_b: ZONE_B.to_string(),
        })
        .await?;

    let allowed = workload_connect(&procs, IP_B, 9);
    anyhow::ensure!(
        !out(&allowed).contains("EPERM"),
        "AllowComm did not allow cross-zone connect to {IP_B}:9: {}",
        out(&allowed)
    );
    println!(
        "allowed cross-zone connect -> {IP_B}:9 : {} (NOT EPERM — AllowComm permits zone pair)",
        out(&allowed)
    );

    // --- Network-OPEN (Bridged) caller: open mode does not bypass zone-pair. ---
    // Control: an unmapped non-loopback destination is reachable (no EPERM —
    // ECONNREFUSED from the dummy interface is the expected network outcome),
    // proving zone-c is genuinely network-open.
    let open_unmapped = workload_connect(&bridged_procs, IP_UNMAPPED, 9);
    anyhow::ensure!(
        !out(&open_unmapped).contains("EPERM"),
        "bridged zone was denied an UNMAPPED destination {IP_UNMAPPED}:9: {}",
        out(&open_unmapped)
    );
    println!(
        "bridged unmapped connect -> {IP_UNMAPPED}:9 : {} (NOT EPERM — open zone reaches unmapped destinations)",
        out(&open_unmapped)
    );

    // The same open zone connecting to a MAPPED zone-b IP (no AllowComm
    // between zone-c and zone-b) must be denied: zone-pair beats open mode.
    let before_open = hook_deny(&mut client, "socket_connect").await?;
    let open_cross = workload_connect(&bridged_procs, IP_B, 9);
    let after_open = hook_deny(&mut client, "socket_connect").await?;
    anyhow::ensure!(
        out(&open_cross).contains("EPERM"),
        "bridged zone reached mapped cross-zone IP {IP_B}:9 without AllowComm: {}",
        out(&open_cross)
    );
    anyhow::ensure!(
        after_open.saturating_sub(before_open) == 1,
        "socket_connect deny did not move by 1 for the bridged caller (before={before_open}, after={after_open})"
    );
    println!(
        "bridged cross-zone connect -> {IP_B}:9 : DENIED EPERM, deny_delta=1 (open mode does not bypass zone-pair)"
    );

    println!("=== syva integration evidence: cross-zone TCP by IP-zone map ===");
    println!(
        "zone-a workload: same-zone IP {IP_A} allowed; zone-b IP {IP_B} denied with EPERM until AllowComm flips it to allowed"
    );
    println!(
        "zone-c (Bridged) workload: unmapped {IP_UNMAPPED} reachable; mapped zone-b IP {IP_B} denied with EPERM — network-open zones still honor the zone-pair rule"
    );
    Ok(())
}
