//! syva-oracle — blackbox test binary against a running syva-core.
//!
//! Pattern borrowed from AHTI's `eval/oracle`. Each `#[tokio::test]` function
//! is numbered `case_NNN_short_desc` with a stable ID (never reused). Tests
//! may only import `syva_proto` — no crate-internal types from syva-core or
//! adapters. The oracle treats the running core as opaque: RPCs in, responses
//! out, BPF maps checked via ListZones/ListComms/Status/WatchEvents.
//!
//! Invocation (separate from the workspace):
//!
//! ```text
//! cargo test --manifest-path eval/oracle/Cargo.toml
//! cargo test --manifest-path eval/oracle/Cargo.toml -- case_001 --nocapture
//! ```
//!
//! Environment:
//!
//! - `SYVA_SOCKET` — path to syva-core's Unix socket (default
//!   `/run/syva/syva-core.sock`; often overridden to `/tmp/syva-oracle.sock`
//!   for local runs).
//!
//! When syva-core isn't reachable, each test returns early via
//! `require_core_or_skip!()`. Oracle failures must reflect a genuine
//! contract violation, not a missing service.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use syva_proto::syva_core::syva_core_client::SyvaCoreClient;
use syva_proto::syva_core::*;
use tonic::transport::Channel;

// ---------------------------------------------------------------------------
// Settlement constants
// ---------------------------------------------------------------------------
// BPF map writes land in the kernel on the syscall thread; the adapter-visible
// effect is synchronous. Event stream draining runs on a 100ms tick — allow a
// bit more than one tick for deny events to surface.

const MAP_SETTLE_MS: u64 = 50;
const EVENT_SETTLE_MS: u64 = 250;
const ADAPTER_SETTLE_MS: u64 = 250;
const RECONCILE_TIMEOUT_SECS: u64 = 10;
const PROCESS_EXIT_TIMEOUT_SECS: u64 = 2;

// ---------------------------------------------------------------------------
// Connection helpers
// ---------------------------------------------------------------------------

fn socket_path() -> String {
    std::env::var("SYVA_SOCKET").unwrap_or_else(|_| "/run/syva/syva-core.sock".to_string())
}

async fn connect() -> anyhow::Result<SyvaCoreClient<Channel>> {
    let path = socket_path();
    let channel = tonic::transport::Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
            let path = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(&path).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await?;
    Ok(SyvaCoreClient::new(channel))
}

/// Skip this test if syva-core isn't reachable. Oracle tests should fail only
/// on real contract violations, not on environment issues.
macro_rules! require_core_or_skip {
    () => {
        match connect().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SKIP: syva-core not reachable at {} — {e}", socket_path());
                return;
            }
        }
    };
}

macro_rules! skip {
    ($($arg:tt)*) => {{
        eprintln!("SKIP: {}", format!($($arg)*));
        return;
    }};
}

// ---------------------------------------------------------------------------
// Blackbox process and filesystem helpers
// ---------------------------------------------------------------------------

struct ChildGuard {
    child: Child,
}

impl ChildGuard {
    fn spawn(mut command: Command) -> anyhow::Result<Self> {
        let child = command.spawn()?;
        Ok(Self { child })
    }

    fn try_wait(&mut self) -> anyhow::Result<Option<std::process::ExitStatus>> {
        Ok(self.child.try_wait()?)
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn workspace_root() -> anyhow::Result<PathBuf> {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.exists() {
            let raw = std::fs::read_to_string(&manifest)?;
            if raw.contains("\"syva-adapter-file\"") {
                return Ok(dir);
            }
        }
        if !dir.pop() {
            anyhow::bail!("could not find syva workspace root from CARGO_MANIFEST_DIR");
        }
    }
}

fn target_bin(bin_name: &str) -> anyhow::Result<PathBuf> {
    let path = workspace_root()?
        .join("target")
        .join("debug")
        .join(bin_name);
    if path.exists() {
        Ok(path)
    } else {
        anyhow::bail!(
            "target/debug/{bin_name} not built — run 'cargo build -p syva-adapter-file -p syva-adapter-api -p syva-core' first"
        );
    }
}

fn write_policy(dir: &Path, name: &str, body: &str) -> anyhow::Result<()> {
    std::fs::write(dir.join(format!("{name}.toml")), body)?;
    Ok(())
}

fn remove_policy(dir: &Path, name: &str) -> anyhow::Result<()> {
    std::fs::remove_file(dir.join(format!("{name}.toml")))?;
    Ok(())
}

fn policy_toml(zone_type: &str, allowed_zones: &[&str], allow_ptrace: bool) -> String {
    let allowed = allowed_zones
        .iter()
        .map(|zone| format!("\"{zone}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let capabilities = if allow_ptrace {
        "\"CAP_SYS_PTRACE\""
    } else {
        ""
    };
    format!(
        r#"[zone]
type = "{zone_type}"

[capabilities]
allowed = [{capabilities}]

[resources]
cpu_shares = 1024
memory_limit = "512Mi"
io_weight = 100
pids_max = 256

[network]
mode = "isolated"
allowed_zones = [{allowed}]
allowed_egress = []
allowed_ingress = []

[filesystem]
shared_layers = true
writable_paths = ["/tmp"]
host_paths = []

[devices]
allowed = []

[syscalls]
deny = []
"#
    )
}

fn spawn_file_adapter(policy_dir: &Path) -> anyhow::Result<ChildGuard> {
    let bin = target_bin("syva-file")?;
    let mut command = Command::new(bin);
    command
        .arg("--core-socket")
        .arg(socket_path())
        .arg("--policy-dir")
        .arg(policy_dir)
        .arg("--reconcile-secs")
        .arg("1")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    ChildGuard::spawn(command)
}

fn free_addr() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?)
}

fn free_addr_or_skip() -> Option<SocketAddr> {
    match free_addr() {
        Ok(addr) => Some(addr),
        Err(error) => {
            eprintln!("SKIP: cannot allocate localhost port for API adapter — {error}");
            None
        }
    }
}

fn spawn_api_adapter(addr: SocketAddr) -> anyhow::Result<ChildGuard> {
    let bin = target_bin("syva-api")?;
    let mut command = Command::new(bin);
    command
        .arg("--listen")
        .arg(addr.to_string())
        .arg("--core-socket")
        .arg(socket_path())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    ChildGuard::spawn(command)
}

async fn wait_for_adapter(child: &mut ChildGuard) -> anyhow::Result<()> {
    tokio::time::sleep(Duration::from_millis(ADAPTER_SETTLE_MS)).await;
    if let Some(status) = child.try_wait()? {
        anyhow::bail!("adapter exited early with {status}");
    }
    Ok(())
}

async fn wait_for_zone(
    client: &mut SyvaCoreClient<Channel>,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<ZoneSummary> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(zone) = list_zones(client)
            .await?
            .into_iter()
            .find(|zone| zone.name == name)
        {
            return Ok(zone);
        }
        if Instant::now() >= deadline {
            anyhow::bail!("zone '{name}' did not appear within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_zone_absent(
    client: &mut SyvaCoreClient<Channel>,
    name: &str,
    timeout: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if !list_zones(client)
            .await?
            .iter()
            .any(|zone| zone.name == name)
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("zone '{name}' still present after {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_comm(
    client: &mut SyvaCoreClient<Channel>,
    a: &str,
    b: &str,
    expected: bool,
    timeout: Duration,
) -> anyhow::Result<()> {
    let needle = canon(a, b);
    let deadline = Instant::now() + timeout;
    loop {
        let hit = list_comms(client, None)
            .await?
            .iter()
            .any(|pair| canon(&pair.zone_a, &pair.zone_b) == needle);
        if hit == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!("comm pair {needle:?} did not reach expected={expected}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn http_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> anyhow::Result<(u16, String)> {
    let body = body.unwrap_or("");
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(2))?;
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let status = response
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("invalid HTTP response: {response:?}"))?;
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();
    Ok((status, body))
}

fn run_short_process(
    mut command: Command,
    timeout: Duration,
) -> anyhow::Result<(std::process::ExitStatus, String)> {
    command.stdout(Stdio::null()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            return Ok((status, stderr));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("process did not exit within {timeout:?}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

// ---------------------------------------------------------------------------
// RPC helpers — every call goes through a single helper so tests read like
// specs, not plumbing.
// ---------------------------------------------------------------------------

async fn register_zone(
    client: &mut SyvaCoreClient<Channel>,
    name: &str,
    policy: ZonePolicy,
) -> anyhow::Result<u32> {
    let resp = client
        .register_zone(RegisterZoneRequest {
            zone_name: name.to_string(),
            policy: Some(policy),
        })
        .await?;
    Ok(resp.into_inner().zone_id)
}

async fn remove_zone(
    client: &mut SyvaCoreClient<Channel>,
    name: &str,
    drain: bool,
) -> anyhow::Result<()> {
    let resp = client
        .remove_zone(RemoveZoneRequest {
            zone_name: name.to_string(),
            drain,
        })
        .await?;
    let inner = resp.into_inner();
    if !inner.ok {
        anyhow::bail!("remove_zone({name}) returned not-ok: {}", inner.message);
    }
    Ok(())
}

async fn allow_comm(client: &mut SyvaCoreClient<Channel>, a: &str, b: &str) -> anyhow::Result<()> {
    let resp = client
        .allow_comm(AllowCommRequest {
            zone_a: a.to_string(),
            zone_b: b.to_string(),
        })
        .await?;
    anyhow::ensure!(resp.into_inner().ok, "allow_comm({a},{b}) returned not-ok");
    Ok(())
}

async fn deny_comm(client: &mut SyvaCoreClient<Channel>, a: &str, b: &str) -> anyhow::Result<()> {
    let resp = client
        .deny_comm(DenyCommRequest {
            zone_a: a.to_string(),
            zone_b: b.to_string(),
        })
        .await?;
    anyhow::ensure!(resp.into_inner().ok, "deny_comm({a},{b}) returned not-ok");
    Ok(())
}

async fn list_zones(client: &mut SyvaCoreClient<Channel>) -> anyhow::Result<Vec<ZoneSummary>> {
    Ok(client
        .list_zones(ListZonesRequest {})
        .await?
        .into_inner()
        .zones)
}

async fn list_comms(
    client: &mut SyvaCoreClient<Channel>,
    filter: Option<&str>,
) -> anyhow::Result<Vec<CommPair>> {
    let zone_name = filter.map(String::from).unwrap_or_default();
    Ok(client
        .list_comms(ListCommsRequest { zone_name })
        .await?
        .into_inner()
        .pairs)
}

async fn status(client: &mut SyvaCoreClient<Channel>) -> anyhow::Result<StatusResponse> {
    Ok(client.status(StatusRequest {}).await?.into_inner())
}

/// Standard test policy — no host paths, no allowed_zones, no ptrace.
fn empty_policy() -> ZonePolicy {
    ZonePolicy {
        host_paths: vec![],
        allowed_zones: vec![],
        allow_ptrace: false,
        zone_type: ZoneType::Standard.into(),
    }
}

/// Test helper: canonicalize a comm pair the same way core does (lex order).
fn canon(a: &str, b: &str) -> (String, String) {
    if a <= b {
        (a.into(), b.into())
    } else {
        (b.into(), a.into())
    }
}

/// Build a per-test zone name so concurrent test runs don't collide. Callers
/// pair this with a final `remove_zone` in the assertion path so the oracle
/// leaves no residue in core.
fn zone_name(case: &str, suffix: &str) -> String {
    format!("oracle-{case}-{suffix}")
}

// ---------------------------------------------------------------------------
// Test cases — numbered, stable, never reused.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn case_001_register_zone_assigns_nonzero_id() {
    // Spec: every successful RegisterZone returns a zone_id > 0.
    // zone_id 0 is reserved for ZONE_ID_HOST and must never be handed to a zone.
    let mut c = require_core_or_skip!();
    let name = zone_name("c001", "a");
    let id = register_zone(&mut c, &name, empty_policy())
        .await
        .expect("register");
    assert!(id > 0, "zone_id must be > 0 (got {id})");
    remove_zone(&mut c, &name, false).await.expect("remove");
}

#[tokio::test]
async fn case_002_register_zone_is_idempotent() {
    // Spec: registering the same zone name twice returns the same zone_id
    // (idempotent by design — adapters re-send on reconnect).
    let mut c = require_core_or_skip!();
    let name = zone_name("c002", "a");
    let id1 = register_zone(&mut c, &name, empty_policy())
        .await
        .expect("register 1");
    let id2 = register_zone(&mut c, &name, empty_policy())
        .await
        .expect("register 2");
    assert_eq!(id1, id2, "idempotent register must return same zone_id");
    remove_zone(&mut c, &name, false).await.expect("remove");
}

#[tokio::test]
async fn case_003_list_zones_returns_registered_zones() {
    // Spec: ListZones includes every registered zone by name, with matching id,
    // and `state` must be one of "pending"/"active"/"draining".
    let mut c = require_core_or_skip!();
    let a = zone_name("c003", "a");
    let b = zone_name("c003", "b");
    let id_a = register_zone(&mut c, &a, empty_policy())
        .await
        .expect("register a");
    let id_b = register_zone(&mut c, &b, empty_policy())
        .await
        .expect("register b");
    tokio::time::sleep(Duration::from_millis(MAP_SETTLE_MS)).await;

    let zones = list_zones(&mut c).await.expect("list");
    let got_a = zones.iter().find(|z| z.name == a).expect("missing zone a");
    let got_b = zones.iter().find(|z| z.name == b).expect("missing zone b");
    assert_eq!(got_a.zone_id, id_a);
    assert_eq!(got_b.zone_id, id_b);
    for z in [got_a, got_b] {
        assert!(
            matches!(z.state.as_str(), "pending" | "active" | "draining"),
            "unexpected state '{}' for zone {}",
            z.state,
            z.name,
        );
    }
    remove_zone(&mut c, &a, false).await.ok();
    remove_zone(&mut c, &b, false).await.ok();
}

#[tokio::test]
async fn case_004_status_includes_max_zones() {
    // Spec: StatusResponse.max_zones must match syva_ebpf_common::MAX_ZONES.
    // Adapters use this to warn before hitting the BPF Array cap.
    let mut c = require_core_or_skip!();
    let s = status(&mut c).await.expect("status");
    // MAX_ZONES is 4096 today; this is a contract assertion, not a style choice.
    assert_eq!(
        s.max_zones, 4096,
        "max_zones must match ZONE_POLICY BPF Array capacity"
    );
}

#[tokio::test]
async fn case_005_allow_comm_then_list_surfaces_pair() {
    // Spec: after AllowComm(a,b), ListComms returns a CommPair containing both
    // names. Pair ordering is implementation-defined — the oracle canonicalizes.
    let mut c = require_core_or_skip!();
    let a = zone_name("c005", "a");
    let b = zone_name("c005", "b");
    register_zone(&mut c, &a, empty_policy())
        .await
        .expect("register a");
    register_zone(&mut c, &b, empty_policy())
        .await
        .expect("register b");

    allow_comm(&mut c, &a, &b).await.expect("allow");
    tokio::time::sleep(Duration::from_millis(MAP_SETTLE_MS)).await;

    let pairs = list_comms(&mut c, Some(&a)).await.expect("list");
    let needle = canon(&a, &b);
    let hit = pairs.iter().any(|p| canon(&p.zone_a, &p.zone_b) == needle);
    assert!(
        hit,
        "ListComms filter={a} did not return ({a},{b}); got {pairs:?}"
    );

    remove_zone(&mut c, &a, false).await.ok();
    remove_zone(&mut c, &b, false).await.ok();
}

#[tokio::test]
async fn case_006_deny_comm_retracts_pair() {
    // Spec: DenyComm(a,b) removes the pair from ListComms without disturbing
    // unrelated pairs. This is the gap that motivated wiring DenyComm through
    // every adapter — the oracle proves it at the core layer.
    let mut c = require_core_or_skip!();
    let a = zone_name("c006", "a");
    let b = zone_name("c006", "b");
    let unrelated = zone_name("c006", "c");
    for z in [&a, &b, &unrelated] {
        register_zone(&mut c, z, empty_policy())
            .await
            .expect("register");
    }
    allow_comm(&mut c, &a, &b).await.expect("allow a-b");
    allow_comm(&mut c, &a, &unrelated)
        .await
        .expect("allow a-unrelated");
    tokio::time::sleep(Duration::from_millis(MAP_SETTLE_MS)).await;

    deny_comm(&mut c, &a, &b).await.expect("deny a-b");
    tokio::time::sleep(Duration::from_millis(MAP_SETTLE_MS)).await;

    let pairs = list_comms(&mut c, Some(&a)).await.expect("list");
    let ab = canon(&a, &b);
    let au = canon(&a, &unrelated);
    assert!(
        !pairs.iter().any(|p| canon(&p.zone_a, &p.zone_b) == ab),
        "deny_comm(a,b) did not remove the pair; pairs={pairs:?}",
    );
    assert!(
        pairs.iter().any(|p| canon(&p.zone_a, &p.zone_b) == au),
        "deny_comm(a,b) also removed the unrelated pair (a,unrelated); pairs={pairs:?}",
    );

    for z in [&a, &b, &unrelated] {
        remove_zone(&mut c, z, false).await.ok();
    }
}

#[tokio::test]
async fn case_007_remove_zone_also_drops_its_comms() {
    // Spec: removing a zone purges every comm pair involving it. This is the
    // userspace mirror's contract — the BPF map gets wiped via
    // `remove_zone_comms`, and ListComms must stay consistent with that.
    let mut c = require_core_or_skip!();
    let a = zone_name("c007", "a");
    let b = zone_name("c007", "b");
    register_zone(&mut c, &a, empty_policy())
        .await
        .expect("register a");
    register_zone(&mut c, &b, empty_policy())
        .await
        .expect("register b");
    allow_comm(&mut c, &a, &b).await.expect("allow");
    tokio::time::sleep(Duration::from_millis(MAP_SETTLE_MS)).await;

    remove_zone(&mut c, &a, false).await.expect("remove a");
    tokio::time::sleep(Duration::from_millis(MAP_SETTLE_MS)).await;

    // Now list comms involving `b` — the pair must be gone.
    let pairs = list_comms(&mut c, Some(&b)).await.expect("list");
    let ab = canon(&a, &b);
    assert!(
        !pairs.iter().any(|p| canon(&p.zone_a, &p.zone_b) == ab),
        "removing zone a did not purge its comms; pairs for b: {pairs:?}",
    );

    remove_zone(&mut c, &b, false).await.ok();
}

#[tokio::test]
async fn case_008_list_comms_unknown_zone_is_not_found() {
    // Spec: ListComms with a filter that doesn't match any registered zone
    // returns NotFound. Empty-result would hide typos in caller policy.
    let mut c = require_core_or_skip!();
    let err = c
        .list_comms(ListCommsRequest {
            zone_name: "oracle-c008-does-not-exist".into(),
        })
        .await
        .expect_err("ListComms of unknown zone must error");
    assert_eq!(
        err.code(),
        tonic::Code::NotFound,
        "expected NotFound, got {err:?}"
    );
}

#[tokio::test]
async fn case_009_attach_container_rejects_empty_container_id() {
    // Spec: validate_container_id rejects empty IDs before touching any state.
    // InvalidArgument is the correct gRPC code — an empty ID is malformed,
    // not a missing resource.
    let mut c = require_core_or_skip!();
    let name = zone_name("c009", "a");
    register_zone(&mut c, &name, empty_policy())
        .await
        .expect("register");

    let resp = c
        .attach_container(AttachContainerRequest {
            container_id: String::new(),
            zone_name: name.clone(),
            cgroup_id: 1,
        })
        .await;
    // Empty ID is validated and returned as ok=false (not a gRPC error).
    // Adapters treat this as a refusal, not an infrastructure fault.
    match resp {
        Ok(r) => {
            let inner = r.into_inner();
            assert!(!inner.ok, "empty container_id should yield ok=false");
            assert!(!inner.message.is_empty(), "refusal must carry a message");
        }
        Err(e) => assert_eq!(e.code(), tonic::Code::InvalidArgument, "got {e:?}"),
    }

    // Clean up.
    remove_zone(&mut c, &name, false).await.ok();
}

#[tokio::test]
async fn case_010_file_adapter_startup_toml_registers_zone() {
    let mut c = require_core_or_skip!();
    let dir = tempfile::tempdir().expect("tempdir");
    let web = zone_name("c010", "web");
    let api = zone_name("c010", "api");
    write_policy(dir.path(), &web, &policy_toml("standard", &[&api], true)).expect("policy web");
    write_policy(dir.path(), &api, &policy_toml("standard", &[&web], false)).expect("policy api");
    let mut adapter = match spawn_file_adapter(dir.path()) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut adapter)
        .await
        .expect("adapter starts");

    wait_for_zone(&mut c, &web, Duration::from_secs(RECONCILE_TIMEOUT_SECS))
        .await
        .expect("web appears");
    wait_for_zone(&mut c, &api, Duration::from_secs(RECONCILE_TIMEOUT_SECS))
        .await
        .expect("api appears");
    wait_for_comm(
        &mut c,
        &web,
        &api,
        true,
        Duration::from_secs(RECONCILE_TIMEOUT_SECS),
    )
    .await
    .expect("mutual comm appears");
    remove_zone(&mut c, &web, false).await.ok();
    remove_zone(&mut c, &api, false).await.ok();
}

#[tokio::test]
async fn case_011_file_adapter_runtime_toml_add_registers_zone() {
    let mut c = require_core_or_skip!();
    let dir = tempfile::tempdir().expect("tempdir");
    let name = zone_name("c011", "web");
    let mut adapter = match spawn_file_adapter(dir.path()) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut adapter)
        .await
        .expect("adapter starts");
    write_policy(dir.path(), &name, &policy_toml("standard", &[], false)).expect("policy");
    wait_for_zone(&mut c, &name, Duration::from_secs(RECONCILE_TIMEOUT_SECS))
        .await
        .expect("zone appears");
    remove_zone(&mut c, &name, false).await.ok();
}

#[tokio::test]
async fn case_012_file_adapter_toml_remove_removes_zone() {
    let mut c = require_core_or_skip!();
    let dir = tempfile::tempdir().expect("tempdir");
    let name = zone_name("c012", "web");
    write_policy(dir.path(), &name, &policy_toml("standard", &[], false)).expect("policy");
    let mut adapter = match spawn_file_adapter(dir.path()) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut adapter)
        .await
        .expect("adapter starts");
    wait_for_zone(&mut c, &name, Duration::from_secs(RECONCILE_TIMEOUT_SECS))
        .await
        .expect("zone appears");
    remove_policy(dir.path(), &name).expect("remove policy");
    wait_for_zone_absent(&mut c, &name, Duration::from_secs(RECONCILE_TIMEOUT_SECS))
        .await
        .expect("zone removed");
}

#[tokio::test]
async fn case_013_file_adapter_toml_modify_updates_policy() {
    let mut c = require_core_or_skip!();
    let dir = tempfile::tempdir().expect("tempdir");
    let web = zone_name("c013", "web");
    let api = zone_name("c013", "api");
    write_policy(dir.path(), &web, &policy_toml("standard", &[], false)).expect("policy web");
    write_policy(dir.path(), &api, &policy_toml("standard", &[], false)).expect("policy api");
    let mut adapter = match spawn_file_adapter(dir.path()) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut adapter)
        .await
        .expect("adapter starts");
    wait_for_zone(&mut c, &web, Duration::from_secs(RECONCILE_TIMEOUT_SECS))
        .await
        .expect("web appears");
    wait_for_zone(&mut c, &api, Duration::from_secs(RECONCILE_TIMEOUT_SECS))
        .await
        .expect("api appears");
    write_policy(dir.path(), &web, &policy_toml("standard", &[&api], false)).expect("policy web");
    write_policy(dir.path(), &api, &policy_toml("standard", &[&web], false)).expect("policy api");
    wait_for_comm(
        &mut c,
        &web,
        &api,
        true,
        Duration::from_secs(RECONCILE_TIMEOUT_SECS),
    )
    .await
    .expect("comm updated");
    remove_zone(&mut c, &web, false).await.ok();
    remove_zone(&mut c, &api, false).await.ok();
}

#[tokio::test]
async fn case_014_file_adapter_privileged_zone_type_registers() {
    let mut c = require_core_or_skip!();
    let dir = tempfile::tempdir().expect("tempdir");
    let name = zone_name("c014", "priv");
    write_policy(dir.path(), &name, &policy_toml("privileged", &[], false)).expect("policy");
    let mut adapter = match spawn_file_adapter(dir.path()) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut adapter)
        .await
        .expect("adapter starts");
    wait_for_zone(&mut c, &name, Duration::from_secs(RECONCILE_TIMEOUT_SECS))
        .await
        .expect("privileged zone appears");
    remove_zone(&mut c, &name, false).await.ok();
}

#[tokio::test]
async fn case_015_file_adapter_ptrace_capability_registers() {
    let mut c = require_core_or_skip!();
    let dir = tempfile::tempdir().expect("tempdir");
    let name = zone_name("c015", "ptrace");
    write_policy(dir.path(), &name, &policy_toml("standard", &[], true)).expect("policy");
    let mut adapter = match spawn_file_adapter(dir.path()) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut adapter)
        .await
        .expect("adapter starts");
    wait_for_zone(&mut c, &name, Duration::from_secs(RECONCILE_TIMEOUT_SECS))
        .await
        .expect("ptrace policy zone appears");
    remove_zone(&mut c, &name, false).await.ok();
}

#[tokio::test]
async fn case_016_file_adapter_rejects_core_and_cp_flags_together() {
    let bin = match target_bin("syva-file") {
        Ok(path) => path,
        Err(error) => skip!("{error}"),
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let mut command = Command::new(bin);
    command
        .arg("--core-socket")
        .arg("/tmp/syva-oracle-nope.sock")
        .arg("--cp-endpoint")
        .arg("http://127.0.0.1:1")
        .arg("--team-id")
        .arg("00000000-0000-0000-0000-000000000001")
        .arg("--policy-dir")
        .arg(dir.path());
    let (status, stderr) =
        run_short_process(command, Duration::from_secs(PROCESS_EXIT_TIMEOUT_SECS)).expect("run");
    assert!(!status.success(), "process must fail");
    assert!(
        stderr.contains("core-socket") && stderr.contains("cp-endpoint"),
        "{stderr}"
    );
}

#[tokio::test]
async fn case_017_file_adapter_rejects_missing_target_flag() {
    let bin = match target_bin("syva-file") {
        Ok(path) => path,
        Err(error) => skip!("{error}"),
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let mut command = Command::new(bin);
    command.arg("--policy-dir").arg(dir.path());
    let (status, stderr) =
        run_short_process(command, Duration::from_secs(PROCESS_EXIT_TIMEOUT_SECS)).expect("run");
    assert!(!status.success(), "process must fail");
    assert!(
        stderr.contains("one of") || stderr.contains("required") || stderr.contains("core-socket"),
        "{stderr}"
    );
}

#[tokio::test]
async fn case_018_file_adapter_malformed_toml_does_not_poison_valid_policy() {
    let mut c = require_core_or_skip!();
    let dir = tempfile::tempdir().expect("tempdir");
    let valid = zone_name("c018", "valid");
    write_policy(dir.path(), &valid, &policy_toml("standard", &[], false)).expect("valid policy");
    write_policy(dir.path(), "broken", "[network\nnot = valid").expect("broken policy");
    let mut adapter = match spawn_file_adapter(dir.path()) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut adapter)
        .await
        .expect("adapter starts");
    wait_for_zone(&mut c, &valid, Duration::from_secs(RECONCILE_TIMEOUT_SECS))
        .await
        .expect("valid zone appears despite malformed TOML");
    remove_zone(&mut c, &valid, false).await.ok();
}

#[tokio::test]
async fn case_019_file_adapter_retries_until_core_socket_appears() {
    skip!("requires oracle-controlled syva-core lifecycle on a Linux BPF host");
}

#[tokio::test]
async fn case_030_api_post_zone_registers_in_core() {
    let mut c = require_core_or_skip!();
    let Some(addr) = free_addr_or_skip() else {
        return;
    };
    let mut api = match spawn_api_adapter(addr) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut api).await.expect("api starts");
    let name = zone_name("c030", "web");
    let body = format!(
        r#"{{"name":"{name}","policy_json":{{"host_paths":[],"allow_ptrace":false,"zone_type":"standard"}}}}"#
    );
    let (status_code, _) = http_request(addr, "POST", "/v1/zones", Some(&body)).expect("post");
    assert_eq!(status_code, 201);
    wait_for_zone(&mut c, &name, Duration::from_secs(RECONCILE_TIMEOUT_SECS))
        .await
        .expect("zone appears");
    remove_zone(&mut c, &name, false).await.ok();
}

#[tokio::test]
async fn case_031_api_list_zones_matches_core_names() {
    let mut c = require_core_or_skip!();
    let name = zone_name("c031", "web");
    register_zone(&mut c, &name, empty_policy())
        .await
        .expect("register");
    let Some(addr) = free_addr_or_skip() else {
        return;
    };
    let mut api = match spawn_api_adapter(addr) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut api).await.expect("api starts");
    let (status_code, body) = http_request(addr, "GET", "/v1/zones", None).expect("get");
    assert_eq!(status_code, 200);
    assert!(body.contains(&name), "{body}");
    remove_zone(&mut c, &name, false).await.ok();
}

#[tokio::test]
async fn case_032_api_get_zone_matches_core_view() {
    let mut c = require_core_or_skip!();
    let name = zone_name("c032", "web");
    register_zone(&mut c, &name, empty_policy())
        .await
        .expect("register");
    let Some(addr) = free_addr_or_skip() else {
        return;
    };
    let mut api = match spawn_api_adapter(addr) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut api).await.expect("api starts");
    let (status_code, body) =
        http_request(addr, "GET", &format!("/v1/zones/{name}"), None).expect("get");
    assert_eq!(status_code, 200);
    assert!(body.contains(&name), "{body}");
    remove_zone(&mut c, &name, false).await.ok();
}

#[tokio::test]
async fn case_033_api_put_zone_updates_core_view() {
    let mut c = require_core_or_skip!();
    let name = zone_name("c033", "web");
    register_zone(&mut c, &name, empty_policy())
        .await
        .expect("register");
    let Some(addr) = free_addr_or_skip() else {
        return;
    };
    let mut api = match spawn_api_adapter(addr) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut api).await.expect("api starts");
    let body = r#"{"if_version":0,"policy_json":{"host_paths":[],"allow_ptrace":true,"zone_type":"standard"}}"#;
    let (status_code, response) =
        http_request(addr, "PUT", &format!("/v1/zones/{name}"), Some(body)).expect("put");
    assert_eq!(status_code, 200, "{response}");
    assert!(response.contains(&name), "{response}");
    remove_zone(&mut c, &name, false).await.ok();
}

#[tokio::test]
async fn case_034_api_delete_zone_removes_from_core() {
    let mut c = require_core_or_skip!();
    let name = zone_name("c034", "web");
    register_zone(&mut c, &name, empty_policy())
        .await
        .expect("register");
    let Some(addr) = free_addr_or_skip() else {
        return;
    };
    let mut api = match spawn_api_adapter(addr) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut api).await.expect("api starts");
    let (status_code, _) =
        http_request(addr, "DELETE", &format!("/v1/zones/{name}"), None).expect("delete");
    assert_eq!(status_code, 204);
    wait_for_zone_absent(&mut c, &name, Duration::from_secs(RECONCILE_TIMEOUT_SECS))
        .await
        .expect("zone absent");
}

#[tokio::test]
async fn case_035_api_malformed_json_returns_4xx_without_core_change() {
    let mut c = require_core_or_skip!();
    let before = list_zones(&mut c).await.expect("list before").len();
    let Some(addr) = free_addr_or_skip() else {
        return;
    };
    let mut api = match spawn_api_adapter(addr) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut api).await.expect("api starts");
    let (status_code, body) =
        http_request(addr, "POST", "/v1/zones", Some("{not-json")).expect("post malformed");
    assert!((400..500).contains(&status_code), "{status_code}: {body}");
    let after = list_zones(&mut c).await.expect("list after").len();
    assert_eq!(before, after);
}

#[tokio::test]
async fn case_036_api_get_missing_zone_returns_404() {
    let _c = require_core_or_skip!();
    let Some(addr) = free_addr_or_skip() else {
        return;
    };
    let mut api = match spawn_api_adapter(addr) {
        Ok(child) => child,
        Err(error) => skip!("{error}"),
    };
    wait_for_adapter(&mut api).await.expect("api starts");
    let (status_code, _) =
        http_request(addr, "GET", "/v1/zones/oracle-c036-missing", None).expect("get missing");
    assert_eq!(status_code, 404);
}

#[tokio::test]
async fn case_037_api_rejects_core_and_cp_flags_together() {
    let bin = match target_bin("syva-api") {
        Ok(path) => path,
        Err(error) => skip!("{error}"),
    };
    let mut command = Command::new(bin);
    command
        .arg("--listen")
        .arg("127.0.0.1:0")
        .arg("--core-socket")
        .arg("/tmp/syva-oracle-nope.sock")
        .arg("--cp-endpoint")
        .arg("http://127.0.0.1:1")
        .arg("--team-id")
        .arg("00000000-0000-0000-0000-000000000001");
    let (status, stderr) =
        run_short_process(command, Duration::from_secs(PROCESS_EXIT_TIMEOUT_SECS)).expect("run");
    assert!(!status.success(), "process must fail");
    assert!(
        stderr.contains("core-socket") && stderr.contains("cp-endpoint"),
        "{stderr}"
    );
}

#[tokio::test]
async fn case_038_api_returns_5xx_while_core_is_down_then_recovers() {
    skip!("requires oracle-controlled syva-core lifecycle on a Linux BPF host");
}

#[tokio::test]
async fn case_039_api_missing_core_socket_waits_without_crashing() {
    let bin = match target_bin("syva-api") {
        Ok(path) => path,
        Err(error) => skip!("{error}"),
    };
    let Some(addr) = free_addr_or_skip() else {
        return;
    };
    let mut command = Command::new(bin);
    command
        .arg("--listen")
        .arg(addr.to_string())
        .arg("--core-socket")
        .arg("/tmp/syva-oracle-missing-core.sock")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = ChildGuard::spawn(command).expect("spawn api");
    tokio::time::sleep(Duration::from_secs(PROCESS_EXIT_TIMEOUT_SECS)).await;
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "API should keep retrying"
    );
}

#[tokio::test]
async fn case_040_register_100_zones_succeeds_and_status_counts_them() {
    let mut c = require_core_or_skip!();
    let names = (0..100)
        .map(|idx| zone_name("c040", &format!("z{idx:03}")))
        .collect::<Vec<_>>();
    for name in &names {
        register_zone(&mut c, name, empty_policy())
            .await
            .expect("register");
    }
    let zones = list_zones(&mut c).await.expect("list");
    for name in &names {
        assert!(
            zones.iter().any(|zone| zone.name == *name),
            "missing {name}"
        );
    }
    let s = status(&mut c).await.expect("status");
    assert!(
        s.zones_active >= 100,
        "zones_active={} < 100",
        s.zones_active
    );
    for name in &names {
        remove_zone(&mut c, name, false).await.ok();
    }
}

#[tokio::test]
#[ignore = "stress case fills the full zone map; run explicitly on a disposable Linux BPF host"]
async fn case_041_register_past_max_zones_fails_cleanly() {
    let mut c = require_core_or_skip!();
    let max = status(&mut c).await.expect("status").max_zones;
    let mut registered = Vec::new();
    for idx in 0..max {
        let name = zone_name("c041", &format!("z{idx:04}"));
        register_zone(&mut c, &name, empty_policy())
            .await
            .expect("register up to max");
        registered.push(name);
    }
    let overflow = zone_name("c041", "overflow");
    let err = c
        .register_zone(RegisterZoneRequest {
            zone_name: overflow,
            policy: Some(empty_policy()),
        })
        .await
        .expect_err("register past max must fail");
    assert!(
        matches!(
            err.code(),
            tonic::Code::FailedPrecondition
                | tonic::Code::ResourceExhausted
                | tonic::Code::Internal
        ),
        "unexpected code: {err:?}"
    );
    for name in registered {
        remove_zone(&mut c, &name, false).await.ok();
    }
}

#[tokio::test]
async fn case_042_allow_comm_same_zone_is_invalid_argument() {
    let mut c = require_core_or_skip!();
    let name = zone_name("c042", "a");
    register_zone(&mut c, &name, empty_policy())
        .await
        .expect("register");
    let err = c
        .allow_comm(AllowCommRequest {
            zone_a: name.clone(),
            zone_b: name.clone(),
        })
        .await
        .expect_err("same-zone comm must fail");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
    remove_zone(&mut c, &name, false).await.ok();
}

#[tokio::test]
async fn case_043_allow_comm_unknown_zone_is_not_found() {
    let mut c = require_core_or_skip!();
    let name = zone_name("c043", "a");
    let phantom = zone_name("c043", "missing");
    register_zone(&mut c, &name, empty_policy())
        .await
        .expect("register");
    let err = c
        .allow_comm(AllowCommRequest {
            zone_a: name.clone(),
            zone_b: phantom,
        })
        .await
        .expect_err("phantom comm must fail");
    assert_eq!(err.code(), tonic::Code::NotFound);
    remove_zone(&mut c, &name, false).await.ok();
}

#[tokio::test]
async fn case_044_status_zones_active_matches_list_zones_len() {
    let mut c = require_core_or_skip!();
    let names = (0..3)
        .map(|idx| zone_name("c044", &format!("z{idx}")))
        .collect::<Vec<_>>();
    for name in &names {
        register_zone(&mut c, name, empty_policy())
            .await
            .expect("register");
    }
    let zones = list_zones(&mut c).await.expect("list");
    let s = status(&mut c).await.expect("status");
    assert_eq!(s.zones_active as usize, zones.len());
    for name in &names {
        remove_zone(&mut c, name, false).await.ok();
    }
}

#[tokio::test]
async fn case_045_status_uptime_is_monotonic() {
    let mut c = require_core_or_skip!();
    let first = status(&mut c).await.expect("status 1").uptime_secs;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let second = status(&mut c).await.expect("status 2").uptime_secs;
    assert!(
        second >= first,
        "uptime went backwards: {first} -> {second}"
    );
}

#[tokio::test]
async fn case_046_rapid_register_remove_same_name_leaves_zone_absent() {
    let mut c = require_core_or_skip!();
    let name = zone_name("c046", "flap");
    for _ in 0..10 {
        register_zone(&mut c, &name, empty_policy())
            .await
            .expect("register");
        remove_zone(&mut c, &name, false).await.expect("remove");
    }
    let zones = list_zones(&mut c).await.expect("list");
    assert!(
        !zones.iter().any(|zone| zone.name == name),
        "zone leaked after churn"
    );
}

#[tokio::test]
async fn case_047_register_zone_empty_name_is_invalid_argument() {
    let mut c = require_core_or_skip!();
    let err = c
        .register_zone(RegisterZoneRequest {
            zone_name: String::new(),
            policy: Some(empty_policy()),
        })
        .await
        .expect_err("empty name must fail");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn case_048_register_zone_path_traversal_name_is_invalid_argument() {
    let mut c = require_core_or_skip!();
    for bad in ["../etc/passwd", "foo/bar"] {
        let err = c
            .register_zone(RegisterZoneRequest {
                zone_name: bad.to_string(),
                policy: Some(empty_policy()),
            })
            .await
            .expect_err("path-like zone name must fail");
        assert_eq!(err.code(), tonic::Code::InvalidArgument, "name={bad}");
    }
}

#[tokio::test]
async fn case_049_list_zones_during_churn_returns_consistent_snapshots() {
    let mut writer = require_core_or_skip!();
    let mut reader = match connect().await {
        Ok(client) => client,
        Err(error) => skip!("second core connection failed: {error}"),
    };
    let names = (0..25)
        .map(|idx| zone_name("c049", &format!("z{idx:02}")))
        .collect::<Vec<_>>();
    let writer_names = names.clone();
    let handle = tokio::spawn(async move {
        for name in &writer_names {
            register_zone(&mut writer, name, empty_policy()).await?;
            remove_zone(&mut writer, name, false).await?;
        }
        anyhow::Ok(())
    });

    for _ in 0..25 {
        let zones = list_zones(&mut reader).await.expect("list during churn");
        for zone in zones {
            assert!(
                !zone.name.is_empty(),
                "ListZones returned half-formed empty name"
            );
            assert!(zone.zone_id > 0, "ListZones returned half-formed zero id");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    handle.await.expect("join").expect("writer");
    for name in &names {
        remove_zone(&mut reader, name, false).await.ok();
    }
}

// ---------------------------------------------------------------------------
// Case inventory (for the harness) — keep this in sync with the cases above.
// ---------------------------------------------------------------------------
//
// case_001_register_zone_assigns_nonzero_id
// case_002_register_zone_is_idempotent
// case_003_list_zones_returns_registered_zones
// case_004_status_includes_max_zones
// case_005_allow_comm_then_list_surfaces_pair
// case_006_deny_comm_retracts_pair
// case_007_remove_zone_also_drops_its_comms
// case_008_list_comms_unknown_zone_is_not_found
// case_009_attach_container_rejects_empty_container_id
// case_010_file_adapter_startup_toml_registers_zone
// case_011_file_adapter_runtime_toml_add_registers_zone
// case_012_file_adapter_toml_remove_removes_zone
// case_013_file_adapter_toml_modify_updates_policy
// case_014_file_adapter_privileged_zone_type_registers
// case_015_file_adapter_ptrace_capability_registers
// case_016_file_adapter_rejects_core_and_cp_flags_together
// case_017_file_adapter_rejects_missing_target_flag
// case_018_file_adapter_malformed_toml_does_not_poison_valid_policy
// case_019_file_adapter_retries_until_core_socket_appears
// case_030_api_post_zone_registers_in_core
// case_031_api_list_zones_matches_core_names
// case_032_api_get_zone_matches_core_view
// case_033_api_put_zone_updates_core_view
// case_034_api_delete_zone_removes_from_core
// case_035_api_malformed_json_returns_4xx_without_core_change
// case_036_api_get_missing_zone_returns_404
// case_037_api_rejects_core_and_cp_flags_together
// case_038_api_returns_5xx_while_core_is_down_then_recovers
// case_039_api_missing_core_socket_waits_without_crashing
// case_040_register_100_zones_succeeds_and_status_counts_them
// case_041_register_past_max_zones_fails_cleanly
// case_042_allow_comm_same_zone_is_invalid_argument
// case_043_allow_comm_unknown_zone_is_not_found
// case_044_status_zones_active_matches_list_zones_len
// case_045_status_uptime_is_monotonic
// case_046_rapid_register_remove_same_name_leaves_zone_absent
// case_047_register_zone_empty_name_is_invalid_argument
// case_048_register_zone_path_traversal_name_is_invalid_argument
// case_049_list_zones_during_churn_returns_consistent_snapshots

fn main() {
    // The oracle is test-only; `cargo run` is a no-op but prevents bin-target
    // complaints when building the binary alongside the tests.
    let _ = EVENT_SETTLE_MS; // keep-alive so a future event-stream case isn't orphaned
    println!("syva-oracle — run via `cargo test --manifest-path eval/oracle/Cargo.toml`");
}
