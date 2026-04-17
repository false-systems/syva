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

use std::time::Duration;

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
                eprintln!(
                    "SKIP: syva-core not reachable at {} — {e}",
                    socket_path()
                );
                return;
            }
        }
    };
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

async fn remove_zone(client: &mut SyvaCoreClient<Channel>, name: &str, drain: bool) -> anyhow::Result<()> {
    let resp = client
        .remove_zone(RemoveZoneRequest { zone_name: name.to_string(), drain })
        .await?;
    let inner = resp.into_inner();
    if !inner.ok {
        anyhow::bail!("remove_zone({name}) returned not-ok: {}", inner.message);
    }
    Ok(())
}

async fn allow_comm(client: &mut SyvaCoreClient<Channel>, a: &str, b: &str) -> anyhow::Result<()> {
    let resp = client
        .allow_comm(AllowCommRequest { zone_a: a.to_string(), zone_b: b.to_string() })
        .await?;
    anyhow::ensure!(resp.into_inner().ok, "allow_comm({a},{b}) returned not-ok");
    Ok(())
}

async fn deny_comm(client: &mut SyvaCoreClient<Channel>, a: &str, b: &str) -> anyhow::Result<()> {
    let resp = client
        .deny_comm(DenyCommRequest { zone_a: a.to_string(), zone_b: b.to_string() })
        .await?;
    anyhow::ensure!(resp.into_inner().ok, "deny_comm({a},{b}) returned not-ok");
    Ok(())
}

async fn list_zones(client: &mut SyvaCoreClient<Channel>) -> anyhow::Result<Vec<ZoneSummary>> {
    Ok(client.list_zones(ListZonesRequest {}).await?.into_inner().zones)
}

async fn list_comms(
    client: &mut SyvaCoreClient<Channel>,
    filter: Option<&str>,
) -> anyhow::Result<Vec<CommPair>> {
    let zone_name = filter.map(String::from).unwrap_or_default();
    Ok(client.list_comms(ListCommsRequest { zone_name }).await?.into_inner().pairs)
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
    if a <= b { (a.into(), b.into()) } else { (b.into(), a.into()) }
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
    let id = register_zone(&mut c, &name, empty_policy()).await.expect("register");
    assert!(id > 0, "zone_id must be > 0 (got {id})");
    remove_zone(&mut c, &name, false).await.expect("remove");
}

#[tokio::test]
async fn case_002_register_zone_is_idempotent() {
    // Spec: registering the same zone name twice returns the same zone_id
    // (idempotent by design — adapters re-send on reconnect).
    let mut c = require_core_or_skip!();
    let name = zone_name("c002", "a");
    let id1 = register_zone(&mut c, &name, empty_policy()).await.expect("register 1");
    let id2 = register_zone(&mut c, &name, empty_policy()).await.expect("register 2");
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
    let id_a = register_zone(&mut c, &a, empty_policy()).await.expect("register a");
    let id_b = register_zone(&mut c, &b, empty_policy()).await.expect("register b");
    tokio::time::sleep(Duration::from_millis(MAP_SETTLE_MS)).await;

    let zones = list_zones(&mut c).await.expect("list");
    let got_a = zones.iter().find(|z| z.name == a).expect("missing zone a");
    let got_b = zones.iter().find(|z| z.name == b).expect("missing zone b");
    assert_eq!(got_a.zone_id, id_a);
    assert_eq!(got_b.zone_id, id_b);
    for z in [got_a, got_b] {
        assert!(
            matches!(z.state.as_str(), "pending" | "active" | "draining"),
            "unexpected state '{}' for zone {}", z.state, z.name,
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
    assert_eq!(s.max_zones, 4096, "max_zones must match ZONE_POLICY BPF Array capacity");
}

#[tokio::test]
async fn case_005_allow_comm_then_list_surfaces_pair() {
    // Spec: after AllowComm(a,b), ListComms returns a CommPair containing both
    // names. Pair ordering is implementation-defined — the oracle canonicalizes.
    let mut c = require_core_or_skip!();
    let a = zone_name("c005", "a");
    let b = zone_name("c005", "b");
    register_zone(&mut c, &a, empty_policy()).await.expect("register a");
    register_zone(&mut c, &b, empty_policy()).await.expect("register b");

    allow_comm(&mut c, &a, &b).await.expect("allow");
    tokio::time::sleep(Duration::from_millis(MAP_SETTLE_MS)).await;

    let pairs = list_comms(&mut c, Some(&a)).await.expect("list");
    let needle = canon(&a, &b);
    let hit = pairs.iter().any(|p| canon(&p.zone_a, &p.zone_b) == needle);
    assert!(hit, "ListComms filter={a} did not return ({a},{b}); got {pairs:?}");

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
        register_zone(&mut c, z, empty_policy()).await.expect("register");
    }
    allow_comm(&mut c, &a, &b).await.expect("allow a-b");
    allow_comm(&mut c, &a, &unrelated).await.expect("allow a-unrelated");
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
    register_zone(&mut c, &a, empty_policy()).await.expect("register a");
    register_zone(&mut c, &b, empty_policy()).await.expect("register b");
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
        .list_comms(ListCommsRequest { zone_name: "oracle-c008-does-not-exist".into() })
        .await
        .expect_err("ListComms of unknown zone must error");
    assert_eq!(err.code(), tonic::Code::NotFound, "expected NotFound, got {err:?}");
}

#[tokio::test]
async fn case_009_attach_container_rejects_empty_container_id() {
    // Spec: validate_container_id rejects empty IDs before touching any state.
    // InvalidArgument is the correct gRPC code — an empty ID is malformed,
    // not a missing resource.
    let mut c = require_core_or_skip!();
    let name = zone_name("c009", "a");
    register_zone(&mut c, &name, empty_policy()).await.expect("register");

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

fn main() {
    // The oracle is test-only; `cargo run` is a no-op but prevents bin-target
    // complaints when building the binary alongside the tests.
    let _ = EVENT_SETTLE_MS; // keep-alive so a future event-stream case isn't orphaned
    println!("syva-oracle — run via `cargo test --manifest-path eval/oracle/Cargo.toml`");
}
