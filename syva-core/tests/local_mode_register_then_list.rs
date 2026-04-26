//! Manual integration test for local-mode zone registration.
//!
//! Run on Linux as root with a `syva` group present:
//!
//! ```text
//! sudo -E cargo test -p syva-core --test local_mode_register_then_list -- --ignored --nocapture
//! ```

mod common;

use syva_proto::syva_core::{ListZonesRequest, RegisterZoneRequest, ZonePolicy};

#[tokio::test]
#[ignore = "requires Linux, root privileges, BPF LSM support, and group 'syva'"]
async fn local_mode_register_then_list() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let socket_path = dir.path().join("syva-core.sock");
    let _core = common::spawn_core(&socket_path)?;

    let mut client = common::wait_for_core(&socket_path).await?;
    client
        .register_zone(RegisterZoneRequest {
            zone_name: "phase-one-test".to_string(),
            policy: Some(ZonePolicy {
                host_paths: Vec::new(),
                allowed_zones: Vec::new(),
                allow_ptrace: false,
                zone_type: 0,
            }),
        })
        .await?;

    let zones = client
        .list_zones(ListZonesRequest {})
        .await?
        .into_inner()
        .zones;
    assert!(zones.iter().any(|zone| zone.name == "phase-one-test"));
    Ok(())
}
