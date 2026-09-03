pub mod syva_core {
    // tonic generates one `Result<_, tonic::Status>` per RPC method, and
    // `Status` is 176 bytes — past clippy's `result_large_err` threshold. The
    // lint fires ~30 times on code we neither wrote nor can edit: it is
    // regenerated from the .proto on every build. Scoped to this module so it
    // can never hide an oversized `Err` in a crate we do own.
    #![allow(clippy::result_large_err)]

    tonic::include_proto!("syva.core.v1");
}

#[cfg(test)]
mod tests {
    #[test]
    fn proto_compiles() {
        // If this test exists and the crate builds, proto compiled successfully.
        // The build.rs compile step is the real test.
    }

    #[test]
    fn register_zone_request_has_required_fields() {
        use crate::syva_core::RegisterZoneRequest;
        let req = RegisterZoneRequest {
            zone_name: "test".to_string(),
            policy: None,
        };
        assert_eq!(req.zone_name, "test");
    }
}
