pub mod syva_core {
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
