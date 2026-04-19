fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_well_known_types(true)
        .extern_path(".google.protobuf", "::prost_types")
        .compile_protos(
            &["proto/syva_core.proto", "proto/syva_control.proto"],
            &["proto/"],
        )?;
    Ok(())
}
