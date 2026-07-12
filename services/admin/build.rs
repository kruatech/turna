fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false) // admin is client-only
        .compile(&["proto/management.proto"], &["proto"])?;
    Ok(())
}
