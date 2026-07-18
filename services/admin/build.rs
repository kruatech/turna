fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Single source of truth: compile the canonical management contract from the
    // control crate directly, so the admin client can never drift from the
    // server's proto. (A divergent local copy previously dropped fields like
    // node_id / idempotency_key and the audit RPCs, breaking this build.)
    let proto = "../../crates/control/proto/management.proto";
    let include = "../../crates/control/proto";
    println!("cargo:rerun-if-changed={proto}");
    tonic_prost_build::configure()
        .build_server(false) // admin is client-only
        .build_client(true)
        .compile_protos(&[proto], &[include])?;
    Ok(())
}
