fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a client-only stub from the control-plane's management.proto.
    // We build our own client (rather than depending on the heavyweight
    // `turna-control` crate, which pulls in the gRPC server, session, auth,
    // state-backend and crypto) so the CLI stays small.
    tonic_prost_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(
            &["../../crates/control/proto/management.proto"],
            &["../../crates/control/proto"],
        )?;
    Ok(())
}
