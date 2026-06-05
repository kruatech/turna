# turna

High-performance TURN/STUN server written in Rust (RFC 5766, RFC 8656, RFC 5389).

> Turna is the Turkish name of the crane — a migratory bird that relays itself
> across continents. This server does the same for your packets.

## Features

- STUN binding and full TURN allocation lifecycle (Allocate / Refresh /
  CreatePermission / ChannelBind / Send & Data indications)
- UDP and TCP relay transports
- Long-term credential mechanism, JWT-based auth, rate limiting and
  credential rotation
- Pluggable state backend (in-memory, Tarantool) for clustered deployments
- gRPC control plane + CLI (`turnactl`) for live management
- OpenTelemetry tracing and Prometheus metrics out of the box
- Graceful drain, session migration and crash recovery
- Continuously fuzzed STUN/TURN parsers (cargo-fuzz, see `fuzz/`)

## Quick start

```bash
cargo build --release
./target/release/turna-node --config deploy/turn.toml
```

See [docs/QUICKSTART.md](docs/QUICKSTART.md) for a complete walkthrough,
[docs/CONFIGURATION.md](docs/CONFIGURATION.md) for all options and
[docs/DEPLOY.md](docs/DEPLOY.md) for Docker / Helm deployments.

## Using turna as a library

All components are published as workspace crates and can be consumed via a
git dependency:

```toml
[dependencies]
turna-relay = { git = "https://github.com/kruatech/turna", tag = "v0.1.0" }
```

## Benchmarks

`bench/` contains a reproducible differential benchmark against coturn.
See [bench/README.md](bench/README.md).

## Security

Parsers are fuzz-tested continuously; the threat model and security
invariants live in [docs/security/](docs/security/). To report a
vulnerability, see [docs/SECURITY.md](docs/SECURITY.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
