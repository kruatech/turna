# Integration & soak tests

Workspace test crates that exercise turna beyond the per-crate unit tests:

- `tests/integration` (`turna-integration-tests`) — STUN/TURN protocol checks
  and a live end-to-end lifecycle driven against a running `turna-node`.
- `tests/soak` (`turna-soak`) — resource/leak and throughput checks.

Run everything in the workspace:

```bash
cargo test --workspace --all-features
```

## `turna-integration-tests`

Source: `tests/integration/src/lib.rs`.

### Live end-to-end (UDP)

These talk to a real `turna-node` over UDP and drive the full lifecycle
(Binding → Allocate 401 → authed Allocate → Refresh → CreatePermission →
ChannelBind → ChannelData). If `TURNA_TEST_TARGET` is unset, each test spawns a
hermetic node on ephemeral ports (temporary tokio config, waits for `/ready`,
killed together with the test process via `PR_SET_PDEATHSIG`). If
`TURNA_TEST_TARGET` is set, that external server is used instead.

| Test | What it checks |
|---|---|
| `stun_binding` | STUN Binding request → success |
| `malformed_packet_ignored` | server ignores malformed input |
| `concurrent_bindings` | many parallel Binding requests |
| `turn_allocate` | Allocate 401 → authed Allocate → relayed address |
| `turn_allocate_wrong_password` | wrong credentials are rejected |
| `turn_refresh` | Refresh lifetime |
| `turn_create_permission` | CreatePermission |
| `turn_channel_bind` | ChannelBind |
| `turn_channel_data_relay` | ChannelData relay round-trip |

By default an unreachable server makes these tests **skip** (the
`skip_if_no_server!` macro). Set `TURNA_TEST_REQUIRE_SERVER=1` to turn that skip
into a hard failure, so a green CI run cannot hide an unexercised e2e cycle:

```bash
TURNA_TEST_REQUIRE_SERVER=1 cargo test -p turna-integration-tests
```

### Pure unit tests (no server)

Run with no network and no server:
`binding_request_format`, `xor_mapped_address_parsing`,
`long_term_key_rfc_vector`, `turn_msg_encode_length`, `channel_data_format`,
`error_code_parsing`, `time_limited_credentials_format`.

### Cluster tests

`cluster_redirect_distribution`, `cluster_redirect_is_plain_alternate_server`,
`turn_migration_rebind_and_replay`. Gated at runtime by `cluster_enabled()`;
they need a server configured for cluster redirect / mobility, otherwise they
skip.

### DTLS end-to-end

`dtls_e2e::stun_binding_over_dtls` is gated behind both the `dtls` cargo feature
and `#[ignore]`, so it never runs in a plain `cargo test`. It needs a live
server built and configured with `--features dtls`:

```bash
cargo test -p turna-integration-tests --features dtls -- --ignored dtls
```

### Auth modes / environment

Pick the mode that matches the server's `[turn.auth]` configuration.

| Variable | Meaning |
|---|---|
| `TURNA_TEST_TARGET` | external `host:port` to test against (default: hermetic spawn) |
| `TURNA_TEST_USER` / `TURNA_TEST_PASS` | static long-term users (defaults: `testuser` / `testpass`) |
| `TURNA_TEST_SECRET` | enables coturn-style time-limited credentials (SharedSecret mode) |
| `TURNA_TEST_DEBUG` | hex-dump HMAC inputs/outputs |
| `TURNA_TEST_REQUIRE_SERVER` | turn reachability skips into failures |

- **SharedSecret** (coturn lt-cred-mech): set `TURNA_TEST_SECRET` to the same
  value the server uses.
- **LongTerm** (static users): leave `TURNA_TEST_SECRET` unset; configure the
  server with users matching `TURNA_TEST_USER` / `TURNA_TEST_PASS`.

## `turna-soak`

Source: `tests/soak/src/lib.rs`. Resource-bound and throughput checks:

| Test | What it checks |
|---|---|
| `bytes_pool_no_leak_under_load` | buffer pool does not leak under load |
| `bytes_clone_is_zero_copy_and_drops_cleanly` | zero-copy clone + clean drop |
| `allocation_store_arc_no_leak` | allocation store `Arc`s are released |
| `processor_actually_processes_packets` | the processor actually consumes packets |

`full_soak_10k_allocs_1m_packets` is `#[ignore]`d (long-running); run it
explicitly:

```bash
cargo test -p turna-soak -- --ignored --nocapture
```

## Related test entry points (elsewhere in the tree)

- Fuzzing: `fuzz/` — see `fuzz/README.md`.
- Backend differential e2e: `scripts/e2e/` — see `scripts/e2e/README.md`.
- Benchmark vs coturn: `bench/` — see `bench/README.md`.
- Property tests: `crates/protocol/proto-stun/tests/property.rs`,
  `crates/protocol/proto-turn/tests/property.rs`.
- Loom model: `turna-qos` token-bucket (`RUSTFLAGS="--cfg loom"`).
