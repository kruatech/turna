# Production Readiness & Known Limitations

This document is the operational risk register for turna: what is safe to run
today, what is experimental, and the configuration that keeps you on the
well-tested path. It complements the product positioning in
[`why-turna.md`](why-turna.md) and the security material in
[`security/`](security/).

Each risk is rated for **severity** (impact if it bites) and **likelihood**
(how easily you hit it). These are engineering judgements, not guarantees.

---

## Recommended production configuration

Stay on this profile unless you are deliberately testing the experimental
datapaths:

- **`transport = "tokio"`** — the epoll + `recvmmsg`/`sendmmsg` datapath. It is
  the most exercised backend and has a fully-verified graceful drain. The
  io_uring backend now has a lame-duck drain too (R2), but it is experimental
  and runtime-unverified (R2, R5).
- **Set `turn.auth.shared_secret`** explicitly (`openssl rand -hex 32`). The
  placeholder default is refused in production.
- **Pin `turn.migration.ticket_secret`** and use the **same value on every
  node** when clustering. With `cluster_mode = true` an empty secret is now a
  hard configuration error (R-A).
- **Enable the BPF socket pre-filter** on Linux (`TURNA_BPF_FILTER=1`) to drop
  non-STUN/ChannelData garbage in the kernel before it reaches userspace.
- **Use mTLS for the gRPC management plane** — see [`MTLS.md`](MTLS.md).
- **For clustering**, run Tarantool replicated (2+ nodes) and set
  `cluster.persistence.mode = "write_behind"`.
- **Run the `bench/` suite** against your target configuration before rollout.

### Metrics to watch

- `tarantool_writes_dropped_total` — write-behind backpressure / data loss risk.
- `failover_errors_total` — backend errors during failover sweeps.
- `turna_relay_route_forwarded_ratio` — cost of migration on the io_uring
  datapath (see R-D); 0.0 when every relay send is handled locally.

---

## Risk register

### R1 — io_uring datapath is experimental (correctness vs. tokio)

After a client migration (RFC 8016) the client's main-socket traffic can
reshard onto a different io_uring worker than the one that owns its relay
socket. The relay path is **no longer lost**: sharded ownership forwards the
send to the owning worker over a command channel, and the owner never
re-forwards (anti-loop). However this has so far been verified **only
statically** (syn parse + `cargo check` of the worker logic against
`relay_route.rs`), not against a live io_uring ring.

- **Severity:** Medium · **Likelihood:** Medium (io_uring + migration only)
- **Mitigation:** run `transport = "tokio"`. Runtime verification of the
  io_uring path is tracked as a Linux-only task (`cargo test --features
  io-uring` + a migration load run).

### R2 — io_uring worker drain is implemented, runtime-unverified

The tokio datapath drains gracefully: the `DrainOrchestrator`
(`crates/common/src/drain.rs`) stops accepting new allocations, notifies
signaling, waits for sessions to expire, then force-closes; FD-passing
graceful **restart** (`crates/relay/src/graceful.rs`) hands live sockets to a
successor process.

The io_uring worker pool now has a **true graceful drain**. On the shutdown
signal the node sets `metrics.set_draining(true)` (and, on a cluster,
`ClusterRouting::begin_drain()`), so the already-tested processor path rejects
**new** allocations with `508 Server Draining` — or `300 Try Alternate` to
another node when clustered. Each worker keeps its main socket armed, so
existing clients' `Send`/`ChannelData` and all established relay flows continue
through the grace window (`cluster.drain_grace_secs`); only new allocations are
turned away. At the deadline the worker drops its routes from the shared table,
closes its relay sockets, and runs a bounded **wait-until-reclaimed** loop
(≤250 ms) that drives the ring until the in-flight cancellations complete and
the registered buffer/msghdr blocks return to their pools, then exits. The node
`join`s the worker threads instead of abandoning them. This reuses the proven
drain-rejection logic; the io_uring-specific teardown is **verified statically
only** — it has not run against a live ring.

- **Severity:** Low–Medium (down from High once verified) · **Likelihood:**
  High on any restart
- **Mitigation:** run `transport = "tokio"` until the io_uring drain is
  exercised on Linux (`cargo test --features io-uring` + a drain-under-load
  run: `kill -TERM` under traffic, confirm `buffers_available` recovers, the
  `turna_relay_route_*` counters quiesce, and established media survives grace).

### R3 — AF_XDP is not a usable backend

AF_XDP is **not wired into the transport**. `select.rs` exposes only
`Auto` / `IoUring` / `Tokio` (there is no AF_XDP preference), and the
`af_xdp` module is not even declared in `crates/transport/src/lib.rs`, so it is
not compiled into the build. The file `af_xdp.rs` contains real low-level
scaffolding (UMEM allocation, socket/bind, ring setup, poll, frame-ownership
protocol) behind a `--features af-xdp` intent, but the **datapath itself is a
placeholder**: `recv_batch` returns an empty `Vec` and `send_to` is a no-op.

Note this is distinct from the **eBPF socket pre-filter** (`bpf_filter.rs`),
which *is* real and recommended (`TURNA_BPF_FILTER=1`).

- **Severity:** Informational (no operational hazard; it is simply absent)
- **Likelihood:** N/A — it is never on the runtime path.
- **Status:** scaffolding only; do not expect AF_XDP throughput today.

### R4 — Separate the two "TCP/TLS" features (they are both implemented)

Earlier write-ups conflated two independent things. They are different and
both exist in the tree:

- **TURN over TCP/TLS (client↔server transport, TURNS).** Implemented:
  `crates/transport/src/tcp_tls.rs` (rustls acceptor, ALPN, STUN/ChannelData
  framing over TCP/TLS, certificate hot-reload, connection limits, idle
  timeout) bridged to the transport-agnostic `PacketProcessor` via
  `crates/relay/src/tls_bridge.rs`. Gated behind the `tls` feature; default
  port 5349. DTLS (TLS over UDP) is **not** implemented.
- **RFC 6062 TCP relay allocations (TCP relayed *through* the server).**
  Implemented: `crates/relay/src/tcp_relay.rs` — the
  Connect → WaitingForBind → ConnectionBind → Bound state machine for
  CONNECT / CONNECTION-BIND.

- **Severity:** Low–Medium · **Likelihood:** depends on use
- **Caveat:** both paths have **limited test coverage** relative to the UDP
  datapath. Exercise them under your own load before relying on them.

### R5 — Sharded-ownership routing is experimental (static-checked only)

The relay-affinity forwarding (R1) has been validated by syn parse and
`cargo check` of the worker logic, **not** by a live io_uring ring. The
current wake-up mechanism is polling (`cmd_poll_timeout = 500µs`, a
CPU↔forward-latency trade-off); an eventfd-based v2 is deferred.

- **Severity:** Medium · **Likelihood:** Medium (io_uring + migration only)
- **Mitigation:** `transport = "tokio"`; runtime verification on Linux pending.

**Follow-up — eventfd wakeup (design, not yet implemented).** The cross-worker
forward path currently relies on the worker loop unparking every
`cmd_poll_timeout` (500 µs) to drain its command channel — a CPU↔latency
trade-off. A v2 would register an `eventfd` per worker in its io_uring ring
(an `IORING_OP_POLL_ADD` / read on the eventfd) and have a forwarding worker
`write(8 bytes)` to the owner's eventfd right after `tx.send(cmd)`. The owner
then wakes immediately on the eventfd completion, drains the channel, and
re-arms the poll. This removes the polling tax and cuts forward latency to a
wakeup. It is deliberately **not** implemented blind here: it touches the ring
setup (`uring.rs`) and the hot forward path (section-0 core) and can only be
validated against a live ring, so it belongs on the Linux box with a
forward-latency benchmark.

### R6 — No runtime user management over gRPC

`TurnCore::add_user` returns `CoreError::Unimplemented`
(`crates/control/src/turn_core_impl.rs`) by design: LongTerm users are defined
in config and SharedSecret/REST mode keeps no per-user records, so the call
fails honestly instead of pretending a user was created.

- **Severity:** Low · **Likelihood:** Low
- **Workaround:** configure LongTerm users in `turn.toml`, or use
  SharedSecret/REST credentials. Runtime CRUD is a future item.

### R-A — Cross-node migration requires an identical `ticket_secret` (mitigated)

Connection migration mints mobility tickets keyed by `ticket_secret`. With an
empty secret each node derives an **independent random per-process key**, so a
ticket minted on node A is invalid on node B and cross-node migration silently
fails. This previously only produced a `warn!`.

- **Severity:** High (for clusters) → **now mitigated**: configuration
  validation hard-errors when `turn.migration.enabled` is set, `cluster_mode =
  true`, and `ticket_secret` is empty (single non-production nodes still get a
  warning, since a random key only costs them tickets across a restart).
- **Residual:** Low — operators must still set the **same** value on every
  node; a per-node mismatch is not (and cannot be) detected locally.

### R-B — io_uring restart: data-plane bindings still close at exit

See R2 — the drain now rejects new allocations (508/300), keeps existing
client↔peer media flowing through the grace window, unregisters a departing
worker's routes from the shared table, waits (bounded) for in-flight ops to
reclaim, and joins the threads. What it still does **not** do is hand the live
UDP relay socket bindings to a successor process: at the end of grace they are
closed. State in Tarantool persists; live io_uring relay bindings do not
survive the restart (unlike the tokio path's FD-passing restart).

- **Severity:** Low–Medium (down from High once R2 is verified) · **Likelihood:**
  High on restart
- **Mitigation:** `transport = "tokio"` (FD-passing restart preserves live
  bindings); verify the io_uring drain on Linux. FD-passing for the io_uring
  pool is a larger future item.

### R-C — Migration cost was previously invisible (mitigated)

The relay forward-path counters (`RelayRouteStats`: `send_local`,
`send_forwarded`, `send_forward_failed`, `send_stale`, `route_miss`,
`owner_cleanup_stale`) were not exported, so the price of migration on the
io_uring datapath could not be seen in production.

- **Severity:** Medium → **now mitigated**: `/metrics` exposes all six counters
  as `turna_relay_route_*_total`, plus the derived
  `turna_relay_route_forwarded_ratio` gauge (forwarded / (local + forwarded)).
  Present only on io_uring builds, where the route table exists.

---

## Verification status

| Area | How verified |
|---|---|
| Config validation (R-A), relay-route metrics (R-C), worker routing logic (R1/R5), io_uring lame-duck drain (R2, Fix 4) | Static: unit tests + syn parse + `cargo check` |
| io_uring runtime (sharded ownership, lame-duck drain) | **Not yet** — needs Linux + `cargo test --features io-uring` and a drain-under-load run |
| UDP datapath, auth, session, parsers | Unit + integration + fuzz + soak (see `tests/`, `fuzz/`) |

When in doubt, prefer the tokio datapath and the metrics above.
