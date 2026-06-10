# Design: AF_XDP zero-copy datapath

Status: **partially implemented.** The pure L2–L4 stack (Phase 2) and the
feature/module shell (Phase 0) are now in the tree and unit-tested; the unsafe
ring/mmap datapath (Phase 1) and the `select`/worker integration (Phase 4)
remain. This document is the full plan; per-phase status is marked below.

## 1. Goal

A third transport backend (alongside `tokio` and `io_uring`) that moves UDP in
and out of userspace via an AF_XDP socket (XSK) sharing a UMEM with the kernel,
bypassing the network stack for the media path. Target: higher pps and lower
per-packet CPU than the io_uring datapath on NICs that support XDP.

## 2. Current state (precise)

- `crates/transport/src/af_xdp.rs` exists and contains **real low-level
  scaffolding**: `Umem` (mmap'd frame area, `alloc_frame`/`free_frame`,
  frame-ownership `unsafe Send/Sync`), `AfXdpSocket` (`create`/`bind`, ring-size
  setup for fill/comp/rx/tx, `poll`, `wakeup_tx`), `AfXdpConfig`, and an
  `AfXdpTransport` wrapper.
- The **datapath itself is a placeholder**: `AfXdpTransport::recv_batch`
  returns an empty `Vec`, and `send_to` is a no-op (see the `// placeholder`
  comments). The ring producer/consumer index arithmetic is not implemented.
- The module is **not wired in**: `crates/transport/src/lib.rs` has no
  `pub mod af_xdp;`, so it is not compiled. `select.rs` has no `AfXdp` variant
  (only `Auto`/`IoUring`/`Tokio`). `crates/transport/Cargo.toml` has no
  `af-xdp` feature.
- There is a separate, real **eBPF socket pre-filter** (`bpf_filter.rs`,
  `TURNA_BPF_FILTER=1`) — unrelated to AF_XDP but a useful starting point for
  the XDP program work in Phase 3.

## 3. Why this is hard (the real work)

AF_XDP is not "another socket". A working datapath needs all of:

1. **Ring producer/consumer logic.** Four single-producer/single-consumer rings
   (fill, rx, completion, tx) in mmap'd memory, driven by atomic producer/
   consumer indices read via `XDP_MMAP_OFFSETS`. `recv_batch`/`send_to` must
   correctly publish/consume descriptors without racing the kernel. This is the
   part most likely to produce a use-after-free if the frame-ownership protocol
   (already sketched in `Umem`) is off by one.
2. **A mini L2–L4 stack.** An XSK delivers/accepts **full Ethernet frames**, not
   UDP payloads. RX: parse ETH → IP(v4/v6) → UDP, drop everything else, extract
   `(payload, src SocketAddr)`. TX: build ETH (destination MAC via the kernel
   neighbour table / ARP), IP (+ checksum), UDP (+ checksum). This is real
   networking code turna does not have today.
3. **An XDP/eBPF redirect program** loaded on the NIC that `XDP_REDIRECT`s the
   matching traffic (our listen port / queue) into an `XSKMAP`. Without it the
   XSK sees nothing.
4. **NIC/driver + privileges.** Zero-copy needs a driver with AF_XDP ZC support;
   otherwise XDP "copy mode" (slower but driver-agnostic). Requires `CAP_NET_RAW`
   + `CAP_BPF` (or root).
5. **Queue-level sharding.** AF_XDP binds one XSK per NIC RX queue. The
   thread-per-core model maps one worker → one queue (the AF_XDP analogue of the
   io_uring `SO_REUSEPORT` sharding). Relay sockets to peers also need AF_XDP TX
   with per-peer header building — a significant extra surface.

## 4. Strong recommendation

Do **not** hand-roll the ring/mmap math. Adopt a maintained binding:

- `xsk-rs` (safe-ish AF_XDP/XSK wrapper over libbpf), or
- `libxdp`/`libbpf` via `libbpf-rs` for the XDP program + XSKMAP.

This removes the highest-risk part (item 1) and the BPF loading (item 3), and
lets us focus on the L2–L4 stack and integration. Start in **XDP copy mode** for
correctness (works on any NIC), then enable zero-copy where the driver supports
it.

## 5. Phased plan

**Phase 0 — wiring shell (small, compiles, no datapath). [DONE — except the
`lib.rs` module line, which is applied manually to avoid clobbering the real
file].**
- `transport/Cargo.toml`: `af-xdp = []` feature added (dependency-free for now;
  adopt `xsk-rs` for the ring datapath in Phase 1). ✅
- `lib.rs`: `#[cfg(all(target_os = "linux", feature = "af-xdp"))] pub mod af_xdp;`
  — add this one line by hand (see the round notes).
- `select.rs`: add `TransportPreference::AfXdp` + `TransportBackend::AfXdp` and a
  `probe_af_xdp()`; `resolve()` only picks it when explicitly requested. **TODO
  (Phase 4)** — deferred so it doesn't force an `AfXdp` arm into `main.rs`'s
  transport match before the datapath exists.

**Phase 1 — RX/TX over the rings (datapath core). [TODO — unsafe/xsk-rs].**
- Implement `recv_batch` (drain RX ring → `ReceivedFrame`s) and `send_to`
  (alloc frame, fill, submit to TX ring, `wakeup_tx` when `need_wakeup`), via
  `xsk-rs`. The placeholders now point at the `frame` functions below.

**Phase 2 — L2–L4 parse/build. [DONE — unit-tested].**
- `af_xdp::frame::parse_eth_ipv4_udp` (ETH/IP/UDP → src/dst + payload offset)
  and `frame::build_eth_ipv4_udp` (build headers + IPv4/UDP checksums) are
  implemented with round-trip and checksum-validity tests (`cargo test
  --features af-xdp`). IPv6 is still a TODO.

**Phase 3 — XDP redirect program.**
- Minimal XDP program: match our UDP listen port → `bpf_redirect_map` into the
  XSKMAP for the bound queue; pass everything else to the stack. Load via
  `libbpf-rs`. Reuse patterns from `bpf_filter.rs`.

**Phase 4 — integration.**
- A dedicated AF_XDP worker loop (or reuse the `worker.rs` thread-per-core shape):
  one XSK per RX queue, all bound to the listen port, sharded by queue (ethtool
  RSS / XDP). Decide how relay sockets to peers are handled — likely AF_XDP TX
  with cached per-peer ETH/IP headers. This is the largest integration piece and
  interacts with the relay-route sharded ownership (RFC 8016) the same way the
  io_uring pool does.

## 6. Test strategy

- **Unit (here / CI, no hardware):** ring descriptor accounting, ETH/IP/UDP
  parse + checksum build, frame-ownership invariants.
- **Integration (your Linux box / CI with privileges):** `veth` pair in a
  network namespace with an XDP program in copy mode — exercises the full path
  without a special NIC. Then a real NIC with ZC for performance.
- **Perf gate:** pps and cycles/packet vs the io_uring backend in `bench/`,
  including the garbage-flood profile.

## 7. Effort & risk

- **Effort:** large (multi-week), dominated by Phase 2 (L2–L4) and Phase 4
  (integration), even with `xsk-rs` removing Phase 1/3 risk.
- **Risk:** `unsafe`-heavy; an off-by-one in frame ownership is a UAF on the
  media hot path. Mitigations: adopt `xsk-rs`; copy mode first; keep AF_XDP an
  explicit opt-in (never `Auto`) until it has soaked.
- **Until then:** `af_xdp.rs` stays unwired and documented as scaffolding (see
  PRODUCTION_READINESS.md R3); `transport = "tokio"` remains the default.
