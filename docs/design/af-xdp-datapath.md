# Design: AF_XDP zero-copy datapath

Status: **experimental, explicit opt-in.** The config and transport selection
path now know about `transport = "af_xdp"`, and the node runtime calls the
XSK-based datapath (`turna_transport::af_xdp::xsk::XskDatapath`) when built on
Linux with `--features af-xdp`. This is not a production-default backend and is
never selected by `auto`.

## Goal

AF_XDP is a Linux datapath that moves packets between a NIC queue and userspace
through an XSK/UMEM ring, bypassing the normal UDP socket stack. The target is a
lower CPU-per-packet media path for very high packet-rate TURN deployments on
hardware that supports XDP/AF_XDP well.

## Current implementation

There are two AF_XDP-related layers in the tree:

1. **Runtime path:** `services/node/src/af_xdp_listener.rs` uses
   `turna_transport::af_xdp::xsk::XskDatapath`. This is the path selected by
   `transport = "af_xdp"` after `turna_transport::select` confirms AF_XDP is
   available for the build/platform.
2. **Low-level scaffolding:** `crates/transport/src/af_xdp.rs` still contains
   hand-rolled `Umem`, `AfXdpSocket`, and `AfXdpTransport` types. The
   `AfXdpTransport::recv_batch` and `send_to` methods intentionally fail loudly
   with `unimplemented!()` because that wrapper is not the supported runtime
   path.

The active XSK path is still Phase-1/experimental:

- Linux-only and feature-gated by `af-xdp`.
- IPv4-focused in the first phase.
- Requires privileges and NIC/queue/XDP setup.
- Requires `[turn.af_xdp]` MAC configuration or an environment where neighbour
  resolution/header construction is already handled as expected.
- Needs a hardware-specific validation run before production traffic.

## Configuration

```toml
[turn]
transport = "af_xdp"

[turn.af_xdp]
interface = "eth0"
queue_id = 0
frame_count = 4096
frame_size = 2048
fill_ring_size = 2048
comp_ring_size = 2048
rx_ring_size = 2048
tx_ring_size = 2048
zero_copy = false
need_wakeup = true
src_mac = "aa:bb:cc:dd:ee:ff"
dst_mac = "11:22:33:44:55:66"
```

`auto` does not select AF_XDP. Operators must request it explicitly.

## Why this path is risky

AF_XDP is not just another UDP socket. A correct backend must maintain all of
these invariants:

1. **Frame ownership:** a UMEM frame must have exactly one owner: kernel RX,
   userspace parser, TX ring, completion ring, or free list. Double-free or
   reuse-before-completion is a datapath memory-safety bug.
2. **Ring ordering:** fill/RX/TX/completion rings require correct producer and
   consumer index publication.
3. **Full L2-L4 framing:** XSK works with Ethernet frames, not just UDP payloads.
   The backend must parse/build Ethernet, IPv4, UDP, and checksums.
4. **Queue sharding:** one XSK binds to a NIC queue. RSS/XDP program setup must
   steer the TURN listener traffic to the expected queue(s).
5. **Neighbour/MAC correctness:** TX frames need correct source and destination
   MACs. Placeholders are fine for tests, not for production.

## Test strategy before production

1. Build explicitly:

   ```sh
   cargo build --release --features af-xdp --bin turna-node
   ```

2. Validate config:

   ```sh
   turna-node --dump-config /etc/turna/turn.toml
   ```

3. Start in a lab using a veth pair or a dedicated NIC queue.
4. Generate STUN/TURN allocation traffic and verify packet counters, relay
   behaviour, and no frame-pool exhaustion.
5. Repeat with zero-copy enabled only after copy-mode works.
6. Compare with `transport = "tokio"` and `transport = "io_uring"` using the
   same relay range and client load.

## Production guidance

- Do not enable AF_XDP just because the feature compiles.
- Keep `transport = "tokio"` for normal deployments.
- Treat AF_XDP as a hardware-specific performance project with its own soak,
  packet-capture, and failure-injection plan.
- Keep `docs/security/unsafe-inventory.json` and `docs/unsafe-audit.md` in sync
  whenever AF_XDP unsafe code changes.
