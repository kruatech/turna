# AF_XDP Phase 2 — implementation plan (COMPLETED)

> **STATUS: all four items shipped and validated on hardware (IPv4 + IPv6).** See
> `docs/roadmap/IMPLEMENTATION_STATUS.md` → "Stage 4b" for what landed. This file is
> kept as the record of *how* it was planned, not as a task list.
>
> It has already caused one wrong conclusion. Read as a status document it says
> IPv6, netlink neighbour resolution and ring metrics are outstanding — all three
> are in the code (`build_eth_ipv6_udp`, `maybe_ndp_reply`, `crate::neighbor` with
> rtnetlink 0.21, `turna_afxdp_tx_inflight`), and `send_to` resolves the next hop
> per destination rather than using a single static MAC. If you are asking "what is
> left for AF_XDP", the answer is **not code**: it is recorded evidence on the
> target NIC, plus per-queue metric labels once multi-queue binding exists.
> Everything below the line is the original plan text, unchanged.

> **Found 2026-08-19: `zero_copy` conflates two orthogonal settings.**
>
> `cfg.zero_copy` drives both the XSK bind flag (`XDP_ZEROCOPY` vs `XDP_COPY`,
> `af_xdp.rs:1451`) and the XDP attach mode (NATIVE/DRV vs SKB/generic,
> `af_xdp.rs:1196`). Those are independent: the attach mode decides *where the
> program runs*, zero-copy decides *whether the driver DMAs into the UMEM*.
>
> The consequence shows up on veth, which supports native XDP attach but not
> zero-copy: there is no way to ask for a native attach without also asking for
> zero-copy, which the device refuses. So the lab is stuck in SKB mode.
>
> Fix, when someone takes this on: separate keys — `attach_mode = "native"|"skb"` and
> `zero_copy = true|false` — with the current single flag kept as a compatible
> default. Not done here: it changes the meaning of an existing config key, and
> nothing verified which combinations the target NIC actually supports.

> **Found 2026-08-19: `frame_count` above 2× the ring size silently kills RX.**
>
> `af_xdp.rs` honours `cfg.frame_count` but pins the rings to the xsk-rs defaults
> ("for first-light use library defaults (frame 4096, rings 2048) and honour only
> frame_count"). The RX half of the UMEM has to fit the 2048-entry fill ring, so:
>
> | `frame_count` | `umem_free_frames` | RX |
> |---|---|---|
> | 4096 (default) | 2016 | works — 2015 frames received |
> | 16384 | 8160 | **dead — 0 frames received, no error anywhere** |
>
> Nothing reports it. The socket binds, the program attaches, readiness reads 1, and
> not a single packet arrives.
>
> Related: `[turn.af_xdp]` exposes `fill_ring_size`, `comp_ring_size`, `rx_ring_size`
> and `tx_ring_size`, and **all four are ignored** — the same comment says so. A
> config key that does nothing is worse than an absent one, because it invites exactly
> the change that breaks RX.
>
> Fix, when someone takes this on: size the rings from `frame_count` (or honour the
> four ring keys), and refuse a combination where the RX frames cannot fit the fill
> ring instead of accepting it and going quiet.

---

These are the remaining AF_XDP code items. They are **not** written blind here:
each needs the compiler + AF_XDP hardware in the loop, and writing netlink wire
formats / mmap ring offsets / IPv6 parsing from memory would be guessing. This
file is the task breakdown to implement them safely. File references are to
`crates/transport/src/af_xdp.rs` unless noted.

Phase-1 status (done): IPv4 Eth/IP/UDP build+parse with correct checksums; ARP
reply for our own IP (`maybe_arp_reply`); next-hop MAC via default-route gateway
from `/proc/net/route` + `/proc/net/arp` (`resolve_dst_mac`); metrics
`turna_afxdp_arp_replies_total`, `turna_afxdp_neighbor_unresolved`.

---

## 1. Full neighbor resolution (netlink RTM_GETNEIGH)

**Why:** `resolve_dst_mac` resolves only the default gateway, once at bind, from
the ARP cache. On-link peers, multiple routes, and live refresh are missing; an
empty ARP cache yields the zero placeholder (TX silently undeliverable).

**Plan:**
- Introduce a `NeighborResolver` owning a `HashMap<IpAddr, ([u8;6], Instant)>`
  cache with a TTL.
- Resolve per-destination at TX: route lookup (on-link vs via-gateway), then
  next-hop MAC. Prefer the `rtnetlink` crate (RTM_GETROUTE + RTM_GETNEIGH) over
  hand-rolled `AF_NETLINK` parsing — add `rtnetlink` (+ `netlink-packet-route`)
  under the `af-xdp` feature in `Cargo.toml`.
- On cache miss / stale: optionally send an active ARP request (we already build
  ARP frames in `maybe_arp_reply`; add `send_arp_request`) and retry.
- Wire `send_to` / `send_to_from` to resolve `target`'s next-hop instead of using
  the single `self.dst_mac`.
- Metric: make `neighbor_miss` a real counter (incremented per-TX when no MAC is
  resolvable) — replaces the static `neighbor_unresolved` gauge meaning.

**Touch points:** `resolve_dst_mac`, `XskDatapath` (add resolver field),
`send_to`/`send_to_from`, `Cargo.toml` (feature deps).
**Risk:** netlink message construction/parsing — verify against `rtnetlink` docs;
test on the veth lab (add a second namespace so routes/neighbors are real).

## 2. IPv6 support

**Why:** `af_xdp.rs` is IPv4-only (the module header marks IPv6 a TODO);
`maybe_arp_reply` returns `false` for a V6 `local_addr`.

**Plan:**
- `frame::build_eth_ipv6_udp` analogous to `build_eth_ipv4_udp`. Note: IPv6 has
  **no** header checksum; the UDP checksum is **mandatory** and uses the IPv6
  pseudo-header (src/dst 128-bit + upper-layer length + next-header). Reuse
  `udp_checksum` with a v6 pseudo-header variant.
- `recv_batch`: demux `ETHERTYPE_IPV6` (0x86DD); parse the fixed 40-byte IPv6
  header (+ skip known extension headers) down to UDP.
- NDP: `maybe_ndp_reply` answering ICMPv6 Neighbor Solicitation for our IP
  (parallel to `maybe_arp_reply`); requires the ICMPv6 checksum (pseudo-header).
- Lift the `SocketAddr::V6 => return false` guards.

**Touch points:** `frame` module (build + parse + checksum), `recv_batch` demux,
new `maybe_ndp_reply`, `local_addr` V6 paths.
**Risk:** IPv6 extension-header parsing and ICMPv6/UDP pseudo-header checksums —
unit-test the pure `frame` functions (they are `no kernel/ring` and already
unit-testable per the module layout).

## 3. Ring-pending metrics

**Why:** current AF_XDP gauges cover UMEM free frames but not per-ring occupancy
(fill/comp/rx/tx), which is the backpressure signal for the datapath.

**Plan:**
- The `FillQueue`/`CompQueue`/`RxQueue`/`TxQueue` wrappers hold cached
  producer/consumer indices over the mmap'd rings. Add an `pending(&self) -> u32`
  (producer − consumer) or `available()` to each.
- Expose via `XskDatapath` getters (mirror `free_frames()`):
  `fill_pending()`, `comp_pending()`, `rx_pending()`, `tx_pending()`.
- In `af_xdp_listener` loop, store into new health gauges
  `turna_afxdp_{fill,comp,rx,tx}_pending`.

**Touch points:** the four queue structs (index accessors), `XskDatapath`
getters, `af_xdp_listener` loop, `crates/health/src/lib.rs` (4 gauges + export).
**Risk:** must read the correct cached prod/cons (an acquire load paired with the
kernel's release store — see the ownership comment near the RX loop). Low if the
queue wrappers already track these; do not re-mmap.

## 4. Per-`{queue}` metric labels

**Why:** metrics are process-level (single queue). Multi-queue deployments want
`{queue="N"}` labels.

**Plan:** the health export is a single label-free `format!`. Labels need a
label-aware emission path (like `render_tenant_metrics`, which already emits
`turna_tenant_allocations_total{tenant="…"}`). Model the per-queue afxdp metrics
on that helper rather than the flat `format!`.

**Touch points:** `crates/health/src/lib.rs` export.
**Risk:** low (pattern exists); only relevant once multi-queue binding lands.

---

## Suggested order

1. Ring-pending (smallest, no new deps, pure observability).
2. Neighbor resolution (unblocks real over-the-wire TX; needs `rtnetlink`).
3. IPv6 (largest; build on the pure `frame` unit tests).
4. Per-queue labels (only with multi-queue).

Each should land behind `cargo build -p turna-transport --features af-xdp` green
and be exercised on the veth lab (two namespaces for real routing/neighbors).
