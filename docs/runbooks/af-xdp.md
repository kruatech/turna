# AF_XDP datapath — deploy & runbook

> **Status: Experimental (Phase 1).** Compiles and passes startup preflight;
> TX neighbor (ARP/NDP) MAC resolution is a placeholder/follow-up, and runtime
> needs a veth lab or an XDP-capable NIC. Not recommended for production yet.
> See `docs/compatibility/transport-backends.md`.

The AF_XDP backend binds an AF_XDP socket to a specific NIC queue and runs a
busy-poll RX → process → TX loop. It assumes an **externally-loaded XDP program**
steers the relevant traffic to that queue; the server never loads or removes the
XDP program itself, and leaves it untouched on shutdown.

## Capabilities & prerequisites

- Linux, binary built with `--features af-xdp`.
- Build deps for `xsk-rs`/libbpf: `clang llvm libelf-dev zlib1g-dev libbpf-dev`.
- `CAP_NET_RAW` on the process:
  ```bash
  sudo setcap cap_net_raw+ep ./target/release/turna-node
  ```
- A NIC (or veth) whose target queue is steered to the AF_XDP socket by an
  XDP program you load and own.

## Configuration

`transport = "af_xdp"` plus a `[turn.af_xdp]` section. See
`docs/CONFIGURATION.md` for the full key list; the constrained ones:

- `frame_size` ≥ 2048 and ≥ MTU+14.
- `fill_ring_size` a power of two.
- `interface` must exist and be up; `queue_id` must exist on it.

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
src_mac = ""        # placeholder until neighbor resolution lands
dst_mac = ""
```

## Startup preflight

Before touching any kernel resource the node validates: ring geometry
(power-of-two, `frame_size ≥ 2048`), interface exists/up (`/sys/class/net`),
queue `rx-<N>` exists, `frame_size ≥ MTU+14`, and `CAP_NET_RAW`
(`/proc/self/status` `CapEff`). Any failure aborts startup with the list of
problems.

## Local veth lab

Scripts under `scripts/lab/` exercise the datapath on a veth pair without a real
NIC. Run as root, in order:

```bash
sudo scripts/lab/af_xdp_veth_setup.sh    # create veth pair + addressing
sudo scripts/lab/af_xdp_smoke.sh         # boot node on af_xdp + smoke traffic
sudo scripts/lab/af_xdp_cleanup.sh       # tear down
```

## Metrics

Loop-level counters on `/metrics`:

- `turna_afxdp_rx_frames_total`, `turna_afxdp_tx_frames_total`
- `turna_afxdp_rx_bytes_total`, `turna_afxdp_tx_bytes_total`
- `turna_afxdp_parse_drops_total` — frames received that matched no TURN/relay
  port (undemuxable)
- `turna_afxdp_tx_drops_total` — send failures
- `turna_afxdp_relay_ports_registered` — relay ports currently demuxed (gauge)
- `turna_afxdp_umem_free_frames` — free UMEM frames (gauge)

Not yet exposed (need datapath/ARP internals): ARP/NDP reply counts,
neighbor-miss, per-ring (fill/comp/rx/tx) pending depths, `{queue}` labels.

Alert rules covering `turna_afxdp_parse_drops_total` and
`turna_afxdp_umem_free_frames` are in `docs/alerts/transport-backends.yml`.

## Graceful shutdown

`SIGTERM`/`SIGINT` (after the optional drain grace) flips the shutdown watch; the
busy-poll loop observes it within one poll interval and returns, releasing the
XSK socket and UMEM via RAII. The operator-owned XDP program is not modified.

## Known limitations (Phase 1)

- TX `src_mac`/`dst_mac` are static config; ARP/netlink neighbor resolution is a
  follow-up. Empty values are placeholders.
- Single queue, no `{queue}`-labelled metrics.
- Runtime not yet validated here beyond compilation + preflight.
