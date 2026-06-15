# Transport Backends

turna supports three datapath backends for the TURN listener, selected at
startup via configuration. This document covers their requirements, build
prerequisites, configuration, observability, and a benchmark template to be
filled with measured numbers.

> Numbers in the benchmark section are **placeholders**. Fill them with values
> measured on your own hardware; do not treat the blanks as results.

## Backends at a glance

| Backend    | `transport` value | Auto-selected? | Privileges            | Notes                                  |
|------------|-------------------|----------------|-----------------------|----------------------------------------|
| Tokio UDP  | `tokio`           | yes (default)  | none                  | Portable default.                      |
| io_uring   | `io_uring`        | **no**         | none (normal UDP)     | Linux only; per-core worker pool.      |
| AF_XDP     | `af_xdp`          | **no**         | `CAP_NET_RAW`/root    | Linux only; attaches an XDP program.   |

`io_uring` and `af_xdp` are **never** chosen by `auto`/default — they must be
requested explicitly. If requested but unavailable on the host, startup logs the
reason and the backend selection reflects that.

## Kernel requirements

These are the minimum kernel versions targeted by turna for each backend/mode:

| Backend / mode                       | Minimum kernel |
|--------------------------------------|----------------|
| io_uring (with `IORING_FEAT_NODROP`) | 5.5            |
| AF_XDP, copy mode (`zero_copy=false`)| 5.10           |
| AF_XDP, zero-copy / multi-queue      | 5.15           |

AF_XDP attach mode is derived from `zero_copy`:

- `zero_copy = false` → SKB / generic mode (`xdpgeneric`), works on virtually any
  driver including `veth`.
- `zero_copy = true` → native / driver (DRV) mode, requires NIC driver support.

Verified during testing on kernel 6.14, clang 18, in SKB mode on a `veth` pair.

## Build prerequisites

Both high-performance backends are gated behind Cargo features:

| Feature     | Enables          | Extra build deps                                   |
|-------------|------------------|----------------------------------------------------|
| `io-uring`  | io_uring backend | none beyond a Linux toolchain                      |
| `af-xdp`    | AF_XDP backend   | C/BPF toolchain to build the embedded XDP program  |

### `af-xdp` toolchain

The `af-xdp` build compiles an embedded XDP program (`xdp_turn.c`) to BPF object
code at build time via `clang -target bpf`, and links libxdp/libbpf transitively
through `xsk-rs → libxdp-sys → libbpf-sys` (libbpf is built from vendored source).

Required on the build host:

- `clang` and `llvm` (BPF target codegen; tested with clang 18)
- `linux-libc-dev` — provides the arch UAPI headers (e.g. `asm/types.h` under
  `/usr/include/<arch>-linux-gnu`). The build script discovers this path via
  `cc -print-multiarch` and adds it to the BPF compile include path.
- `libelf` development headers and `zlib` development headers (needed to build
  the vendored libbpf)

Debian/Ubuntu:

```bash
sudo apt-get install -y clang llvm linux-libc-dev libelf-dev zlib1g-dev
```

Build the node with the desired backend(s):

```bash
cargo build -p turna-node --features io-uring
cargo build -p turna-node --features af-xdp
cargo build -p turna-node --features io-uring,af-xdp
```

> Note on `--all-features`: enabling everything also turns on `quic` together
> with `web-transport`. `web-transport` (wtransport) bundles its own `quinn`,
> which can conflict with the standalone `quinn` dependency. A compile failure
> under `--all-features` is most likely this feature combination, not the
> transport backends. For a focused check use
> `--features io-uring,af-xdp`.

## Selecting a backend

Set the backend under `[turn]` in the config file:

```toml
[turn]
transport = "io_uring"   # or "af_xdp", "tokio", "auto"
listen     = "0.0.0.0:3478"
```

### AF_XDP-specific requirements

- `listen` **must be a concrete IP**, not `0.0.0.0`. The address is used both as
  the TX source IP and to seed the BPF port map; a wildcard address is not valid
  for this backend.
- The interface and queue are configured under `[turn.af_xdp]`.

```toml
[turn]
transport   = "af_xdp"
listen      = "10.0.0.1:3478"
external_ip = "10.0.0.1"

[turn.af_xdp]
interface = "eth0"
queue_id  = 0
zero_copy = false        # false = SKB/copy mode; true = native/zero-copy
need_wakeup = true
# src_mac / dst_mac: optional static overrides. If dst_mac is unset and no
# default-route MAC can be resolved at startup, the datapath resolves next-hop
# MACs dynamically per destination (ARP/NDP) at send time.
```

Other `[turn.af_xdp]` fields control UMEM and ring sizing: `frame_count`,
`frame_size`, `fill_ring_size`, `comp_ring_size`, `rx_ring_size`,
`tx_ring_size`. Run `turna-node <config> --dump-config` to see the
fully-resolved values and defaults in effect.

### io_uring-specific configuration

```toml
[turn]
transport = "io_uring"
listen    = "0.0.0.0:3478"

[turn.io_uring]
relay_socket_capacity_per_worker = 256   # range 1..=1024
```

io_uring runs a per-core worker pool (one worker per CPU thread) bound to cores;
relay sockets are distributed across workers up to the per-worker capacity.

### Interactions to be aware of

- **Peer filter.** The default `[turn.peer_filter]` profile (`internet-facing`)
  denies private/RFC1918 and loopback peers — a `ChannelBind` to such a peer is
  rejected with `403 Forbidden`. For LAN/loopback testing set
  `profile = "lan"` (and `allow_loopback_peers` for loopback). This is policy,
  independent of the chosen transport.
- **Health/metrics port.** The health server defaults to `0.0.0.0:8080`. If that
  port is occupied the bind fails; move it via `[health].listen`.

## Observability

Metrics are exposed by the health server at `/metrics` (Prometheus text format).

### AF_XDP (`turna_afxdp_*`)

| Metric                                  | Type    | Meaning                                                        |
|-----------------------------------------|---------|----------------------------------------------------------------|
| `turna_afxdp_rx_frames_total`           | counter | Frames received off the queue (redirected into the xsk).       |
| `turna_afxdp_rx_bytes_total`            | counter | Received TURN payload bytes.                                   |
| `turna_afxdp_tx_frames_total`           | counter | Frames sent.                                                   |
| `turna_afxdp_tx_bytes_total`            | counter | Bytes sent.                                                    |
| `turna_afxdp_parse_drops_total`         | counter | Frames matching no TURN/relay port (undemuxable).              |
| `turna_afxdp_tx_drops_total`            | counter | Send failures.                                                 |
| `turna_afxdp_relay_ports_registered`    | gauge   | Relay ports currently demuxed by the datapath (BPF port map).  |
| `turna_afxdp_umem_free_frames`          | gauge   | Free UMEM frames available for RX/TX.                          |
| `turna_afxdp_arp_replies_total`         | counter | ARP replies sent for the datapath's own IP.                    |
| `turna_afxdp_ndp_replies_total`         | counter | IPv6 Neighbour Advertisements sent for the datapath's own IP.  |
| `turna_afxdp_neighbor_unresolved`       | gauge   | Static next-hop MAC unresolved (1 = zero placeholder).         |
| `turna_afxdp_neighbor_cache_entries`    | gauge   | Resolved next-hop MAC entries currently cached.                |
| `turna_afxdp_tx_inflight`               | gauge   | Frames submitted to the TX ring, not yet completed.            |

Note: `neighbor_unresolved` reflects the **static** `dst_mac` fallback only; the
per-destination dynamic resolver is reflected by `neighbor_cache_entries`.

### io_uring (`turna_uring_*`)

| Metric                              | Type  | Meaning                                                      |
|-------------------------------------|-------|--------------------------------------------------------------|
| `turna_uring_workers`               | gauge | io_uring worker threads in the pool.                         |
| `turna_uring_inflight_send_slots`   | gauge | Occupied send slots, main + relay, summed over workers.      |

## Graceful shutdown

On `SIGTERM` both backends enter a lame-duck drain bounded by
`[cluster].drain_grace_secs` (default 5s):

- Existing flows keep running during the grace window; new allocations are
  rejected upstream.
- io_uring waits until every relay is reclaimed **and** all in-flight send slots
  complete before tearing a worker down, so in-flight sends are not dropped.
  Each worker logs `worker drain complete; exiting loop … fully_reclaimed=true
  sends_inflight_remaining=0`. A worker holding relays with no traffic to close
  them holds them for the full grace window, then force-closes at the deadline.
- AF_XDP detaches its XDP program on clean shutdown.

If a process is killed with `SIGKILL`, an AF_XDP program may remain attached to
the interface; remove it manually:

```bash
sudo ip link set dev <iface> xdpgeneric off   # SKB mode
sudo ip link set dev <iface> xdp off          # native mode
```

## Benchmark results (TEMPLATE — fill with measured values)

Record the test environment and replace every `___` with a measured value. Do
not publish the template with blanks.

### Environment

| Field            | Value |
|------------------|-------|
| CPU              | `___` |
| Cores / threads  | `___` |
| NIC / driver     | `___` |
| Kernel           | `___` |
| turna version    | `___` |
| Build profile    | `release` |
| Load generator   | `___` |
| Packet size      | `___` |
| Duration         | `___` |

### io_uring vs Tokio — CPU at fixed load

Acceptance target: io_uring CPU within ~10% of Tokio at the same offered load.

| Offered load (pps) | Tokio CPU % | io_uring CPU % | Delta % |
|--------------------|-------------|----------------|---------|
| `___`              | `___`       | `___`          | `___`   |
| `___`              | `___`       | `___`          | `___`   |
| `___`              | `___`       | `___`          | `___`   |

### AF_XDP — throughput

| Metric                         | Tokio | AF_XDP |
|--------------------------------|-------|--------|
| Max sustained pps (no loss)    | `___` | `___`  |
| Throughput (Gbps)              | `___` | `___`  |
| CPU % at max sustained pps     | `___` | `___`  |

### Method notes

- `___` (how CPU was measured — e.g. per-core utilisation source)
- `___` (how offered load was generated and verified delivered)
- `___` (loss criterion / how "no loss" was confirmed)

## Appendix: local verification harness

The setup used to validate the backends on a single host, with a peer in a
separate network namespace so traffic actually traverses the device.

```bash
# veth pair; peer end in a netns
sudo ip link add veth0 type veth peer name veth1
sudo ip addr add 10.123.0.1/24 dev veth0
sudo ip link set veth0 up
sudo ip netns add turnatest
sudo ip link set veth1 netns turnatest
sudo ip netns exec turnatest ip addr add 10.123.0.2/24 dev veth1
sudo ip netns exec turnatest ip link set veth1 up
sudo ip netns exec turnatest ip link set lo up

# run the node (AF_XDP: listen on the concrete veth IP, iface veth0, zero_copy=false)
sudo ./target/debug/turna-node config.toml

# drive a TURN client from the peer namespace (long-term cred via static user)
sudo ip netns exec turnatest turnutils_uclient \
  -y -u <user> -w <pass> -e 10.123.0.2 -p 3478 -n 3 10.123.0.1

# observe
curl -s http://127.0.0.1:8080/metrics | grep -E 'turna_(afxdp|uring)_'

# teardown (removes the veth pair and any attached XDP program)
sudo ip netns del turnatest
sudo ip link del veth0
```
