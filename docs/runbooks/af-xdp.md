# AF_XDP datapath — build and verification

**Status: supported within the verified Linux IPv4 UDP copy-mode scope.**
See [support evidence and unresolved limitations](../verification/af-xdp-supported-2026-09-22.md).
Validated deployment: Linux 6.8.0-87 / `virtio_net`, queues 0 and 1, SKB/copy
and native/copy. Other drivers/kernels, IPv6 WAN and zero-copy are not established
by these runs. Revalidate the target deployment before enabling.

WAN media acceptance permits up to 0.01% missing echoes; it is not a zero-loss
guarantee. Churn acceptance requires zero operation errors and full cleanup.
Earlier WAN churn timeouts remain unexplained; the later PASS is not a proven fix.
Use [bounded TX diagnostics](../verification/af-xdp-tx-trace.md) if they recur.

The node loads its embedded selective XDP program; do not load a redirect-all
program manually. It redirects only the configured destination IP and registered
TURN/relay UDP ports. TCP and ARP/NDP remain on the kernel path.

## Build first, without sudo

Linux build dependencies: clang, llvm, linux-libc-dev, libelf-dev, zlib1g-dev,
libbpf-dev, pkg-config and protobuf-compiler. Use the repository's pinned toolchain.

```bash
cargo test --locked -p turna-config
cargo test --locked -p turna-transport --features af-xdp
cargo test --locked -p turna-node --features af-xdp af_xdp_listener
cargo build --locked --release -p turna-node --features af-xdp
cargo build --locked --release -p turna-load-test
python3 scripts/verify/test_af_xdp_filter.py
```

The C filter test uses GCC on x86_64 Linux. It mocks BPF helpers and cannot establish
kernel verifier acceptance. The Rust ownership tests do not substitute for live rings.

## Isolated lab

```bash
sudo env SKIP_BUILD=1 bash scripts/verify/af-xdp-lab.sh
```

Uses a new veth/network namespace and health port 19100, never the public NIC.
Existing lab links/namespaces/output directories or an occupied health port cause
failure. Conformance and relayed media must pass. Zero client loss/errors and clean
node exit are required; a forced kill after the 60-second deadline is a failure.
The trap tears down only the lab resources created by this invocation.

## Real interface preparation

For the cloud host discussed in this record:

```bash
bash scripts/verify/af-xdp-preflight.sh ens3
```

This command only inventories the NIC. No attach, queue changes or offload changes.
Cloud has `virtio_net` and two reported RX queues. Configuration must cover both:

```toml
[turn.af_xdp]
interface = "ens3"
queue_ids = [0, 1]
attach_mode = "skb"
zero_copy = false
```

Set the existing `[turn].listen` to the intended concrete address; wildcard is
refused. Use an isolated test port/range and validate authentication/peer policy.
Do not reuse production credentials in exported test artifacts.

`attach_mode = "native"` with `zero_copy = false` requests native XDP with copy;
`zero_copy = true` forces native zero-copy. The kernel-reported socket mode is
checked and logged. Unsupported modes fail without silently downgrading.
`auto` preserves legacy selection: native with zero-copy, otherwise SKB.

All RX queues enumerated in sysfs must be covered. Empty `queue_ids` uses the
legacy `queue_id` (0 by default) and therefore works only for a matching
single-queue interface. Per-queue UMEM increases memory proportionally.

Privileged lab execution uses root. A capability-only production setup must allow
XSK bind, BPF load and XDP attach; `CAP_NET_RAW` alone is not a complete recipe.
Do not replace/detach someone else's existing XDP program to make a test pass.

## Geometry and monitoring

Current library geometry is fixed: frames 4096 bytes, all rings 2048 entries,
frame_count at most 4096. Configuration rejects inert size overrides. MTU plus
Ethernet header must fit the frame. Native zero-copy support is driver-dependent.

Track `turna_afxdp_readiness`, `turna_transport_readiness`, RX/TX counters,
`turna_afxdp_tx_drops_total`, `turna_afxdp_relay_ports_registered`,
`turna_afxdp_umem_free_frames`, `turna_afxdp_tx_inflight`, neighbor cache size,
RSS, open FDs and allocations. Ring gauges aggregate across queues; TX counters
record submission, not proof that a peer received media. Verify echoed payloads.

SIGTERM/SIGINT follows node drain, then each XSK drains TX with a bounded wait.
The last shared program owner detaches Turna's program; detach failures are logged.
After a run, verify node exit, released ports and the interface's XDP state.

Historical `scripts/lab/af_xdp_smoke.sh` predates the embedded loader; use the
verification script above. Long cloud runs and 30–40 minute physical-NIC checks
follow only after the short build/lab/hardware gates pass.
