# AF_XDP hardening — pending Linux runtime verification

> Current status: **supported within the verified Linux IPv4 UDP copy-mode scope**.
> See [scope, evidence and unresolved limitations](../verification/af-xdp-supported-2026-09-22.md).
> This historical record describes its original run or plan; it is not the current support matrix.

This patch does not promote AF_XDP to supported. The historical veth evidence
belongs to the previous revision. Changes below require fresh compilation and
kernel tests before touching a shared production interface.

## Implemented changes

- Retain partial fill submissions separately from RX scratch, retry before polling.
- On TX ring-full, return the descriptor and report a failed send. On an ambiguous
  submission/wakeup error, stop the datapath without recycling a possibly published
  descriptor. Reap completions during idle polling and drain TX at shutdown.
- Poll failures are fatal instead of being reported as an empty receive batch.
- One XSK per configured RX queue, separate UMEMs and one shared XDP program/map.
  Startup requires coverage of all enumerated RX queues; no RSS/NIC setting is changed.
- Independent `attach_mode` (auto/skb/native) and `zero_copy`. Verify actual copy
  mode using Linux XDP_OPTIONS; fail rather than silently downgrade.
- Embedded filter redirects only matching destination IP and registered UDP ports.
  TCP, ARP/NDP, unrelated addresses/ports and unsupported L2/L3 forms pass to the kernel.
- Reserve the main UDP port. Require a concrete listen IP. Readiness follows
  successful creation of all sockets and the filter.
- Fail on relay-map registration errors, release that allocation and suppress its
  queued success reply. Map deletion errors are no longer silently ignored.
- Periodically reap expired allocations and reconcile held relay sockets/maps even
  while idle; normal explicit deletion uses the same owned resources.
- Strict IP/UDP lengths and checksum validation; truncated IPv6 is rejected.
- Resolve neighbors within the configured interface; cap cache/attempt maps and
  evict on a timer independently of continuous incoming work.
- Lab runner requires zero media loss and clean node exit, refuses existing lab
  resources, uses health port 19100, and supports building before privileged execution.

## Validation performed in the editing environment

- Host-compiled tests execute the real C filter with mocked BPF helpers: both queue
  selections, other address/port, TCP, ARP, fragments, truncated headers and IPv6/NDP.
  This does not replace BPF verifier or attach testing.
- Rust syntax parsed; shell syntax and documentation claims checked.
- Rust toolchain, libxdp compilation and AF_XDP kernel execution are unavailable in
  the editing environment. No Rust build, regression-test or live NIC PASS is claimed.

Added Rust regressions cover partial refill across batches, TX full/success/ambiguous
error ownership, corrupt/truncated frame rejection, queue/mode parsing and bounded
neighbor-cache churn. Run these before the lab. Runtime map failures, idle expiry,
mode reporting, multiqueue traffic and clean detach require kernel-level checks too.

## Acceptance sequence

1. Linux build and Rust unit tests, then `scripts/verify/test_af_xdp_filter.py`.
2. Isolated veth SKB/copy lab: conformance and two-way media beyond UMEM pool size,
   no client errors or missing frames, clean exit. This lab never attaches to ens3.
3. Inspect cloud `virtio_net` with `scripts/verify/af-xdp-preflight.sh ens3`.
   Cloud reports two queues: use `queue_ids = [0, 1]`. Preserve any pre-existing
   XDP program; do not issue blanket `xdp off` commands on a shared interface.
4. Separate short hardware runs for SKB/copy, native/copy and, only if available,
   native/zero-copy. An unsupported mode is not a PASS in that mode.
5. Local physical-NIC validation within the operator's 30–40 minute budget.
6. Extended cloud runs only after short tests pass; track memory, descriptors,
   relay registrations, UMEM availability, TX in-flight, readiness and verified media.

The initial deliverable provides build/lab gates and read-only hardware inventory.
It does not automatically attach to the cloud NIC or claim a hardware result.

## Scope limits to retain

Each datapath is single-stack to its concrete listen address. VLAN and IPv6 extension
headers are not accelerated; fragmented IPv4 passes out of the filter and is not
reassembled by this datapath. A successful copy-mode run says nothing about
zero-copy. Neighbor misses still use the configured/default gateway fallback until
resolution succeeds; cold-neighbor and route-change behaviour needs a live test.

AF_XDP redirect bypasses the ordinary UDP receive path; do not assume a host INPUT
firewall is the admission gate for redirected packets. Use the application's auth,
limits and peer policy, and upstream filtering as appropriate. The IP/port filter
limits the traffic captured; it is not a source-IP firewall.
