# AF_XDP — support scope and verification — 2026-09-22

## Status and scope

**Supported within the verified Linux IPv4 UDP copy-mode scope**, explicitly
selected with `transport = "af_xdp"` and the `af-xdp` build feature. Tokio remains
the default. This is a scoped maintenance/support decision, not a claim that
all earlier failures have an identified fix or that every NIC is compatible.

Verified deployment: Ubuntu 24.04, Linux **6.8.0-87-generic**, `virtio_net` on
cloud's `ens3`, two RX queues (`queue_ids = [0, 1]`), MTU 1500. The WAN client was
on a separate Linux host (kz). Both **SKB/copy** and **native/copy** carried TURN
control and UDP relay traffic. Extended media and the final churn run used
native/copy. This is a virtual NIC deployment, not a physical-NIC qualification.

Not established by this record: native zero-copy, other drivers/kernels, IPv6 WAN,
VLAN/IPv6-extension-header acceleration, fragmented relay/reassembly, cold-neighbor
recovery, route changes, arbitrary listener/backend combinations or maximum capacity.
The IPv6 frame implementation exists; it is not a substitute for an IPv6 WAN run.
Revalidate after kernel, driver, interface or topology changes.

## Evidence

| Run | Observed result | Scope |
|---|---|---|
| Veth lab `afxdp-20260920-004704` | Conformance passed; 601/601, 2401/2401 and 4001/4001 media echoes; RX/TX 7108/7108; node exit 0 | SKB/copy; traffic exceeded the UMEM pool; five peer-policy rejections were expected negative probes |
| SKB WAN `afxdp-wan-cloud-repeat-20260920-011205` / `afxdp-wan-kz-repeat-300s-20260920-041337` | 30010/30010 echoes, zero errors; relay registrations returned to zero; node exit 0 | Five-minute IPv4 media; operator-provided output |
| Native WAN `afxdp-native-cloud-20260920-012759` / `afxdp-native-kz-20260920-042806` | 30010/30010 echoes; both queues covered, no parse/TX drops; clean detach | Five-minute native/copy media; operator-provided output |
| Four-hour native media `afxdp-native-cloud-4h-20260920-013921` / `afxdp-native-kz-4h-20260920-044053` | 1440012 sent, 1439975 received, **37 missing**, zero client errors; **99.99743% delivery** | Archived results reviewed; original strict zero-loss client verdict was FAIL; meets subsequently agreed WAN threshold of at least 99.99% delivery |
| Tokio control `tokio-churn-open-kz-20260922-013101` | 6278/6278 operations, zero errors over 120.186 s | Operator-provided control comparison; not AF_XDP evidence |
| Native diagnostic `afxdp-txtrace-cloud-20260922-021002` / `afxdp-txtrace-kz-20260922-051023` | 6766/6766 operations, zero errors; 13544 unique STUN transactions each had RX, TX submission and completion; no retransmitted requests; maximum completion latency 1280 us | Both archives reviewed; UMEM readback diagnostics enabled, no corruption detected; tracing can affect timing |
| Native final churn `afxdp-churn-final-cloud-20260922-022153` / `afxdp-churn-final-kz-20260922-052159` | **49647/49647 operations**, zero errors over **900.182 s**, 55.152 completed cycles/s | Operator-provided result JSON and server summary; `--trace` omitted; full final raw archives not reviewed when this record was written |

The load client's `allocate` workload counts confirmed authenticated
Allocate/Refresh(0) cycles, not individual UDP datagrams. Initial setup and STUN
retransmissions make server packet counts differ from operation counts.

The final server stayed up for 1200 seconds, including the post-client idle window:

- Queue 0: RX/TX **49865/49865**; queue 1: **49454/49454**; parse/TX drops zero.
- RSS start/end window medians **44800/45312 KiB**, growth **512 KiB**; peak 45312 KiB.
- Open FDs **20 → 20**.
- Active allocations, registered relay ports, TX in-flight, send-queue drops and
  processor panics all zero at final sampling.
- Node exit **0**, XDP detached; server resource/cleanup verdict PASS.

The reviewed four-hour server data showed RSS approximately 43392 → 44288 KiB,
FDs returning from load to 20, zero final active allocations/relay registrations/
TX in-flight, no reported parse/TX drops, exit 0 and detach. This does not establish
zero packet loss: client media loss remains explicitly recorded above.

## Earlier failures and limits of the conclusion

Earlier churn first hit the allocation rate limiter (486; 19886 rate-limited
requests). A test-specific trusted tier removed that confounder. Subsequent
native and SKB runs still saw occasional Allocate/Delete response timeouts.
UDP retry and bounded server response replay were added, but some short runs
still failed afterwards. **Their root cause remains unknown.**

A reviewed client capture showed five failed transactions with identical requests
sent at approximately 0, 0.5 and 1.5 seconds, with no corresponding reply visible
at the client capture point. Server TX submission totals alone cannot localize a
loss to the network, driver or userspace. Early Tokio comparison attempts were
invalid because of an unopened test port or because the client started after the
server's automatic shutdown. The valid Tokio control passed.

Later native runs passed both with diagnostics and, for 15 minutes, without them.
This is evidence of successful operation, **not a demonstrated root-cause fix**.
Retain the previous failures in support investigations. A recurrence is a finding
to investigate with [TX diagnostics](af-xdp-tx-trace.md), not a reason to silently
increase deadlines or relax the churn gate. SKB has shorter media evidence; do not
attribute the native four-hour or final churn results to SKB.

## Operational contract

- The node loads its embedded destination-IP/UDP-port-selective XDP filter.
  It passes unrelated traffic, TCP and ARP/NDP to the kernel. It is not a source
  ACL: redirected UDP does not traverse ordinary kernel UDP INPUT admission.
- Configure a concrete listen IP and every enumerated RX queue. Preserve existing
  operator-owned XDP programs. XSK/BPF/XDP setup needs privileges; tests used root.
- `attach_mode` and copy mode are independent. `zero_copy = false` was tested;
  successful native attach is not evidence of zero-copy. Requested socket mode
  is checked; an unsupported bind/attach must fail rather than silently downgrade.
- Current geometry: 4096-byte frames, 2048-entry rings, at most 4096 UMEM frames
  per queue. Unsupported geometry overrides are rejected.
- Monitor allocations, relay registrations, RX/TX drops, readiness, RSS and FDs.
  TX submission/completion is not proof of remote receipt; keep client results.
- UDP control replay is bounded by cache capacity/retention; it is not a guarantee
  for arbitrary late duplicates. Verify auth/rate limits for the deployment.
- Default diagnostic tracing is off. It copies/checks buffers and logs bounded
  transaction metadata; diagnostic performance is not a capacity benchmark.

Build/lab instructions: [runbook](../runbooks/af-xdp.md).
WAN media/churn runner and acceptance: [WAN verification](af-xdp-wan.md).
Historical implementation work: [hardening record](af-xdp-hardening-2026-09-19.md).
This documentation change alters no runtime defaults or acceptance thresholds.
