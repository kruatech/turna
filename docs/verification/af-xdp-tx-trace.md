# AF_XDP STUN TX diagnostic

This patch instruments the unresolved WAN churn timeouts. It does not establish
that AF_XDP, the driver, or the network is responsible, and is not a support
promotion or a timeout/retry-policy change.

Enable only for a short isolated test with `af-xdp-wan.py serve --trace` (or
`TURNA_AFXDP_TRACE=1` for a directly launched node). The WAN runner explicitly
disables tracing without the flag. No logging filter change is necessary.

Per queue, the trace records up to 100,000 events in node.log, then emits a cap
warning. Entries contain STUN TxID, type, endpoints, length, UMEM address and
completion latency. They do not contain STUN attributes or credentials. The
pending map holds only submitted STUN frames awaiting completion, bounded by
the UMEM pool. The diagnostic adds copies, checksum checks and logging overhead;
do not use its timings as a performance benchmark.

Stages:

- `rx`: a checksum-valid Ethernet/IP/UDP frame with a STUN header reached userspace.
- `tx_submitted`: the library accepted its descriptor into TX. Before submission,
  UMEM readback must exactly match the constructed Ethernet frame.
- `tx_completed`: completion returned the descriptor; readback still matches the
  bytes saved before submission. This means buffer ownership returned, not that
  a peer received the packet.
- `tx_corrupted`: completion returned the descriptor but its bytes changed. This
  sets a fatal I/O error. Reuse of an outstanding traced address and pre-submit
  readback mismatch also set fatal I/O errors.

Client transaction timeouts now include local socket, server, TxID, attempts and
original deadline. Retry timing and acceptance thresholds remain unchanged.
Search that TxID in node.log and, if available, the client-side capture. A trace
cap, an incomplete capture, or a passing rerun must not be treated as proof of
where an earlier packet was lost. Receipt at the client interface but no accepted
response requires inspection of checksums, STUN framing and client matching.

Run 120 seconds of churn with a 300-second server lifetime, starting the client
immediately after READY. Keep node.log, summary.json, resources.jsonl,
metrics-final.txt, client.err and result.json. The existing runner's cleanup and
client verdicts remain authoritative; tracing does not relax them.

Validation in the editing environment: seven Python WAN gate tests pass; Rust
syntax parsing passes. No Rust compiler or AF_XDP-capable execution environment
was available. Compile and run the added `trace_` tests on Linux before running
this diagnostic.
