# Runbook — encrypted transports (TURNS, DTLS, QUIC/WebTransport)

Operator response for the alerts in `docs/alerts/transport-backends.yml`. Config
reference: `docs/CONFIGURATION.md`. Metric definitions:
`docs/OBSERVABILITY.md` → "Encrypted-transport metrics".

Maturity before you start: TURNS and DTLS are **beta**, QUIC/WebTransport is
**experimental** (`docs/feature-support.md`). The UDP/tokio path is always the
fallback — if an encrypted listener is unhealthy and clients can reach UDP, the
fastest mitigation is usually to stop advertising the encrypted URI, not to debug
under pressure.

## First triage: is the listener even up?

```promql
turna_tls_readiness    # 0=starting/disabled, 1=ready, 2=degraded, 3=draining
turna_dtls_readiness
turna_quic_readiness
```

`2` means that listener's socket is no longer bound **while the process is
alive**. `/ready` can still be green, because process readiness is a separate
signal — this is exactly the case the per-listener gauges exist for.

A `0` on a listener you enabled means it never started. Check the log at startup:
enabling `[turn.dtls]`, `[turn.quic]`, or `web_transport = true` without the
matching Cargo feature (`dtls`, `quic`, `web-transport`) is a hard startup error,
so a running process with `0` points at a listener that failed after config
validation — look for `DTLS listener exited` / `QUIC listener exited` /
`TURNS server stopped` in the log.

---

## TurnaTlsCertReloadFailing — **critical**

`rate(turna_tls_cert_reload_failures_total[15m]) > 0`

The TURNS listener detected changed certificate files, tried to load them, and
failed. It is **still serving the previous certificate** — no outage yet, but
when the old certificate expires TURNS stops working.

1. Find the error: `journalctl -u turna | grep 'cert reload failed'`.
2. Usual causes, in order of likelihood:
   - the renewal wrote the cert but not yet the key (or vice versa) and the
     reload caught a half-written pair — check `turna_tls_cert_reloads_total`,
     if it incremented afterwards the transient resolved itself;
   - file permissions changed (the renewal hook wrote as root with 0600);
   - the new key is not a format `rustls` accepts (PKCS#8 / PKCS#1 / SEC1).
3. Verify the pair by hand:
   ```bash
   openssl x509 -in /etc/turna/tls/cert.pem -noout -enddate
   openssl pkey -in /etc/turna/tls/key.pem -noout -check
   ```
4. Fix the files. The next poll (`[tls].cert_reload_secs`, default 30s) picks
   them up — no restart needed.

Which listeners reload at all:

| listener | hot-reload | on failure |
|---|---|---|
| TURNS (`[tls]`) | yes, `cert_reload_secs` | keeps previous cert, counter increments |
| QUIC, `web_transport = true` | yes, `[turn.quic].cert_reload_secs` | same, `turna_quic_cert_reload_failures_total` |
| QUIC, `web_transport = false` | **no** | rotation needs a restart |
| DTLS | **no** | logs `DTLS certificate material changed on disk`; needs a restart |

So if you rotate a certificate shared between `[tls]`, `[turn.quic]` and
`[turn.dtls]`, TURNS and WebTransport pick it up within their poll interval while
DTLS keeps serving the old one until the node restarts. Plan the restart, or give
DTLS its own certificate with a longer validity.

---

## TurnaTlsAcceptErrors — **critical**

`rate(turna_tls_accept_errors_total[5m]) > 0`

`accept()` is failing. The listener survives (with backoff) rather than dying as
it used to, but new TURNS connections are being lost while this fires.

1. Almost always `EMFILE` — file-descriptor exhaustion. Confirm:
   ```bash
   cat /proc/$(pidof turna-node)/limits | grep 'open files'
   ls /proc/$(pidof turna-node)/fd | wc -l
   ```
2. Each TURNS connection is one fd; each allocation adds a relay socket. If the
   count is near the limit, either raise `LimitNOFILE` (systemd) /
   `ulimit -n`, or lower `[tls].max_connections` to a value the limit supports.
3. If fds are not exhausted, check for `ECONNABORTED` storms (a load balancer
   health-checking by opening and immediately closing TCP).

---

## TurnaTlsHandshakeFailuresHigh / TurnaQuicHandshakeFailuresHigh — warning

Clients are failing the TLS/QUIC handshake.

1. **Rule it out first: is it scanners?** Port 5349 and 5350 on the public
   internet get scanned constantly. Compare with
   `turna_tls_connections_total` — a low ratio of *completed* handshakes plus
   near-zero allocations means noise, not a client problem. Consider a lower
   alert threshold only after you know your baseline.
2. Real client failures: check certificate validity and that the chain the
   server sends is complete (missing intermediates fail on mobile clients but
   work in a browser that caches them):
   ```bash
   openssl s_client -connect <host>:5349 -alpn stun.turn -showcerts </dev/null
   ```
3. ALPN mismatch: with `[tls].enable_alpn = true` the server advertises
   `stun.turn`. A client that demands a different protocol fails. Setting
   `enable_alpn = false` is a valid workaround for a broken client.
4. **DTLS has no equivalent alert on purpose** — its handshake runs inside the
   DTLS stack below the point the server can observe, so a failed DTLS handshake
   produces no metric at all. Diagnose DTLS handshakes with a packet capture
   (`tcpdump -i any udp port 5349`) and the client's own logs.

---

## TurnaDtlsOutboundOversize — warning

`rate(turna_dtls_outbound_oversize_total[5m]) > 0`

Relayed payloads exceed `[turn.dtls].mtu`, so they are dropped. A DTLS record
cannot be fragmented at the record layer, and relying on IP fragmentation is a
silent one-way media failure — the client sends fine and receives nothing.

1. Raise `[turn.dtls].mtu` toward the real path MTU (valid range 576..65535,
   default 1200). Restart to apply.
2. Prefer fixing it at the source: the media sender should respect a smaller
   packet size. A TURN server dropping oversized relayed datagrams is a symptom
   of a sender ignoring path MTU.
3. This is a config/topology problem, not a load problem — it does not resolve
   on its own.

---

## TurnaDtlsOutboundDrops — warning

`rate(turna_dtls_outbound_dropped_total[5m]) > 0`

A session's bounded egress queue filled and the **newest** datagram was dropped
(drop-newest is deliberate: the alternative is blocking the relay return path
for every other session).

1. If it correlates with high bitrate: raise
   `[turn.dtls].outbound_queue_capacity` (default 1024).
2. If it correlates with a few specific clients: that client is not draining its
   socket. Dropping is the correct behaviour; do not raise the queue to mask it.
3. Check CPU — a saturated node shows this alongside
   `turna_send_queue_dropped_total`.

---

## TurnaQuicControlDroppedNoStream — warning

`rate(turna_quic_control_dropped_no_stream_total[5m]) > 0`

The server had a STUN/TURN response to send but the session had no open bidi
stream to answer on, so the client is silently not getting replies.

1. This is a client stream-lifecycle problem: the framing contract expects the
   client to keep a bidi stream open for control (see
   `crates/relay/src/quic_bridge.rs` module docs).
2. On the **raw-QUIC** path (`web_transport = false`) the server answers on the
   stream the request arrived on; on the **WebTransport** path it cannot route
   per stream (the underlying library exposes no stable stream index), so a
   client that closes and reopens streams per request is more likely to hit this
   there. Testing with `web_transport = false` is a useful bisection step.

---

## Per-IP and capacity rejections — warning

`turna_tls_rejected_per_ip_total`, `turna_dtls_rejected_per_ip_total`,
`turna_quic_rejected_per_ip_total`, and the `*_rejected_over_cap_total` family.

Decide which of two situations you are in — the metric alone cannot tell you:

- **CGNAT / corporate NAT**: many real clients behind one address. Raise
  `max_connections_per_ip` / `max_sessions_per_ip`, or set it to `0` (unlimited)
  and rely on the global cap.
- **Slot-exhaustion abuse**: one address opening sessions it never uses. Leave
  the cap in place; that is it working. On the QUIC WebTransport path the refusal
  happens before the handshake, so it costs the server almost nothing — that is
  the cheapest place to absorb this. Correlate with
  `turna_auth_failures` and `turna_active_allocations` — abuse usually shows
  many sessions and few or no successful allocations.

The `over_cap` variants mean the *global* cap was reached. Check
`turna_tls_active_connections` / `turna_dtls_active_sessions` /
`turna_quic_active_sessions` against the configured maximum. If real demand
outgrew the cap, raise it **and** confirm the fd limit supports it (see
TurnaTlsAcceptErrors above).

---

## TurnaTlsFramingErrors — warning

`rate(turna_tls_framing_errors_total[5m]) > 1`

Connections are being closed because the peer sent invalid or over-sized
TURN-over-TCP framing. The stream cannot be resynchronised, so the connection
dies — this counter exists so that looks different from a normal disconnect.

1. Something non-TURN is talking to 5349 (an HTTP health check, a scanner, a
   misrouted client). Confirm with the peer addresses in the logs.
2. A real client hitting it means `[tls].max_frame_size` (default 64 KiB) is
   below what it sends, or the client adds an RFC 4571 length prefix. Turna
   implements RFC 5766/8656 §11.5 framing (self-delimiting, **no** 2-byte
   prefix), which is what browser WebRTC and coturn send.

---

## Draining and restarts

All three listeners now drain cooperatively on `SIGTERM`: they stop accepting and
let established connections/sessions wind down, bounded by
`[cluster].drain_grace_secs`. During a drain `*_readiness` reads `3` — that is
expected, do not page on it.

When a control connection or session closes, its allocation is released
immediately (the connection is the allocation's 5-tuple), so a rolling restart
frees relay ports promptly instead of holding them for a full lifetime.
