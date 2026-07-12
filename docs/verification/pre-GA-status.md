# turna — verification status before GA (v0.3.0-rc.1)

A map of readiness: what is verified, by what method, with what result — and,
honestly, what is NOT verified. References the detailed reports under docs/.
Purpose: a basis for the RC → GA decision.

## 1. What is verified (method → result)

### Endurance / stability over time
- Soak 12h (docs/soak/v0.3.0-rc.1.md): 518M packets, flat RSS (~10-11 MB, no
  growth), stable fd, panics/send_queue_dropped/parser = 0, latency Avg 170us /
  P99 500us.
- Endurance 5+ days: single turna process, continuous load. Finished at
  uptime 434,908 s (more than 5 full days), 130M packets, 21.4 GB, RSS flat and
  below start (10 MB -> ~6-8.5 MB, no leak), fd stable 45-46, error counters 0
  throughout the soak window. Caveat: the sampler lost continuity on an SSH
  disconnect (mid-period samples missing), but uptime + 130M packets with no
  crash + start/finish RSS points bound the leak question. Manual DTLS tests in
  the last hour added to total_allocations/auth_failures and are NOT part of the
  soak. See soak/endurance-v0.3.0-rc.1.md.

### TURNS / TLS transport
- openssl s_client establishes TLS 1.2 and 1.3, ALPN stun.turn, server presents
  a correct cert. With a trusted Let's Encrypt cert (turna.krutilin.pro via
  Caddy): Verify return code 0 (ok), full chain.

### Browser interop, multi-OS (docs/interop/v0.3.0-rc.1.md)
- Chrome 150 (Blink), Firefox 152 (Gecko), Safari 26.5 (WebKit) — each 5/5 over
  TURNS with a trusted LE cert: allocate, auth-negative (401), end-to-end relay
  data (50/50 echo), TLS transport, RAF. Firefox note: network.proxy.type=5
  broke ICE gathering; =0 -> 5/5 (client config, not a turna defect).

### REQUESTED-ADDRESS-FAMILY (0x0017)
- Confirmed by live browsers (allocate does not answer 420 to browser RAF).

### Failover / cluster (docs/failover/v0.3.0-rc.1.md)
- P1 fix (init.lua return unpack -> return res): list functions return all rows.
- Dirty scenarios: split-brain (concurrent/stale claim) via CAS, exactly one
  wins; multi-kill (loop over all dead); flapping (suspicion debounce); revert
  on failed rehydrate; clock-skew (CAS keeps correctness, needs NTP).
- 5 integration tests green against live Tarantool: claim_is_atomic,
  stale_claim_rejected, sweep_reassigns_dead_node, list_functions_return_all_rows,
  round_trip.

### Scale (docs/scale/v0.3.0-rc.1.md)
- 50,000 allocations (realistic JSON ~458 B, 23.7 MB), live Tarantool: count
  0.02 ms (O(1)), list(0,100) 0.10 ms, find_by_node 84 ms (all 50k by index),
  claim x50k 3147 ms local. Indexed access scales; large-node failover is tens
  of seconds (sequential claim over iproto) — documented linear limit.

### DTLS (docs/dtls/v0.3.0-rc.1.md)
- Transport verified: build --features "tls dtls" green; listener starts
  (fail-closed config validation); DTLS 1.2 handshake via openssl s_client -dtls
  with operator LE cert, Verify return code 0. TURNS(TCP)+DTLS(UDP) coexist on
  :5349. Fail-closed fix: a configured-but-unloadable cert refuses to start (was
  a silent fallback to ephemeral self-signed). Key must be PKCS#8 ECDSA-P-256.

### admin (dashboard + control)
- Stage 1 (read-only): proxies GET /status /metrics /health /ready /cluster;
  React SPA; verified live through a tunnel on real run data.
- Stage 2 (mutations via gRPC + auth): implemented and verified live — admin ->
  gRPC (:5350) -> control plane. Live test: node.drain/undrain (draining
  toggles), failover.status (GetServerStats), auth gate (no token -> 401). HTTP
  mutation removed (post_json deleted), gRPC-only. Fail-closed on non-loopback
  plaintext gRPC.

### Operations — runbooks
- docs/runbooks/incidents.md: 20+ alerts from turna-rc.yml -> symptom/diagnose/
  action, tied to /ready /status /metrics.
- docs/runbooks/tarantool-backup.md: persistence (operator's volume), online
  backup (box.snapshot + snap/xlog), restore, safe-restart, schema-upgrade
  caveat, accepted write-behind loss.

## 2. Evidence (what we tested with)

openssl s_client (-dtls / TLS); real browsers + a single-file WebRTC tester;
cargo test against live Tarantool 2.11 (Docker); in-Tarantool timing for scale;
curl along admin->gRPC->CP; long runs + /status sampling; live admin via tunnel.

## 3. What is NOT verified / caveats

- Real network, functional: broadly CONFIRMED over TCP/TLS. Browsers on iOS,
  iPadOS, Android, Windows, Linux, macOS reached the node over the public
  internet (home Wi-Fi and mobile 4G/5G) and passed 5/5 on TURNS-over-TCP.
- Real network, UDP: external UDP does NOT arrive on this infrastructure, and
  this was verified, not assumed. A bare UDP datagram from an external VPS to an
  unused port (nc, turna not involved) produced zero packets at the server's
  kernel (tcpdump), while TCP/5349 connects fine; mobile 4G shows the same. Root
  cause is ISP/CGNAT dropping inbound UDP — not a turna defect (it binds
  0.0.0.0:3478/udp and processes 130M UDP packets locally in the endurance run).
- Real network, UDP load/stress: still NOT done. The load generator is UDP-only
  and external UDP is filtered here, so a non-loopback UDP stress needs a
  datacenter host with unfiltered UDP (or an inbound-UDP path). Synthetic
  loopback load (soak/endurance) and TCP/TLS interop stand in until then.
- Multi-week/month staging: only 12h soak + 5+d endurance.
- Alert threshold calibration: not calibrated against real diverse traffic
  (synthetic single-type run). Approximate.
- Independent security audit / pentest: NOT performed (internal audit-closeouts
  exist from earlier work, but not an external independent one).
- Full allocate-over-DTLS by a live TURN client: transport/handshake verified,
  the full TURN cycle over DTLS is not (no ready DTLS-TURN client; the STUN layer
  is transport-independent and verified on UDP/TURNS).
- Mobile and multi-OS browsers: CLOSED. iPhone (Safari/Chrome), Android
  (Chrome/Firefox), iPad (Chrome), Windows (Chrome), Linux (Chrome), plus the
  earlier macOS (Chrome/Firefox/Safari) — each 5/5 over TCP/TLS from the
  external network. See docs/interop/v0.3.0-rc.1.md. (Older browser versions
  still untested.)
- IPv6 relay, QUIC/WebTransport, AF_XDP: feature-gated / out of scope for this RC.
- admin stage 2 in production: verified locally (CP+admin on a laptop) over
  plaintext-loopback + token. mTLS mode is implemented but not exercised in a
  deployed setup. Recommendation: symmetric fail-closed (admin listen
  non-loopback + no token -> refuse; currently only WARN).

## 4. RC -> GA readiness

Technical code blockers are closed: transports (UDP/TURNS/DTLS), failover (P1 +
dirty scenarios + CAS), scale (50k characterized), stability (soak + endurance,
no leaks), interop (mobile + multi-OS browsers), control (admin stage 1+2), operations
(runbooks), docs (consistent, honest about the verified/unverified boundary).

Remaining to GA is mostly external / process, not code:
1. Real-network load from an external generator (non-loopback).
2. Multi-week/month staging with real traffic.
3. Alert threshold calibration against real traffic.
4. Independent security audit / pentest.
5. Minor: allocate-over-DTLS (niche); admin stage 2 in a production posture
   (mTLS / exposed) not yet exercised. (Mobile/multi-OS browsers and the
   symmetric fail-closed are now DONE — see above.)

Summary: the codebase and its verification are at a mature RC level. What remains
is closed by time, real traffic, and external auditors — not by writing more
code. The documentation honestly reflects the verified boundary.
