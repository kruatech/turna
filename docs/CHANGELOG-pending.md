# CHANGELOG — pending section

Empty. Entries accumulate here between releases and move into `CHANGELOG.md`
under a version heading at release time; the last move was 0.4.0.

### Changed — read this one first

- **`[turn.dtls] demux` now defaults to `true`.** A config with
  `[turn.dtls] enabled = true` and no `demux` key takes the demultiplexer path
  after upgrading, where before it took `webrtc_dtls::listener::listen()`.

  The stock listener held the default because it was the path with a recorded
  24-hour run — not because it was better. Two §7 P0 requirements are unreachable
  on it rather than unimplemented: `listen()` owns the socket and fixes its
  certificate at bind time, and the handshake completes below `accept()` where
  nothing can rate-limit it.

  Both halves of the evidence are now on record. Correctness:
  `scripts/verify/dtls-demux.sh`, 9 of 9, including the per-IP handshake limiter
  refusing 15 handshakes before any DTLS state was created. Stability:
  `docs/soak/soak-24h-dtls-2026-09-01.md` — 24 hours, eleven DTLS cycles identical
  to three significant figures, a spread of 16 frames in 1.7 million, zero egress
  drops, and the node exiting cleanly on SIGTERM.

  *To keep the previous behaviour:* set `demux = false`. Note that
  `cert_reload_secs` and `max_handshakes_per_sec_per_ip` must then be removed —
  validation refuses them on the stock path, because there they read as protection
  that is not there.

  *Not established:* a real NIC. The run was over loopback, and handshakes over a
  network lose packets — which is where a demultiplexer is most likely to differ
  from a listener that owns its socket.

### Added

- **Two shared secrets during a rotation window** — `[turn.auth]
  previous_shared_secret`, and the same key per tenant. Rotating the secret used to
  invalidate every credential already issued, so the documented workaround was to
  schedule a low-traffic window. With this set, credentials signed with either
  validate.

  `turna_auth_previous_secret_total` counts what still uses the old one. That
  counter is not an extra: a rotation ends by removing the old secret, and without
  a number an operator cannot tell whether that is safe.

- **`[turn.auth] require_sha256`** refuses clients that can only do MD5 long-term
  keys. SHA-256 was already preferred when a client advertises it; the fallback was
  silent. Off by default — most deployed TURN clients predate RFC 8489.

### Fixed

- **`--dump-config` printed the backend URI whole**, and a Tarantool URI is
  `user:password@host`. The password was disclosed on the line directly above one
  that carefully masks the password field.

- **`auth failed` was logged at WARN for requests with no credentials at all.**
  RFC 5389 §10.2 requires the client to send one, get 401 with a realm and nonce,
  and only then sign — so that was one warning per allocation attempt: 4.8 GB of
  log per hour at soak rates, which filled a 50 GB disk. Now DEBUG.
  `IntegrityFailed`, which means a wrong password, stays at WARN.
