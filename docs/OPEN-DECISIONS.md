# Open decisions and unclosed items

State as of 2026-08-19, after the transport verification pass. Everything that could
be closed by writing code or running something has been; what is listed here is
waiting on a decision, on an external dependency, or on hardware.

Each decision states what has already been established, so the choice can be made
from facts rather than re-derived.

---

## Decisions

### 0. Hot rotation of the shared secret — opened 2026-08-28

There is none. Measured: `SIGHUP` is not handled, and `UpdateConfig` carries
allocation limits rather than the secret. `[turn.auth] shared_secret` changes only
with a restart.

That matters because the shared secret is the credential a leak would force you to
change, and changing it means restarting every node. Certificate rotation is hot
and verified under load; this is not.

*Mitigating:* ephemeral credentials derived from it carry a TTL, so ones already
issued expire on their own.

Three options, in rough order of cost:

- **Document it and leave it.** A rolling restart is a supported operation and a
  compromised secret is rare. Cheapest, and honest as long as it is written where a
  customer sees it — which it now is, as R13.
- **Add the secret to `UpdateConfig`.** The machinery exists: idempotency keys,
  optimistic concurrency, an audit trail. The question is whether a credential
  should travel over the management API at all, given that anyone who can call it
  can already mint sessions.
- **Accept two secrets during a rotation window.** What a deployment actually
  wants: the node honours credentials signed by either while the fleet catches up.
  Correct, and the most work.

Not decided. Recorded so that it is a choice rather than a gap nobody noticed.

### 1. Lift the `production = true` gate on RFC 6062 TCP relay? — lifted 2026-08-25

**Established.** Interop is recorded (`docs/interop/transports-2026-08-19.md`): Allocate
over TCP, CreatePermission, Connect, ConnectionBind and data in both directions — in
both the plain form and the one that pipelines the first application bytes into the
same write as `ConnectionBind`. That second case is what RFC 6062 §5.4 permits and what
the detach prebuffer in `transport::tcp_tls` exists to handle; it had never been
exercised by a real client before.

**The gate was there for want of that evidence.** It now stands as a policy choice, not
a missing prerequisite: one line in `config::validate()`.

**The actual question** is whether you are prepared to support TCP relay in production —
it consumes a listener and a connection per relayed peer, which is a different
operational profile from UDP.

**Decided: lifted.** The refusal in `config::validate()` is gone. Interop was
since confirmed a second time against coturn's own client
(`docs/interop/coturn-2026-08-23.md`), so two independent implementations agree
about the wire.

The sizing consequence is documented rather than enforced: a refusal cannot make
a capacity decision on an operator's behalf, and one that pretends to just means
the feature is unavailable to everyone. What remains genuinely missing is IPv6 on
this path — an IPv6 `Connect` is refused with 440 — which is recorded in
`docs/protocol-gap.md`.

### 2. Flip `[turn.dtls] demux` to `true` by default? — evidence gathered 2026-08-28

`scripts/verify/dtls-demux.sh`, **nine checks of nine**:

- relays 21 612 frames across 12 concurrent sessions, zero errors
- certificate hot-reload live: 0 → 1, no reload failures
- per-IP handshake rate limiter: **15 handshakes refused** before any DTLS state
  was created
- drain releases the listener; node exits in 12 s with status 0, UDP port freed

Both of those are §7 P0 requirements, and neither is available on the stock path
for structural reasons rather than missing work: `listen()` owns the socket and
fixes its configuration at bind time, and the handshake completes below `accept()`
where nothing can rate-limit it. Config validation already refuses the two keys
unless `demux = true`, and says why.

**What is still missing: a 24-hour run.** The stock path holds the default because
one exists for it. The soak script has no DTLS parameters, so this needs the script
extended first — and that extension is itself unverified work, a poor thing to add
immediately before a release.

**No longer an argument against it.** An earlier reading of this verification
concluded the demux path fails to release its socket and segfaults. Neither was
true: `kill -0` succeeds on a zombie, so the check watched an already-dead process
for 45 seconds, and the only core on the host was bash's from an interrupted run.
The real defect was the runtime not shutting down — see R12 in
`docs/PRODUCTION_READINESS.md` — and it affected every path equally.

### 2-old. The original framing, superseded

**Established.** Both paths carry an allocation and relay media
(`docs/interop/transports-2026-08-19.md`). `demux = true` adds concurrent handshakes,
pre-handshake admission, a per-IP rate limit and certificate hot-reload — none of which
the stock `webrtc_dtls::listen()` path can have, because its handshake runs below
`accept()`.

**Against flipping now:** the stock path is the one with production mileage. The demux
path has one lab run.

**Suggested:** leave the default, let anyone who wants those properties opt in, and flip
after a release cycle of real use. Nothing is lost by waiting; a regression in the
default DTLS path would be.

### 3. `ADDITIONAL-ADDRESS-FAMILY` (RFC 8656 §7.2) — which storage shape?

One Allocate asking for both families, which is what a dual-stack WebRTC client wants.
The protocol work is small; the state work is not, because `turna_allocations` is keyed
by `relay_port` and one allocation cannot hold two.

Full analysis, per-option edit lists and the test list:
[docs/design/additional-address-family.md](design/additional-address-family.md).

| | Option | Cost |
|---|---|---|
| 1 | Second port inside the `data` blob | No schema migration — `serde(default)` is the established pattern here. But the v6 port has no index, so port-collision detection and `pool_states` cover half the allocation. An existing test (`rehydrate_double_port_conflict`) would keep passing while covering only the v4 half. |
| 3 | Composite primary key | Correct model, both ports indexed, quota counting unaffected. Needs a migration for live data, and `init.lua` plus the Rust `INIT_SCRIPT` must move together. |

**Recommended:** option 3 if a schema migration is acceptable in this release, otherwise
option 1 with the halved guarantee written down at the call site rather than discovered
later. Not option 2 (two tuples per allocation) — it double-counts `by_user` quotas and
makes refresh and remove non-atomic.

**Prerequisite either way:** plain IPv6 relaying is verified
(`docs/interop/relayed-media-2026-08-19.md`), so this no longer stacks on an unverified
base.

### 4. `node_migration.rs` — wire it or delete it?

The module has no callers outside `lib.rs`. Only same-node mobility works today
(RFC 8016 tickets in `turna_transport::migration`).

**Wiring** needs control-plane gRPC state transfer plus fencing — a task, not an edit.
**Deleting** is minutes.

Until decided it is marked unwired in its own module header, the docs say the same, and
`scripts/check-doc-claims.sh` asserts the two agree — so it cannot quietly start
looking supported.

### 5. SCTP — keep it refused, or remove it?

No RFC defines TURN-over-SCTP, so interop is impossible by construction: there is
nothing to be compatible with. The implementation has **no hardening at all** — no
per-IP cap, no rate limit, no `turna_sctp_*` metrics, no readiness, no drain — and its
control channel is plaintext, which is a step back from TURNS.

**For removal:** dead code that has to compile and be maintained, and that carries risk
if anyone enables it. An allocation leak was found in it this cycle
(`ConnectionClosed` did not release the relay port) precisely because it exists.

**For keeping:** if a customer ever needs it, reviving beats rewriting.

**Note if kept:** bringing it to the level of the other transports is roughly one
working session (limits, metrics, readiness, drain, a load client). That work would not
move any readiness metric, because there is no standard to be interoperable with and the
production gate is a decision rather than a missing prerequisite.

### 6. Is RFC 5780 (NAT behaviour discovery) wanted?

Not implemented — no `ChangeRequest`, `OtherAddress` or `ResponseOrigin` anywhere. It
needs a two-address deployment topology, so this is a deployment question before it is
a coding one.

Worth knowing: the documentation used to claim the codec was complete. That false claim
is what hid the `ATTR_ALTERNATE_SERVER` wire bug for as long as it did.

---

## Unclosed, waiting on something external

### mTLS for TURNS clients — closed 2026-08-20

Verified by `scripts/verify/mtls.sh`: a client with a valid certificate is accepted, a
client with none is refused while `require_client_cert = true`, and with the flag off a
client without a certificate still gets in (the staged-rollout mode).

The refusal is the case that carries the result. A server accepting everybody is
indistinguishable from a working one if only the happy path is run.

The script mints a throwaway private CA, because client certificates come from a CA you
run — public issuers sign server certificates only. That is not a workaround; it is how
mTLS works, and `docs/MTLS.md` says the same of the management plane.

Still out of scope, deliberately: revocation. No CRL, no OCSP, consistent with the
management plane — revoking means rotating the CA.

### AF_XDP on a real NIC

Correctness is verified on a veth lab (`docs/interop/af-xdp-2026-08-19.md`): conformance
plus relayed media at three rates, 7124 frames, zero loss.

But the lab attaches in **SKB (generic) mode**, which copies every frame and reproduces
none of the kernel-bypass behaviour AF_XDP exists for. Numbers from it are not capacity
figures. A real NIC needs a dedicated interface: the XDP program intercepts traffic
below the stack, so it cannot share the interface carrying your traffic.

### OAuth (RFC 7635)

The one gap that is not a client. RFC 7635 is about a **third party**: an authorization
server issues an AEAD token under a key shared with the TURN server, and the client only
presents it. A token issuer written here would test one reading of the spec against
itself, which is not interop.

Deliberately deferred. The gate stays.

---

### A failed health bind is not fatal

Observed 2026-08-20 while setting up the WebTransport run: the node ran for eight
minutes with `[health]` configured on a port already held by an unrelated process. It
kept serving traffic, and the metrics being scraped belonged to the other process —
so the node looked observable and healthy while its own health listener did not exist.

Failing to bind a configured listener is fatal for the TURN, TURNS, DTLS and QUIC
ports. Health appears not to follow that rule. Worth deciding deliberately: an
operator who configures `[health]` and gets no error reasonably believes monitoring is
in place.

Not investigated beyond the observation.

### An idle DTLS listener warns every ten seconds

`accept() exceeded the bound` is logged at WARN once per `accept_timeout_secs` on a
listener with nothing wrong. On the stock path `accept()` blocks waiting for the next
client, hits the bound, logs, and loops — so an idle deployment produces 8 640 warnings
a day, which is how an operator learns to filter out the line that is meant to signal a
stalled handshake.

The distinction to draw: a timeout with **no handshake started** is the idle case and
belongs at DEBUG; a timeout with a handshake **begun and abandoned** is what the warning
was written for and should stay at WARN. `turna_dtls_accept_timeouts_total` already
counts them, so nothing is lost by quietening the idle case.

Observed 2026-08-23 during the load runs (`docs/soak/transport-load-2026-08-23.md`).

## In the roadmap rather than open

### AF_XDP ring-size keys are accepted and ignored

`[turn.af_xdp]` exposes `fill_ring_size`, `comp_ring_size`, `rx_ring_size` and
`tx_ring_size`; the rings are pinned to the library defaults. This also creates a trap:
`frame_count` above twice the ring size leaves the fill ring unseedable and RX stops
silently (`docs/roadmap/af-xdp-phase2.md`).

**Attempted and reverted 2026-08-19.** Wiring the keys through is a few lines, but it
moves the UMEM geometry, which means reconciling the shipped defaults (4096 frames does
not satisfy `fill + tx + scratch`), the validation, and the lab script's own
`FRAME_COUNT` — all at once. The change was correct and still landed as a regression
because it went out without a lab run. Not cheap; treat it as a task with a test plan.

### `zero_copy` conflates two orthogonal settings

It drives both the XSK bind flag (`XDP_ZEROCOPY` vs `XDP_COPY`) and the XDP attach mode
(NATIVE vs SKB). Those are independent, and the coupling means a native attach cannot be
requested without also requesting zero-copy — which veth refuses, so the lab is stuck in
SKB mode.

Fix is separate keys with the current flag kept as a compatible default. Nothing has
verified which combinations the target NIC supports, so this wants a NIC before it wants
code.

---

## What is not on this list

Every transport now carries a TURN allocation and relays media in both directions, with
the runs recorded in [docs/interop/](interop/) and [docs/soak/](soak/). The default
production profile — UDP over tokio, TURNS, long-term credentials, Tarantool — is
verified end to end, including three hours of endurance without a leak.

Two findings from that work are worth carrying forward as a pattern rather than as two
incidents: the io_uring datapath went deaf after exactly 64 relayed packets, and the
AF_XDP datapath after exactly 2015 frames. Both were resource leaks that presented as a
hard stop at a pool or slot count, both were invisible to every existing check, and both
were found by comparing a counter against the size of the thing it was exhausting. If a
third datapath appears, look there first.
