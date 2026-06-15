# Audit-3 Closeout (Code Review) — 2026-06

Companion to `audit-closeout-2026-06.md` (Audit-1 security/perf + Audit-2
operational). Covers the 14 Audit-3 code-review findings. All code changes were
delivered as project-root-relative archives, applied with `unzip -o`, and built
green by the owner.

## Status by finding

| ID | Sev | Status | Delivery | Summary of fix |
|----|-----|--------|----------|----------------|
| A3-C1 | Critical | **Closed** | 20, 22 | Removed cross-allocation pointer subtraction in `handle_send_indication` (`data.as_ptr() - raw.as_ptr()`); `data` is a slice into an owned `Attribute::Data(Vec)`, so the offset was bogus and could panic. Now `Bytes::copy_from_slice(data)`. Latent (never-tested-path), not a regression. |
| A3-H1 | High | **Closed** | 21 | `ChannelBind` now enforces RFC 8656 §12.2 uniqueness *before* any mutation: channel→different-peer or peer→different-channel ⇒ `SessionError::ChannelConflict` → 400. Atomic, no torn `channels_reverse`. |
| A3-M1 | Medium | **Closed** | 21, 29 | `CreatePermission` validates **all** XOR-PEER-ADDRESS: collect → reject the whole request (403) if any peer is forbidden → create none/all. e2e test (multi-peer + multicast-forbidden) added to `tests/integration`. |
| A3-L1 | Low | **Closed** | 23 | `handle_allocate` authenticates **before** the 437/442 checks, so an unauthenticated client can no longer probe allocation/transport state (437 vs 401 disclosure). |
| A3-O1 | Low | **Closed** | 23 | Worker `process()` wrapped in `catch_unwind`; panics drop the packet, bump `turna_processor_panics_total`, worker survives. Belt-and-suspenders over C1. |
| A3-Q1 | Quality | **Closed** | 20 | `if let Err(_) = create_for_tenant` → `.is_err()` (was a CI blocker under `-D warnings`). |
| A3-Q2 | Quality | **Closed** | 23 | Allocate path does one `store.get` post-create (id + epoch captured once) instead of two shard-lock acquisitions. |
| A3-Q3 | Quality | **Closed** | 25 | Removed the dead duplicate `long_term_key` from `proto-stun/integrity.rs`; single source of truth is `turna_crypto::long_term_key`. |
| A3-Q4 | Quality | **Closed** | 24 | USERNAME/REALM parse strictly as UTF-8 (reject, not `from_utf8_lossy`-repair) since both feed the long-term key. NONCE/SOFTWARE/ERROR-reason stay lossy (display/echo, fail-closed). |
| A3-Q5 | Quality | **Closed** | 25 | `verify_message_integrity` uses `hmac::Mac::verify_slice` (vetted constant-time compare); hand-rolled `constant_time_eq` removed. No new dependency. |
| A3-F2 | Feature | **Closed** | 29 | EVEN-PORT / RESERVATION-TOKEN: new attributes, even-port allocator + 30s token reservation in `PortAllocator`, `handle_allocate` wiring (mutual-exclusion → 400, token claim → 508 on invalid, RESERVATION-TOKEN echo). |
| A3-F4 | Feature | **Closed** | 26 | Real IP DF bit: allocation-scoped DONT-FRAGMENT sets `IP_MTU_DISCOVER=IP_PMTUDISC_DO` on the relay socket (Linux; no-op on macOS dev). Was a length-check approximation only. |
| A3-F1 | Feature | **Design / deferred** | 30 | RFC 6062 TCP allocations. Blocked: no TCP/TLS client transport exists, and the connectionless `process()→Actions` model doesn't fit connection-oriented TCP. Design doc + 7-chunk plan delivered; needs owner decision on TCP transport scope. |
| A3-F3 | Feature | **Deferred** | — | ICMP→Data error. Requires building `IP_RECVERR`/`MSG_ERRQUEUE` reads from scratch in the unsafe io_uring core + the §18.13 ICMP attribute. Recommended path: do the synchronous frag-needed slice (EMSGSIZE on relay-send, pairs with F4) before the async errqueue chunk. |

## Related hygiene / ops deliveries

| Delivery | Contents |
|----------|----------|
| 22 | Build fix — test used `msg.encode()` as `-> usize`; it returns `Result` since Audit-1/M2. |
| 27 | `qos/Cargo.toml` loom `check-cfg` (CI `-D warnings` fix); removed now-unused `md5` dep from `proto-stun` (post-Q3). |
| 28 | `docs/alerts/turna.yml` — 17 Prometheus rules on real `/metrics` names (incl. `turna_processor_panics_total` from O1). |

## Owner action items

1. **F1 / TCP transport** — decide whether a TCP/TLS TURN control transport is in
   scope. If yes, send `crates/protocol/proto-stun/src/method.rs` to land chunk 1
   (proto-stun primitives), then scope chunk 2 (the transport) as a project.
2. **F3** — confirm the RFC 8656 §18.13 ICMP attribute wire layout/codepoint, and
   decide frag-needed-first (lower risk) vs full errqueue.
3. **Alert tuning** — thresholds/`for` windows in `turna.yml` are starting points;
   tune to the traffic profile before paging. Validate with `promtool check rules`.
4. **`md5` dep removal** — confirm with `cargo machete` (no `proto-stun` file
   outside those reviewed uses md5).

## Carried over from Audit-1/2 (owner-side, unchanged)

- tonic `0.12.3 → 0.14.x` upgrade — unblocks RUSTSEC ignores + real CRL for mTLS.
- `UserStore::warm_revocations` — 3-line call to add when `UserStore` is
  instantiated (Phase-2 user-auth not yet wired into node/control-plane).
- P1 zero-copy forward / P4 lock-free limiter — hardware benchmark validation.

## Tally

Audit-3: **10 of 14 closed** (C1, H1, M1, L1, O1, Q1–Q5, F2, F4); 2 features
deferred with documented blockers (F1 design, F3); plus build-hygiene + alerts.
Audit-1 and Audit-2 remain fully closed.
