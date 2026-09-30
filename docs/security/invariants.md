# Security Invariants — turna

**Date:** 2026-05-23  
**Version:** 1.0

This document formalizes the system's security invariants. Every invariant must hold for any input. Violating an invariant is a security bug.

---

## 1. Authentication and authorization

### INV-AUTH-01: MESSAGE-INTEGRITY before state mutation
> The MESSAGE-INTEGRITY check must complete successfully **before** any state change.

**Implementation:** `processor.rs` — `auth.validate(msg, raw)` is called before `store.create()`, `store.refresh()`, `store.add_permission()`, `store.add_channel()`.  
**Violation:** creating an allocation without a valid HMAC.

### INV-AUTH-02: A TURN allocation does not outlive the authenticated session
> A TURN allocation cannot exist longer than the credentials it was created with.

**Implementation:** `CredentialRotationManager::cleanup()` removes allocations when credentials expire + grace period.  
**Violation:** an active allocation without valid credentials.

### INV-AUTH-03: Expired permissions are not reused
> A packet from a peer without an active permission must be dropped.

**Implementation:** `alloc.has_permission(&peer_addr)` is checked on every relay_recv.  
**Violation:** forwarding a packet from a peer whose permission was never granted or has expired.

### INV-AUTH-04: JWT replay protection
> Every JWT has a unique `jti`. A revoked token is not accepted.

**Implementation:** `UserStore::verify_token()` checks `TokenBlacklist` by `jti` after signature verification.  
**Violation:** accepting a token after `revoke_token()` has been called.

### INV-AUTH-05: JWT issuer validation
> Tokens with `iss != "turna-auth"` are rejected regardless of signature.

**Implementation:** `verify_jwt()` sets `validation.set_issuer(&["turna-auth"])`.  
**Violation:** accepting a token with an arbitrary issuer.

---

## 2. Parser and protocol

### INV-PARSE-01: The parser does not panic on arbitrary input
> `StunMessage::decode()`, `parse_compound()`, `decode_channel_data()` return `Err` on any input. Panics are forbidden.

**Implementation:** hard limits + exhaustive tests + fuzzing corpus.  
**Verification:** `cargo fuzz run fuzz_stun`, `fuzz_turn`, `fuzz_rtcp`, `fuzz_turn_lifecycle`, `fuzz_stun_semantic`.

### INV-PARSE-02: Packet size is bounded before memory allocation
> The `length` field in the STUN header cannot cause an allocation of more than `MAX_MESSAGE_LEN=4096` bytes.

**Implementation:** `header.rs` — `length > MAX_MESSAGE_LEN` is checked before any allocation.  
**Violation:** allocating a buffer sized from an untrusted length field.

### INV-PARSE-03: Attribute size is bounded
> A single attribute value does not exceed `MAX_ATTRIBUTE_VALUE_LEN=1500` bytes.

**Implementation:** `attribute.rs` — checked before the bounds check.  
**Violation:** allocating a Vec from an untrusted attr_len.

### INV-PARSE-04: Attribute count is bounded
> A single STUN message contains at most `MAX_ATTRIBUTES_PER_MESSAGE=32` attributes.

**Implementation:** `attribute.rs` — `attrs.len() >= MAX_ATTRIBUTES_PER_MESSAGE` is checked before `push`.  
**Violation:** unbounded Vec growth from a single packet.

### INV-PARSE-05: The ChannelData buffer includes padding
> The buffer passed to `encode_channel_data` must be at least `(4 + data.len() + 3) & !3` bytes.

**Implementation:** `message.rs` — assert before writing the padding.  
**Violation:** OOB write with an unaligned payload.

---

## 3. Relay and quotas

### INV-RELAY-01: Quotas are checked before forwarding
> The bandwidth quota is checked before the packet is passed to the peer.

**Implementation:** `processor.rs` — `alloc.check_bandwidth()` before `add_bytes()` and `Action::Forward`.  
**Violation:** forwarding when the quota is exceeded.

### INV-RELAY-02: Replayed transaction ID is rejected
> A nonce with an expired or invalid value returns 438 Stale Nonce.

**Implementation:** `NonceManager::validate(client, nonce)` — the nonce is stateless and
bound to the client address (IP:port): `HMAC(server_key, ts || client)`,
`server_key` is ephemeral per process. Valid for ≤ 630 s (600 s lifetime + 30 s
grace); an invalid MAC, a different client or an expired nonce → 438 Stale Nonce.
**Violation:** accepting an old nonce or a nonce issued to a different client.

### INV-RELAY-03: Channel number is valid
> ChannelBind is accepted only for channel 0x4000–0x7FFE.

**Implementation:** `turn::is_valid_channel(channel)` in `handle_channel_bind`.  
**Violation:** binding to a channel outside the allowed range.

---

## 4. Unsafe code

### INV-UNSAFE-01: HugePagePool — no active buffers on drop
> `HugePagePool` must not be dropped while any `PoolBuffer` from it exists.

**Implementation:** `drop()` panics if `allocated > 0`.  
**Enforcement:** keep the pool in an `Arc`, shared with the workers.

### INV-UNSAFE-02: Umem::frame_slice — address within the UMEM
> `addr + len <= umem.size` before any access to the mmap region.

**Implementation:** `assert!` in `frame_slice` and `frame_slice_mut` with a diagnostic message.  
**Violation:** OOB access to the mmap region (possible with a driver bug in AF_XDP).

### INV-UNSAFE-03: MsgHdrStorage — stable address
> `MsgHdrStorage` is not moved after `setup_recv`/`setup_send`.

**Implementation:** stored in `Box<[MsgHdrStorage]>` — a heap allocation with a fixed address.  
**Violation:** any `Vec<MsgHdrStorage>` that can reallocate.

### INV-UNSAFE-04: Umem::new — geometry without overflow (USF-008)
> `frame_count > 0 && frame_size > 0 && frame_count * frame_size` does not overflow `usize`.

**Implementation:** `checked_mul` + zero check in `Umem::new`, before `mmap`; otherwise `Err`.  
**Violation:** a wrapped (understated) `size` would make the bounds check from INV-UNSAFE-02 useless (validation against a region that is too small). Especially important for configs from an untrusted source.

### INV-UNSAFE-05: Umem Sync — frame access only within the userspace ownership window
> `&Umem::frame_slice(addr, ..)` is called only for a frame whose RX descriptor has already been dequeued from the RX ring and not yet returned to the FILL ring; a single frame is never aliased from two threads at once.

**Implementation:** a documented invariant on `unsafe impl Sync for Umem` (the AF_XDP frame ownership protocol); not enforced by types.  
**Violation:** reading a frame before dequeue or after refill = a data race with kernel RX DMA (UB). The invariant must be rechecked whenever the RX loop is restructured; the alternative is to remove `Sync` (Umem is not shared as `&Umem` between threads).

---

## 5. Invariant verification

| Invariant | Verification method |
|---|---|
| INV-AUTH-* | Unit tests in `crates/auth/`, integration tests |
| INV-PARSE-* | Fuzzing: `cargo fuzz run fuzz_stun / fuzz_turn / ...` |
| INV-RELAY-* | Unit tests in `crates/relay/src/processor.rs` |
| INV-UNSAFE-* | ASAN/UBSAN/TSAN sanitizer runs |
