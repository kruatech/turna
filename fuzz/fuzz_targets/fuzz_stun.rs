//! Fuzz target: STUN message parser
//!
//! Exercises every public entry point of `turna-proto-stun` on arbitrary bytes.
//! The goal is to prove that no input can cause a panic, infinite loop, or
//! unbounded allocation — only `Err(StunError::*)` returns.
//!
//! Contract under test:
//!   ∀ data: &[u8] — none of the calls below panic, hang, or OOM.

#![no_main]
use libfuzzer_sys::fuzz_target;

use turna_proto_stun::{
    attribute::parse_attributes,
    header::MessageHeader,
    message::{decode_channel_data, is_channel_data, is_stun_message, StunMessage},
};

fuzz_target!(|data: &[u8]| {
    // ── Path 1: full STUN message decode ────────────────────────────────────
    // Exercises MessageHeader::decode (magic cookie, length caps, alignment),
    // then parse_attributes (per-attr length caps, count cap, fixed-size
    // attribute validators, XOR address decoder, string conversions).
    let _ = StunMessage::decode(data);

    // ── Path 2: ChannelData decode ──────────────────────────────────────────
    // TURN ChannelData has its own 4-byte framing (channel + length), entirely
    // separate from the STUN header path.  Exercises the bounds check in
    // decode_channel_data independently of StunMessage.
    let _ = decode_channel_data(data);

    // ── Path 3: header-only decode ──────────────────────────────────────────
    // Hits the early-exit checks (buffer too short, bad cookie, odd length,
    // length > MAX_MESSAGE_LEN, unknown method) without needing a valid body.
    let _ = MessageHeader::decode(data);

    // ── Path 4: attribute parser with fuzzer-supplied transaction ID ─────────
    // parse_attributes is normally called with a validated TID extracted from
    // a verified header.  Feeding it arbitrary body bytes + arbitrary TID
    // exercises the padding arithmetic, attribute-value bounds, count guard,
    // and each attribute branch without the header checks acting as a filter.
    if data.len() >= 12 {
        let mut tid = [0u8; 12];
        tid.copy_from_slice(&data[..12]);
        let _ = parse_attributes(&data[12..], &tid);
    }

    // ── Path 5: classifier helpers ───────────────────────────────────────────
    // These are called on every incoming UDP packet before the parser is
    // invoked.  They must never panic on any input.
    let _ = is_stun_message(data);
    let _ = is_channel_data(data);

    // ── Path 6: HMAC verification ────────────────────────────────────────────
    // verify_integrity is only reachable when a decode succeeded (it needs
    // a parsed MessageIntegrity attribute and the original raw bytes).
    // Using a fixed fuzz key is intentional — we are testing the verification
    // logic / HMAC arithmetic, not the key material itself.
    if let Ok(msg) = StunMessage::decode(data) {
        let _ = msg.verify_integrity(data, b"fuzz_integrity_key");
    }
});
