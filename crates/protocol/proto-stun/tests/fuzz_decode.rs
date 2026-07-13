//! Adversarial / no-panic tests for the STUN decoder.
//!
//! `property.rs` only roundtrips *well-formed* messages (`decode(encode(x)) == x`).
//! It never feeds hostile input to `decode`, so it cannot catch a slice/overflow
//! panic on attacker-controlled bytes. These tests close that gap: decoding
//! arbitrary bytes must always return `Ok` or a structured `StunError` — never
//! panic. The DoS-guard *limits* (oversized attribute, too many attributes, bad
//! magic cookie) are already unit-tested in `src/`; this file is about the
//! no-panic property over the whole input space plus a few deterministic edges
//! the roundtrip suite never produces.

use proptest::prelude::*;
use turna_proto_stun::message::{
    decode_channel_data, encode_channel_data, is_channel_data, is_stun_message, StunMessage,
};

proptest! {
    /// Decoding arbitrary bytes must never panic. Every classifier/decoder on the
    /// hot path is exercised with the same hostile buffer.
    #[test]
    fn decode_arbitrary_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 0..2048)
    ) {
        let _ = StunMessage::decode(&bytes); // Ok or Err — must not panic
        let _ = is_stun_message(&bytes);
        let _ = is_channel_data(&bytes);
        let _ = decode_channel_data(&bytes);
    }

    /// If a hostile buffer happens to decode, re-encoding the parsed message must
    /// also not panic (guards against a value that parses but overflows on encode).
    #[test]
    fn decode_then_reencode_never_panics(
        bytes in proptest::collection::vec(any::<u8>(), 20..2048)
    ) {
        if let Ok(msg) = StunMessage::decode(&bytes) {
            let mut out = [0u8; 4096];
            let _ = msg.encode(&mut out); // must not panic (may Err on space)
        }
    }

    /// `encode_channel_data` into an arbitrarily-sized buffer must return
    /// `BufferTooShort` rather than asserting/panicking (regression for M2).
    #[test]
    fn encode_channel_data_never_panics(
        channel in any::<u16>(),
        data in proptest::collection::vec(any::<u8>(), 0..600),
        cap in 0usize..700,
    ) {
        let mut buf = vec![0u8; cap];
        let _ = encode_channel_data(&mut buf, channel, &data);
    }
}

/// Valid 20-byte header whose declared message length points past the buffer.
/// Must be a structured error, not an out-of-bounds panic.
#[test]
fn declared_length_beyond_buffer_is_error_not_panic() {
    let mut buf = vec![0u8; 20];
    buf[0] = 0x00;
    buf[1] = 0x01; // Binding request
    buf[2] = 0x01;
    buf[3] = 0x00; // message length = 256 (multiple of 4), but no body follows
    buf[4..8].copy_from_slice(&0x2112_A442u32.to_be_bytes()); // magic cookie
                                                              // transaction id left as zeros
    assert!(
        StunMessage::decode(&buf).is_err(),
        "declared length beyond buffer must be an error"
    );
}

/// ChannelData frame whose declared length overflows the buffer.
#[test]
fn channel_data_length_overflow_is_error_not_panic() {
    let buf = [0x40u8, 0x00, 0xFF, 0xFF, 0x01, 0x02];
    assert!(decode_channel_data(&buf).is_err());
    assert!(
        !is_channel_data(&buf),
        "over-long length must not classify as ChannelData"
    );
}

/// Every truncated buffer shorter than a full header must be safe.
#[test]
fn tiny_buffers_are_safe() {
    for n in 0..20usize {
        let buf = vec![0u8; n];
        let _ = StunMessage::decode(&buf); // short header → Err, no panic
        let _ = is_stun_message(&buf);
        let _ = is_channel_data(&buf);
        let _ = decode_channel_data(&buf);
    }
}
