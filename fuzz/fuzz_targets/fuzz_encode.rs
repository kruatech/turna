#![no_main]
//! Fuzz the STUN/ChannelData *encode* paths.
//!
//! M2 changed `encode` / `encode_value` / `encode_channel_data` to return
//! `Result` instead of writing past a short buffer. This target hammers those
//! paths with adversarial buffer sizes and asserts the safety invariant: for
//! any output buffer length, encoding either reports a length that stays within
//! the buffer or fails cleanly — it never panics and never writes out of
//! bounds (a stray OOB write is caught as a crash by the sanitizer).

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use turna_proto_stun::message::{decode_channel_data, encode_channel_data, StunMessage};

#[derive(Arbitrary, Debug)]
struct Input {
    /// Raw bytes parsed as a STUN message, then re-encoded.
    packet: Vec<u8>,
    /// Fuzzer-chosen output buffer size for the STUN re-encode.
    out_len: u16,
    /// Inputs for the ChannelData encode path.
    channel: u16,
    payload: Vec<u8>,
    cd_out_len: u16,
}

fuzz_target!(|input: Input| {
    // 1. STUN encode path (covers encode() and, transitively, encode_value()).
    if let Ok(msg) = StunMessage::decode(&input.packet) {
        let mut buf = vec![0u8; input.out_len as usize];
        if let Ok(n) = msg.encode(&mut buf) {
            // A reported length must never exceed the buffer it was given.
            assert!(n <= buf.len(), "encode() reported {n} > buffer {}", buf.len());
            // Re-decoding the bytes we just wrote must not panic.
            let _ = StunMessage::decode(&buf[..n]);
        }
        // Err(BufferTooShort) is the expected, panic-free failure mode.
    }

    // 2. ChannelData encode path (the other M2 site).
    let mut cd = vec![0u8; input.cd_out_len as usize];
    if let Ok(n) = encode_channel_data(&mut cd, input.channel, &input.payload) {
        assert!(n <= cd.len(), "encode_channel_data() reported {n} > buffer {}", cd.len());
        let _ = decode_channel_data(&cd[..n]);
    }
});
