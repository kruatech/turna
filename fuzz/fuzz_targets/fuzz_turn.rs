//! Fuzz target: TURN protocol parser
//!
//! `turna-proto-turn` re-exports the STUN parser and adds TURN-specific helpers.
//! This target differs from `fuzz_stun` primarily through its seed corpus:
//! the seeds here are valid TURN messages (Allocate, ChannelBind, Refresh,
//! ChannelData), so libFuzzer's coverage-guided mutations explore the TURN
//! attribute branches (LIFETIME, REQUESTED-TRANSPORT, XOR-PEER-ADDRESS,
//! CHANNEL-NUMBER, DATA) much earlier than starting from raw random bytes.
//!
//! Additionally, `decode_channel_data` and `is_valid_channel` are exercised
//! here directly because they are the hot path for TURN data forwarding.
//!
//! Contract under test:
//!   ∀ data: &[u8] — no panic, no infinite loop, no unbounded allocation.

#![no_main]
use libfuzzer_sys::fuzz_target;

use turna_proto_stun::message::{
    decode_channel_data, is_channel_data, is_stun_message, StunMessage,
};
use turna_proto_turn::is_valid_channel;

fuzz_target!(|data: &[u8]| {
    // ── Path 1: ChannelData decode ──────────────────────────────────────────
    // TURN ChannelData is the highest-throughput path in a media server.
    // The seed corpus contains valid ChannelData frames so the fuzzer mutates
    // around the channel number range (0x4000–0x7FFE) and length field.
    let _ = decode_channel_data(data);

    // ── Path 2: STUN/TURN message decode ────────────────────────────────────
    // Seeds here are TURN control messages (Allocate, Refresh, ChannelBind,
    // CreatePermission, Send/Data Indication).  The same decode code runs as
    // in fuzz_stun, but starting from TURN-shaped inputs guides coverage
    // toward TURN attribute parsing branches faster.
    let _ = StunMessage::decode(data);

    // ── Path 3: classifier helpers ───────────────────────────────────────────
    // Called on every incoming packet before dispatch.  Must never panic.
    let _ = is_channel_data(data);
    let _ = is_stun_message(data);

    // ── Path 4: channel-number validator ────────────────────────────────────
    // The TURN server calls is_valid_channel on every ChannelBind request and
    // on every forwarded ChannelData frame.  Trivially cheap but should never
    // panic on any u16 value.
    if data.len() >= 2 {
        let ch = u16::from_be_bytes([data[0], data[1]]);
        let _ = is_valid_channel(ch);
    }
});
