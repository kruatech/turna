//! WebTransport → relay bridge ("turna WebTransport framing v1").
//!
//! Connects the QUIC/WebTransport transport (`turna_transport::quic`) to the
//! transport-agnostic [`PacketProcessor`](crate::processor::PacketProcessor),
//! mirroring how [`tls_bridge`](crate::tls_bridge) connects the TLS transport.
//!
//! Framing contract:
//!   * **Bidi streams** carry a byte stream of concatenated, self-describing
//!     TURN messages — identical to the TURNS/TCP framing:
//!       - STUN/TURN: 20-byte header + length (header bytes 2..4); body is
//!         already 4-aligned.
//!       - ChannelData: 4-byte header + length (bytes 2..4), **padded to a
//!         4-byte boundary** over the stream (RFC 5766 §11.5). The padding is
//!         consumed off the wire but not handed to the processor.
//!         [`StreamFramer`] reassembles whole messages from arbitrarily-chunked
//!         stream data, then each goes to `process_slice`.
//!   * **Datagrams** carry exactly one TURN message each (datagram-bounded — no
//!     length prefix, no padding), handed straight to `process_slice`.
//!   * **Outbound**: `Action::Send` for control responses is written back on
//!     the bidi stream; media (ChannelData) as a datagram. The actual write is
//!     the caller's job (it owns the wtransport session handle) — this module
//!     returns the `Action`s to deliver.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::processor::{Action, PacketProcessor};
use turna_transport::quic::QuicEvent;

/// Reassembles complete TURN messages from a bidi stream's byte chunks.
///
/// A single message is bounded (STUN/ChannelData length is a 16-bit field, so
/// ≤ ~64 KiB), so the internal buffer never grows past one in-flight message.
#[derive(Default)]
pub struct StreamFramer {
    buf: Vec<u8>,
}

impl StreamFramer {
    /// Append freshly-received stream bytes.
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Pop the next complete logical message, or `None` if more bytes are
    /// needed. For ChannelData the 4-byte-boundary padding is consumed off the
    /// wire but excluded from the returned message (so the processor sees the
    /// same bytes it would off UDP).
    pub fn next_message(&mut self) -> Option<Vec<u8>> {
        loop {
            if self.buf.len() < 4 {
                return None;
            }
            let b0 = self.buf[0];
            let len = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize;

            // STUN/TURN: top two bits of the first byte are 00 (types
            // 0x000..0x3FFF). ChannelData: channel number 0x4000..0x7FFF, i.e.
            // first byte 0x40..=0x7F.
            let (wire_len, logical_len) = if b0 & 0xC0 == 0x00 {
                let total = 20 + len;
                (total, total)
            } else if (0x40..=0x7f).contains(&b0) {
                let pad = (4 - (len % 4)) % 4;
                (4 + len + pad, 4 + len)
            } else {
                // Unknown leading byte — resync by dropping one byte. Defensive;
                // a well-behaved client never hits this.
                self.buf.drain(0..1);
                continue;
            };

            if self.buf.len() < wire_len {
                return None;
            }
            let msg: Vec<u8> = self.buf.drain(0..wire_len).collect();
            return Some(msg[..logical_len].to_vec());
        }
    }
}

struct SessionCtx {
    remote: SocketAddr,
    framer: StreamFramer,
}

/// Bridges `QuicEvent`s into the processor. Tracks per-session remote address
/// (needed as the `src` for `process_slice`) and a per-session stream framer.
pub struct QuicBridge {
    processor: Arc<PacketProcessor>,
    sessions: HashMap<String, SessionCtx>,
}

impl QuicBridge {
    pub fn new(processor: Arc<PacketProcessor>) -> Self {
        Self {
            processor,
            sessions: HashMap::new(),
        }
    }

    /// Resolve which live session an outbound `Action`'s target belongs to
    /// (reverse of the session → remote map), so a response routes back over
    /// the originating WebTransport session. Returns `None` if no session has
    /// that remote (e.g. the client disconnected).
    pub fn session_for_addr(&self, addr: SocketAddr) -> Option<String> {
        self.sessions
            .iter()
            .find(|(_, ctx)| ctx.remote == addr)
            .map(|(id, _)| id.clone())
    }

    /// Feed one `QuicEvent`. Returns the `Action`s the caller must deliver back
    /// over the originating session (control on the bidi stream, media as a
    /// datagram — see the module contract).
    pub fn on_event(&mut self, ev: QuicEvent) -> Vec<Action> {
        let processor = self.processor.clone();
        match ev {
            QuicEvent::NewSession(s) => {
                self.sessions.insert(
                    s.session_id.clone(),
                    SessionCtx {
                        remote: s.remote_addr,
                        framer: StreamFramer::default(),
                    },
                );
                Vec::new()
            }
            QuicEvent::SessionClosed { session_id, .. } => {
                self.sessions.remove(&session_id);
                Vec::new()
            }
            QuicEvent::Datagram { session_id, data } => match self.sessions.get(&session_id) {
                Some(ctx) => processor.process_slice(&data, ctx.remote),
                None => Vec::new(),
            },
            QuicEvent::StreamData { session_id, data, .. } => {
                let mut out = Vec::new();
                if let Some(ctx) = self.sessions.get_mut(&session_id) {
                    ctx.framer.push(&data);
                    while let Some(msg) = ctx.framer.next_message() {
                        out.extend(processor.process_slice(&msg, ctx.remote));
                    }
                }
                out
            }
            QuicEvent::BiStreamOpened { .. } | QuicEvent::ConnectionMigrated { .. } => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stun_msg(body_len: usize) -> Vec<u8> {
        let mut m = vec![0u8; 20 + body_len];
        m[0] = 0x00; // top two bits 00 → STUN
        m[2..4].copy_from_slice(&(body_len as u16).to_be_bytes());
        m
    }

    fn channel_data(payload_len: usize) -> Vec<u8> {
        // Unpadded ChannelData (the "logical" message, as on UDP).
        let mut m = vec![0u8; 4 + payload_len];
        m[0] = 0x40; // channel number 0x4000.. → ChannelData
        m[1] = 0x00;
        m[2..4].copy_from_slice(&(payload_len as u16).to_be_bytes());
        m
    }

    #[test]
    fn frames_a_stun_message_split_across_chunks() {
        let msg = stun_msg(8);
        let mut f = StreamFramer::default();
        f.push(&msg[..5]);
        assert!(f.next_message().is_none(), "incomplete → None");
        f.push(&msg[5..]);
        assert_eq!(f.next_message(), Some(msg.clone()));
        assert!(f.next_message().is_none());
    }

    #[test]
    fn frames_two_concatenated_messages() {
        let a = stun_msg(0);
        let b = stun_msg(4);
        let mut f = StreamFramer::default();
        let mut wire = a.clone();
        wire.extend_from_slice(&b);
        f.push(&wire);
        assert_eq!(f.next_message(), Some(a));
        assert_eq!(f.next_message(), Some(b));
        assert!(f.next_message().is_none());
    }

    #[test]
    fn channel_data_padding_is_consumed_but_not_returned() {
        // payload_len 5 → 4 header + 5 = 9 on the logical message; padded to 12
        // on the wire (3 pad bytes).
        let logical = channel_data(5);
        let mut wire = logical.clone();
        wire.extend_from_slice(&[0, 0, 0]); // 3 pad bytes to reach 12
        let next = stun_msg(0); // a following message proves the pad was consumed
        wire.extend_from_slice(&next);

        let mut f = StreamFramer::default();
        f.push(&wire);
        assert_eq!(f.next_message(), Some(logical), "ChannelData without padding");
        assert_eq!(f.next_message(), Some(next), "next message starts after the pad");
    }

    #[test]
    fn resyncs_past_a_garbage_leading_byte() {
        let good = stun_msg(0);
        let mut wire = vec![0xFFu8]; // not STUN, not ChannelData
        wire.extend_from_slice(&good);
        let mut f = StreamFramer::default();
        f.push(&wire);
        assert_eq!(f.next_message(), Some(good));
    }
}
