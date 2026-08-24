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

/// Hard ceiling on buffered stream bytes. One logical message is at most
/// `20 + u16::MAX` (STUN) so anything beyond this means the stream is
/// desynchronised or hostile; the buffer is dropped rather than grown.
const MAX_FRAMER_BUFFER: usize = 128 * 1024;

impl StreamFramer {
    /// Bytes currently buffered awaiting a complete message (test/observability).
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Append freshly-received stream bytes.
    pub fn push(&mut self, data: &[u8]) {
        if self.buf.len().saturating_add(data.len()) > MAX_FRAMER_BUFFER {
            tracing::warn!(
                buffered = self.buf.len(),
                incoming = data.len(),
                limit = MAX_FRAMER_BUFFER,
                "QUIC stream framer buffer limit exceeded; discarding buffer (desynchronised stream)"
            );
            self.buf.clear();
            return;
        }
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
    /// Bidi stream the session's most recent control message arrived on, so a
    /// response goes back on that stream rather than whichever one the client
    /// happened to open first.
    last_stream: Option<u64>,
}

/// Bridges `QuicEvent`s into the processor. Tracks per-session remote address
/// (needed as the `src` for `process_slice`) and a per-session stream framer.
pub struct QuicBridge {
    processor: Arc<PacketProcessor>,
    sessions: HashMap<String, SessionCtx>,
    /// Reverse index of `sessions` (remote address → session id). Every outbound
    /// packet needs this lookup, and scanning the session map for each one was
    /// O(sessions) on the egress hot path.
    by_addr: HashMap<SocketAddr, String>,
}

impl QuicBridge {
    pub fn new(processor: Arc<PacketProcessor>) -> Self {
        Self {
            processor,
            sessions: HashMap::new(),
            by_addr: HashMap::new(),
        }
    }

    /// Resolve which live session an outbound `Action`'s target belongs to, so a
    /// response routes back over the originating session. Returns `None` if no
    /// session has that remote (e.g. the client disconnected).
    pub fn session_for_addr(&self, addr: SocketAddr) -> Option<String> {
        self.by_addr.get(&addr).cloned()
    }

    /// Bidi stream to answer a control response on for this session (the one its
    /// most recent request arrived on), or `None` for a datagram-only session.
    pub fn control_stream_for(&self, session_id: &str) -> Option<u64> {
        self.sessions.get(session_id).and_then(|c| c.last_stream)
    }

    /// Re-key a session after a QUIC connection migration (the client's address
    /// changed but the connection survived).
    pub fn migrate(&mut self, session_id: &str, old_addr: SocketAddr, new_addr: SocketAddr) {
        if let Some(ctx) = self.sessions.get_mut(session_id) {
            ctx.remote = new_addr;
        }
        self.by_addr.remove(&old_addr);
        self.by_addr.insert(new_addr, session_id.to_string());
    }

    /// Feed one `QuicEvent`. Returns the `Action`s the caller must deliver back
    /// over the originating session (control on the bidi stream, media as a
    /// datagram — see the module contract).
    pub fn on_event(&mut self, ev: QuicEvent) -> Vec<Action> {
        let processor = self.processor.clone();
        match ev {
            QuicEvent::NewSession(s) => {
                self.by_addr.insert(s.remote_addr, s.session_id.clone());
                self.sessions.insert(
                    s.session_id.clone(),
                    SessionCtx {
                        remote: s.remote_addr,
                        framer: StreamFramer::default(),
                        last_stream: None,
                    },
                );
                Vec::new()
            }
            QuicEvent::SessionClosed { session_id, .. } => {
                if let Some(ctx) = self.sessions.remove(&session_id) {
                    // Only drop the reverse entry if it still points at us: a
                    // migrated session may have handed the old address on.
                    if self.by_addr.get(&ctx.remote).map(|s| s.as_str())
                        == Some(session_id.as_str())
                    {
                        self.by_addr.remove(&ctx.remote);
                    }
                }
                Vec::new()
            }
            QuicEvent::Datagram { session_id, data } => match self.sessions.get(&session_id) {
                // `process_owned`, NOT `process_slice`: the latter emits
                // `ForwardZeroCopy { offset, len }` for ChannelData, which the
                // QUIC egress cannot resolve back into bytes — every
                // client→peer media datagram was silently dropped.
                Some(ctx) => processor.process_owned(data, ctx.remote),
                None => Vec::new(),
            },
            QuicEvent::StreamData {
                session_id,
                data,
                stream_id,
            } => {
                let mut out = Vec::new();
                if let Some(ctx) = self.sessions.get_mut(&session_id) {
                    // Remember which stream to answer on.
                    ctx.last_stream = Some(stream_id);
                    ctx.framer.push(&data);
                    while let Some(msg) = ctx.framer.next_message() {
                        // Owned message from the framer — see the `Datagram`
                        // arm for why `process_slice` must not be used here.
                        out.extend(processor.process_owned(msg, ctx.remote));
                    }
                }
                out
            }
            // Migration is applied by the caller via `migrate()` (it also has to
            // re-key the shared client_sinks registry), so nothing to do here.
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
        assert_eq!(
            f.next_message(),
            Some(logical),
            "ChannelData without padding"
        );
        assert_eq!(
            f.next_message(),
            Some(next),
            "next message starts after the pad"
        );
    }

    #[test]
    fn framer_buffer_is_bounded() {
        // A stream that never yields a complete message must not grow the buffer
        // without limit. One logical message is at most 20 + u16::MAX, so hitting
        // MAX_FRAMER_BUFFER means the stream is desynchronised: drop the buffer.
        let mut f = StreamFramer::default();
        // A STUN header claiming a body far larger than any single push, so
        // `next_message` keeps returning None while bytes accumulate.
        let mut header = vec![0u8; 20];
        header[0] = 0x00;
        header[2..4].copy_from_slice(&u16::MAX.to_be_bytes());
        f.push(&header);
        assert!(f.next_message().is_none(), "incomplete message");

        // Push well past the cap in chunks.
        let chunk = vec![0u8; 32 * 1024];
        for _ in 0..8 {
            f.push(&chunk);
        }
        assert!(
            f.buffered() <= MAX_FRAMER_BUFFER,
            "framer buffer must stay bounded, was {}",
            f.buffered()
        );
    }

    #[test]
    fn framer_recovers_after_buffer_reset() {
        // After a reset the framer must still parse a fresh, well-formed message.
        let mut f = StreamFramer::default();
        f.push(&vec![0u8; MAX_FRAMER_BUFFER + 1]);
        let good = stun_msg(0);
        f.push(&good);
        assert_eq!(f.next_message(), Some(good));
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
