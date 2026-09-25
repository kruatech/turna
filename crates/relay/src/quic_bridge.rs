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
    failed: bool,
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
        if self.failed {
            return;
        }
        if self.buf.len().saturating_add(data.len()) > MAX_FRAMER_BUFFER {
            tracing::warn!(
                buffered = self.buf.len(),
                incoming = data.len(),
                limit = MAX_FRAMER_BUFFER,
                "QUIC stream framer buffer limit exceeded; discarding buffer (desynchronised stream)"
            );
            self.buf.clear();
            self.failed = true;
            return;
        }
        self.buf.extend_from_slice(data);
    }

    /// Pop the next complete logical message, or `None` if more bytes are
    /// needed. For ChannelData the 4-byte-boundary padding is consumed off the
    /// wire but excluded from the returned message (so the processor sees the
    /// same bytes it would off UDP).
    pub fn next_message(&mut self) -> Option<Vec<u8>> {
        {
            if self.failed || self.buf.len() < 4 {
                return None;
            }
            let b0 = self.buf[0];
            let len = u16::from_be_bytes([self.buf[2], self.buf[3]]) as usize;

            // STUN/TURN: top two bits of the first byte are 00 (types
            // 0x000..0x3FFF). ChannelData: channel number 0x4000..0x7FFF, i.e.
            // first byte 0x40..=0x7F.
            let (wire_len, logical_len) = if b0 & 0xC0 == 0x00 {
                if !len.is_multiple_of(4)
                    || (self.buf.len() >= 8 && self.buf[4..8] != [0x21, 0x12, 0xa4, 0x42])
                {
                    self.failed = true;
                    self.buf.clear();
                    return None;
                }
                let total = 20 + len;
                (total, total)
            } else if (0x40..=0x7f).contains(&b0) {
                let pad = (4 - (len % 4)) % 4;
                (4 + len + pad, 4 + len)
            } else {
                self.failed = true;
                self.buf.clear();
                return None;
            };

            if self.buf.len() < wire_len {
                return None;
            }
            let msg: Vec<u8> = self.buf.drain(0..wire_len).collect();
            Some(msg[..logical_len].to_vec())
        }
    }
}

struct SessionCtx {
    remote: SocketAddr,
    framers: HashMap<u64, StreamFramer>,
    /// Bidi stream the session's most recent control message arrived on, so a
    /// response goes back on that stream rather than whichever one the client
    /// happened to open first.
    last_stream: Option<u64>,
    /// Distinguishes this session from an earlier one with the same id, so a
    /// parked request is never re-processed on a session that replaced it.
    seq: u64,
}

/// A control message parked on a credential lookup (`[turn.auth.webhook]`),
/// handed back to the listener when the lookup finishes. The listener passes
/// it to [`QuicBridge::reprocess`].
#[derive(Debug)]
pub struct QuicRetry {
    session_id: String,
    seq: u64,
    stream_id: u64,
    msg: Vec<u8>,
}

/// Bridges `QuicEvent`s into the processor. Tracks per-session remote address
/// (needed as the `src` for `process_slice`) and a separate framer for each stream.
pub struct QuicBridge {
    processor: Arc<PacketProcessor>,
    sessions: HashMap<String, SessionCtx>,
    /// Reverse index of `sessions` (remote address → session id). Every outbound
    /// packet needs this lookup, and scanning the session map for each one was
    /// O(sessions) on the egress hot path.
    by_addr: HashMap<SocketAddr, String>,
    failed_sessions: Vec<String>,
    /// Stream messages waiting on a credential lookup. QUIC streams are
    /// reliable, so the client does not retransmit a request the processor
    /// left unanswered; it is re-processed from here instead. `None` until the
    /// listener opts in with [`with_credential_retry`](Self::with_credential_retry):
    /// without it such a request goes unanswered, as before.
    parked: Option<crate::stream_retry::ParkingLot<u64, QuicRetry>>,
    next_seq: u64,
}

impl QuicBridge {
    pub fn new(processor: Arc<PacketProcessor>) -> Self {
        Self {
            processor,
            sessions: HashMap::new(),
            by_addr: HashMap::new(),
            failed_sessions: Vec::new(),
            parked: None,
            next_seq: 0,
        }
    }

    /// Re-process stream requests parked on credential lookups: they come back
    /// on `retry`, and the listener feeds each to [`reprocess`](Self::reprocess).
    pub fn with_credential_retry(mut self, retry: tokio::sync::mpsc::Sender<QuicRetry>) -> Self {
        self.parked = Some(crate::stream_retry::ParkingLot::new(retry));
        self
    }

    /// Process a stream control message; park it if its credentials are being
    /// looked up. Media (datagrams) never comes here: those clients retransmit.
    fn process_stream_msg(
        &mut self,
        session_id: &str,
        stream_id: u64,
        msg: Vec<u8>,
    ) -> Vec<Action> {
        let Some(ctx) = self.sessions.get(session_id) else {
            return Vec::new();
        };
        let (remote, seq) = (ctx.remote, ctx.seq);
        let keep = self.parked.as_ref().map(|_| msg.clone());
        let mut actions = self.processor.process_owned(msg, remote);
        if let (Some(lot), Some(msg)) = (&self.parked, keep) {
            let mut wait = None;
            actions.retain_mut(|a| match a {
                Action::AwaitCredentials { wait: w } => {
                    wait = Some(w.clone());
                    false
                }
                _ => true,
            });
            if let Some(w) = wait {
                let retry = QuicRetry {
                    session_id: session_id.to_string(),
                    seq,
                    stream_id,
                    msg,
                };
                if !lot.park(w, seq, retry) {
                    tracing::debug!(%remote, "credential-wait slots full; QUIC request dropped");
                }
            }
        }
        actions
    }

    /// Process a request that was parked on a credential lookup, if its session
    /// is still the one it arrived on. The response goes back on the stream the
    /// request came in on.
    pub fn reprocess(&mut self, r: QuicRetry) -> Vec<Action> {
        match self.sessions.get_mut(&r.session_id) {
            Some(ctx) if ctx.seq == r.seq => ctx.last_stream = Some(r.stream_id),
            _ => return Vec::new(),
        }
        self.process_stream_msg(&r.session_id, r.stream_id, r.msg)
    }

    pub fn take_failed_sessions(&mut self) -> Vec<String> {
        std::mem::take(&mut self.failed_sessions)
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
    pub fn migrate(
        &mut self,
        session_id: &str,
        old_addr: SocketAddr,
        new_addr: SocketAddr,
    ) -> bool {
        let Some(ctx) = self.sessions.get_mut(session_id) else {
            return false;
        };
        if ctx.remote != old_addr
            || self
                .by_addr
                .get(&new_addr)
                .is_some_and(|id| id != session_id)
            || self
                .processor
                .migrate_quic_allocation(old_addr, new_addr)
                .is_err()
        {
            return false;
        }
        ctx.remote = new_addr;
        self.by_addr.remove(&old_addr);
        self.by_addr.insert(new_addr, session_id.to_string());
        true
    }

    /// Feed one `QuicEvent`. Returns the `Action`s the caller must deliver back
    /// over the originating session (control on the bidi stream, media as a
    /// datagram — see the module contract).
    pub fn on_event(&mut self, ev: QuicEvent) -> Vec<Action> {
        let processor = self.processor.clone();
        match ev {
            QuicEvent::NewSession(s) => {
                self.by_addr.insert(s.remote_addr, s.session_id.clone());
                self.next_seq += 1;
                self.sessions.insert(
                    s.session_id.clone(),
                    SessionCtx {
                        remote: s.remote_addr,
                        framers: HashMap::new(),
                        last_stream: None,
                        seq: self.next_seq,
                    },
                );
                Vec::new()
            }
            QuicEvent::SessionClosed { session_id, .. } => {
                if let Some(ctx) = self.sessions.remove(&session_id) {
                    if let Some(lot) = &self.parked {
                        lot.forget(ctx.seq);
                    }
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
                let mut msgs = Vec::new();
                if let Some(ctx) = self.sessions.get_mut(&session_id) {
                    // Remember which stream to answer on.
                    ctx.last_stream = Some(stream_id);
                    let framer = ctx.framers.entry(stream_id).or_default();
                    framer.push(&data);
                    while let Some(msg) = framer.next_message() {
                        msgs.push(msg);
                    }
                    if framer.failed {
                        self.failed_sessions.push(session_id.clone());
                    }
                }
                // Owned messages from the framer — see the `Datagram` arm for
                // why `process_slice` must not be used here.
                for msg in msgs {
                    out.extend(self.process_stream_msg(&session_id, stream_id, msg));
                }
                out
            }
            QuicEvent::StreamReadClosed {
                session_id,
                stream_id,
            } => {
                if let Some(ctx) = self.sessions.get_mut(&session_id) {
                    ctx.framers.remove(&stream_id);
                    if ctx.last_stream == Some(stream_id) {
                        ctx.last_stream = None;
                    }
                }
                Vec::new()
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

    fn bridge_fixture() -> (QuicBridge, Arc<turna_session::AllocationStore>, SocketAddr) {
        use turna_auth::{AuthMode, AuthRegistry};
        let store = Arc::new(turna_session::AllocationStore::new(40000, 40100, 100));
        let auth = Arc::new(AuthRegistry::new(AuthMode::SharedSecret {
            realm: "turna".into(),
            secret: std::env::var("TURNA_TEST_NONCE_SECRET")
                .expect("source .env.test.example")
                .into_bytes(),
            previous: None,
        }));
        let processor = Arc::new(PacketProcessor::new(
            store.clone(),
            auth,
            "127.0.0.1".parse().unwrap(),
            Arc::new(turna_health::Metrics::new()),
        ));
        let mut bridge = QuicBridge::new(processor);
        let addr = "127.0.0.1:51000".parse().unwrap();
        bridge.on_event(QuicEvent::NewSession(
            turna_transport::quic::WebTransportSession {
                session_id: "test".into(),
                remote_addr: addr,
                local_addr: "127.0.0.1:3479".parse().unwrap(),
                connection_id: vec![],
                datagrams_available: true,
                alpn: "stun.turn".into(),
                created_at: std::time::Instant::now(),
            },
        ));
        (bridge, store, addr)
    }

    fn binding(id: u8) -> Vec<u8> {
        let mut msg = vec![0; 20];
        msg[1] = 1;
        msg[4..8].copy_from_slice(&0x2112a442u32.to_be_bytes());
        msg[8..20].fill(id);
        msg
    }

    fn chunk(bridge: &mut QuicBridge, stream_id: u64, data: &[u8]) -> Vec<Action> {
        bridge.on_event(QuicEvent::StreamData {
            session_id: "test".into(),
            stream_id,
            data: data.to_vec(),
        })
    }

    fn reply_tid(actions: Vec<Action>) -> Vec<u8> {
        actions
            .into_iter()
            .find_map(|a| match a {
                Action::Send { data, .. } => Some(data[8..20].to_vec()),
                _ => None,
            })
            .expect("Binding response")
    }

    #[test]
    fn interleaved_streams_keep_frames_and_replies_separate() {
        let (mut b, _, _) = bridge_fixture();
        let a = binding(1);
        let c = binding(2);
        assert!(chunk(&mut b, 10, &a[..9]).is_empty());
        assert_eq!(reply_tid(chunk(&mut b, 20, &c)), vec![2; 12]);
        assert_eq!(b.control_stream_for("test"), Some(20));
        assert_eq!(reply_tid(chunk(&mut b, 10, &a[9..])), vec![1; 12]);
        assert_eq!(b.control_stream_for("test"), Some(10));
    }

    #[test]
    fn stream_eof_discards_only_its_own_partial_frame() {
        let (mut b, _, _) = bridge_fixture();
        let msg = binding(3);
        chunk(&mut b, 1, &msg[..8]);
        chunk(&mut b, 2, &msg[..8]);
        b.on_event(QuicEvent::StreamReadClosed {
            session_id: "test".into(),
            stream_id: 1,
        });
        assert!(!b.sessions["test"].framers.contains_key(&1));
        assert_eq!(reply_tid(chunk(&mut b, 2, &msg[8..])), vec![3; 12]);
    }

    #[test]
    fn migration_preserves_allocation_and_bidirectional_relay_indices() {
        let (mut b, store, old) = bridge_fixture();
        let new = "127.0.0.1:52000".parse().unwrap();
        let relay = "127.0.0.1:40000".parse().unwrap();
        let peer: SocketAddr = "8.8.8.8:9000".parse().unwrap();
        store
            .create(old, relay, "test".into(), vec![], 600)
            .unwrap();
        store.add_permission(&old, peer.ip()).unwrap();
        store.add_channel(&old, 0x4000, peer).unwrap();
        let id = store.get(&old).unwrap().allocation_id.clone();
        assert!(b.migrate("test", old, new));
        assert!(store.get(&old).is_none());
        assert_eq!(store.get_by_id(&id), Some(new));
        assert_eq!(store.get_by_relay(&relay), Some(new));
        assert_eq!(store.get_by_channel(40000, 0x4000), Some(new));
        assert_eq!(b.session_for_addr(new).as_deref(), Some("test"));
        let actions = b.on_event(QuicEvent::Datagram {
            session_id: "test".into(),
            data: channel_data(4),
        });
        assert!(actions.iter().any(
            |a| matches!(a, Action::Forward { target, relay_port: 40000, .. } if *target == peer)
        ));
        b.processor.release_for_closed_connection(new);
        assert!(store.get_by_id(&id).is_none());
        assert!(store.get_by_relay(&relay).is_none());
    }

    #[test]
    fn migration_collision_leaves_original_allocation_and_routing() {
        let (mut b, store, old) = bridge_fixture();
        let new = "127.0.0.1:52000".parse().unwrap();
        let relay = "127.0.0.1:40000".parse().unwrap();
        let other = "127.0.0.1:40001".parse().unwrap();
        store
            .create(old, relay, "first".into(), vec![], 600)
            .unwrap();
        store
            .create(new, other, "second".into(), vec![], 600)
            .unwrap();
        assert!(!b.migrate("test", old, new));
        assert_eq!(store.get_by_relay(&relay), Some(old));
        assert_eq!(store.get_by_relay(&other), Some(new));
        assert_eq!(b.session_for_addr(old).as_deref(), Some("test"));
        assert!(b.session_for_addr(new).is_none());
    }

    #[test]
    fn migration_before_allocate_and_stale_event() {
        let (mut b, _, old) = bridge_fixture();
        let new = "127.0.0.1:52000".parse().unwrap();
        assert!(b.migrate("test", old, new));
        assert!(!b.migrate("test", old, new));
        assert_eq!(b.session_for_addr(new).as_deref(), Some("test"));
    }

    fn stun_msg(body_len: usize) -> Vec<u8> {
        let mut m = vec![0u8; 20 + body_len];
        m[0] = 0x00; // top two bits 00 → STUN
        m[4..8].copy_from_slice(&0x2112a442u32.to_be_bytes());
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
    fn oversized_stream_is_terminal() {
        // After a reset the framer must still parse a fresh, well-formed message.
        let mut f = StreamFramer::default();
        f.push(&vec![0u8; MAX_FRAMER_BUFFER + 1]);
        let good = stun_msg(0);
        f.push(&good);
        assert_eq!(f.next_message(), None);
        assert!(f.failed);
    }

    #[test]
    fn garbage_stream_is_terminal() {
        let good = stun_msg(0);
        let mut wire = vec![0xFFu8]; // not STUN, not ChannelData
        wire.extend_from_slice(&good);
        let mut f = StreamFramer::default();
        f.push(&wire);
        assert_eq!(f.next_message(), None);
        assert!(f.failed);
    }
}

/// `[turn.auth.webhook]` over QUIC streams: a request whose USERNAME is being
/// looked up is parked and re-processed, because the client will not
/// retransmit on a reliable stream; a session that closes meanwhile gets
/// nothing.
#[cfg(test)]
mod credential_retry_tests {
    use super::*;
    use std::time::Duration;
    use turna_auth::webhook::{CredentialCache, FetchOutcome, WebhookSettings};
    use turna_proto_stun::attribute::Attribute;
    use turna_proto_stun::header::MessageClass;
    use turna_proto_stun::message::StunMessage;
    use turna_proto_stun::method::Method;

    fn password() -> String {
        turna_crypto::random_key_32()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    struct Fixture {
        bridge: QuicBridge,
        cache: Arc<CredentialCache>,
        _jobs: tokio::sync::mpsc::Receiver<turna_auth::webhook::FetchJob>,
        retry: tokio::sync::mpsc::Receiver<QuicRetry>,
    }

    fn fixture() -> Fixture {
        let (cache, jobs) = CredentialCache::new(
            "q",
            WebhookSettings {
                positive_ttl: Duration::from_secs(60),
                negative_ttl: Duration::from_secs(60),
                error_ttl: Duration::from_secs(60),
                max_entries: 16,
                queue_depth: 16,
            },
        );
        let mode = turna_auth::AuthMode::long_term("q", [("local", password())])
            .with_webhook(cache.clone());
        let processor = Arc::new(PacketProcessor::new(
            Arc::new(turna_session::AllocationStore::new(41000, 41100, 16)),
            Arc::new(turna_auth::AuthRegistry::new(mode)),
            "127.0.0.1".parse().unwrap(),
            Arc::new(turna_health::Metrics::new()),
        ));
        let (tx, retry) = tokio::sync::mpsc::channel(16);
        let mut bridge = QuicBridge::new(processor).with_credential_retry(tx);
        bridge.on_event(QuicEvent::NewSession(
            turna_transport::quic::WebTransportSession {
                session_id: "s".into(),
                remote_addr: "127.0.0.1:51500".parse().unwrap(),
                local_addr: "127.0.0.1:3479".parse().unwrap(),
                connection_id: vec![],
                datagrams_available: true,
                alpn: "stun.turn".into(),
                created_at: std::time::Instant::now(),
            },
        ));
        Fixture {
            bridge,
            cache,
            _jobs: jobs,
            retry,
        }
    }

    fn send(b: &mut QuicBridge, msg: &[u8]) -> Vec<Action> {
        b.on_event(QuicEvent::StreamData {
            session_id: "s".into(),
            stream_id: 4,
            data: msg.to_vec(),
        })
    }

    fn reply(actions: &[Action]) -> Option<StunMessage> {
        actions.iter().find_map(|a| match a {
            Action::Send { data, .. } => StunMessage::decode(data).ok(),
            _ => None,
        })
    }

    /// Challenge, then an Allocate for `user` signed with `pass`.
    fn allocate(b: &mut QuicBridge, user: &str, pass: &str) -> Vec<u8> {
        let mut probe = StunMessage::new(Method::Allocate, MessageClass::Request);
        probe.add(Attribute::RequestedTransport(17));
        let mut buf = [0u8; 256];
        let n = probe.encode(&mut buf).unwrap();
        let challenge = reply(&send(b, &buf[..n])).expect("401");
        let nonce = challenge.get_nonce().unwrap().to_string();
        let mut m = StunMessage::new(Method::Allocate, MessageClass::Request);
        m.add(Attribute::RequestedTransport(17));
        m.add(Attribute::Username(user.into()));
        m.add(Attribute::Realm("q".into()));
        m.add(Attribute::Nonce(nonce));
        let key = turna_crypto::long_term_key(user, "q", pass);
        let mut buf = [0u8; 512];
        let n = m.encode_with_integrity(&mut buf, &key).unwrap();
        buf[..n].to_vec()
    }

    #[tokio::test]
    async fn parked_stream_request_is_answered_after_the_lookup() {
        let mut f = fixture();
        let pw = password();
        let req = allocate(&mut f.bridge, "remote", &pw);
        let first = send(&mut f.bridge, &req);
        assert!(reply(&first).is_none(), "nothing answered while pending");
        assert!(
            !first
                .iter()
                .any(|a| matches!(a, Action::AwaitCredentials { .. })),
            "the bridge keeps the wait to itself"
        );
        f.cache.complete(
            "remote",
            FetchOutcome::Found {
                keys: turna_auth::UserKeys::derive("remote", "q", &pw),
                ttl: None,
            },
        );
        let r = tokio::time::timeout(Duration::from_secs(2), f.retry.recv())
            .await
            .expect("re-injected")
            .unwrap();
        let answer = reply(&f.bridge.reprocess(r)).expect("answered");
        assert!(matches!(answer.class, MessageClass::SuccessResponse));
        assert_eq!(f.bridge.control_stream_for("s"), Some(4));
    }

    #[tokio::test]
    async fn a_closed_session_gets_nothing() {
        let mut f = fixture();
        let req = allocate(&mut f.bridge, "remote", &password());
        let _ = send(&mut f.bridge, &req);
        f.bridge.on_event(QuicEvent::SessionClosed {
            session_id: "s".into(),
            reason: "gone".into(),
        });
        f.cache.complete("remote", FetchOutcome::NotFound);
        assert!(
            tokio::time::timeout(Duration::from_millis(200), f.retry.recv())
                .await
                .is_err(),
            "no re-injection for a closed session"
        );
    }
}
