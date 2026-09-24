//! RTP stream quality analyzer.
//!
//! Inspects RTP headers on forwarded packets to compute:
//! - Packet loss (gaps in sequence numbers, credited back when a late packet
//!   fills the gap)
//! - Out-of-order arrivals (a sequence number below the highest seen)
//! - Jitter (RFC 3550 §6.4.1 interarrival jitter)
//! - Bitrate (bytes per second)
//!
//! Thread-safe: uses DashMap for per-stream state.
//!
//! # What it can and cannot see
//!
//! Only the RTP header, which SRTP leaves in the clear — so this works on
//! encrypted media. It cannot see SDP, so the RTP clock rate is *guessed* from
//! the payload type: 48 kHz for PT 0/8/111 (treated as audio), 90 kHz otherwise.
//! PCMU/PCMA really run at 8 kHz, so their jitter reads 6x too low. Jitter is
//! therefore a trend to watch, not an absolute to compare with a client's
//! `getStats()`. Loss and ordering do not depend on the clock rate.
//!
//! Streams are keyed by `(SSRC, direction)`. RTCP multiplexed on the same port
//! (RFC 5761) is skipped: its packet types land in RTP PT 64..=95, which RTP
//! must not use.
//!
//! # Hairpinned media
//!
//! When both endpoints of a call are clients of this server, each packet
//! crosses it twice: client→peer on the sender's allocation, then peer→client on
//! the receiver's. Keying by direction makes those two observations two streams,
//! one per leg, each measured correctly. Keyed by SSRC alone they were one
//! stream fed every packet twice, 0 µs apart — which read as a duplicate per
//! packet and pulled jitter toward zero. The cost is that hairpinned media is
//! *counted* once per leg in the packet counters. That is the same thing the
//! relay's own byte counters do (it relays those bytes twice) and is the
//! documented behaviour, not an accident; the per-leg loss figures are exact.
//!
//! # Sequence handling (RFC 3550 A.1)
//!
//! A jump of `MAX_DROPOUT` or more ahead, or more than `MAX_MISORDER` behind,
//! is not believed on its own: the packet is set aside and the stream resyncs
//! only if the *next* packet follows it in sequence (a sender restart or SSRC
//! reuse). A late packet within `MAX_MISORDER` credits back loss only if it was
//! really missing — a bitmap of the last 128 sequence numbers tells a late
//! arrival from a duplicate of an old packet.
//!
//! # One analyzer per worker
//!
//! Every `PacketProcessor` gets its own analyzer through [`RtpAnalyzer::registered`]
//! (per io_uring worker, per datapath), so the per-packet map update never
//! contends across workers. The node's periodic publisher samples all of them
//! through [`RtpAnalyzer::for_each_registered`]. A stream's packets stay on one
//! worker: a client's 5-tuple hashes to one SO_REUSEPORT worker, and a relay
//! socket belongs to one worker.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Instant;
use turna_proto_rtp::RtpHeader;

/// Which leg of the relay a packet was observed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// From a TURN client, towards its peer.
    ClientToPeer,
    /// From a peer, towards the TURN client.
    PeerToClient,
}

/// RFC 3550 A.1 `MAX_MISORDER`: how far behind the highest sequence a packet
/// may be and still be a late arrival rather than a restart.
const MAX_MISORDER: u16 = 100;

/// Per-stream (SSRC, direction) quality state.
struct StreamState {
    ssrc: u32,
    /// Owner (client address).
    client: SocketAddr,
    /// Whether this is audio or video.
    is_audio: bool,
    /// Highest sequence number seen (RFC 3550 `max_seq`).
    last_seq: u16,
    /// Bit k set = sequence `last_seq - k` has been received (k < 128).
    seen: u128,
    /// RFC 3550 `bad_seq`: after an unbelievable jump, the sequence number the
    /// next packet must carry for the stream to resync onto it.
    bad_seq: Option<u16>,
    /// Total packets received.
    packets_received: u64,
    /// Total packets expected (based on seq gaps).
    packets_expected: u64,
    /// Total packets lost: forward gaps, minus late arrivals that filled one.
    packets_lost: u64,
    /// Packets that arrived with a sequence number below the highest seen
    /// (late, i.e. reordered in transit). Duplicates of the latest packet are
    /// not counted here.
    packets_out_of_order: u64,
    /// Counter values at the last [`RtpAnalyzer::sample`], for interval deltas.
    sampled_received: u64,
    sampled_expected: u64,
    sampled_lost: u64,
    sampled_out_of_order: u64,
    /// Jitter estimate (RFC 3550 algorithm), in microseconds.
    jitter_us: f64,
    /// Last packet arrival time.
    last_arrival: Instant,
    /// Last RTP timestamp.
    last_rtp_ts: u32,
    /// Total bytes received.
    bytes_total: u64,
    /// Window start for bitrate calculation.
    window_start: Instant,
    /// Bytes in current window.
    window_bytes: u64,
    /// Current bitrate in bps.
    bitrate_bps: u64,
    /// First packet flag.
    first_packet: bool,
}

impl StreamState {
    fn new(ssrc: u32, client: SocketAddr, is_audio: bool) -> Self {
        let now = Instant::now();
        Self {
            ssrc,
            client,
            is_audio,
            last_seq: 0,
            seen: 0,
            bad_seq: None,
            packets_received: 0,
            packets_expected: 0,
            packets_lost: 0,
            packets_out_of_order: 0,
            sampled_received: 0,
            sampled_expected: 0,
            sampled_lost: 0,
            sampled_out_of_order: 0,
            jitter_us: 0.0,
            last_arrival: now,
            last_rtp_ts: 0,
            bytes_total: 0,
            window_start: now,
            window_bytes: 0,
            bitrate_bps: 0,
            first_packet: true,
        }
    }

    fn update(&mut self, header: &RtpHeader, packet_size: usize) {
        let now = Instant::now();
        self.packets_received += 1;
        self.bytes_total += packet_size as u64;
        self.window_bytes += packet_size as u64;

        if self.first_packet {
            self.init_seq(header.sequence_number);
            self.last_rtp_ts = header.timestamp;
            self.last_arrival = now;
            self.first_packet = false;
            self.packets_expected = 1;
            return;
        }

        // RFC 3550 A.1 update_seq, with a seen-bitmap for late arrivals.
        let seq = header.sequence_number;
        let udelta = seq.wrapping_sub(self.last_seq);
        if udelta == 0 {
            // Duplicate of the latest packet: neither loss nor reordering, and
            // no new jitter sample.
            return;
        } else if udelta < MAX_DROPOUT {
            // Ahead, with a permissible gap: udelta - 1 packets missing for now
            // (a late arrival below credits one back).
            let lost = (udelta - 1) as u64;
            self.packets_lost += lost;
            self.packets_expected += udelta as u64;
            self.seen = if udelta >= 128 {
                0
            } else {
                self.seen << udelta
            };
            self.seen |= 1;
            self.last_seq = seq;
            self.bad_seq = None;
        } else if udelta <= u16::MAX - MAX_MISORDER {
            // A jump too large to believe from one packet: a restart, SSRC
            // reuse, or garbage. Resync only when the next packet follows it.
            if self.bad_seq == Some(seq) {
                // Two in sequence on the new numbering: accept it. Both
                // packets are received, none is lost.
                self.init_seq(seq);
                self.packets_expected += 2;
                // New timestamp space too: re-anchor jitter rather than feed
                // it the difference between two unrelated clocks.
                self.last_rtp_ts = header.timestamp;
                self.last_arrival = now;
                return;
            } else {
                self.bad_seq = Some(seq.wrapping_add(1));
                return;
            }
        } else {
            // Up to MAX_MISORDER behind the highest: late, or a duplicate of
            // an old packet.
            let back = self.last_seq.wrapping_sub(seq) as u32;
            let bit = 1u128 << back.min(127);
            if back < 128 && self.seen & bit != 0 {
                // Already received: a duplicate. No loss credit, no reorder.
                return;
            }
            if back < 128 {
                self.seen |= bit;
            }
            self.packets_out_of_order += 1;
            // It was counted lost when the gap it belongs to was seen, so
            // credit it back. `last_seq` stays at the highest sequence seen:
            // moving it backwards would make the next in-order packet look like
            // a fresh gap and count the same loss twice.
            self.packets_lost = self.packets_lost.saturating_sub(1);
        }

        // Jitter calculation (RFC 3550 A.8)
        // Clock rate: 48000 for Opus audio, 90000 for video
        let clock_rate: f64 = if self.is_audio { 48000.0 } else { 90000.0 };
        let transit_diff = {
            let arrival_diff_us = now.duration_since(self.last_arrival).as_micros() as f64;
            // Signed: a reordered packet carries an earlier timestamp, and an
            // unsigned difference would wrap to ~2^32 ticks and spike the
            // estimate by hours.
            let rtp_diff = header.timestamp.wrapping_sub(self.last_rtp_ts) as i32 as f64;
            let rtp_diff_us = (rtp_diff / clock_rate) * 1_000_000.0;
            (arrival_diff_us - rtp_diff_us).abs()
        };
        self.jitter_us += (transit_diff - self.jitter_us) / 16.0;

        self.last_rtp_ts = header.timestamp;
        self.last_arrival = now;

        // Bitrate: recalculate every second
        let window_elapsed = now.duration_since(self.window_start).as_secs_f64();
        if window_elapsed >= 1.0 {
            self.bitrate_bps = (self.window_bytes as f64 * 8.0 / window_elapsed) as u64;
            self.window_bytes = 0;
            self.window_start = now;
        }
    }

    /// Start counting sequence numbers from `seq` (first packet, or resync).
    fn init_seq(&mut self, seq: u16) {
        self.last_seq = seq;
        self.seen = 1;
        self.bad_seq = None;
    }

    fn loss_percent(&self) -> f64 {
        if self.packets_expected == 0 {
            return 0.0;
        }
        (self.packets_lost as f64 / self.packets_expected as f64) * 100.0
    }

    fn jitter_ms(&self) -> f64 {
        self.jitter_us / 1000.0
    }
}

/// RFC 3550 A.1 `MAX_DROPOUT`: a forward jump at least this large is a
/// resynchronisation, not loss.
const MAX_DROPOUT: u16 = 3000;

/// RTP payload types 64..=95 collide with RTCP packet types (RFC 5761 §4) and
/// are never used for RTP; seeing one means the packet is RTCP.
fn is_rtcp_range(payload_type: u8) -> bool {
    (64..=95).contains(&payload_type)
}

/// One stream's figures for the interval since the previous
/// [`RtpAnalyzer::sample`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct StreamSample {
    pub is_audio: bool,
    /// Sequence numbers the interval spanned.
    pub interval_expected: u64,
    /// Of those, still missing at sample time.
    pub interval_lost: u64,
    /// Current RFC 3550 jitter estimate, ms (see the module docs on clock rate).
    pub jitter_ms: f64,
}

/// Everything [`RtpAnalyzer::sample`] measured since its previous call. The
/// totals are non-negative deltas, suitable for adding to Prometheus counters.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SampleReport {
    pub streams: Vec<StreamSample>,
    pub received: u64,
    pub expected: u64,
    /// Loss is credited back when a late packet arrives; a credit that lands
    /// after the sample which counted the loss cannot be subtracted from a
    /// counter, so such packets stay counted as lost. Late by more than a
    /// sampling interval is lost for any real-time purpose anyway.
    pub lost: u64,
    pub out_of_order: u64,
}

/// Snapshot of a stream's quality metrics.
#[derive(Debug, Clone)]
pub struct StreamQuality {
    pub ssrc: u32,
    pub client: SocketAddr,
    pub is_audio: bool,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub packets_out_of_order: u64,
    pub loss_percent: f64,
    pub jitter_ms: f64,
    pub bitrate_bps: u64,
}

/// RTP quality analyzer — thread-safe, one per relay server.
pub struct RtpAnalyzer {
    streams: DashMap<(u32, Direction), StreamState>,
}

/// Analyzers handed out by [`RtpAnalyzer::registered`]. Weak, so a dropped
/// processor's analyzer goes away with it; dead entries are pruned when the
/// registry is walked.
fn registry() -> &'static Mutex<Vec<Weak<RtpAnalyzer>>> {
    static REG: OnceLock<Mutex<Vec<Weak<RtpAnalyzer>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(Vec::new()))
}

impl RtpAnalyzer {
    pub fn new() -> Self {
        Self {
            streams: DashMap::new(),
        }
    }

    /// A new analyzer, registered for [`Self::for_each_registered`].
    ///
    /// One per `PacketProcessor`, so each io_uring worker updates its own map
    /// and the per-packet shard lock never contends across workers. (A single
    /// process-wide map did: every packet on every worker took a write lock in
    /// one shared DashMap.)
    pub fn registered() -> Arc<RtpAnalyzer> {
        let a = Arc::new(RtpAnalyzer::new());
        let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
        reg.retain(|w| w.strong_count() > 0);
        reg.push(Arc::downgrade(&a));
        a
    }

    /// Every live registered analyzer. The registry lock is held only to copy
    /// the list; sampling happens after, one analyzer at a time.
    pub fn all_registered() -> Vec<Arc<RtpAnalyzer>> {
        let mut reg = registry().lock().unwrap_or_else(|p| p.into_inner());
        reg.retain(|w| w.strong_count() > 0);
        reg.iter().filter_map(Weak::upgrade).collect()
    }

    /// Per-stream interval figures and totals since the previous call, and
    /// move every stream's marks forward. Meant for one periodic caller.
    pub fn sample(&self) -> SampleReport {
        let mut report = SampleReport::default();
        for mut e in self.streams.iter_mut() {
            let s = e.value_mut();
            let received = s.packets_received - s.sampled_received;
            let expected = s.packets_expected - s.sampled_expected;
            let lost = s.packets_lost.saturating_sub(s.sampled_lost);
            let ooo = s.packets_out_of_order - s.sampled_out_of_order;
            s.sampled_received = s.packets_received;
            s.sampled_expected = s.packets_expected;
            s.sampled_lost = s.packets_lost;
            s.sampled_out_of_order = s.packets_out_of_order;
            report.received += received;
            report.expected += expected;
            report.lost += lost;
            report.out_of_order += ooo;
            report.streams.push(StreamSample {
                is_audio: s.is_audio,
                interval_expected: expected,
                interval_lost: lost.min(expected),
                jitter_ms: s.jitter_ms(),
            });
        }
        report
    }

    /// Analyze an RTP packet payload. Call on every forwarded packet.
    /// Returns true if analysis succeeded (valid RTP).
    pub fn analyze(&self, data: &[u8], client: SocketAddr, dir: Direction) -> bool {
        let header = match RtpHeader::parse(data) {
            Ok(h) => h,
            Err(_) => return false,
        };
        if is_rtcp_range(header.payload_type) {
            return false;
        }

        let is_audio = header.is_audio();
        let packet_size = data.len();

        self.streams
            .entry((header.ssrc, dir))
            .or_insert_with(|| StreamState::new(header.ssrc, client, is_audio))
            .update(&header, packet_size);

        true
    }

    /// Get quality snapshot for all active streams.
    pub fn get_all_quality(&self) -> Vec<StreamQuality> {
        self.streams
            .iter()
            .map(|entry| {
                let s = entry.value();
                StreamQuality {
                    ssrc: s.ssrc,
                    client: s.client,
                    is_audio: s.is_audio,
                    packets_received: s.packets_received,
                    packets_lost: s.packets_lost,
                    packets_out_of_order: s.packets_out_of_order,
                    loss_percent: s.loss_percent(),
                    jitter_ms: s.jitter_ms(),
                    bitrate_bps: s.bitrate_bps,
                }
            })
            .collect()
    }

    /// Get aggregate quality stats.
    pub fn aggregate(&self) -> AggregateQuality {
        AggregateQuality::from_streams(&self.get_all_quality())
    }

    /// Remove stale streams (no packets for > 30s).
    pub fn cleanup_stale(&self) -> usize {
        let cutoff = Instant::now() - std::time::Duration::from_secs(30);
        let stale: Vec<(u32, Direction)> = self
            .streams
            .iter()
            .filter(|e| e.value().last_arrival < cutoff)
            .map(|e| *e.key())
            .collect();
        let count = stale.len();
        for key in stale {
            self.streams.remove(&key);
        }
        count
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

impl AggregateQuality {
    /// Aggregate over streams from any number of analyzers.
    pub fn from_streams(streams: &[StreamQuality]) -> Self {
        if streams.is_empty() {
            return AggregateQuality::default();
        }

        let total_streams = streams.len() as u64;
        let audio_streams = streams.iter().filter(|s| s.is_audio).count() as u64;
        let video_streams = total_streams - audio_streams;

        let avg_loss = streams.iter().map(|s| s.loss_percent).sum::<f64>() / total_streams as f64;
        let max_loss = streams
            .iter()
            .map(|s| s.loss_percent)
            .fold(0.0f64, f64::max);
        let avg_jitter = streams.iter().map(|s| s.jitter_ms).sum::<f64>() / total_streams as f64;
        let max_jitter = streams.iter().map(|s| s.jitter_ms).fold(0.0f64, f64::max);
        let total_bitrate: u64 = streams.iter().map(|s| s.bitrate_bps).sum();

        AggregateQuality {
            total_streams,
            audio_streams,
            video_streams,
            avg_loss_percent: avg_loss,
            max_loss_percent: max_loss,
            avg_jitter_ms: avg_jitter,
            max_jitter_ms: max_jitter,
            total_bitrate_bps: total_bitrate,
        }
    }
}

impl Default for RtpAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Aggregate quality across all streams.
#[derive(Debug, Clone, Default)]
pub struct AggregateQuality {
    pub total_streams: u64,
    pub audio_streams: u64,
    pub video_streams: u64,
    pub avg_loss_percent: f64,
    pub max_loss_percent: f64,
    pub avg_jitter_ms: f64,
    pub max_jitter_ms: f64,
    pub total_bitrate_bps: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const PT_OPUS: u8 = 111;
    const PT_VP8: u8 = 96;

    fn pkt(pt: u8, seq: u16, ts: u32, ssrc: u32) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0] = 0x80;
        b[1] = pt;
        b[2..4].copy_from_slice(&seq.to_be_bytes());
        b[4..8].copy_from_slice(&ts.to_be_bytes());
        b[8..12].copy_from_slice(&ssrc.to_be_bytes());
        b
    }

    fn client() -> SocketAddr {
        "192.0.2.1:5000".parse().unwrap()
    }

    fn feed(a: &RtpAnalyzer, seqs: &[u16], ssrc: u32) {
        for &s in seqs {
            assert!(a.analyze(
                &pkt(PT_OPUS, s, s as u32 * 960, ssrc),
                client(),
                Direction::ClientToPeer
            ));
        }
    }

    #[test]
    fn in_order_stream_has_no_loss_or_reordering() {
        let a = RtpAnalyzer::new();
        feed(&a, &(1..=50).collect::<Vec<_>>(), 1);
        let q = &a.get_all_quality()[0];
        assert_eq!(q.packets_received, 50);
        assert_eq!(q.packets_lost, 0);
        assert_eq!(q.packets_out_of_order, 0);
        assert_eq!(q.loss_percent, 0.0);
    }

    #[test]
    fn a_gap_is_loss() {
        let a = RtpAnalyzer::new();
        feed(&a, &[1, 2, 3, 6, 7], 2); // 4 and 5 missing
        let q = &a.get_all_quality()[0];
        assert_eq!(q.packets_lost, 2);
        assert!((q.loss_percent - 2.0 / 7.0 * 100.0).abs() < 1e-9);
    }

    /// The case the old code got wrong twice: it counted the late packet's gap
    /// as loss, then moved `last_seq` backwards and counted the next packet as
    /// a second gap.
    #[test]
    fn reordering_is_not_loss() {
        let a = RtpAnalyzer::new();
        feed(&a, &[1, 2, 4, 3, 5, 6], 3);
        let q = &a.get_all_quality()[0];
        assert_eq!(q.packets_lost, 0, "3 arrived late, nothing was lost");
        assert_eq!(q.packets_out_of_order, 1);
        assert_eq!(q.packets_received, 6);
    }

    #[test]
    fn duplicates_are_neither_loss_nor_reordering() {
        let a = RtpAnalyzer::new();
        feed(&a, &[1, 2, 2, 3], 4);
        let q = &a.get_all_quality()[0];
        assert_eq!(q.packets_lost, 0);
        assert_eq!(q.packets_out_of_order, 0);
    }

    #[test]
    fn sequence_wrap_is_in_order() {
        let a = RtpAnalyzer::new();
        feed(&a, &[65534, 65535, 0, 1], 5);
        let q = &a.get_all_quality()[0];
        assert_eq!(q.packets_lost, 0);
        assert_eq!(q.packets_out_of_order, 0);
    }

    #[test]
    fn a_huge_jump_is_a_resync_not_loss() {
        let a = RtpAnalyzer::new();
        feed(&a, &[1, 2, 20_000, 20_001], 6);
        assert_eq!(a.get_all_quality()[0].packets_lost, 0);
    }

    #[test]
    fn rtcp_is_not_analysed() {
        let a = RtpAnalyzer::new();
        // RTCP SR: byte 1 = 200 → PT field 72.
        let mut sr = pkt(0, 0, 0, 7);
        sr[1] = 200;
        assert!(!a.analyze(&sr, client(), Direction::ClientToPeer));
        assert_eq!(a.stream_count(), 0);
    }

    /// A reordered packet carries an earlier RTP timestamp. Unsigned, the
    /// difference wrapped to ~2^32 ticks and the jitter estimate jumped by
    /// hours from one packet.
    #[test]
    fn reordering_does_not_explode_jitter() {
        let a = RtpAnalyzer::new();
        for s in [1u16, 2, 4, 3, 5] {
            a.analyze(
                &pkt(PT_VP8, s, s as u32 * 3000, 8),
                client(),
                Direction::ClientToPeer,
            );
        }
        let j = a.get_all_quality()[0].jitter_ms;
        assert!(j < 1_000.0, "jitter {j} ms after one reordered packet");
    }

    #[test]
    fn sample_reports_interval_deltas_and_moves_the_marks() {
        let a = RtpAnalyzer::new();
        feed(&a, &[1, 2, 5], 9); // 3, 4 lost
        let r = a.sample();
        assert_eq!(r.received, 3);
        assert_eq!(r.expected, 5);
        assert_eq!(r.lost, 2);
        assert_eq!(r.streams.len(), 1);
        assert_eq!(r.streams[0].interval_expected, 5);
        assert_eq!(r.streams[0].interval_lost, 2);
        assert!(r.streams[0].is_audio);

        // 4 arrives late: out-of-order, loss credited within the stream, but
        // the delta cannot go negative.
        feed(&a, &[4, 6], 9);
        let r = a.sample();
        assert_eq!(r.received, 2);
        assert_eq!(r.expected, 1);
        assert_eq!(r.lost, 0);
        assert_eq!(r.out_of_order, 1);

        // Nothing new: all zero.
        let r = a.sample();
        assert_eq!(
            (r.received, r.expected, r.lost, r.out_of_order),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn registered_analyzers_are_listed_until_dropped() {
        let a = RtpAnalyzer::registered();
        let b = RtpAnalyzer::registered();
        let all = RtpAnalyzer::all_registered();
        assert!(all.iter().any(|x| Arc::ptr_eq(x, &a)));
        assert!(all.iter().any(|x| Arc::ptr_eq(x, &b)));
        drop(all);
        let b_ptr = Arc::as_ptr(&b);
        drop(b);
        assert!(!RtpAnalyzer::all_registered()
            .iter()
            .any(|x| Arc::as_ptr(x) == b_ptr));
    }

    /// RFC 3550 A.1: a sender restart that jumps *backwards* resyncs after two
    /// packets in sequence, with no loss and no reordering counted.
    #[test]
    fn backward_restart_resyncs_after_two_in_sequence() {
        let a = RtpAnalyzer::new();
        feed(&a, &[1000, 1001, 1002, 5, 6, 7, 8], 11);
        let q = &a.get_all_quality()[0];
        assert_eq!(q.packets_lost, 0);
        assert_eq!(q.packets_out_of_order, 0);
        // And the new numbering is tracked: a gap after resync is loss.
        feed(&a, &[10], 11);
        assert_eq!(a.get_all_quality()[0].packets_lost, 1);
    }

    /// One stray packet far away is not believed: the stream carries on.
    #[test]
    fn a_single_stray_jump_is_ignored() {
        let a = RtpAnalyzer::new();
        feed(&a, &[1, 2, 3, 40_000, 4, 5], 12);
        let q = &a.get_all_quality()[0];
        assert_eq!(q.packets_lost, 0);
        assert_eq!(q.packets_out_of_order, 0);
    }

    /// A duplicate of an old (already received) packet must not credit loss
    /// back: only a packet that was really missing does.
    #[test]
    fn duplicate_of_an_old_packet_does_not_credit_loss() {
        let a = RtpAnalyzer::new();
        feed(&a, &[1, 2, 5, 3, 3, 2, 6], 13); // 3,4 missing; 3 late; then dups
        let q = &a.get_all_quality()[0];
        assert_eq!(q.packets_lost, 1, "only 4 is still missing");
        assert_eq!(q.packets_out_of_order, 1, "one late packet, the rest dups");
    }

    /// The two legs of a hairpinned call are separate streams.
    #[test]
    fn directions_are_separate_streams() {
        let a = RtpAnalyzer::new();
        for s in 1..=5u16 {
            let p = pkt(PT_OPUS, s, s as u32 * 960, 14);
            a.analyze(&p, client(), Direction::ClientToPeer);
            a.analyze(&p, client(), Direction::PeerToClient);
        }
        let qs = a.get_all_quality();
        assert_eq!(qs.len(), 2);
        assert!(qs
            .iter()
            .all(|q| q.packets_received == 5 && q.packets_lost == 0));
    }
}
