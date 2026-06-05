//! RTP stream quality analyzer.
//!
//! Inspects RTP headers on forwarded packets to compute:
//! - Packet loss (gaps in sequence numbers)
//! - Jitter (variation in inter-arrival time)
//! - Bitrate (bytes per second)
//!
//! Thread-safe: uses DashMap for per-stream state.

use dashmap::DashMap;
use std::net::SocketAddr;
use std::time::Instant;
use turna_proto_rtp::RtpHeader;

/// Per-stream (SSRC) quality state.
struct StreamState {
    ssrc: u32,
    /// Owner (client address).
    client: SocketAddr,
    /// Whether this is audio or video.
    is_audio: bool,
    /// Last seen sequence number.
    last_seq: u16,
    /// Total packets received.
    packets_received: u64,
    /// Total packets expected (based on seq gaps).
    packets_expected: u64,
    /// Total packets lost.
    packets_lost: u64,
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
            packets_received: 0,
            packets_expected: 0,
            packets_lost: 0,
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
            self.last_seq = header.sequence_number;
            self.last_rtp_ts = header.timestamp;
            self.last_arrival = now;
            self.first_packet = false;
            self.packets_expected = 1;
            return;
        }

        // Packet loss detection
        let expected_seq = self.last_seq.wrapping_add(1);
        let seq_diff = header.sequence_number.wrapping_sub(expected_seq);

        if seq_diff == 0 {
            // In order
            self.packets_expected += 1;
        } else if seq_diff < 0x8000 {
            // Forward gap: seq_diff packets missing
            let lost = seq_diff as u64;
            self.packets_lost += lost;
            self.packets_expected += 1 + lost;
        } else {
            // Out of order (arrived late) — don't count as loss
            self.packets_expected += 1;
        }

        // Jitter calculation (RFC 3550 A.8)
        // Clock rate: 48000 for Opus audio, 90000 for video
        let clock_rate: f64 = if self.is_audio { 48000.0 } else { 90000.0 };
        let transit_diff = {
            let arrival_diff_us = now.duration_since(self.last_arrival).as_micros() as f64;
            let rtp_diff = header.timestamp.wrapping_sub(self.last_rtp_ts) as f64;
            let rtp_diff_us = (rtp_diff / clock_rate) * 1_000_000.0;
            (arrival_diff_us - rtp_diff_us).abs()
        };
        self.jitter_us += (transit_diff - self.jitter_us) / 16.0;

        self.last_seq = header.sequence_number;
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

/// Snapshot of a stream's quality metrics.
#[derive(Debug, Clone)]
pub struct StreamQuality {
    pub ssrc: u32,
    pub client: SocketAddr,
    pub is_audio: bool,
    pub packets_received: u64,
    pub packets_lost: u64,
    pub loss_percent: f64,
    pub jitter_ms: f64,
    pub bitrate_bps: u64,
}

/// RTP quality analyzer — thread-safe, one per relay server.
pub struct RtpAnalyzer {
    streams: DashMap<u32, StreamState>,
}

impl RtpAnalyzer {
    pub fn new() -> Self {
        Self {
            streams: DashMap::new(),
        }
    }

    /// Analyze an RTP packet payload. Call on every forwarded packet.
    /// Returns true if analysis succeeded (valid RTP).
    pub fn analyze(&self, data: &[u8], client: SocketAddr) -> bool {
        let header = match RtpHeader::parse(data) {
            Ok(h) => h,
            Err(_) => return false,
        };

        let is_audio = header.is_audio();
        let packet_size = data.len();

        self.streams
            .entry(header.ssrc)
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
                    loss_percent: s.loss_percent(),
                    jitter_ms: s.jitter_ms(),
                    bitrate_bps: s.bitrate_bps,
                }
            })
            .collect()
    }

    /// Get aggregate quality stats.
    pub fn aggregate(&self) -> AggregateQuality {
        let streams = self.get_all_quality();
        if streams.is_empty() {
            return AggregateQuality::default();
        }

        let total_streams = streams.len() as u64;
        let audio_streams = streams.iter().filter(|s| s.is_audio).count() as u64;
        let video_streams = total_streams - audio_streams;

        let avg_loss = streams.iter().map(|s| s.loss_percent).sum::<f64>() / total_streams as f64;
        let max_loss = streams.iter().map(|s| s.loss_percent).fold(0.0f64, f64::max);
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

    /// Remove stale streams (no packets for > 30s).
    pub fn cleanup_stale(&self) -> usize {
        let cutoff = Instant::now() - std::time::Duration::from_secs(30);
        let stale: Vec<u32> = self.streams
            .iter()
            .filter(|e| e.value().last_arrival < cutoff)
            .map(|e| *e.key())
            .collect();
        let count = stale.len();
        for ssrc in stale {
            self.streams.remove(&ssrc);
        }
        count
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

impl Default for RtpAnalyzer {
    fn default() -> Self { Self::new() }
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
