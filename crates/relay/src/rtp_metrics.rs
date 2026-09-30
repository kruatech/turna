//! Publish the RTP analyzer's measurements into the metrics registry.
//!
//! One caller, on a fixed interval: the node spawns it once, whichever datapath
//! is running. It used to live in `RelayServer::run`'s maintenance loop, which
//! only the tokio datapath runs — so on io_uring and AF_XDP the RTP gauges read
//! zero while media flowed. Each processor (each io_uring worker) has its own
//! analyzer; this samples every registered one, one after another, so no lock
//! is held across workers.
//!
//! Every number here is one the analyzer computes from RTP headers
//! (`turna_rtp_analyzer`): sequence gaps, late arrivals, RFC 3550 jitter.
//! Nothing is estimated beyond what its module docs describe.

use std::sync::atomic::Ordering::Relaxed;

use std::sync::Arc;
use turna_health::Metrics;

use turna_rtp_analyzer::{AggregateQuality, RtpAnalyzer};

/// Minimum sequence numbers a stream must span in an interval before its loss
/// ratio is recorded. Below it a single lost packet reads as 50 % loss and the
/// histogram fills with noise from streams that are starting or stopping.
pub const MIN_INTERVAL_PACKETS: u64 = 10;

/// Take one sample and publish it, then drop streams idle for 30 s.
///
/// - counters: `turna_rtp_packets{,_expected,_lost,_out_of_order}_total` grow by
///   the interval's deltas;
/// - histograms: one jitter observation per live stream, one loss-ratio
///   observation per stream that spanned at least [`MIN_INTERVAL_PACKETS`];
/// - gauges: the existing `turna_rtp_*` aggregate gauges, as before.
///
/// Sampling precedes the stale-stream cleanup, so a stream's last packets are
/// counted before it is forgotten.
pub fn publish(analyzers: &[Arc<RtpAnalyzer>], metrics: &Metrics) {
    let mut report = turna_rtp_analyzer::SampleReport::default();
    for a in analyzers {
        let r = a.sample();
        report.received += r.received;
        report.expected += r.expected;
        report.lost += r.lost;
        report.out_of_order += r.out_of_order;
        report.streams.extend(r.streams);
    }
    metrics.rtp_packets.fetch_add(report.received, Relaxed);
    metrics
        .rtp_packets_expected
        .fetch_add(report.expected, Relaxed);
    metrics.rtp_packets_lost.fetch_add(report.lost, Relaxed);
    metrics
        .rtp_packets_out_of_order
        .fetch_add(report.out_of_order, Relaxed);
    for s in &report.streams {
        // A stream that sent nothing this interval has a stale jitter value;
        // recording it again would weight idle streams like active ones.
        if s.interval_expected == 0 {
            continue;
        }
        metrics
            .histograms
            .observe_value("turna_rtp_stream_jitter_seconds", s.jitter_ms / 1000.0);
        if s.interval_expected >= MIN_INTERVAL_PACKETS {
            metrics.histograms.observe_value(
                "turna_rtp_stream_loss_ratio",
                s.interval_lost as f64 / s.interval_expected as f64,
            );
        }
    }

    let all: Vec<_> = analyzers.iter().flat_map(|a| a.get_all_quality()).collect();
    let agg = AggregateQuality::from_streams(&all);
    metrics.rtp_streams.store(agg.total_streams, Relaxed);
    metrics
        .rtp_avg_loss_pct_x100
        .store((agg.avg_loss_percent * 100.0) as u64, Relaxed);
    metrics
        .rtp_max_loss_pct_x100
        .store((agg.max_loss_percent * 100.0) as u64, Relaxed);
    metrics
        .rtp_avg_jitter_us
        .store((agg.avg_jitter_ms * 1000.0) as u64, Relaxed);
    metrics
        .rtp_max_jitter_us
        .store((agg.max_jitter_ms * 1000.0) as u64, Relaxed);
    metrics
        .rtp_total_bitrate_kbps
        .store(agg.total_bitrate_bps / 1000, Relaxed);
    for a in analyzers {
        a.cleanup_stale();
    }
}

/// [`publish`] for every analyzer registered by a live `PacketProcessor`.
pub fn publish_global(metrics: &Metrics) {
    publish(&RtpAnalyzer::all_registered(), metrics);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(seq: u16, ssrc: u32) -> Vec<u8> {
        let mut b = vec![0u8; 20];
        b[0] = 0x80;
        b[1] = 96;
        b[2..4].copy_from_slice(&seq.to_be_bytes());
        b[4..8].copy_from_slice(&(seq as u32 * 3000).to_be_bytes());
        b[8..12].copy_from_slice(&ssrc.to_be_bytes());
        b
    }

    #[test]
    fn publish_adds_deltas_and_observes_histograms() {
        let a = Arc::new(RtpAnalyzer::new());
        let m = Metrics::new();
        let src = "192.0.2.1:1".parse().unwrap();
        // 20 spanned, 2 lost (seq 5 and 6), one late arrival of 6 → 1 lost.
        for s in (1..=4).chain(7..=20).chain(std::iter::once(6)) {
            a.analyze(
                &pkt(s, 42),
                src,
                turna_rtp_analyzer::Direction::ClientToPeer,
            );
        }
        publish(std::slice::from_ref(&a), &m);
        assert_eq!(m.rtp_packets.load(Relaxed), 19);
        assert_eq!(m.rtp_packets_expected.load(Relaxed), 20);
        assert_eq!(m.rtp_packets_lost.load(Relaxed), 1);
        assert_eq!(m.rtp_packets_out_of_order.load(Relaxed), 1);
        assert_eq!(m.rtp_streams.load(Relaxed), 1);
        let loss = m.histograms.get("turna_rtp_stream_loss_ratio").unwrap();
        assert_eq!(loss.total_count(), 1);
        assert!((loss.sum_seconds() - 0.05).abs() < 1e-6);
        let jitter = m.histograms.get("turna_rtp_stream_jitter_seconds").unwrap();
        assert_eq!(jitter.total_count(), 1);

        // Second publish with no traffic: counters unchanged, no observations.
        publish(std::slice::from_ref(&a), &m);
        assert_eq!(m.rtp_packets.load(Relaxed), 19);
        assert_eq!(loss.total_count(), 1);
        assert_eq!(jitter.total_count(), 1);
    }

    /// Two workers' analyzers are summed, and the aggregate gauges cover both.
    #[test]
    fn publish_sums_across_worker_analyzers() {
        let a = Arc::new(RtpAnalyzer::new());
        let b = Arc::new(RtpAnalyzer::new());
        let m = Metrics::new();
        let src = "192.0.2.1:1".parse().unwrap();
        for s in 1..=10u16 {
            a.analyze(&pkt(s, 1), src, turna_rtp_analyzer::Direction::ClientToPeer);
            b.analyze(&pkt(s, 2), src, turna_rtp_analyzer::Direction::PeerToClient);
        }
        publish(&[a, b], &m);
        assert_eq!(m.rtp_packets.load(Relaxed), 20);
        assert_eq!(m.rtp_streams.load(Relaxed), 2);
    }

    #[test]
    fn short_intervals_are_not_recorded_as_loss() {
        let a = Arc::new(RtpAnalyzer::new());
        let m = Metrics::new();
        let src = "192.0.2.1:1".parse().unwrap();
        for s in [1u16, 3] {
            a.analyze(&pkt(s, 7), src, turna_rtp_analyzer::Direction::ClientToPeer);
        }
        publish(std::slice::from_ref(&a), &m);
        assert_eq!(
            m.histograms
                .get("turna_rtp_stream_loss_ratio")
                .unwrap()
                .total_count(),
            0,
            "3 packets spanned is below MIN_INTERVAL_PACKETS"
        );
        assert_eq!(
            m.rtp_packets_lost.load(Relaxed),
            1,
            "the counter still counts it"
        );
    }
}
