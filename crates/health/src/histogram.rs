//! Lock-free Prometheus-compatible histograms for latency tracking.
//!
//! Features:
//! - Pre-defined buckets optimized for TURN (µs to ms range)
//! - Lock-free via per-bucket AtomicU64
//! - Multiple named histograms (stun_latency, relay_latency, auth_latency)
//! - Prometheus text format output
//!
//! Usage:
//!   let reg = HistogramRegistry::new();
//!   reg.observe("stun_request_duration_seconds", duration);
//!   let output = reg.render_prometheus();

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

// ---------------------------------------------------------------------------
// Histogram
// ---------------------------------------------------------------------------

/// A single histogram with pre-defined buckets.
pub struct Histogram {
    name: String,
    help: String,
    buckets: Vec<f64>,
    counts: Vec<AtomicU64>,
    sum: AtomicU64,   // sum in nanoseconds
    count: AtomicU64, // total observations
}

impl Histogram {
    pub fn new(name: &str, help: &str, buckets: Vec<f64>) -> Self {
        let n = buckets.len();
        let counts = (0..=n).map(|_| AtomicU64::new(0)).collect();
        Self {
            name: name.into(),
            help: help.into(),
            buckets,
            counts,
            sum: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    /// Record an observation.
    pub fn observe(&self, value: Duration) {
        let secs = value.as_secs_f64();
        self.count.fetch_add(1, Ordering::Relaxed);
        self.sum
            .fetch_add(value.as_nanos() as u64, Ordering::Relaxed);

        // Increment all buckets where value <= boundary
        for (i, &boundary) in self.buckets.iter().enumerate() {
            if secs <= boundary {
                self.counts[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        // +Inf bucket (always incremented)
        self.counts[self.buckets.len()].fetch_add(1, Ordering::Relaxed);
    }

    /// Render in Prometheus text exposition format.
    pub fn render(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push_str(&format!("# HELP {} {}\n", self.name, self.help));
        out.push_str(&format!("# TYPE {} histogram\n", self.name));

        for (i, &boundary) in self.buckets.iter().enumerate() {
            let count = self.counts[i].load(Ordering::Relaxed);
            out.push_str(&format!(
                "{}_bucket{{le=\"{:.6}\"}} {}\n",
                self.name, boundary, count
            ));
        }

        let total = self.counts[self.buckets.len()].load(Ordering::Relaxed);
        out.push_str(&format!("{}_bucket{{le=\"+Inf\"}} {}\n", self.name, total));

        let sum_ns = self.sum.load(Ordering::Relaxed);
        out.push_str(&format!(
            "{}_sum {:.9}\n",
            self.name,
            sum_ns as f64 / 1_000_000_000.0
        ));
        out.push_str(&format!(
            "{}_count {}\n",
            self.name,
            self.count.load(Ordering::Relaxed)
        ));

        out
    }

    pub fn total_count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn sum_seconds(&self) -> f64 {
        self.sum.load(Ordering::Relaxed) as f64 / 1_000_000_000.0
    }

    pub fn avg_seconds(&self) -> f64 {
        let c = self.count.load(Ordering::Relaxed);
        if c == 0 {
            0.0
        } else {
            self.sum_seconds() / c as f64
        }
    }

    /// Estimate a quantile (`q` in `0.0..=1.0`) in seconds via linear
    /// interpolation across the cumulative bucket counts — the same approach as
    /// Prometheus `histogram_quantile`. Returns `0.0` when there are no
    /// observations. A quantile that falls in the open-ended `+Inf` bucket is
    /// clamped to the highest finite boundary, since a bucketed histogram cannot
    /// resolve a value above its last boundary.
    pub fn percentile(&self, q: f64) -> f64 {
        let total = self.count.load(Ordering::Relaxed);
        if total == 0 || self.buckets.is_empty() {
            return 0.0;
        }
        let rank = q.clamp(0.0, 1.0) * total as f64;

        // `counts[i]` is cumulative: the number of observations <= buckets[i].
        let mut prev_cum = 0.0_f64;
        let mut prev_bound = 0.0_f64;
        for (i, &bound) in self.buckets.iter().enumerate() {
            let cum = self.counts[i].load(Ordering::Relaxed) as f64;
            if cum >= rank {
                let in_bucket = cum - prev_cum;
                if in_bucket <= 0.0 {
                    return bound;
                }
                let frac = (rank - prev_cum) / in_bucket;
                return prev_bound + (bound - prev_bound) * frac;
            }
            prev_cum = cum;
            prev_bound = bound;
        }
        // Rank is in the +Inf bucket: clamp to the highest finite boundary.
        *self.buckets.last().unwrap()
    }
}

// ---------------------------------------------------------------------------
// Pre-defined bucket sets
// ---------------------------------------------------------------------------

/// Buckets for STUN/TURN request processing latency.
/// Range: 5µs to 100ms (most requests < 1ms).
pub fn stun_latency_buckets() -> Vec<f64> {
    vec![
        0.000_005, // 5µs
        0.000_010, // 10µs
        0.000_025, // 25µs
        0.000_050, // 50µs
        0.000_100, // 100µs
        0.000_250, // 250µs
        0.000_500, // 500µs
        0.001,     // 1ms
        0.002_5,   // 2.5ms
        0.005,     // 5ms
        0.010,     // 10ms
        0.025,     // 25ms
        0.050,     // 50ms
        0.100,     // 100ms
    ]
}

/// Buckets for relay forwarding latency.
/// Range: 1µs to 10ms (hot path, should be < 100µs).
pub fn relay_latency_buckets() -> Vec<f64> {
    vec![
        0.000_001, // 1µs
        0.000_002, // 2µs
        0.000_005, // 5µs
        0.000_010, // 10µs
        0.000_025, // 25µs
        0.000_050, // 50µs
        0.000_100, // 100µs
        0.000_500, // 500µs
        0.001,     // 1ms
        0.010,     // 10ms
    ]
}

/// Buckets for authentication latency.
/// Range: 10µs to 50ms (HMAC computation).
pub fn auth_latency_buckets() -> Vec<f64> {
    vec![
        0.000_010, // 10µs
        0.000_050, // 50µs
        0.000_100, // 100µs
        0.000_500, // 500µs
        0.001,     // 1ms
        0.005,     // 5ms
        0.010,     // 10ms
        0.050,     // 50ms
    ]
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// Registry of named histograms. Thread-safe.
pub struct HistogramRegistry {
    histograms: HashMap<String, Histogram>,
}

impl HistogramRegistry {
    /// Create registry with default TURN histograms.
    pub fn new() -> Self {
        let mut histograms = HashMap::new();

        histograms.insert(
            "turna_stun_request_duration_seconds".into(),
            Histogram::new(
                "turna_stun_request_duration_seconds",
                "STUN/TURN request processing latency",
                stun_latency_buckets(),
            ),
        );

        histograms.insert(
            "turna_relay_forward_duration_seconds".into(),
            Histogram::new(
                "turna_relay_forward_duration_seconds",
                "ChannelData relay forwarding latency",
                relay_latency_buckets(),
            ),
        );

        histograms.insert(
            "turna_auth_duration_seconds".into(),
            Histogram::new(
                "turna_auth_duration_seconds",
                "Authentication processing latency",
                auth_latency_buckets(),
            ),
        );

        histograms.insert(
            "turna_allocation_lifetime_seconds".into(),
            Histogram::new(
                "turna_allocation_lifetime_seconds",
                "Allocation lifetime duration",
                vec![10.0, 30.0, 60.0, 120.0, 300.0, 600.0, 1800.0, 3600.0],
            ),
        );

        histograms.insert(
            "turna_runtime_config_apply_duration_seconds".into(),
            Histogram::new(
                "turna_runtime_config_apply_duration_seconds",
                "Runtime configuration and user-limit apply latency",
                vec![
                    0.001, 0.005, 0.010, 0.025, 0.050, 0.100, 0.250, 0.500, 1.0, 2.5, 5.0,
                ],
            ),
        );

        Self { histograms }
    }

    /// Observe a value for a named histogram.
    pub fn observe(&self, name: &str, duration: Duration) {
        if let Some(h) = self.histograms.get(name) {
            h.observe(duration);
        }
    }

    /// Get a histogram by name.
    pub fn get(&self, name: &str) -> Option<&Histogram> {
        self.histograms.get(name)
    }

    /// Render all histograms in Prometheus text format.
    pub fn render_prometheus(&self) -> String {
        let mut out = String::with_capacity(4096);
        let mut names: Vec<&String> = self.histograms.keys().collect();
        names.sort();
        for name in names {
            out.push_str(&self.histograms[name].render());
            out.push('\n');
        }
        out
    }
}

impl Default for HistogramRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observe_and_count() {
        let h = Histogram::new("test", "help", vec![0.001, 0.01, 0.1]);
        h.observe(Duration::from_micros(500)); // 0.0005s → bucket 0.001
        h.observe(Duration::from_millis(5)); // 0.005s → bucket 0.01
        h.observe(Duration::from_millis(50)); // 0.05s → bucket 0.1

        assert_eq!(h.total_count(), 3);
    }

    #[test]
    fn render_format() {
        let h = Histogram::new("test_seconds", "Test metric", vec![0.01, 0.1]);
        h.observe(Duration::from_millis(5));

        let output = h.render();
        assert!(output.contains("# HELP test_seconds Test metric"));
        assert!(output.contains("# TYPE test_seconds histogram"));
        assert!(output.contains("test_seconds_bucket{le=\"0.010000\"}"));
        assert!(output.contains("test_seconds_bucket{le=\"+Inf\"}"));
        assert!(output.contains("test_seconds_sum"));
        assert!(output.contains("test_seconds_count 1"));
    }

    #[test]
    fn registry_default() {
        let reg = HistogramRegistry::new();
        assert!(reg.get("turna_stun_request_duration_seconds").is_some());
        assert!(reg.get("turna_relay_forward_duration_seconds").is_some());
        assert!(reg.get("turna_auth_duration_seconds").is_some());
    }

    #[test]
    fn registry_observe_render() {
        let reg = HistogramRegistry::new();
        reg.observe(
            "turna_stun_request_duration_seconds",
            Duration::from_micros(100),
        );
        reg.observe(
            "turna_stun_request_duration_seconds",
            Duration::from_millis(1),
        );

        let output = reg.render_prometheus();
        assert!(output.contains("turna_stun_request_duration_seconds_count 2"));
    }

    #[test]
    fn avg_calculation() {
        let h = Histogram::new("t", "h", vec![1.0]);
        h.observe(Duration::from_secs(2));
        h.observe(Duration::from_secs(4));
        let avg = h.avg_seconds();
        assert!((avg - 3.0).abs() < 0.001);
    }

    #[test]
    fn percentile_empty_is_zero() {
        let h = Histogram::new("t", "h", vec![0.001, 0.01, 0.1]);
        assert_eq!(h.percentile(0.99), 0.0);
    }

    #[test]
    fn percentile_interpolates_within_bucket() {
        // Boundaries 1s and 2s. Ten observations of 0.5s land in the first
        // bucket; ten of 1.5s land in the second bucket. p99 at rank 19.8 sits in
        // the second bucket and interpolates between 1.0 and 2.0.
        let h = Histogram::new("t", "h", vec![1.0, 2.0]);
        for _ in 0..10 {
            h.observe(Duration::from_millis(500));
        }
        for _ in 0..10 {
            h.observe(Duration::from_millis(1500));
        }
        let p99 = h.percentile(0.99);
        assert!(
            (1.0..=2.0).contains(&p99),
            "p99 must fall in the second bucket, got {p99}"
        );

        // p50 (rank 10) sits exactly at the first boundary.
        let p50 = h.percentile(0.50);
        assert!((p50 - 1.0).abs() < 0.001, "p50 should be ~1.0s, got {p50}");
    }

    #[test]
    fn percentile_above_last_boundary_clamps() {
        // A single huge observation falls in the +Inf bucket; p99 clamps to the
        // highest finite boundary rather than returning infinity.
        let h = Histogram::new("t", "h", vec![0.001, 0.01]);
        h.observe(Duration::from_secs(5));
        assert_eq!(h.percentile(0.99), 0.01);
    }
}
