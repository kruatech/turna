//! Node-wide relay bandwidth cap — `[turn.relay] max_total_bytes_per_sec`.
//!
//! One token bucket, in bytes, shared by every allocation and every datapath.
//! It is the node-level counterpart of the per-allocation quota: that one stops
//! a single client from taking the uplink, this one stops the *sum* of clients
//! from exceeding what the operator has decided the node may carry (a paid
//! egress allowance, a shared uplink, a noisy-neighbour budget).
//!
//! Same semantics as the per-allocation quota, deliberately: over the cap a
//! packet is **dropped**, not queued, and both directions draw on one budget.
//!
//! # Cost
//!
//! Every relayed packet does a CAS on one shared atomic, so under many cores the
//! cache line bounces. That is the price of an exact global figure; it is paid
//! only when the cap is configured (the processor holds an `Option`, and `None`
//! — the default — is a branch on a pointer).

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Lock-free byte-rate token bucket.
pub struct ByteRateLimiter {
    /// Refill, bytes per second.
    rate: u64,
    /// Bucket depth, bytes.
    burst: u64,
    tokens: AtomicU64,
    /// Last refill, microseconds since `base`.
    last_us: AtomicU64,
    base: Instant,
}

impl std::fmt::Debug for ByteRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ByteRateLimiter")
            .field("rate", &self.rate)
            .field("burst", &self.burst)
            .finish_non_exhaustive()
    }
}

impl ByteRateLimiter {
    /// `rate` bytes/second with a one-second burst: video is bursty (a key
    /// frame is tens of packets in a few milliseconds) and a sub-second bucket
    /// would drop those while the average sits well under the cap.
    pub fn new(rate: u64) -> Self {
        Self::with_burst(rate, rate)
    }

    pub fn with_burst(rate: u64, burst: u64) -> Self {
        let burst = burst.max(1);
        Self {
            rate,
            burst,
            tokens: AtomicU64::new(burst),
            last_us: AtomicU64::new(0),
            base: Instant::now(),
        }
    }

    pub fn rate(&self) -> u64 {
        self.rate
    }

    /// Take `n` bytes from the bucket. `false` = over capacity, drop the packet.
    #[inline]
    pub fn try_consume(&self, n: u64) -> bool {
        let now = self.base.elapsed().as_micros() as u64;
        self.try_consume_at(n, now)
    }

    fn try_consume_at(&self, n: u64, now_us: u64) -> bool {
        self.refill(now_us);
        self.tokens
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |t| t.checked_sub(n))
            .is_ok()
    }

    /// Credit the time since the last refill. Only the thread that wins the CAS
    /// on `last_us` adds tokens, so concurrent callers cannot double-credit one
    /// interval. Time too short to make a whole byte is left on the clock rather
    /// than truncated away, so low rates do not silently lose credit.
    #[inline]
    fn refill(&self, now_us: u64) {
        let last = self.last_us.load(Ordering::Acquire);
        if now_us <= last {
            return;
        }
        let elapsed = now_us - last;
        let add = (elapsed as u128 * self.rate as u128 / 1_000_000) as u64;
        if add == 0 {
            return;
        }
        // Advance the clock only by the time converted into whole bytes.
        let used_us = (add as u128 * 1_000_000 / self.rate.max(1) as u128) as u64;
        if self
            .last_us
            .compare_exchange(
                last,
                last + used_us.min(elapsed),
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            let burst = self.burst;
            let _ = self
                .tokens
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |t| {
                    Some(t.saturating_add(add).min(burst))
                });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_refill_at_rate() {
        let b = ByteRateLimiter::with_burst(1_000, 1_000);
        assert!(b.try_consume_at(600, 0));
        assert!(b.try_consume_at(400, 0));
        assert!(!b.try_consume_at(1, 0), "bucket empty");
        // 100 ms at 1000 B/s is 100 bytes.
        assert!(b.try_consume_at(100, 100_000));
        assert!(!b.try_consume_at(1, 100_000));
    }

    #[test]
    fn refill_never_exceeds_the_burst() {
        let b = ByteRateLimiter::with_burst(1_000, 500);
        assert!(b.try_consume_at(500, 0));
        // Ten seconds idle refills to the burst, not to 10 000.
        assert!(b.try_consume_at(500, 10_000_000));
        assert!(!b.try_consume_at(1, 10_000_000));
    }

    #[test]
    fn low_rates_do_not_lose_fractional_credit() {
        // 3 B/s: a refill every 100 ms adds 0.3 bytes. Truncating each one would
        // never refill at all.
        let b = ByteRateLimiter::with_burst(3, 3);
        assert!(b.try_consume_at(3, 0));
        for step in 1..=10u64 {
            b.refill(step * 100_000);
        }
        assert!(
            b.try_consume_at(3, 1_000_000),
            "one second at 3 B/s is 3 bytes"
        );
    }

    #[test]
    fn concurrent_consumers_never_overdraw() {
        let b = std::sync::Arc::new(ByteRateLimiter::with_burst(1, 10_000));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let b = b.clone();
                std::thread::spawn(move || (0..5_000).filter(|_| b.try_consume_at(1, 0)).count())
            })
            .collect();
        let granted: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(granted, 10_000, "exactly the burst is granted, never more");
    }
}
