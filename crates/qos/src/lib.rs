//! Quality of Service — rate limiting

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

/// Per-IP rate limiter using token bucket.
pub struct RateLimiter {
    buckets: HashMap<IpAddr, TokenBucket>,
    max_tokens: u32,
    refill_rate: u32, // tokens per second
    /// Hard cap on tracked IPs. When full, new IPs are rate-limited immediately.
    /// Prevents unbounded HashMap growth under spoofed-source-IP DDoS.
    max_entries: usize,
}

struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    /// Create limiter: max_tokens burst size, refill_rate tokens/sec.
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self::with_max_entries(max_tokens, refill_rate, 65536)
    }

    /// Create limiter with explicit entry cap.
    /// When `max_entries` unique IPs are tracked, new IPs are denied until
    /// `cleanup()` frees space. This bounds memory to ~O(max_entries * 40 bytes).
    pub fn with_max_entries(max_tokens: u32, refill_rate: u32, max_entries: usize) -> Self {
        Self {
            buckets: HashMap::with_capacity(max_entries.min(4096)),
            max_tokens,
            refill_rate,
            max_entries,
        }
    }

    /// Default: 10000 requests burst, 50000/sec refill, 65536 max IPs (~2.5 MB).
    pub fn default_limiter() -> Self {
        Self::new(10000, 50000)
    }

    /// Check if request from IP is allowed.
    pub fn check(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let max = self.max_tokens as f64;
        let rate = self.refill_rate as f64;

        // Enforce entry cap: if full and IP is unknown, deny immediately.
        // This bounds memory usage and prevents HashMap OOM under IP spoofing.
        if !self.buckets.contains_key(&ip) && self.buckets.len() >= self.max_entries {
            tracing::warn!(%ip, "rate limiter table full, denying new IP");
            return false;
        }

        let bucket = self.buckets.entry(ip).or_insert(TokenBucket {
            tokens: max,
            last_refill: now,
        });

        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(max);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            tracing::warn!(%ip, "rate limited");
            false
        }
    }

    /// Clean up old entries (call periodically).
    pub fn cleanup(&mut self, max_age_secs: f64) {
        let now = Instant::now();
        self.buckets
            .retain(|_, b| now.duration_since(b.last_refill).as_secs_f64() < max_age_secs);
    }
}

// ── Sharded Rate Limiter (lock-free, P4) ──────────────────────────────────────
//
// Previously `Vec<Mutex<RateLimiter>>` — every packet locked a shard. Now each
// source key owns a single `AtomicU64` token bucket updated by a CAS loop, and
// the key→bucket map is a lock-free `DashMap`. The hot path takes no mutex: an
// allowed packet commits one successful CAS; a denied packet (the flood case)
// is read-only — no store at all.
//
// The bucket packs (tokens | last_refill_ms) into one u64, so refill+consume is
// a single atomic transaction with no torn state between the two fields — the
// race the audit flagged. `try_acquire` takes time/burst/rate as plain args so
// the CAS logic is deterministically model-checkable under `loom` (see
// `loom_bucket` below); `DashMap` itself is upstream-validated and out of scope
// for the loom model.

use dashmap::DashMap;

#[cfg(loom)]
use loom::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(loom))]
use std::sync::atomic::{AtomicU64, Ordering};

const DEFAULT_SHARDS: usize = 16;

// Packed bucket layout: high 24 bits = tokens, low 40 bits = last-refill
// timestamp in ms since the limiter's base Instant (40 bits ≈ 34800 years).
const TS_BITS: u64 = 40;
const TS_MASK: u64 = (1 << TS_BITS) - 1;
const TOKEN_MASK: u64 = (1 << (64 - TS_BITS)) - 1; // 24 bits → max burst 16_777_215

#[inline]
fn pack(tokens: u64, ts_ms: u64) -> u64 {
    ((tokens & TOKEN_MASK) << TS_BITS) | (ts_ms & TS_MASK)
}

#[inline]
fn unpack(state: u64) -> (u64, u64) {
    (state >> TS_BITS, state & TS_MASK)
}

/// Pure refill. Integer math; leftover sub-token time is preserved by advancing
/// `ts` only by the time actually converted into whole tokens, so low refill
/// rates don't silently lose credit.
#[inline]
fn refill(tokens: u64, last_ts: u64, now_ts: u64, max: u64, rate: u64) -> (u64, u64) {
    if rate == 0 || now_ts <= last_ts {
        return (tokens.min(max), last_ts);
    }
    let elapsed = now_ts - last_ts;
    let added = (elapsed as u128 * rate as u128 / 1000) as u64;
    if added == 0 {
        return (tokens, last_ts); // accumulate time until a whole token forms
    }
    let new_tokens = (tokens + added).min(max);
    let new_ts = if new_tokens >= max {
        now_ts // bucket full — drop the unused credit
    } else {
        let consumed_ms = (added as u128 * 1000 / rate as u128) as u64;
        last_ts + consumed_ms
    };
    (new_tokens, new_ts)
}

/// Single-`AtomicU64` token bucket. An allowed request commits
/// `(tokens-1, refilled_ts)` atomically; a denied request makes no store
/// (refill is a pure function of the stored state, so recomputing next call is
/// equivalent — and keeps floods off the write path).
struct AtomicTokenBucket {
    state: AtomicU64,
}

impl AtomicTokenBucket {
    #[inline]
    fn new(tokens: u64, now_ms: u64) -> Self {
        Self {
            state: AtomicU64::new(pack(tokens, now_ms)),
        }
    }

    #[inline]
    fn try_acquire(&self, now_ms: u64, max: u64, rate: u64) -> bool {
        loop {
            let cur = self.state.load(Ordering::Acquire);
            let (tokens, last_ts) = unpack(cur);
            let (refilled, new_ts) = refill(tokens, last_ts, now_ms, max, rate);
            if refilled < 1 {
                return false; // no token even after refill — read-only deny
            }
            let want = pack(refilled - 1, new_ts);
            if self
                .state
                .compare_exchange_weak(cur, want, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return true;
            }
            // lost the race; reload and retry
        }
    }

    /// Last-refill timestamp (ms since base), for cleanup aging.
    #[inline]
    fn last_ts(&self) -> u64 {
        unpack(self.state.load(Ordering::Relaxed)).1
    }
}

/// Lock-free per-key token-bucket limiter. Public API matches the previous
/// mutex-sharded version, so `TieredRateLimiter` and callers are untouched.
pub struct ShardedRateLimiter {
    buckets: DashMap<IpAddr, AtomicTokenBucket>,
    base: Instant,
    max_tokens: u32,
    refill_rate: u32,
    /// Hard cap on tracked keys; bounds memory under spoofed-source floods.
    max_entries: usize,
}

impl ShardedRateLimiter {
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self::with_shards(max_tokens, refill_rate, DEFAULT_SHARDS)
    }

    /// `n_shards` is accepted for API compatibility but unused — the lock-free
    /// map needs no static sharding.
    pub fn with_shards(max_tokens: u32, refill_rate: u32, _n_shards: usize) -> Self {
        debug_assert!(
            (max_tokens as u64) <= TOKEN_MASK,
            "max_tokens exceeds the 24-bit packed token field"
        );
        Self {
            buckets: DashMap::with_capacity(4096),
            base: Instant::now(),
            max_tokens,
            refill_rate,
            max_entries: 65536,
        }
    }

    pub fn default_limiter() -> Self {
        Self::new(10_000, 50_000)
    }

    #[inline]
    fn now_ms(&self) -> u64 {
        (self.base.elapsed().as_millis() as u64) & TS_MASK
    }

    /// Check if a request from `ip` is allowed. Lock-free on the hot path.
    pub fn check(&self, ip: IpAddr) -> bool {
        let now = self.now_ms();
        let max = self.max_tokens as u64;
        let rate = self.refill_rate as u64;

        // Fast path: existing bucket, no map mutation, shared read lock only.
        if let Some(b) = self.buckets.get(&ip) {
            return b.try_acquire(now, max, rate);
        }

        // Unknown IP: enforce the entry cap before inserting so a spoofed-source
        // flood can't grow the map without bound.
        if self.buckets.len() >= self.max_entries {
            tracing::warn!(%ip, "rate limiter table full, denying new IP");
            return false;
        }
        // entry() collapses the race where two threads insert the same new IP.
        let b = self
            .buckets
            .entry(ip)
            .or_insert_with(|| AtomicTokenBucket::new(max, now));
        b.try_acquire(now, max, rate)
    }

    /// Drop buckets idle for `max_age_secs`. Call periodically.
    pub fn cleanup(&self, max_age_secs: f64) {
        let now = self.now_ms();
        let max_age_ms = (max_age_secs * 1000.0) as u64;
        self.buckets
            .retain(|_, b| now.saturating_sub(b.last_ts()) < max_age_ms);
    }

    pub fn shard_count(&self) -> usize {
        DEFAULT_SHARDS
    }
}

// ── Tiered rate limiting (M1) ─────────────────────────────────────────────────
//
// A single per-IP limiter misses two real abuse patterns:
//
//   1. **Subnet floods with spoofed/rotating source IPs.** Each packet looks
//      like a new IP, so a per-IP bucket never trips. A per-prefix bucket
//      (/24 for IPv4, /48 for IPv6) caps an entire allocation block.
//
//   2. **Expensive-method floods.** Allocate / CreatePermission / ChannelBind
//      cost far more than forwarding ChannelData (auth, HMAC, map inserts).
//      A dedicated, stricter limiter per method throttles them independently
//      of the cheap data path.
//
// `TieredRateLimiter` composes the existing `ShardedRateLimiter` for each tier
// so all the bucket/cap/cleanup logic is reused.

/// Mask an address to its aggregation prefix: /24 for IPv4, /48 for IPv6.
pub fn aggregation_prefix(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], 0))
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], 0, 0, 0, 0, 0))
        }
    }
}

/// Tunable limits for [`TieredRateLimiter`]. Rates are (burst, refill/sec).
#[derive(Clone, Copy, Debug)]
pub struct TieredLimits {
    pub per_ip: (u32, u32),
    pub per_prefix: (u32, u32),
    pub allocate: (u32, u32),
    pub create_permission: (u32, u32),
    pub channel_bind: (u32, u32),
}

impl Default for TieredLimits {
    fn default() -> Self {
        Self {
            // Cheap data-plane gate: generous.
            per_ip: (10_000, 50_000),
            // A /24 or /48 as a whole gets a higher aggregate ceiling.
            per_prefix: (40_000, 200_000),
            // Expensive control-plane methods: strict, per source IP.
            allocate: (32, 16),
            create_permission: (128, 64),
            channel_bind: (128, 64),
        }
    }
}

/// Per-IP + per-prefix + per-method rate limiting.
pub struct TieredRateLimiter {
    per_ip: ShardedRateLimiter,
    per_prefix: ShardedRateLimiter,
    allocate: ShardedRateLimiter,
    create_permission: ShardedRateLimiter,
    channel_bind: ShardedRateLimiter,
}

impl TieredRateLimiter {
    pub fn new(limits: TieredLimits) -> Self {
        Self {
            per_ip: ShardedRateLimiter::new(limits.per_ip.0, limits.per_ip.1),
            per_prefix: ShardedRateLimiter::new(limits.per_prefix.0, limits.per_prefix.1),
            allocate: ShardedRateLimiter::new(limits.allocate.0, limits.allocate.1),
            create_permission: ShardedRateLimiter::new(
                limits.create_permission.0,
                limits.create_permission.1,
            ),
            channel_bind: ShardedRateLimiter::new(limits.channel_bind.0, limits.channel_bind.1),
        }
    }

    /// Per-packet gate: allowed only if BOTH the source IP and its /24-or-/48
    /// prefix are under their limits. Cheap; safe to call on every packet.
    #[inline]
    pub fn check_ingress(&self, ip: IpAddr) -> bool {
        // Per-IP first (most selective); only consume a prefix token if the IP
        // passed, so a single hot IP doesn't drain the whole prefix budget.
        if !self.per_ip.check(ip) {
            return false;
        }
        self.per_prefix.check(aggregation_prefix(ip))
    }

    /// Per-IP-only ingress gate (single shard lock). Used on the ChannelData
    /// media path (P5): established sessions are bounded by the per-allocation
    /// bandwidth quota and unknown sources are dropped at the allocation
    /// lookup, so the second (per-prefix) lock that `check_ingress` takes is
    /// redundant there.
    #[inline]
    pub fn check_ingress_ip(&self, ip: IpAddr) -> bool {
        self.per_ip.check(ip)
    }

    /// Per-source-IP gate for the (expensive) Allocate method.
    #[inline]
    pub fn check_allocate(&self, ip: IpAddr) -> bool {
        self.allocate.check(ip)
    }

    /// Per-source-IP gate for CreatePermission.
    #[inline]
    pub fn check_create_permission(&self, ip: IpAddr) -> bool {
        self.create_permission.check(ip)
    }

    /// Per-source-IP gate for ChannelBind.
    #[inline]
    pub fn check_channel_bind(&self, ip: IpAddr) -> bool {
        self.channel_bind.check(ip)
    }

    /// Cleanup all tiers (call periodically from a maintenance task).
    pub fn cleanup(&self, max_age_secs: f64) {
        self.per_ip.cleanup(max_age_secs);
        self.per_prefix.cleanup(max_age_secs);
        self.allocate.cleanup(max_age_secs);
        self.create_permission.cleanup(max_age_secs);
        self.channel_bind.cleanup(max_age_secs);
    }
}

#[cfg(test)]
mod tiered_tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn prefix_masks_correctly() {
        assert_eq!(aggregation_prefix(ip("203.0.113.45")), ip("203.0.113.0"));
        assert_eq!(
            aggregation_prefix(ip("2001:db8:abcd:1234::1")),
            ip("2001:db8:abcd::")
        );
    }

    #[test]
    fn per_method_allocate_is_stricter_than_per_ip() {
        let rl = TieredRateLimiter::new(TieredLimits {
            allocate: (3, 0), // burst 3, no refill
            ..Default::default()
        });
        let a = ip("198.51.100.7");
        assert!(rl.check_allocate(a));
        assert!(rl.check_allocate(a));
        assert!(rl.check_allocate(a));
        assert!(!rl.check_allocate(a), "4th Allocate must be throttled");
        // The data-plane gate for the same IP is unaffected.
        assert!(rl.check_ingress(a));
    }

    #[test]
    fn prefix_catches_rotating_ips() {
        // Tiny prefix budget; per-IP budget large. Distinct IPs in one /24
        // must still trip the prefix limiter.
        let rl = TieredRateLimiter::new(TieredLimits {
            per_ip: (1_000, 0),
            per_prefix: (2, 0),
            ..Default::default()
        });
        assert!(rl.check_ingress(ip("203.0.113.1")));
        assert!(rl.check_ingress(ip("203.0.113.2")));
        assert!(
            !rl.check_ingress(ip("203.0.113.3")),
            "prefix budget exhausted"
        );
    }
}

#[cfg(test)]
mod bucket_tests {
    use super::*;

    #[test]
    fn burst_then_refill() {
        let b = AtomicTokenBucket::new(2, 0);
        assert!(b.try_acquire(0, 2, 1000)); // rate 1000/sec
        assert!(b.try_acquire(0, 2, 1000));
        assert!(!b.try_acquire(0, 2, 1000)); // burst exhausted at t=0
        assert!(b.try_acquire(1, 2, 1000)); // +1ms → +1 token
        assert!(!b.try_acquire(1, 2, 1000));
    }

    #[test]
    fn rate_zero_never_refills() {
        let b = AtomicTokenBucket::new(1, 0);
        assert!(b.try_acquire(0, 1, 0));
        assert!(!b.try_acquire(1_000_000, 1, 0)); // far in the future, still empty
    }

    #[test]
    fn sub_token_time_accumulates_not_lost() {
        // rate 10/sec → 1 token per 100ms; a 50ms gap must not silently refill.
        let b = AtomicTokenBucket::new(1, 0);
        assert!(b.try_acquire(0, 1, 10)); // consume the 1
        assert!(!b.try_acquire(50, 1, 10)); // 50ms*10/1000 = 0 added
        assert!(b.try_acquire(100, 1, 10)); // 100ms*10/1000 = 1 added (time kept)
    }

    #[test]
    fn never_exceeds_max_on_refill() {
        let b = AtomicTokenBucket::new(0, 0);
        // Huge gap would add far more than max; must cap at burst (2).
        assert!(b.try_acquire(10_000, 2, 1000));
        assert!(b.try_acquire(10_000, 2, 1000));
        assert!(!b.try_acquire(10_000, 2, 1000));
    }
}

// Loom model of the bucket CAS. Run with:
//   RUSTFLAGS="--cfg loom" cargo test -p turna-qos --lib loom_bucket
// Loom enumerates thread interleavings to prove the CAS loop neither
// double-grants nor loses a token. DashMap is not loom-instrumented, so the
// model targets a single shared bucket directly.
#[cfg(loom)]
mod loom_bucket {
    use super::AtomicTokenBucket;
    use loom::sync::Arc;

    #[test]
    fn no_double_grant_under_contention() {
        loom::model(|| {
            let burst = 2u64;
            let bucket = Arc::new(AtomicTokenBucket::new(burst, 0));

            let b1 = bucket.clone();
            let t1 = loom::thread::spawn(move || {
                let mut got = 0u64;
                // rate 0 so there is no refill — exactly `burst` tokens exist.
                if b1.try_acquire(0, burst, 0) {
                    got += 1;
                }
                if b1.try_acquire(0, burst, 0) {
                    got += 1;
                }
                got
            });

            let mut got = 0u64;
            if bucket.try_acquire(0, burst, 0) {
                got += 1;
            }
            if bucket.try_acquire(0, burst, 0) {
                got += 1;
            }

            let total = got + t1.join().unwrap();
            // Exactly `burst`: no interleaving may grant more (double-spend) or
            // fewer (a lost successful decrement).
            assert_eq!(total, burst, "granted {total}, expected exactly {burst}");
        });
    }
}
