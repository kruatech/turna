//! Quality of Service — rate limiting, backpressure

pub mod backpressure;

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

// ── Sharded Rate Limiter ──────────────────────────────────────────────────────
//
// Заменяет один глобальный Mutex<RateLimiter> на N независимых шардов.
// Каждый IP хэшируется в шард — contention снижается в N раз.
// Для 16 шардов: 16 потоков могут проверять rate limit одновременно.

use parking_lot::Mutex;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

const DEFAULT_SHARDS: usize = 16;

pub struct ShardedRateLimiter {
    shards: Vec<Mutex<RateLimiter>>,
}

impl ShardedRateLimiter {
    pub fn new(max_tokens: u32, refill_rate: u32) -> Self {
        Self::with_shards(max_tokens, refill_rate, DEFAULT_SHARDS)
    }

    pub fn with_shards(max_tokens: u32, refill_rate: u32, n_shards: usize) -> Self {
        let per_shard_entries = 65536 / n_shards;
        let shards = (0..n_shards)
            .map(|_| {
                Mutex::new(RateLimiter::with_max_entries(
                    max_tokens,
                    refill_rate,
                    per_shard_entries,
                ))
            })
            .collect();
        Self { shards }
    }

    pub fn default_limiter() -> Self {
        Self::new(10_000, 50_000)
    }

    #[inline]
    fn shard_for(&self, ip: IpAddr) -> usize {
        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len()
    }

    /// Check if request from IP is allowed. Lock-contention reduced by shard count.
    pub fn check(&self, ip: IpAddr) -> bool {
        let idx = self.shard_for(ip);
        self.shards[idx].lock().check(ip)
    }

    /// Cleanup all shards periodically.
    pub fn cleanup(&self, max_age_secs: f64) {
        for shard in &self.shards {
            shard.lock().cleanup(max_age_secs);
        }
    }

    pub fn shard_count(&self) -> usize {
        self.shards.len()
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
