//! Per-source-IP handshake rate limiting, shared by the encrypted listeners.
//!
//! Extracted from `crate::quic`, where it was gated behind
//! `any(feature = "quic", feature = "web-transport")` and therefore unreachable
//! from the TURNS listener in a `--features tls` build. The logic is transport
//! agnostic (a token bucket keyed by source IP), so it is ungated here and used
//! by both `tcp_tls` and `quic`.

/// Per-source-IP handshake rate limiter (token bucket).
///
/// `max_sessions_per_ip` bounds how many sessions a source may hold at once,
/// which a source that opens and immediately drops sessions never trips — it
/// stays at one concurrent session while making us pay for a QUIC/H3 handshake
/// every time. This bounds the rate instead. Checked BEFORE the handshake on
/// both paths, so a refused attempt costs a map lookup.
///
/// Entries are reclaimed lazily: a bucket that has been full (i.e. idle) for
/// longer than the refill window is dropped on the next sweep, so the map is
/// bounded by the number of *active* sources, not by every IP ever seen.
pub struct HandshakeLimiter {
    rate_per_sec: f64,
    burst: f64,
    buckets:
        std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (f64, std::time::Instant)>>,
}

impl HandshakeLimiter {
    /// `rate == 0` disables the limiter entirely (`allow` always returns true).
    pub fn new(rate_per_sec: u32, burst: u32) -> Self {
        // A burst below the rate would make a legitimate client that opens a few
        // sessions at once fail; default to twice the rate when unset.
        let burst = if burst == 0 {
            rate_per_sec.saturating_mul(2)
        } else {
            burst
        };
        Self {
            rate_per_sec: f64::from(rate_per_sec),
            burst: f64::from(burst.max(1)),
            buckets: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.rate_per_sec > 0.0
    }

    /// Take one token for `ip`. `false` = over the limit, refuse the handshake.
    pub fn allow(&self, ip: std::net::IpAddr) -> bool {
        if !self.enabled() {
            return true;
        }
        let now = std::time::Instant::now();
        let mut m = match self.buckets.lock() {
            Ok(g) => g,
            // A poisoned lock must not deny service.
            Err(_) => return true,
        };
        let entry = m.entry(ip).or_insert((self.burst, now));
        let elapsed = now.saturating_duration_since(entry.1).as_secs_f64();
        entry.0 = (entry.0 + elapsed * self.rate_per_sec).min(self.burst);
        entry.1 = now;
        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            true
        } else {
            false
        }
    }

    /// Drop idle (full) buckets. Cheap; call from the listener's periodic tick.
    pub fn sweep(&self) {
        if !self.enabled() {
            return;
        }
        let now = std::time::Instant::now();
        if let Ok(mut m) = self.buckets.lock() {
            let burst = self.burst;
            let rate = self.rate_per_sec;
            m.retain(|_, (tokens, last)| {
                let refilled = (*tokens
                    + now.saturating_duration_since(*last).as_secs_f64() * rate)
                    .min(burst);
                // Keep only buckets still carrying debt.
                refilled < burst
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_limiter_disabled_allows_everything() {
        let l = HandshakeLimiter::new(0, 0);
        assert!(!l.enabled());
        let ip: std::net::IpAddr = "203.0.113.7".parse().unwrap();
        for _ in 0..1000 {
            assert!(l.allow(ip), "a disabled limiter must never refuse");
        }
    }

    #[test]
    fn handshake_limiter_spends_burst_then_refuses() {
        // rate 1/s, burst 3: three immediate handshakes pass, the fourth does not.
        let l = HandshakeLimiter::new(1, 3);
        assert!(l.enabled());
        let ip: std::net::IpAddr = "203.0.113.8".parse().unwrap();
        assert!(l.allow(ip));
        assert!(l.allow(ip));
        assert!(l.allow(ip));
        assert!(!l.allow(ip), "burst exhausted");
    }

    #[test]
    fn handshake_limiter_is_per_ip() {
        let l = HandshakeLimiter::new(1, 1);
        let a: std::net::IpAddr = "203.0.113.9".parse().unwrap();
        let b: std::net::IpAddr = "203.0.113.10".parse().unwrap();
        assert!(l.allow(a));
        assert!(!l.allow(a), "a is out of tokens");
        assert!(l.allow(b), "b must not be affected by a");
    }

    #[test]
    fn handshake_limiter_default_burst_is_twice_the_rate() {
        // burst = 0 means "pick a sane default", not "no burst" — otherwise a
        // client opening two sessions at once would be refused at rate >= 1.
        let l = HandshakeLimiter::new(5, 0);
        let ip: std::net::IpAddr = "203.0.113.11".parse().unwrap();
        let mut allowed = 0;
        for _ in 0..20 {
            if l.allow(ip) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 10, "burst should default to 2x rate");
    }
}
