//! Rate Limiting и квотирование
//!
//! - Allocation quotas per user / per organization
//! - Bandwidth accounting (sliding window)
//! - STUN auth rate limiting per IP
//! - IP blocking после N неудачных попыток
//! - Lock-free атомарные счётчики на hot path

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Debug, Error)]
pub enum RateLimitError {
    #[error("user {user}: allocation limit {current}/{max}")]
    AllocationLimit { user: String, current: u32, max: u32 },
    #[error("user {user}: bandwidth {current_bps}/{max_bps} bps")]
    BandwidthLimit { user: String, current_bps: u64, max_bps: u64 },
    #[error("IP {ip}: {count}/{max} per {window:?}")]
    RequestRate { ip: IpAddr, count: u32, max: u32, window: Duration },
    #[error("org {org}: allocation limit {current}/{max}")]
    OrgAllocationLimit { org: String, current: u32, max: u32 },
}

pub type Result<T> = std::result::Result<T, RateLimitError>;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub default_user: UserLimits,
    pub default_org: OrgLimits,
    pub auth_rate: AuthRateConfig,
    pub cleanup_interval: Duration,
    pub user_ttl: Duration,
}

#[derive(Debug, Clone)]
pub struct UserLimits {
    pub max_allocations: u32,
    pub max_bandwidth_bps: u64,
    pub max_lifetime: u32,
    pub max_permissions: u32,
}

#[derive(Debug, Clone)]
pub struct OrgLimits {
    pub max_allocations: u32,
    pub max_bandwidth_bps: u64,
}

#[derive(Debug, Clone)]
pub struct AuthRateConfig {
    pub max_per_window: u32,
    pub window: Duration,
    pub max_failures: u32,
    pub block_duration: Duration,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            default_user: UserLimits { max_allocations: 10, max_bandwidth_bps: 10_000_000, max_lifetime: 3600, max_permissions: 50 },
            default_org: OrgLimits { max_allocations: 1000, max_bandwidth_bps: 1_000_000_000 },
            auth_rate: AuthRateConfig { max_per_window: 100, window: Duration::from_secs(60), max_failures: 10, block_duration: Duration::from_secs(300) },
            cleanup_interval: Duration::from_secs(60),
            user_ttl: Duration::from_secs(3600),
        }
    }
}

// ---------------------------------------------------------------------------
// User State
// ---------------------------------------------------------------------------

struct UserState {
    allocs: AtomicU32,
    bw_bytes: AtomicU64,
    bw_start: std::sync::Mutex<Instant>,
    custom: Option<UserLimits>,
    org: Option<String>,
    last_active: std::sync::Mutex<Instant>,
}

impl UserState {
    fn new(custom: Option<UserLimits>, org: Option<String>) -> Self {
        Self {
            allocs: AtomicU32::new(0), bw_bytes: AtomicU64::new(0),
            bw_start: std::sync::Mutex::new(Instant::now()),
            custom, org, last_active: std::sync::Mutex::new(Instant::now()),
        }
    }
    fn touch(&self) { if let Ok(mut t) = self.last_active.lock() { *t = Instant::now(); } }
}

struct SlidingWindow {
    current: AtomicU32,
    previous: AtomicU32,
    start: std::sync::Mutex<Instant>,
    window: Duration,
}

impl SlidingWindow {
    fn new(window: Duration) -> Self {
        Self { current: AtomicU32::new(0), previous: AtomicU32::new(0), start: std::sync::Mutex::new(Instant::now()), window }
    }

    fn increment(&self) -> u32 {
        let now = Instant::now();
        let mut start = self.start.lock().unwrap();
        let elapsed = now.duration_since(*start);
        if elapsed >= self.window * 2 {
            self.previous.store(0, Ordering::Relaxed);
            self.current.store(1, Ordering::Relaxed);
            *start = now; return 1;
        }
        if elapsed >= self.window {
            self.previous.store(self.current.load(Ordering::Relaxed), Ordering::Relaxed);
            self.current.store(1, Ordering::Relaxed);
            *start = now; return 1;
        }
        let cur = self.current.fetch_add(1, Ordering::Relaxed) + 1;
        let prev = self.previous.load(Ordering::Relaxed);
        let w = 1.0 - (elapsed.as_secs_f64() / self.window.as_secs_f64());
        (prev as f64 * w + cur as f64) as u32
    }
}

struct IpBlock {
    failures: AtomicU32,
    blocked_until: std::sync::Mutex<Option<Instant>>,
}

// ---------------------------------------------------------------------------
// Rate Limiter
// ---------------------------------------------------------------------------

pub struct RateLimiter {
    config: RateLimitConfig,
    users: DashMap<String, Arc<UserState>>,
    orgs: DashMap<String, (AtomicU32, AtomicU64)>,
    auth_counters: DashMap<IpAddr, Arc<SlidingWindow>>,
    ip_blocks: DashMap<IpAddr, Arc<IpBlock>>,
    custom_user: DashMap<String, UserLimits>,
    custom_org: DashMap<String, OrgLimits>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config, users: DashMap::new(), orgs: DashMap::new(),
            auth_counters: DashMap::new(), ip_blocks: DashMap::new(),
            custom_user: DashMap::new(), custom_org: DashMap::new(),
        }
    }

    // --- Auth rate ---

    pub fn check_auth_rate(&self, ip: IpAddr) -> Result<()> {
        if let Some(b) = self.ip_blocks.get(&ip) {
            if let Ok(g) = b.blocked_until.lock() { if g.map(|u| Instant::now() < u).unwrap_or(false) {
                return Err(RateLimitError::RequestRate { ip, count: self.config.auth_rate.max_per_window, max: self.config.auth_rate.max_per_window, window: self.config.auth_rate.window });
            }}
        }
        let ctr = self.auth_counters.entry(ip).or_insert_with(|| Arc::new(SlidingWindow::new(self.config.auth_rate.window))).clone();
        let count = ctr.increment();
        if count > self.config.auth_rate.max_per_window {
            return Err(RateLimitError::RequestRate { ip, count, max: self.config.auth_rate.max_per_window, window: self.config.auth_rate.window });
        }
        Ok(())
    }

    pub fn record_auth_failure(&self, ip: IpAddr) {
        let b = self.ip_blocks.entry(ip).or_insert_with(|| Arc::new(IpBlock { failures: AtomicU32::new(0), blocked_until: std::sync::Mutex::new(None) })).clone();
        let n = b.failures.fetch_add(1, Ordering::Relaxed) + 1;
        if n >= self.config.auth_rate.max_failures {
            if let Ok(mut u) = b.blocked_until.lock() { *u = Some(Instant::now() + self.config.auth_rate.block_duration); }
            warn!(%ip, n, "IP blocked");
        }
    }

    pub fn record_auth_success(&self, ip: IpAddr) { self.ip_blocks.remove(&ip); }

    // --- Allocation quota ---

    pub fn try_allocate(&self, user: &str, org: Option<&str>) -> Result<()> {
        let limits = self.user_limits(user);
        let state = self.users.entry(user.into()).or_insert_with(|| Arc::new(UserState::new(self.custom_user.get(user).map(|l| l.clone()), org.map(Into::into)))).clone();
        state.touch();

        let cur = state.allocs.fetch_add(1, Ordering::Relaxed);
        if cur >= limits.max_allocations {
            state.allocs.fetch_sub(1, Ordering::Relaxed);
            return Err(RateLimitError::AllocationLimit { user: user.into(), current: cur, max: limits.max_allocations });
        }

        if let Some(org) = org {
            let ol = self.org_limits(org);
            let os = self.orgs.entry(org.into()).or_insert_with(|| (AtomicU32::new(0), AtomicU64::new(0)));
            let oc = os.0.fetch_add(1, Ordering::Relaxed);
            if oc >= ol.max_allocations {
                os.0.fetch_sub(1, Ordering::Relaxed);
                state.allocs.fetch_sub(1, Ordering::Relaxed);
                return Err(RateLimitError::OrgAllocationLimit { org: org.into(), current: oc, max: ol.max_allocations });
            }
        }
        Ok(())
    }

    pub fn release_allocation(&self, user: &str, org: Option<&str>) {
        if let Some(s) = self.users.get(user) { s.allocs.fetch_sub(1, Ordering::Relaxed); }
        if let Some(o) = org { if let Some(os) = self.orgs.get(o) { os.0.fetch_sub(1, Ordering::Relaxed); } }
    }

    // --- Bandwidth ---

    #[inline]
    pub fn account_bandwidth(&self, user: &str, bytes: u64) -> Result<()> {
        if let Some(s) = self.users.get(user) {
            let lim = s.custom.as_ref().unwrap_or(&self.config.default_user);
            { let start = s.bw_start.lock().unwrap(); if start.elapsed() >= Duration::from_secs(1) { s.bw_bytes.store(0, Ordering::Relaxed); drop(start); if let Ok(mut st) = s.bw_start.lock() { *st = Instant::now(); } } }
            let cur = s.bw_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
            if cur * 8 > lim.max_bandwidth_bps {
                return Err(RateLimitError::BandwidthLimit { user: user.into(), current_bps: cur * 8, max_bps: lim.max_bandwidth_bps });
            }
        }
        Ok(())
    }

    // --- Config ---

    pub fn set_user_limits(&self, user: &str, l: UserLimits) { self.custom_user.insert(user.into(), l); }
    pub fn set_org_limits(&self, org: &str, l: OrgLimits) { self.custom_org.insert(org.into(), l); }
    pub fn user_limits(&self, user: &str) -> UserLimits { self.custom_user.get(user).map(|l| l.clone()).unwrap_or_else(|| self.config.default_user.clone()) }
    pub fn org_limits(&self, org: &str) -> OrgLimits { self.custom_org.get(org).map(|l| l.clone()).unwrap_or_else(|| self.config.default_org.clone()) }

    // --- Metrics ---

    pub fn user_alloc_count(&self, user: &str) -> u32 {
        self.users.get(user).map(|s| s.allocs.load(Ordering::Relaxed)).unwrap_or(0)
    }

    pub fn total_users(&self) -> usize { self.users.len() }
    pub fn total_allocations(&self) -> u32 { self.users.iter().map(|e| e.allocs.load(Ordering::Relaxed)).sum() }

    // --- Cleanup ---

    pub fn cleanup(&self) -> (usize, usize) {
        let ttl = self.config.user_ttl;
        let mut ur = 0;
        self.users.retain(|_, s| {
            let idle = s.last_active.lock().map(|t| t.elapsed() > ttl).unwrap_or(false);
            if s.allocs.load(Ordering::Relaxed) == 0 && idle { ur += 1; false } else { true }
        });
        let mut ir = 0;
        let now = Instant::now();
        self.ip_blocks.retain(|_, b| {
            let still = b.blocked_until.lock().ok().and_then(|g| *g).map(|u| now < u).unwrap_or(false);
            if !still { ir += 1; } still
        });
        (ur, ir)
    }

    pub fn spawn_cleanup(self: &Arc<Self>) {
        let me = Arc::clone(self);
        let interval = me.config.cleanup_interval;
        tokio::spawn(async move { loop {
            tokio::time::sleep(interval).await;
            let (u, i) = me.cleanup();
            if u > 0 || i > 0 { debug!(users = u, ips = i, "cleanup"); }
        }});
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> RateLimiter {
        let mut c = RateLimitConfig::default();
        c.default_user.max_allocations = 3;
        c.auth_rate.max_per_window = 5;
        c.auth_rate.max_failures = 3;
        RateLimiter::new(c)
    }

    #[test]
    fn alloc_limits() {
        let l = limiter();
        assert!(l.try_allocate("a", None).is_ok());
        assert!(l.try_allocate("a", None).is_ok());
        assert!(l.try_allocate("a", None).is_ok());
        assert!(l.try_allocate("a", None).is_err());
        assert!(l.try_allocate("b", None).is_ok());
    }

    #[test]
    fn alloc_release() {
        let l = limiter();
        for _ in 0..3 { l.try_allocate("a", None).unwrap(); }
        l.release_allocation("a", None);
        assert!(l.try_allocate("a", None).is_ok());
    }

    #[test]
    fn auth_rate() {
        let l = limiter();
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        for _ in 0..5 { assert!(l.check_auth_rate(ip).is_ok()); }
        assert!(l.check_auth_rate(ip).is_err());
    }

    #[test]
    fn ip_block() {
        let l = limiter();
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        for _ in 0..3 { l.record_auth_failure(ip); }
        assert!(l.check_auth_rate(ip).is_err());
        l.record_auth_success(ip);
        assert!(l.check_auth_rate(ip).is_ok());
    }

    #[test]
    fn org_limits() {
        let mut c = RateLimitConfig::default();
        c.default_org.max_allocations = 2;
        c.default_user.max_allocations = 10;
        let l = RateLimiter::new(c);
        assert!(l.try_allocate("a", Some("acme")).is_ok());
        assert!(l.try_allocate("b", Some("acme")).is_ok());
        assert!(l.try_allocate("c", Some("acme")).is_err());
    }
}
