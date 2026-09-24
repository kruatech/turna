//! Automatic, temporary source bans — `[turn.auto_ban]`, fail2ban built in.
//!
//! A source that fails authentication `auth_failures` times (or trips a rate
//! limiter `rate_limit_violations` times) inside `window` is dropped outright
//! for `ban`: every packet from it, STUN and ChannelData alike, is discarded at
//! the top of [`PacketProcessor::process`](crate::PacketProcessor::process)
//! before classification, rate limiting, parsing or authentication.
//!
//! # Why it is shaped like this
//!
//! **The check has to be cheaper than what it protects.** It runs on every
//! packet, including the media hot path. With no ban in force it is one relaxed
//! atomic load; with bans in force it is one `DashMap` read on the source key.
//! There is no allowlist scan on that path — an allowlisted source is never
//! *entered* into the table, so it can never be found in it.
//!
//! **Memory is bounded twice.** Offence counters are capped at `max_tracked`
//! (the idlest of a small sample is evicted, the same trade `turna-qos` makes:
//! a spoofed source sends once and ages, a persistent one does not). Bans are
//! capped at `max_bans`; when the table is full of live bans a new one is
//! refused and counted rather than evicting an existing ban — the older ban was
//! earned by the same evidence, and a flood that could push bans out would be a
//! way to unban oneself.
//!
//! **Auth-failure evidence cannot be spoofed; rate-limit evidence can.** The
//! auth-failure trigger is fed only from requests that already carried a valid,
//! client-bound NONCE (the processor validates it before credentials), so the
//! offender completed a round trip from the address being banned. Binding
//! requests with bad MESSAGE-INTEGRITY are *not* counted: they skip the nonce
//! and a forged source could get a victim banned. The rate-limit trigger fires
//! on raw packet floods, which over UDP can carry any source address — that is
//! why it defaults to off and why `docs/security/accepted-risks.md` says so.
//!
//! **Expiry needs no timer.** A ban is an expiry timestamp; the hot-path check
//! compares against it, so an expired ban stops applying at once even if nothing
//! has swept it. [`sweep_and_log`] removes expired entries, emits the `unban`
//! security event, and is driven by the node's maintenance loop.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{info, warn};

use crate::peer_filter::Cidr;

/// What the operator configured. Primitive types only: turna-relay does not
/// depend on turna-config (see `rate_limit_settings` in the node).
#[derive(Debug, Clone)]
pub struct AutoBanSettings {
    /// Auth failures within `window` that trigger a ban. 0 disables the trigger.
    pub auth_failures: u32,
    /// Rate-limit refusals within `window` that trigger a ban. 0 disables it.
    pub rate_limit_violations: u32,
    /// Credential-webhook lookups started (or refused by the per-source lookup
    /// limit) within `window` that trigger a ban. 0 disables it.
    pub credential_lookups: u32,
    /// Counting window.
    pub window: Duration,
    /// How long a ban lasts.
    pub ban: Duration,
    /// Count and ban per /24 (IPv4) or /48 (IPv6) rather than per address.
    pub prefix_scope: bool,
    /// CIDR ranges that are never counted and never banned.
    pub allowlist: Vec<String>,
    /// Cap on sources with a running offence count.
    pub max_tracked: usize,
    /// Cap on simultaneous bans.
    pub max_bans: usize,
}

/// Why a source was counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offence {
    AuthFailure,
    RateLimited,
    /// `[turn.auth.webhook]`: this source started a credential lookup, or was
    /// refused one by the per-source lookup limit. A client logs in with one
    /// or two names; a source cycling through many is enumerating users or
    /// trying to exhaust the lookup queue.
    CredentialLookup,
}

impl Offence {
    fn as_str(self) -> &'static str {
        match self {
            Offence::AuthFailure => "auth_failures",
            Offence::RateLimited => "rate_limit_violations",
            Offence::CredentialLookup => "credential_lookups",
        }
    }
}

/// A ban that was just imposed.
#[derive(Debug, Clone)]
pub struct BanEvent {
    /// The banned key: the address, or the prefix under `prefix_scope`.
    pub key: IpAddr,
    pub offence: Offence,
    /// Offences counted in the window that tipped it.
    pub count: u32,
    pub duration: Duration,
    pub prefix_scope: bool,
}

struct Counter {
    window_start_ms: u64,
    last_ms: u64,
    auth: u32,
    rate_limited: u32,
    lookups: u32,
}

/// The ban table. Shared (`Arc`) by every processor on the node, so a source
/// banned on the UDP path is banned on TURNS, DTLS and QUIC too.
pub struct AutoBan {
    settings: AutoBanSettings,
    allow: Vec<Cidr>,
    base: Instant,
    counters: DashMap<IpAddr, Counter>,
    /// key → expiry, in ms since `base`.
    bans: DashMap<IpAddr, u64>,
    /// Entries in `bans`, live or not yet swept. The hot path's fast exit.
    active: AtomicUsize,
    /// Bans imposed since start.
    pub bans_total: AtomicU64,
    /// Bans refused because `max_bans` live bans were already in force.
    pub bans_refused_full: AtomicU64,
    /// Offence counters evicted to admit a new source.
    pub counter_evictions: AtomicU64,
}

impl std::fmt::Debug for AutoBan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AutoBan")
            .field("settings", &self.settings)
            .field("active", &self.active.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl AutoBan {
    pub fn new(settings: AutoBanSettings) -> Self {
        let allow = crate::peer_filter::parse_ranges(&settings.allowlist, "auto_ban.allowlist");
        Self {
            settings,
            allow,
            base: Instant::now(),
            counters: DashMap::new(),
            bans: DashMap::new(),
            active: AtomicUsize::new(0),
            bans_total: AtomicU64::new(0),
            bans_refused_full: AtomicU64::new(0),
            counter_evictions: AtomicU64::new(0),
        }
    }

    pub fn settings(&self) -> &AutoBanSettings {
        &self.settings
    }

    #[inline]
    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    #[inline]
    fn key(&self, ip: IpAddr) -> IpAddr {
        if self.settings.prefix_scope {
            turna_qos::aggregation_prefix(ip)
        } else {
            ip
        }
    }

    /// Is `ip` banned right now? The per-packet check.
    #[inline]
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        if self.active.load(Ordering::Relaxed) == 0 {
            return false;
        }
        self.is_banned_at(ip, self.now_ms())
    }

    fn is_banned_at(&self, ip: IpAddr, now_ms: u64) -> bool {
        let ip = unmap(ip);
        let live = match self.bans.get(&self.key(ip)) {
            Some(expiry) => *expiry > now_ms,
            None => false,
        };
        // Under prefix scope a ban covers addresses that were never counted,
        // including allowlisted ones inside the banned block. The allowlist wins.
        // Only reached when a ban matched, so the common path pays nothing.
        live && !(self.settings.prefix_scope && self.allowlisted(ip))
    }

    fn allowlisted(&self, ip: IpAddr) -> bool {
        self.allow.iter().any(|c| c.contains(ip))
    }

    /// Count one offence from `ip`. Returns the ban it caused, if any.
    pub fn record(&self, ip: IpAddr, offence: Offence) -> Option<BanEvent> {
        self.record_at(ip, offence, self.now_ms())
    }

    fn record_at(&self, ip: IpAddr, offence: Offence, now_ms: u64) -> Option<BanEvent> {
        let ip = unmap(ip);
        let threshold = match offence {
            Offence::AuthFailure => self.settings.auth_failures,
            Offence::RateLimited => self.settings.rate_limit_violations,
            Offence::CredentialLookup => self.settings.credential_lookups,
        };
        if threshold == 0 || self.allowlisted(ip) {
            return None;
        }
        // Already banned: its packets are dropped before they can offend again,
        // except the ones in flight when the ban landed. Do not re-count those.
        if self.is_banned_at(ip, now_ms) {
            return None;
        }
        let key = self.key(ip);
        let window_ms = self.settings.window.as_millis() as u64;

        if !self.counters.contains_key(&key) && self.counters.len() >= self.settings.max_tracked {
            self.evict_idlest_counter();
        }
        let count = {
            let mut c = self.counters.entry(key).or_insert(Counter {
                window_start_ms: now_ms,
                last_ms: now_ms,
                auth: 0,
                rate_limited: 0,
                lookups: 0,
            });
            if now_ms.saturating_sub(c.window_start_ms) >= window_ms {
                c.window_start_ms = now_ms;
                c.auth = 0;
                c.rate_limited = 0;
                c.lookups = 0;
            }
            c.last_ms = now_ms;
            let slot = match offence {
                Offence::AuthFailure => &mut c.auth,
                Offence::RateLimited => &mut c.rate_limited,
                Offence::CredentialLookup => &mut c.lookups,
            };
            *slot = slot.saturating_add(1);
            *slot
        };
        if count < threshold {
            return None;
        }
        // The guard above is dropped before touching `bans` or removing from
        // `counters`: DashMap locks per shard, and holding a guard across a
        // write to the same shard deadlocks.
        self.counters.remove(&key);
        if !self.impose(key, now_ms) {
            return None;
        }
        Some(BanEvent {
            key,
            offence,
            count,
            duration: self.settings.ban,
            prefix_scope: self.settings.prefix_scope,
        })
    }

    /// Enter a ban. `false` when the table is full of live bans.
    fn impose(&self, key: IpAddr, now_ms: u64) -> bool {
        let expiry = now_ms.saturating_add(self.settings.ban.as_millis() as u64);
        if !self.bans.contains_key(&key) && self.bans.len() >= self.settings.max_bans {
            // Reclaim expired entries before refusing.
            self.sweep_at(now_ms);
            if self.bans.len() >= self.settings.max_bans {
                self.bans_refused_full.fetch_add(1, Ordering::Relaxed);
                return false;
            }
        }
        match self.bans.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut e) => {
                // An expired, unswept ban: re-arm it. Already counted in `active`.
                *e.get_mut() = expiry;
            }
            dashmap::mapref::entry::Entry::Vacant(e) => {
                e.insert(expiry);
                self.active.fetch_add(1, Ordering::Relaxed);
            }
        }
        self.bans_total.fetch_add(1, Ordering::Relaxed);
        true
    }

    fn evict_idlest_counter(&self) {
        const SAMPLE: usize = 8;
        let mut victim: Option<(IpAddr, u64)> = None;
        for e in self.counters.iter().take(SAMPLE) {
            let last = e.value().last_ms;
            if victim.is_none_or(|(_, best)| last < best) {
                victim = Some((*e.key(), last));
            }
        }
        if let Some((k, _)) = victim {
            if self.counters.remove(&k).is_some() {
                self.counter_evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Remove expired bans and stale counters. Returns the keys unbanned.
    pub fn sweep(&self) -> Vec<IpAddr> {
        self.sweep_at(self.now_ms())
    }

    fn sweep_at(&self, now_ms: u64) -> Vec<IpAddr> {
        let mut expired = Vec::new();
        self.bans.retain(|k, expiry| {
            if *expiry <= now_ms {
                expired.push(*k);
                false
            } else {
                true
            }
        });
        if !expired.is_empty() {
            self.active.fetch_sub(expired.len(), Ordering::Relaxed);
        }
        let window_ms = self.settings.window.as_millis() as u64;
        self.counters
            .retain(|_, c| now_ms.saturating_sub(c.window_start_ms) < window_ms);
        expired
    }

    /// Bans in the table (live, or expired and not yet swept).
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }

    /// Sources with a running offence count.
    pub fn tracked(&self) -> usize {
        self.counters.len()
    }
}

/// Emit the security event for a ban just imposed.
///
/// The message text is matched by `turna_observability::syslog_layer`
/// (`"auto-ban"` → `SOURCE_BANNED`), and this module is one of its security
/// targets, so the line reaches the SIEM with `src_ip`, `reason` and `detail`.
/// The address goes through the same redaction switch as every other client
/// address the processor logs.
pub fn log_ban(ev: &BanEvent) {
    warn!(
        src_ip = %crate::processor::loggable_ip(&ev.key),
        reason = ev.offence.as_str(),
        detail = %format!(
            "{} offences in the window; banned for {}s; scope {}",
            ev.count,
            ev.duration.as_secs(),
            if ev.prefix_scope { "prefix" } else { "ip" }
        ),
        "auto-ban: source banned"
    );
}

/// Sweep expired bans and emit one `unban` event per key. Returns the number of
/// bans still in the table, for the `turna_autoban_active` gauge.
pub fn sweep_and_log(ban: &AutoBan) -> usize {
    for key in ban.sweep() {
        info!(
            src_ip = %crate::processor::loggable_ip(&key),
            state = "expired",
            "auto-ban: ban expired, source unbanned"
        );
    }
    ban.active()
}

/// A v4-mapped IPv6 address (`::ffff:a.b.c.d`, from a dual-stack socket) is
/// the IPv4 client: key, allowlist and prefix all use the IPv4 form.
#[inline]
fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> AutoBanSettings {
        AutoBanSettings {
            auth_failures: 3,
            rate_limit_violations: 0,
            credential_lookups: 0,
            window: Duration::from_secs(60),
            ban: Duration::from_secs(600),
            prefix_scope: false,
            allowlist: vec!["10.0.0.0/8".into()],
            max_tracked: 16,
            max_bans: 4,
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn bans_after_threshold_within_window_and_not_before() {
        let b = AutoBan::new(settings());
        let a = ip("203.0.113.7");
        assert!(b.record_at(a, Offence::AuthFailure, 0).is_none());
        assert!(b.record_at(a, Offence::AuthFailure, 10).is_none());
        assert!(!b.is_banned_at(a, 20));
        let ev = b
            .record_at(a, Offence::AuthFailure, 20)
            .expect("third failure bans");
        assert_eq!(ev.key, a);
        assert_eq!(ev.count, 3);
        assert!(b.is_banned_at(a, 21));
        assert_eq!(b.active(), 1);
        assert_eq!(b.bans_total.load(Ordering::Relaxed), 1);
        // A neighbour is unaffected in ip scope.
        assert!(!b.is_banned_at(ip("203.0.113.8"), 21));
    }

    #[test]
    fn window_resets_the_count() {
        let b = AutoBan::new(settings());
        let a = ip("203.0.113.7");
        b.record_at(a, Offence::AuthFailure, 0);
        b.record_at(a, Offence::AuthFailure, 1);
        // Past the 60 s window: counting restarts, so this is failure one.
        assert!(b.record_at(a, Offence::AuthFailure, 61_000).is_none());
        assert!(b.record_at(a, Offence::AuthFailure, 61_001).is_none());
        assert!(b.record_at(a, Offence::AuthFailure, 61_002).is_some());
    }

    #[test]
    fn ban_expires_without_a_sweep_and_the_sweep_reports_it() {
        let b = AutoBan::new(settings());
        let a = ip("198.51.100.1");
        for t in 0..3 {
            b.record_at(a, Offence::AuthFailure, t);
        }
        assert!(b.is_banned_at(a, 599_000));
        // Expiry applies at once on the hot path, before any sweep.
        assert!(!b.is_banned_at(a, 600_003));
        assert_eq!(b.sweep_at(600_003), vec![a]);
        assert_eq!(b.active(), 0);
        assert!(!b.is_banned(a), "fast exit once the table is empty");
    }

    #[test]
    fn allowlisted_sources_are_never_counted_or_banned() {
        let b = AutoBan::new(settings());
        let a = ip("10.1.2.3");
        for t in 0..100 {
            assert!(b.record_at(a, Offence::AuthFailure, t).is_none());
        }
        assert_eq!(b.tracked(), 0);
        assert!(!b.is_banned_at(a, 100));
    }

    #[test]
    fn disabled_trigger_never_bans() {
        let b = AutoBan::new(settings());
        let a = ip("192.0.2.1");
        for t in 0..1000 {
            assert!(b.record_at(a, Offence::RateLimited, t).is_none());
        }
    }

    #[test]
    fn prefix_scope_bans_the_whole_24() {
        let mut s = settings();
        s.prefix_scope = true;
        let b = AutoBan::new(s);
        // Failures spread over three addresses of one /24 add up.
        b.record_at(ip("203.0.113.1"), Offence::AuthFailure, 0);
        b.record_at(ip("203.0.113.2"), Offence::AuthFailure, 1);
        let ev = b
            .record_at(ip("203.0.113.3"), Offence::AuthFailure, 2)
            .expect("third failure in the /24 bans it");
        assert_eq!(ev.key, ip("203.0.113.0"));
        assert!(b.is_banned_at(ip("203.0.113.250"), 3));
        assert!(!b.is_banned_at(ip("203.0.114.1"), 3));
    }

    #[test]
    fn allowlisted_address_inside_a_banned_prefix_is_not_dropped() {
        let mut s = settings();
        s.prefix_scope = true;
        s.allowlist = vec!["203.0.113.200/32".into()];
        let b = AutoBan::new(s);
        for (i, t) in [(1, 0), (2, 1), (3, 2)] {
            b.record_at(ip(&format!("203.0.113.{i}")), Offence::AuthFailure, t);
        }
        assert!(b.is_banned_at(ip("203.0.113.9"), 3));
        assert!(
            !b.is_banned_at(ip("203.0.113.200"), 3),
            "the allowlist wins over a prefix ban"
        );
    }

    #[test]
    fn v4_mapped_sources_are_the_ipv4_client() {
        let mut s = settings();
        s.prefix_scope = true;
        let b = AutoBan::new(s);
        for t in 0..3 {
            b.record_at(ip("::ffff:203.0.113.7"), Offence::AuthFailure, t);
        }
        assert!(b.is_banned_at(ip("203.0.113.8"), 5));
        assert!(
            !b.is_banned_at(ip("::ffff:198.51.100.1"), 5),
            "other IPv4 clients of a dual-stack socket are not in the ban"
        );
        // Allowlist written in IPv4 applies to the mapped form.
        let b = AutoBan::new(settings());
        for t in 0..10 {
            assert!(b
                .record_at(ip("::ffff:10.1.2.3"), Offence::AuthFailure, t)
                .is_none());
        }
    }

    #[test]
    fn credential_lookups_have_their_own_threshold() {
        let mut s = settings();
        s.credential_lookups = 2;
        let b = AutoBan::new(s);
        let a = ip("192.0.2.77");
        assert!(b.record_at(a, Offence::CredentialLookup, 0).is_none());
        // Auth failures do not add to the lookup count, and vice versa.
        assert!(b.record_at(a, Offence::AuthFailure, 1).is_none());
        let ev = b
            .record_at(a, Offence::CredentialLookup, 2)
            .expect("banned");
        assert_eq!(ev.offence, Offence::CredentialLookup);
    }

    #[test]
    fn memory_is_bounded() {
        let b = AutoBan::new(settings());
        // 1000 distinct sources, one failure each: counters stay at the cap.
        for i in 0..1000u32 {
            let a = IpAddr::from(std::net::Ipv4Addr::from(0xC000_0000 + i));
            b.record_at(a, Offence::AuthFailure, i as u64);
        }
        assert!(b.tracked() <= 16, "tracked {} > max_tracked", b.tracked());
        assert!(b.counter_evictions.load(Ordering::Relaxed) > 0);

        // Bans cap at max_bans; the fifth live ban is refused, not evicting one.
        for n in 0..5u32 {
            let a = IpAddr::from(std::net::Ipv4Addr::from(0xCB00_7100 + n));
            for t in 0..3 {
                b.record_at(a, Offence::AuthFailure, 2_000 + t);
            }
        }
        assert_eq!(b.active(), 4);
        assert_eq!(b.bans_refused_full.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn full_table_reclaims_expired_bans_before_refusing() {
        let b = AutoBan::new(settings());
        for n in 0..4u32 {
            let a = IpAddr::from(std::net::Ipv4Addr::from(0xCB00_7100 + n));
            for t in 0..3 {
                b.record_at(a, Offence::AuthFailure, t);
            }
        }
        assert_eq!(b.active(), 4);
        // All four expired; a new ban reclaims them instead of being refused.
        let late = ip("192.0.2.200");
        for t in 0..3 {
            b.record_at(late, Offence::AuthFailure, 700_000 + t);
        }
        assert!(b.is_banned_at(late, 700_010));
        assert_eq!(b.bans_refused_full.load(Ordering::Relaxed), 0);
        assert_eq!(b.active(), 1);
    }
}
