//! Credential lookup through the operator's signalling service —
//! `[turn.auth.webhook]`.
//!
//! When a long-term-credential request names a user that is not configured
//! locally, turna can ask an HTTPS endpoint for that user's key (or password)
//! and cache the answer. The HTTP client lives in the node; this module is the
//! part the **datapath** touches, and it never blocks and never does I/O.
//!
//! # Where this sits, and why
//!
//! `PacketProcessor` is synchronous — one call per packet, shared by the tokio,
//! io_uring and AF_XDP paths — and `AuthMode::validate` runs inside it. An HTTP
//! round trip there would stall a receive worker for the length of the request
//! and every client hashed to it with it. So validation only ever *consults*
//! this cache:
//!
//! - a fresh entry answers at once (`Found` / `NotFound` / `Unavailable`);
//! - a miss enqueues **one** fetch for that username (concurrent requests for
//!   the same name share it) and returns `Pending` with a [`Waiter`];
//! - the processor drops a pending UDP request silently — the client's own STUN
//!   retransmission (RFC 8489 §6.2.1, 500 ms first RTO) arrives after the fetch
//!   completes and hits the cache — and hands the waiter to the TURNS/SCTP
//!   bridges, whose clients do not retransmit, so they can re-process the same
//!   request when the answer lands.
//!
//! # Failure handling: closed
//!
//! A fetch that times out, errors, or returns anything but a well-formed 200 or
//! a 404 caches `Failed` for `error_ttl`, and every request for that user fails
//! with [`crate::AuthError::Unavailable`] until it expires. A full fetch queue
//! is also `Unavailable`. Nothing on this path ever admits a client the
//! signalling service did not vouch for.
//!
//! # Bounds
//!
//! `max_entries` caps the table (expired entries and then the soonest-expiring
//! are evicted; in-flight entries never are), `queue_depth` caps pending
//! fetches, and the node's fetcher caps concurrency. USERNAME is limited to 513
//! bytes by RFC 8489 §14.3; longer names are refused without a lookup.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::mapref::entry::Entry as MapEntry;
use dashmap::DashMap;
use tokio::sync::{mpsc, watch};

use crate::UserKeys;

/// RFC 8489 §14.3: USERNAME is less than 513 bytes.
const MAX_USERNAME_BYTES: usize = 513;

/// Cache tunables, from `[turn.auth.webhook]`.
#[derive(Debug, Clone)]
pub struct WebhookSettings {
    /// How long a found user's keys are trusted without asking again. The
    /// endpoint may shorten it per answer with `ttl_secs`, never lengthen it.
    pub positive_ttl: Duration,
    /// How long "no such user" is remembered.
    pub negative_ttl: Duration,
    /// How long a failed lookup keeps failing without a retry.
    pub error_ttl: Duration,
    /// Cap on cached users (memory bound).
    pub max_entries: usize,
    /// Cap on fetches waiting for a worker.
    pub queue_depth: usize,
}

/// One lookup for the node's fetcher to perform.
#[derive(Debug, Clone)]
pub struct FetchJob {
    pub username: String,
    pub realm: String,
}

/// What a fetch produced.
#[derive(Debug, Clone)]
pub enum FetchOutcome {
    /// The user exists. `ttl` is the endpoint's own cache hint, if it sent one.
    Found {
        keys: UserKeys,
        ttl: Option<Duration>,
    },
    /// The endpoint says the user does not exist (HTTP 404).
    NotFound,
    /// Anything else: timeout, transport error, non-2xx, malformed body.
    Failed,
}

/// Result of consulting the cache.
#[derive(Debug)]
pub enum Lookup {
    Found(UserKeys),
    NotFound,
    /// The last fetch failed, or no fetch could be queued. Fail closed.
    Unavailable,
    /// A fetch is in flight; wait on this, then process the request again.
    Pending(Waiter),
}

/// Resolves when the in-flight fetch it was handed for completes (or its entry
/// is dropped). Cheap to clone; many requests may wait on one fetch.
#[derive(Debug, Clone)]
pub struct Waiter(watch::Receiver<bool>);

impl Waiter {
    /// Wait for the fetch to finish. Callers bound this with their own timeout.
    pub async fn wait(mut self) {
        // Err means the sender was dropped: the entry was evicted or replaced.
        // Either way there is nothing more to wait for.
        let _ = self.0.wait_for(|done| *done).await;
    }
}

enum State {
    Found(UserKeys),
    NotFound,
    Failed,
    InFlight {
        done: watch::Sender<bool>,
        waiter: watch::Receiver<bool>,
    },
}

struct Slot {
    state: State,
    /// ms since `base`. Unused while in flight.
    expires_ms: u64,
}

/// Counters, mirrored into Prometheus by the node.
#[derive(Default, Debug)]
pub struct WebhookStats {
    /// Answered from a cached "found".
    pub hits: AtomicU64,
    /// Answered from a cached "not found".
    pub negative_hits: AtomicU64,
    /// Answered from a cached failure (fail closed).
    pub error_hits: AtomicU64,
    /// No usable entry: a fetch was queued.
    pub misses: AtomicU64,
    /// A request arrived while its user's fetch was already in flight.
    pub coalesced: AtomicU64,
    /// No fetch could be queued (queue full, table full of in-flight entries,
    /// or the fetcher gone). Answered `Unavailable`.
    pub rejected: AtomicU64,
    /// Entries evicted to make room.
    pub evictions: AtomicU64,
}

/// The shared cache. One per realm that has a webhook (today: the base realm).
pub struct CredentialCache {
    realm: String,
    settings: WebhookSettings,
    entries: DashMap<String, Slot>,
    queue: mpsc::Sender<FetchJob>,
    base: Instant,
    pub stats: WebhookStats,
}

impl std::fmt::Debug for CredentialCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialCache")
            .field("realm", &self.realm)
            .field("entries", &self.entries.len())
            .finish_non_exhaustive()
    }
}

impl CredentialCache {
    /// Build the cache and the receiving end of its fetch queue, which the
    /// node's fetcher drains.
    pub fn new(
        realm: impl Into<String>,
        settings: WebhookSettings,
    ) -> (Arc<Self>, mpsc::Receiver<FetchJob>) {
        let (tx, rx) = mpsc::channel(settings.queue_depth.max(1));
        let cache = Arc::new(Self {
            realm: realm.into(),
            settings,
            entries: DashMap::new(),
            queue: tx,
            base: Instant::now(),
            stats: WebhookStats::default(),
        });
        (cache, rx)
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Cached users, including in-flight and expired-but-unswept entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[inline]
    fn now_ms(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    fn answer(&self, slot: &Slot, now_ms: u64) -> Option<Lookup> {
        match &slot.state {
            State::InFlight { waiter, .. } => {
                self.stats.coalesced.fetch_add(1, Ordering::Relaxed);
                Some(Lookup::Pending(Waiter(waiter.clone())))
            }
            _ if slot.expires_ms <= now_ms => None,
            State::Found(keys) => {
                self.stats.hits.fetch_add(1, Ordering::Relaxed);
                Some(Lookup::Found(keys.clone()))
            }
            State::NotFound => {
                self.stats.negative_hits.fetch_add(1, Ordering::Relaxed);
                Some(Lookup::NotFound)
            }
            State::Failed => {
                self.stats.error_hits.fetch_add(1, Ordering::Relaxed);
                Some(Lookup::Unavailable)
            }
        }
    }

    /// Consult the cache without ever starting a fetch. A miss or an in-flight
    /// entry reads as `NotFound`. For request paths whose source address has
    /// not been proven (no NONCE round trip), which must not be able to make
    /// the node send HTTP requests on a forger's behalf.
    pub fn peek(&self, username: &str) -> Lookup {
        let now = self.now_ms();
        match self.entries.get(username) {
            Some(slot) => match &slot.state {
                State::InFlight { .. } => Lookup::NotFound,
                _ => self.answer(&slot, now).unwrap_or(Lookup::NotFound),
            },
            None => Lookup::NotFound,
        }
    }

    /// Consult the cache, starting a fetch on a miss. Never blocks.
    pub fn lookup(&self, username: &str) -> Lookup {
        if username.is_empty() || username.len() >= MAX_USERNAME_BYTES {
            return Lookup::NotFound;
        }
        let now = self.now_ms();
        if let Some(slot) = self.entries.get(username) {
            if let Some(answer) = self.answer(&slot, now) {
                return answer;
            }
        }
        // Make room before inserting. The guard above is dropped: DashMap locks
        // per shard and an eviction may touch the same one.
        if !self.entries.contains_key(username)
            && self.entries.len() >= self.settings.max_entries
            && !self.evict_one(now)
        {
            self.stats.rejected.fetch_add(1, Ordering::Relaxed);
            return Lookup::Unavailable;
        }
        let waiter = match self.entries.entry(username.to_string()) {
            MapEntry::Occupied(mut o) => {
                // Raced with another request for the same user.
                if let Some(answer) = self.answer(o.get(), now) {
                    return answer;
                }
                let (done, waiter) = watch::channel(false);
                o.get_mut().state = State::InFlight {
                    done,
                    waiter: waiter.clone(),
                };
                waiter
            }
            MapEntry::Vacant(v) => {
                let (done, waiter) = watch::channel(false);
                v.insert(Slot {
                    state: State::InFlight {
                        done,
                        waiter: waiter.clone(),
                    },
                    expires_ms: 0,
                });
                waiter
            }
        };
        self.stats.misses.fetch_add(1, Ordering::Relaxed);
        let job = FetchJob {
            username: username.to_string(),
            realm: self.realm.clone(),
        };
        if self.queue.try_send(job).is_err() {
            // Queue full or fetcher gone. Remove the in-flight marker so the
            // next request tries again rather than waiting on nothing; dropping
            // its sender wakes anyone who already cloned the waiter.
            self.entries
                .remove_if(username, |_, s| matches!(s.state, State::InFlight { .. }));
            self.stats.rejected.fetch_add(1, Ordering::Relaxed);
            return Lookup::Unavailable;
        }
        Lookup::Pending(Waiter(waiter))
    }

    /// Record a fetch result and wake its waiters.
    pub fn complete(&self, username: &str, outcome: FetchOutcome) {
        let now = self.now_ms();
        let s = &self.settings;
        let (state, ttl) = match outcome {
            FetchOutcome::Found { keys, ttl } => (
                State::Found(keys),
                ttl.map(|t| t.min(s.positive_ttl)).unwrap_or(s.positive_ttl),
            ),
            FetchOutcome::NotFound => (State::NotFound, s.negative_ttl),
            FetchOutcome::Failed => (State::Failed, s.error_ttl),
        };
        let expires_ms = now.saturating_add(ttl.as_millis() as u64);
        let previous = match self.entries.get_mut(username) {
            Some(mut slot) => {
                let old = std::mem::replace(&mut slot.state, state);
                slot.expires_ms = expires_ms;
                Some(old)
            }
            // Evicted while in flight (cannot happen — in-flight entries are
            // never evicted — or removed by a queue failure). Nothing to do:
            // caching an answer nobody asked to keep would only cost memory.
            None => None,
        };
        if let Some(State::InFlight { done, .. }) = previous {
            let _ = done.send(true);
        }
    }

    /// Drop expired entries. The node calls this periodically; lookups treat an
    /// expired entry as a miss whether or not it has been swept.
    pub fn sweep(&self) {
        let now = self.now_ms();
        self.entries
            .retain(|_, s| matches!(s.state, State::InFlight { .. }) || s.expires_ms > now);
    }

    /// Evict one entry: an expired one if the sample has it, else the one that
    /// expires soonest. Never an in-flight entry. `false` if the sample held
    /// nothing evictable.
    fn evict_one(&self, now: u64) -> bool {
        const SAMPLE: usize = 16;
        let mut victim: Option<(String, u64)> = None;
        for e in self.entries.iter().take(SAMPLE) {
            if matches!(e.value().state, State::InFlight { .. }) {
                continue;
            }
            let exp = e.value().expires_ms;
            if victim.as_ref().is_none_or(|(_, best)| exp < *best) {
                victim = Some((e.key().clone(), exp));
            }
            if exp <= now {
                break;
            }
        }
        match victim {
            Some((k, _)) => {
                let removed = self
                    .entries
                    .remove_if(&k, |_, s| !matches!(s.state, State::InFlight { .. }))
                    .is_some();
                if removed {
                    self.stats.evictions.fetch_add(1, Ordering::Relaxed);
                }
                removed
            }
            None => false,
        }
    }
}

/// `X-Turna-Signature` value for a webhook request: `v1=` followed by the hex
/// HMAC-SHA256 of `"<timestamp>.<body>"` under the configured signing secret.
///
/// The timestamp is the decimal Unix time sent in `X-Turna-Timestamp`; binding
/// it into the MAC lets the receiver reject replays outside its own window.
/// Public so a signalling service written in Rust can verify with the same
/// function, and so the documented contract has one implementation.
pub fn sign_request(secret: &[u8], timestamp: u64, body: &[u8]) -> String {
    let mut msg = Vec::with_capacity(body.len() + 21);
    msg.extend_from_slice(timestamp.to_string().as_bytes());
    msg.push(b'.');
    msg.extend_from_slice(body);
    let mac = turna_crypto::hmac_sha256(secret, &msg);
    let mut out = String::with_capacity(3 + 64);
    out.push_str("v1=");
    for b in mac {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> WebhookSettings {
        WebhookSettings {
            positive_ttl: Duration::from_secs(300),
            negative_ttl: Duration::from_secs(30),
            error_ttl: Duration::from_secs(2),
            max_entries: 4,
            queue_depth: 8,
        }
    }

    fn keys() -> UserKeys {
        UserKeys {
            key_md5: vec![1; 16],
            key_sha256: vec![2; 32],
        }
    }

    #[test]
    fn miss_queues_one_fetch_and_coalesces_concurrent_requests() {
        let (c, mut rx) = CredentialCache::new("r", settings());
        assert!(matches!(c.lookup("alice"), Lookup::Pending(_)));
        assert!(matches!(c.lookup("alice"), Lookup::Pending(_)));
        let job = rx.try_recv().expect("one job queued");
        assert_eq!(job.username, "alice");
        assert_eq!(job.realm, "r");
        assert!(
            rx.try_recv().is_err(),
            "the second request shares the fetch"
        );
        assert_eq!(c.stats.misses.load(Ordering::Relaxed), 1);
        assert_eq!(c.stats.coalesced.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn completion_wakes_waiters_and_is_served_from_cache() {
        let (c, mut rx) = CredentialCache::new("r", settings());
        let Lookup::Pending(w) = c.lookup("alice") else {
            panic!("expected pending")
        };
        let job = rx.recv().await.unwrap();
        let c2 = c.clone();
        let waiter = tokio::spawn(async move { w.wait().await });
        c2.complete(
            &job.username,
            FetchOutcome::Found {
                keys: keys(),
                ttl: None,
            },
        );
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter woke")
            .unwrap();
        match c.lookup("alice") {
            Lookup::Found(k) => assert_eq!(k.key_md5, vec![1; 16]),
            other => panic!("expected Found, got {other:?}"),
        }
        assert_eq!(c.stats.hits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn negative_and_failed_answers_are_cached() {
        let (c, _rx) = CredentialCache::new("r", settings());
        let _ = c.lookup("ghost");
        c.complete("ghost", FetchOutcome::NotFound);
        assert!(matches!(c.lookup("ghost"), Lookup::NotFound));
        let _ = c.lookup("flaky");
        c.complete("flaky", FetchOutcome::Failed);
        assert!(
            matches!(c.lookup("flaky"), Lookup::Unavailable),
            "a failed fetch fails closed"
        );
        assert_eq!(c.stats.negative_hits.load(Ordering::Relaxed), 1);
        assert_eq!(c.stats.error_hits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn expired_entries_refetch() {
        let mut s = settings();
        s.negative_ttl = Duration::from_millis(0);
        let (c, mut rx) = CredentialCache::new("r", s);
        let _ = c.lookup("ghost");
        let _ = rx.try_recv();
        c.complete("ghost", FetchOutcome::NotFound);
        // TTL 0: already expired, so this is a miss with a new fetch.
        assert!(matches!(c.lookup("ghost"), Lookup::Pending(_)));
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn endpoint_ttl_can_shorten_but_not_lengthen() {
        let (c, _rx) = CredentialCache::new("r", settings());
        let _ = c.lookup("a");
        c.complete(
            "a",
            FetchOutcome::Found {
                keys: keys(),
                ttl: Some(Duration::from_secs(86_400)),
            },
        );
        let exp = c.entries.get("a").unwrap().expires_ms;
        assert!(exp <= c.now_ms() + 300_000, "capped at positive_ttl");
    }

    #[test]
    fn full_queue_fails_closed_and_leaves_no_stuck_entry() {
        let mut s = settings();
        s.queue_depth = 1;
        s.max_entries = 100;
        let (c, _rx) = CredentialCache::new("r", s);
        assert!(matches!(c.lookup("a"), Lookup::Pending(_)));
        assert!(matches!(c.lookup("b"), Lookup::Unavailable));
        assert_eq!(c.stats.rejected.load(Ordering::Relaxed), 1);
        assert!(
            c.entries.get("b").is_none(),
            "no in-flight marker left behind"
        );
    }

    #[test]
    fn dropped_fetcher_fails_closed() {
        let (c, rx) = CredentialCache::new("r", settings());
        drop(rx);
        assert!(matches!(c.lookup("a"), Lookup::Unavailable));
    }

    #[test]
    fn table_is_bounded_and_never_evicts_in_flight_entries() {
        let mut s = settings();
        s.queue_depth = 64;
        let (c, _rx) = CredentialCache::new("r", s);
        for i in 0..4 {
            let u = format!("u{i}");
            let _ = c.lookup(&u);
            c.complete(&u, FetchOutcome::NotFound);
        }
        // Full of completed entries: a new user evicts one.
        assert!(matches!(c.lookup("new1"), Lookup::Pending(_)));
        assert_eq!(c.len(), 4);
        assert_eq!(c.stats.evictions.load(Ordering::Relaxed), 1);

        // Now fill with in-flight entries only: nothing can be evicted, so a
        // further user is refused rather than growing the table.
        for i in 0..3 {
            let u = format!("u{i}");
            c.entries.remove(&u);
        }
        for i in 0..3 {
            let _ = c.lookup(&format!("f{i}"));
        }
        assert!(c.len() <= 4);
        assert!(matches!(c.lookup("overflow"), Lookup::Unavailable));
    }

    #[test]
    fn peek_never_fetches() {
        let (c, mut rx) = CredentialCache::new("r", settings());
        assert!(matches!(c.peek("alice"), Lookup::NotFound));
        assert!(rx.try_recv().is_err());
        let _ = c.lookup("alice");
        assert!(matches!(c.peek("alice"), Lookup::NotFound), "in flight");
        c.complete(
            "alice",
            FetchOutcome::Found {
                keys: keys(),
                ttl: None,
            },
        );
        assert!(matches!(c.peek("alice"), Lookup::Found(_)));
    }

    #[test]
    fn oversized_usernames_are_refused_without_a_lookup() {
        let (c, mut rx) = CredentialCache::new("r", settings());
        let long = "x".repeat(600);
        assert!(matches!(c.lookup(&long), Lookup::NotFound));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn signature_is_hmac_sha256_over_timestamp_dot_body() {
        let sig = sign_request(b"k", 1_700_000_000, br#"{"username":"a"}"#);
        assert!(sig.starts_with("v1="));
        assert_eq!(sig.len(), 3 + 64);
        let expected = turna_crypto::hmac_sha256(b"k", br#"1700000000.{"username":"a"}"#);
        let hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(sig, format!("v1={hex}"));
    }
}
