//! Re-processing a stream-transport request that was parked on a credential
//! lookup (`[turn.auth.webhook]`).
//!
//! Over UDP a request whose USERNAME is still being looked up is dropped
//! unanswered, and the client's STUN retransmission comes back into a warm
//! cache. TURNS, SCTP and QUIC-stream clients do not retransmit — the transport
//! is reliable, so RFC 8489 §6.2.2 has them wait 39.5 s for an answer that
//! would never come. Their bridges therefore park the request in a
//! [`ParkingLot`]: when the lookup finishes, the same request is fed back into
//! the bridge's own queue and the processor answers from the cache.
//!
//! # Bounds
//!
//! - [`MAX_PARKED`] requests per bridge, and [`MAX_PER_CONN`] per connection,
//!   so one client cannot take every slot. A request refused a slot is dropped,
//!   like its UDP counterpart.
//! - Requests waiting on the **same lookup** (same realm and USERNAME) share
//!   one waiting task, however many connections they arrived on.
//! - Each waits at most [`MAX_WAIT`], above the largest webhook timeout the
//!   config accepts. The loop cannot spin: a completed lookup is cached for at
//!   least a second, so the re-injected request is answered, not re-parked.
//!
//! # Connections that close meanwhile
//!
//! A bridge calls [`ParkingLot::forget`] when a connection closes: its parked
//! requests are discarded instead of re-injected. The bridges also drop any
//! request for a connection they no longer know, so a re-injected request can
//! never create an allocation for a client that is gone.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;

/// Requests parked at once, per bridge.
pub(crate) const MAX_PARKED: usize = 4096;
/// Requests parked at once, per connection.
pub(crate) const MAX_PER_CONN: usize = 8;
/// Longest a parked request waits before it is re-processed regardless.
pub(crate) const MAX_WAIT: Duration = Duration::from_secs(12);

struct Inner<C, E> {
    /// Lookup key → the requests waiting on it.
    by_lookup: HashMap<Arc<str>, Vec<(C, E)>>,
    per_conn: HashMap<C, usize>,
    total: usize,
}

/// Requests parked on credential lookups, for one bridge. `C` identifies a
/// connection, `E` is whatever the bridge re-injects into its own queue.
pub(crate) struct ParkingLot<C, E> {
    inner: Arc<Mutex<Inner<C, E>>>,
    retry: mpsc::Sender<E>,
    max_total: usize,
    max_per_conn: usize,
}

impl<C, E> ParkingLot<C, E>
where
    C: Copy + Eq + Hash + Send + 'static,
    E: Send + 'static,
{
    /// `retry` is the bridge's own queue; parked requests come back through it.
    pub(crate) fn new(retry: mpsc::Sender<E>) -> Self {
        Self::with_limits(retry, MAX_PARKED, MAX_PER_CONN)
    }

    pub(crate) fn with_limits(
        retry: mpsc::Sender<E>,
        max_total: usize,
        max_per_conn: usize,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                by_lookup: HashMap::new(),
                per_conn: HashMap::new(),
                total: 0,
            })),
            retry,
            max_total,
            max_per_conn,
        }
    }

    /// Park `event` from `conn` until `wait`'s lookup completes. `false` when
    /// the bridge or the connection has no free slot (the request is dropped).
    pub(crate) fn park(&self, wait: turna_auth::webhook::Waiter, conn: C, event: E) -> bool {
        let key: Arc<str> = wait.key().into();
        let first = {
            let mut g = self.inner.lock();
            let used = g.per_conn.get(&conn).copied().unwrap_or(0);
            if g.total >= self.max_total || used >= self.max_per_conn {
                return false;
            }
            *g.per_conn.entry(conn).or_insert(0) += 1;
            g.total += 1;
            let list = g.by_lookup.entry(key.clone()).or_default();
            list.push((conn, event));
            list.len() == 1
        };
        if first {
            // One task per lookup, whoever else joins it.
            let inner = self.inner.clone();
            let retry = self.retry.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(MAX_WAIT, wait.wait()).await;
                let ready = {
                    let mut g = inner.lock();
                    let ready = g.by_lookup.remove(&key).unwrap_or_default();
                    for (c, _) in &ready {
                        release(&mut g, *c);
                    }
                    ready
                };
                for (_, e) in ready {
                    let _ = retry.send(e).await;
                }
            });
        }
        true
    }

    /// Discard everything parked for `conn` (it closed).
    pub(crate) fn forget(&self, conn: C) {
        let mut g = self.inner.lock();
        if !g.per_conn.contains_key(&conn) {
            return;
        }
        let mut dropped = 0;
        for list in g.by_lookup.values_mut() {
            let before = list.len();
            list.retain(|(c, _)| *c != conn);
            dropped += before - list.len();
            // An emptied entry stays: its waiting task removes it.
        }
        g.per_conn.remove(&conn);
        g.total -= dropped;
    }

    #[cfg(test)]
    fn parked(&self) -> usize {
        self.inner.lock().total
    }
}

fn release<C: Eq + Hash, E>(g: &mut Inner<C, E>, conn: C) {
    if let Some(n) = g.per_conn.get_mut(&conn) {
        *n -= 1;
        if *n == 0 {
            g.per_conn.remove(&conn);
        }
    }
    g.total -= 1;
}

#[cfg(test)]
mod tests {
    use super::*;
    use turna_auth::webhook::{CredentialCache, FetchOutcome, Lookup, WebhookSettings};

    fn cache() -> (
        Arc<CredentialCache>,
        mpsc::Receiver<turna_auth::webhook::FetchJob>,
    ) {
        CredentialCache::new(
            "r",
            WebhookSettings {
                positive_ttl: Duration::from_secs(60),
                negative_ttl: Duration::from_secs(60),
                error_ttl: Duration::from_secs(1),
                max_entries: 64,
                queue_depth: 64,
            },
        )
    }

    fn pending(c: &CredentialCache, user: &str) -> turna_auth::webhook::Waiter {
        match c.lookup(user) {
            Lookup::Pending(w) => w,
            other => panic!("expected pending, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn parked_requests_are_reinjected_together_when_the_lookup_completes() {
        let (c, _jobs) = cache();
        let (tx, mut rx) = mpsc::channel::<&'static str>(16);
        let lot = ParkingLot::new(tx);
        // Two connections waiting on the same user share one lookup and task.
        assert!(lot.park(pending(&c, "alice"), 1u32, "a1"));
        assert!(lot.park(pending(&c, "alice"), 2u32, "a2"));
        assert_eq!(lot.inner.lock().by_lookup.len(), 1, "coalesced");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), rx.recv())
                .await
                .is_err(),
            "nothing comes back while the lookup is in flight"
        );
        c.complete("alice", FetchOutcome::NotFound);
        let mut got = vec![rx.recv().await.unwrap(), rx.recv().await.unwrap()];
        got.sort();
        assert_eq!(got, vec!["a1", "a2"]);
        assert_eq!(lot.parked(), 0);
    }

    #[tokio::test]
    async fn one_connection_cannot_take_every_slot() {
        let (c, _jobs) = cache();
        let (tx, _rx) = mpsc::channel::<u32>(64);
        let lot = ParkingLot::with_limits(tx, 16, 8);
        for i in 0..8 {
            assert!(lot.park(pending(&c, &format!("u{i}")), 1u32, i));
        }
        assert!(!lot.park(pending(&c, "u9"), 1u32, 9), "per-connection cap");
        // Another connection still gets its slots.
        for i in 0..8 {
            assert!(lot.park(pending(&c, &format!("v{i}")), 2u32, 100 + i));
        }
        assert!(!lot.park(pending(&c, "w"), 3u32, 200), "bridge-wide cap");
    }

    /// A connection that closes while its request is parked gets nothing
    /// re-injected — so no allocation can be created for a client that is gone.
    #[tokio::test]
    async fn a_closed_connection_is_not_reinjected() {
        let (c, _jobs) = cache();
        let (tx, mut rx) = mpsc::channel::<u32>(16);
        let lot = ParkingLot::new(tx);
        assert!(lot.park(pending(&c, "bob"), 7u32, 7));
        assert!(lot.park(pending(&c, "bob"), 8u32, 8));
        lot.forget(7);
        assert_eq!(lot.parked(), 1);
        c.complete("bob", FetchOutcome::NotFound);
        assert_eq!(rx.recv().await, Some(8));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), rx.recv())
                .await
                .is_err(),
            "the closed connection's request is gone"
        );
        assert_eq!(lot.parked(), 0);
    }
}
