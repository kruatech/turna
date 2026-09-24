//! Re-processing a stream-transport request that was parked on a credential
//! lookup (`[turn.auth.webhook]`).
//!
//! Over UDP a request whose USERNAME is still being looked up is dropped
//! unanswered, and the client's STUN retransmission comes back into a warm
//! cache. TURNS and SCTP clients do not retransmit — the transport is reliable,
//! so RFC 8489 §6.2.2 has them wait 39.5 s for an answer that would never come.
//! The bridges therefore park the request here: when the lookup finishes, the
//! same bytes are fed back into the bridge's own event channel as if they had
//! just arrived, and the processor answers from the cache.
//!
//! Bounded: at most [`MAX_PARKED`] requests wait at once across every bridge,
//! and each waits at most [`MAX_WAIT`] (above the largest webhook timeout the
//! config accepts). A request refused a slot is dropped, like its UDP
//! counterpart; the loop cannot spin, because a completed lookup is cached for
//! at least a second, so the re-injected request is answered, not re-parked.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;

/// Requests parked at once, all bridges together.
pub(crate) const MAX_PARKED: usize = 4096;
/// Longest a parked request waits before it is re-processed regardless.
pub(crate) const MAX_WAIT: Duration = Duration::from_secs(12);

static PARKED: AtomicUsize = AtomicUsize::new(0);

/// Park `event` — the bridge's own "packet received" event for the request —
/// until `wait` resolves, then send it back into `events`. Returns `false` when
/// the parking lot is full (the request is dropped).
///
/// Generic over the event type so it carries no transport types and can be
/// tested on its own.
pub(crate) fn park<E: Send + 'static>(
    wait: turna_auth::webhook::Waiter,
    events: &mpsc::Sender<E>,
    event: E,
) -> bool {
    if PARKED.fetch_add(1, Ordering::AcqRel) >= MAX_PARKED {
        PARKED.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    let events = events.clone();
    tokio::spawn(async move {
        let _ = tokio::time::timeout(MAX_WAIT, wait.wait()).await;
        // The connection may have closed meanwhile; the bridge ignores packets
        // for a connection it no longer knows.
        let _ = events.send(event).await;
        PARKED.fetch_sub(1, Ordering::AcqRel);
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use turna_auth::webhook::{CredentialCache, FetchOutcome, Lookup, WebhookSettings};

    #[tokio::test]
    async fn parked_request_is_reinjected_when_the_lookup_completes() {
        let (cache, _rx) = CredentialCache::new(
            "r",
            WebhookSettings {
                positive_ttl: Duration::from_secs(60),
                negative_ttl: Duration::from_secs(60),
                error_ttl: Duration::from_secs(1),
                max_entries: 8,
                queue_depth: 8,
            },
        );
        let Lookup::Pending(wait) = cache.lookup("alice") else {
            panic!("expected a pending lookup");
        };
        let (tx, mut rx) = mpsc::channel::<&'static str>(4);
        assert!(park(wait, &tx, "request bytes"));
        // Nothing comes back while the lookup is in flight.
        assert!(tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err());
        cache.complete("alice", FetchOutcome::NotFound);
        let got = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("re-injected once the lookup finished");
        assert_eq!(got, Some("request bytes"));
    }
}
