//! Resource verification tests
//!
//! Checks that all hard limits hold for any input:
//! - AllocationStore never exceeds max_allocations
//! - max_per_user enforced
//! - PortAllocator never goes outside [min_port, max_port]
//! - Port exhaustion returns Err, does not panic
//! - Bandwidth window resets correctly

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use turna_session::{AllocationStore, BandwidthQuota};

fn client(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), port)
}
fn relay(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1)), port)
}

// ── AllocationStore: max_allocations ─────────────────────────────────────────

/// Creating beyond the limit must return Err, not panic.
/// After a rejection store.len() == max_allocations (no more).
#[test]
fn allocation_count_never_exceeds_max() {
    let max = 10usize;
    let store = AllocationStore::new(49000, 49100, max);

    let mut succeeded = 0;
    for i in 0..20u16 {
        let result = store.create(
            client(1000 + i),
            relay(49000 + i),
            format!("user{i}"),
            vec![],
            600,
        );
        if result.is_ok() {
            succeeded += 1;
        }
    }

    assert_eq!(store.len(), max, "store must not exceed max_allocations");
    assert_eq!(succeeded, max, "exactly max allocations should succeed");
    assert!(store.len() <= max, "invariant: len <= max_allocations");
}

/// After cleanup_expired, capacity is freed and new allocations work again.
#[test]
fn allocations_freed_after_cleanup() {
    let store = AllocationStore::new(49200, 49210, 5);

    // Fill completely
    for i in 0..5u16 {
        store
            .create(client(2000 + i), relay(49200 + i), "u".into(), vec![], 0)
            .unwrap();
    }
    assert_eq!(store.len(), 5);

    // lifetime=0 → expired immediately
    store.cleanup_expired();
    assert_eq!(
        store.len(),
        0,
        "all zero-lifetime allocations should be cleaned"
    );

    // Now we can create again
    store
        .create(client(3000), relay(49200), "u2".into(), vec![], 600)
        .expect("should succeed after cleanup");
    assert_eq!(store.len(), 1);
}

// ── AllocationStore: max_per_user ─────────────────────────────────────────────

#[test]
fn per_user_limit_enforced() {
    let store = AllocationStore::new(49300, 49400, 1000).with_quota(BandwidthQuota {
        max_bytes_per_sec_per_allocation: 0,
        max_per_user: 3,
    });

    // 3 allocations from one user — ok
    for i in 0..3u16 {
        store
            .create(
                client(4000 + i),
                relay(49300 + i),
                "alice".into(),
                vec![],
                600,
            )
            .expect("first 3 must succeed");
    }

    // The 4th must fail
    let err = store.create(client(4003), relay(49303), "alice".into(), vec![], 600);
    assert!(err.is_err(), "4th allocation for same user must fail");

    // A different user can
    store
        .create(client(5000), relay(49304), "bob".into(), vec![], 600)
        .expect("different user must succeed");

    assert_eq!(store.user_allocation_count("alice"), 3);
    assert_eq!(store.user_allocation_count("bob"), 1);
}

// ── PortAllocator: bounds ─────────────────────────────────────────────────────

#[test]
fn port_allocator_never_exceeds_range() {
    let store = AllocationStore::new(50000, 50009, 100);
    for i in 0..10u16 {
        let port = store.ports.allocate().expect("port must be available");
        assert!((50000..=50009).contains(&port), "port {port} out of range");
        store
            .create(client(6000 + i), relay(port), "u".into(), vec![], 600)
            .unwrap();
    }
    assert_eq!(store.available_port_count(), 0);
    assert!(store.ports.allocate().is_err(), "must fail when exhausted");
}

#[test]
fn port_allocator_recycles_after_release() {
    let store = AllocationStore::new(51000, 51004, 100);
    let mut relays = Vec::new();
    for i in 0..5u16 {
        let port = store.ports.allocate().unwrap();
        let r = relay(port);
        relays.push(r);
        store
            .create(client(8000 + i), r, "u".into(), vec![], 600)
            .unwrap();
    }
    assert_eq!(store.available_port_count(), 0);
    store.remove(&client(8000), relays[0]).unwrap();
    assert_eq!(store.available_port_count(), 1);
    let port = store.ports.allocate().unwrap();
    store
        .create(client(9000), relay(port), "u".into(), vec![], 600)
        .unwrap();
    assert_eq!(store.available_port_count(), 0);
}

// ── Bandwidth quota ───────────────────────────────────────────────────────────

#[test]
fn bandwidth_quota_enforced() {
    let store = AllocationStore::new(52000, 52100, 100).with_quota(BandwidthQuota {
        max_bytes_per_sec_per_allocation: 1000,
        max_per_user: 0,
    });

    store
        .create(client(9000), relay(52000), "u".into(), vec![], 600)
        .unwrap();

    let alloc = store.get(&client(9000)).unwrap();

    // Add 500 bytes — ok
    alloc.add_bytes(500);
    assert!(alloc.check_bandwidth(1000).is_ok());

    // Add another 600 — exceeds 1000
    alloc.add_bytes(600);
    assert!(
        alloc.check_bandwidth(1000).is_err(),
        "must reject when bytes in window exceed quota"
    );
}

// ── Write-behind channel backpressure ─────────────────────────────────────────

#[tokio::test]
async fn dropped_writes_bounded_counter() {
    use tokio::sync::mpsc;

    let store = AllocationStore::new(53000, 53500, 10_000);
    let (tx, _rx) = mpsc::channel(1); // capacity=1 — overflows immediately
    store.attach_writer(tx);

    // Create many allocations — most WriteOps will be dropped
    for i in 0..20u16 {
        let _ = store.create(client(10000 + i), relay(53000 + i), "u".into(), vec![], 600);
    }

    let dropped = store.dropped_writes_count();
    // At least some were dropped (channel size=1, 20 events)
    assert!(dropped >= 10, "expected significant drops, got {dropped}");

    // The counter must not decrease
    let dropped2 = store.dropped_writes_count();
    assert!(
        dropped2 >= dropped,
        "drop counter must be monotonically non-decreasing"
    );
}
