//! Usage records at every allocation teardown path.

use std::net::SocketAddr;
use tokio::sync::mpsc;
use turna_session::{AllocationStore, UsageEndReason, UsageRecordKind};

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[test]
fn no_sink_attached_builds_no_record_and_drops_nothing() {
    let s = AllocationStore::new(41_000, 41_100, 10);
    let c = addr("192.0.2.1:1000");
    let r = addr("10.0.0.1:41000");
    s.create(c, r, "u".into(), vec![], 600).unwrap();
    s.remove(&c, r).unwrap();
    assert_eq!(s.usage_dropped_count(), 0);
}

#[test]
fn released_and_admin_deleted_carry_their_reason_and_totals() {
    let s = AllocationStore::new(41_000, 41_100, 10);
    let (tx, mut rx) = mpsc::channel(8);
    s.attach_usage_sink(tx);

    let c1 = addr("192.0.2.1:1000");
    let r1 = addr("10.0.0.1:41001");
    s.create_for_tenant(c1, r1, "alice".into(), vec![], 600, Some("acme".into()))
        .unwrap();
    {
        let a = s.get(&c1).unwrap();
        a.add_bytes(300); // client → peer
        a.add_bytes(200);
        a.add_bytes_to_client(1000); // peer → client
    }
    s.remove(&c1, r1).unwrap();
    let rec = rx.try_recv().expect("stop record on remove");
    assert_eq!(rec.kind, UsageRecordKind::Stop);
    assert_eq!(rec.end_reason, Some(UsageEndReason::Released));
    assert_eq!(rec.username, "alice");
    assert_eq!(rec.tenant.as_deref(), Some("acme"));
    assert_eq!(rec.transport, "udp");
    assert!(rec.bytes_counted);
    assert_eq!(rec.usage.bytes_from_client, 500);
    assert_eq!(rec.usage.packets_from_client, 2);
    assert_eq!(rec.usage.bytes_to_client, 1000);
    assert_eq!(rec.usage.packets_to_client, 1);
    assert!(rec.start_ms > 0 && rec.event_ms >= rec.start_ms);

    let c2 = addr("192.0.2.2:1000");
    let r2 = addr("10.0.0.1:41002");
    s.create(c2, r2, "bob".into(), vec![], 600).unwrap();
    s.force_remove(&c2);
    let rec = rx.try_recv().expect("stop record on force_remove");
    assert_eq!(rec.end_reason, Some(UsageEndReason::AdminDeleted));
    assert_eq!(rec.tenant, None);

    // Exactly one record per teardown.
    assert!(rx.try_recv().is_err());
}

#[test]
fn expiry_sweep_reports_expired() {
    let s = AllocationStore::new(41_000, 41_100, 10);
    let (tx, mut rx) = mpsc::channel(8);
    s.attach_usage_sink(tx);
    let c = addr("192.0.2.3:1000");
    s.create(c, addr("10.0.0.1:41003"), "carol".into(), vec![], 0)
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert_eq!(s.cleanup_expired(), 1);
    let rec = rx.try_recv().expect("stop record on expiry");
    assert_eq!(rec.end_reason, Some(UsageEndReason::Expired));
}

#[test]
fn interim_records_cover_live_allocations_without_removing_them() {
    let s = AllocationStore::new(41_000, 41_100, 10);
    let c = addr("192.0.2.4:1000");
    s.create(c, addr("10.0.0.1:41004"), "dave".into(), vec![], 600)
        .unwrap();
    s.get(&c).unwrap().add_bytes_to_client(64);
    let recs = s.interim_usage_records();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].kind, UsageRecordKind::Interim);
    assert_eq!(recs[0].end_reason, None);
    assert_eq!(recs[0].usage.bytes_to_client, 64);
    assert_eq!(s.len(), 1, "an interim read must not touch the allocation");
}

/// A full accounting queue drops and counts; teardown itself still completes.
#[test]
fn full_queue_drops_and_counts_without_blocking_teardown() {
    let s = AllocationStore::new(41_000, 41_100, 10);
    let (tx, _rx) = mpsc::channel(1);
    s.attach_usage_sink(tx);
    for i in 0..3u16 {
        let c = addr(&format!("192.0.2.5:{}", 2000 + i));
        let r = addr(&format!("10.0.0.1:{}", 41010 + i));
        s.create(c, r, "eve".into(), vec![], 600).unwrap();
        s.remove(&c, r).unwrap();
    }
    assert_eq!(s.len(), 0);
    assert_eq!(s.usage_dropped_count(), 2);
}

/// Tenant totals and usage records are fed by the same teardown hook, so they
/// agree.
#[test]
fn tenant_totals_match_the_stop_records() {
    let s = AllocationStore::new(41_000, 41_100, 10);
    let (tx, mut rx) = mpsc::channel(8);
    s.attach_usage_sink(tx);
    let c = addr("192.0.2.6:1000");
    let r = addr("10.0.0.1:41020");
    s.create_for_tenant(c, r, "f".into(), vec![], 600, Some("t1".into()))
        .unwrap();
    s.get(&c).unwrap().add_bytes(10);
    s.get(&c).unwrap().add_bytes_to_client(20);
    s.remove(&c, r).unwrap();
    let rec = rx.try_recv().unwrap();
    let (_, bytes, packets, closed) = s
        .tenant_traffic_snapshot()
        .into_iter()
        .find(|(t, ..)| t == "t1")
        .unwrap();
    assert_eq!(
        bytes,
        rec.usage.bytes_from_client + rec.usage.bytes_to_client
    );
    assert_eq!(
        packets,
        rec.usage.packets_from_client + rec.usage.packets_to_client
    );
    assert_eq!(closed, 1);
}
