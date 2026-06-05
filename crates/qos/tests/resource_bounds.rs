//! Resource verification tests for RateLimiter

use std::net::{IpAddr, Ipv4Addr};
use turna_qos::RateLimiter;

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn allows_up_to_burst_then_denies() {
    let mut rl = RateLimiter::new(5, 1);
    let addr = ip(1, 2, 3, 4);
    for _ in 0..5 { assert!(rl.check(addr)); }
    assert!(!rl.check(addr));
}

#[test]
fn different_ips_independent() {
    let mut rl = RateLimiter::new(2, 1);
    let a = ip(10, 0, 0, 1);
    let b = ip(10, 0, 0, 2);
    assert!(rl.check(a)); assert!(rl.check(a)); assert!(!rl.check(a));
    assert!(rl.check(b)); assert!(rl.check(b)); assert!(!rl.check(b));
}

#[test]
fn entry_count_never_exceeds_max_entries() {
    let max = 10usize;
    let mut rl = RateLimiter::with_max_entries(100, 100, max);
    let mut allowed = 0usize;
    let mut denied  = 0usize;
    for i in 0..(max * 3) as u32 {
        let addr = IpAddr::V4(Ipv4Addr::from(0x0A000000 + i));
        if rl.check(addr) { allowed += 1; } else { denied += 1; }
    }
    assert_eq!(allowed, max);
    assert_eq!(denied, max * 2);
}

#[test]
fn cleanup_frees_entries() {
    let max = 5usize;
    let mut rl = RateLimiter::with_max_entries(100, 100, max);
    for i in 0..max as u32 {
        assert!(rl.check(IpAddr::V4(Ipv4Addr::from(i + 1))));
    }
    let new_ip = ip(99, 99, 99, 99);
    assert!(!rl.check(new_ip));
    rl.cleanup(0.0);
    assert!(rl.check(new_ip));
}

#[test]
fn known_ip_not_blocked_when_table_full() {
    let mut rl = RateLimiter::with_max_entries(10, 10, 3);
    let known = ip(192, 168, 1, 1);
    assert!(rl.check(known));
    assert!(rl.check(ip(10, 0, 0, 1)));
    assert!(rl.check(ip(10, 0, 0, 2)));
    assert!(rl.check(known)); // known уже в таблице — не блокируется
}
