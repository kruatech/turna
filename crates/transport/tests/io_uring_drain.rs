//! Graceful-drain test for the io_uring worker pool (audit-2 §9.1 #2).
//!
//! The drain logic in `worker.rs` (stop taking new traffic on `shutdown`, let
//! relay flows finish for `drain_grace`, unregister routes, exit the loop) had
//! no test. The risk flagged by the audit: on a real shutdown a worker might
//! hang (never exit its loop) or leak its thread. This test exercises the real
//! pool: spawn it, flip `shutdown`, and assert every worker thread actually
//! exits within `drain_grace` plus slack — catching both a hang (deadline) and
//! a panic (join).
//!
//! It is gated on Linux + the `io-uring` feature because `run_worker` builds a
//! real io_uring engine. Run it with:
//!   cargo test -p turna-transport --features io-uring --test io_uring_drain
//! On a kernel without io_uring support the worker setup will fail fast; that
//! is an environment signal, not a drain regression.

#![cfg(all(target_os = "linux", feature = "io-uring"))]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use turna_transport::worker::{spawn_worker_pool, ForwardAction, PacketHandler, WorkerPoolConfig};

/// Handler that does nothing — we only care about the worker lifecycle here.
struct NoopHandler;

impl PacketHandler for NoopHandler {
    fn handle_packet(&mut self, _data: &[u8], _source: SocketAddr) -> ForwardAction {
        ForwardAction::None
    }
    fn handle_relay_packet(
        &mut self,
        _data: &[u8],
        _source: SocketAddr,
        _relay_port: u16,
    ) -> ForwardAction {
        ForwardAction::None
    }
}

#[test]
fn worker_pool_drains_and_exits_on_shutdown() {
    let shutdown = Arc::new(AtomicBool::new(false));
    let drain_grace = Duration::from_millis(200);

    let config = WorkerPoolConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(), // ephemeral port
        num_workers: 1,
        shutdown: shutdown.clone(),
        drain_grace,
        ..Default::default()
    };

    let handles = spawn_worker_pool(config, |_id| NoopHandler);

    // Let the worker come up and arm its ring before we ask it to drain.
    std::thread::sleep(Duration::from_millis(150));

    // Trigger graceful drain.
    shutdown.store(true, Ordering::SeqCst);

    // Each worker must exit within drain_grace + generous slack. We poll
    // `is_finished` against a deadline instead of a bare `join()` so a drain
    // *hang* fails the test instead of hanging it forever.
    let deadline = Instant::now() + drain_grace + Duration::from_secs(5);
    for handle in handles {
        while !handle.is_finished() {
            assert!(
                Instant::now() < deadline,
                "worker did not exit within drain_grace + slack — drain hang or thread leak"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        // The thread finished; surface a panic-on-drain as a test failure.
        handle
            .join()
            .expect("worker thread panicked during graceful drain");
    }
}
