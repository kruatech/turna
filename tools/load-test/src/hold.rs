//! `hold` mode: what an active allocation costs the server in resident memory.
//!
//! Sequence: sample the server's RSS; establish N authenticated allocations
//! (optionally each with one permission and one channel); wait `settle`; sample
//! again; release every allocation with Refresh(lifetime=0); wait `settle`; sample
//! a third time. The per-allocation figure is `(held - before) / established`.
//!
//! What the number is and is not: it is resident-set growth of one process while N
//! allocations exist, so it includes the relay socket's kernel-side accounting
//! only insofar as it lands in the process's RSS (socket buffers do not), and it
//! includes whatever the allocator keeps from setup. Compare servers with the same
//! N, on a freshly started server, and read the released figure next to it — an
//! RSS that does not come back down after release is worth a look but is not by
//! itself a leak (allocators retain freed pages).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::procfs;
use crate::turn_client::{self, Creds, Session};

/// Inputs to [`run_hold`].
pub struct HoldParams {
    pub allocations: usize,
    pub parallel: usize,
    pub settle: Duration,
    pub channel: bool,
    pub rtt_ms: u64,
}

/// Outcome of one `hold` run.
#[derive(Debug, Default)]
pub struct HoldReport {
    pub requested: usize,
    pub established: usize,
    pub errs: usize,
    pub channel: bool,
    pub setup_s: f64,
    pub rss_kb_before: Option<u64>,
    pub rss_kb_held: Option<u64>,
    pub rss_kb_released: Option<u64>,
    /// First failure seen, verbatim, so a run that established nothing says why.
    pub first_error: Option<String>,
}

impl HoldReport {
    /// Resident bytes per established allocation, or `None` when it cannot be
    /// computed (no `--server-pid`, or nothing established).
    pub fn rss_bytes_per_allocation(&self) -> Option<f64> {
        procfs::bytes_per_allocation(self.rss_kb_before?, self.rss_kb_held?, self.established)
    }

    /// One JSON object. Field names are a machine contract, like the load modes'.
    pub fn to_json(&self, label: &str) -> String {
        format!(
            "{{\"label\":\"{label}\",\"mode\":\"hold\",\"requested\":{req},\
             \"established\":{est},\"errs\":{errs},\"channel\":{ch},\"setup_s\":{setup:.3},\
             \"rss_kb_before\":{b},\"rss_kb_held\":{h},\"rss_kb_released\":{r},\
             \"rss_bytes_per_allocation\":{per},\"first_error\":{fe}}}",
            label = crate::json_escape(label),
            req = self.requested,
            est = self.established,
            errs = self.errs,
            ch = self.channel,
            setup = self.setup_s,
            b = procfs::json_opt(self.rss_kb_before),
            h = procfs::json_opt(self.rss_kb_held),
            r = procfs::json_opt(self.rss_kb_released),
            per = procfs::json_opt_f(self.rss_bytes_per_allocation(), 0),
            fe = self.first_error.as_deref().map_or_else(
                || "null".to_string(),
                |e| format!("\"{}\"", crate::json_escape(e))
            ),
        )
    }

    pub fn print_report(&self) {
        println!("═══════════════════════════════════════════");
        println!(
            "  Hold: {} of {} allocations established",
            self.established, self.requested
        );
        if self.channel {
            println!("        each with one permission and one channel");
        }
        println!(
            "  Setup:        {:.2} s, {} errors",
            self.setup_s, self.errs
        );
        let kb = |v: Option<u64>| v.map_or_else(|| "n/a".into(), |v| format!("{v} KiB"));
        println!("  RSS before:   {}", kb(self.rss_kb_before));
        println!("  RSS held:     {}", kb(self.rss_kb_held));
        println!("  RSS released: {}", kb(self.rss_kb_released));
        match self.rss_bytes_per_allocation() {
            Some(b) => println!("  Per allocation: {b:.0} bytes resident"),
            None => println!("  Per allocation: n/a (needs --server-pid and >0 established)"),
        }
        if let Some(e) = &self.first_error {
            println!("  First error:  {e}");
        }
        println!("═══════════════════════════════════════════");
    }
}

/// Establish, hold, sample, release, sample. See the module docs.
pub async fn run_hold(server: SocketAddr, creds: &Creds, p: HoldParams) -> HoldReport {
    let mut report = HoldReport {
        requested: p.allocations,
        channel: p.channel,
        rss_kb_before: procfs::sample().map(|s| s.rss_kb),
        ..HoldReport::default()
    };

    // One peer for every allocation: permissions and channels are per
    // allocation, so sharing the address costs nothing and keeps the client from
    // needing two sockets per allocation.
    let peer = if p.channel {
        match UdpSocket::bind(turn_client::peer_bind_addr(false)).await {
            Ok(s) => Some(s),
            Err(e) => {
                report.first_error = Some(format!("peer bind: {e}"));
                return report;
            }
        }
    } else {
        None
    };
    let peer_addr = peer.as_ref().and_then(|s| s.local_addr().ok());

    let gate = Arc::new(Semaphore::new(p.parallel.max(1)));
    let mut setup = JoinSet::new();
    let t0 = Instant::now();
    for _ in 0..p.allocations {
        let Ok(permit) = gate.clone().acquire_owned().await else {
            break;
        };
        let creds = creds.clone();
        let rtt_ms = p.rtt_ms;
        setup.spawn(async move {
            let _permit = permit;
            let mut sess = turn_client::allocate_family(server, &creds, rtt_ms, None)
                .await
                .map_err(|e| format!("{} (STUN {:?})", e.0, e.1))?;
            if let Some(peer) = peer_addr {
                // 0x4000 is inside RFC 8656 §12's 0x4000-0x4FFF on every server;
                // channel numbers are per allocation, so one value serves all.
                let step = match sess.create_permission(peer).await {
                    Ok(()) => sess.channel_bind(0x4000, peer).await,
                    Err(e) => Err(e),
                };
                if let Err(e) = step {
                    sess.release().await;
                    return Err(e.to_string());
                }
            }
            Ok::<Session, String>(sess)
        });
    }
    let mut sessions = Vec::with_capacity(p.allocations);
    while let Some(joined) = setup.join_next().await {
        match joined {
            Ok(Ok(sess)) => sessions.push(sess),
            Ok(Err(e)) => {
                report.errs += 1;
                report.first_error.get_or_insert(e);
            }
            Err(e) => {
                report.errs += 1;
                report.first_error.get_or_insert(format!("task: {e}"));
            }
        }
    }
    report.setup_s = t0.elapsed().as_secs_f64();
    report.established = sessions.len();

    tokio::time::sleep(p.settle).await;
    report.rss_kb_held = procfs::sample().map(|s| s.rss_kb);

    let mut teardown = JoinSet::new();
    for mut sess in sessions {
        let Ok(permit) = gate.clone().acquire_owned().await else {
            break;
        };
        teardown.spawn(async move {
            let _permit = permit;
            sess.release().await;
        });
    }
    while teardown.join_next().await.is_some() {}

    tokio::time::sleep(p.settle).await;
    report.rss_kb_released = procfs::sample().map(|s| s.rss_kb);
    drop(peer);
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A no-auth mock server: every request succeeds. Counts what it saw by method.
    async fn mock_server() -> (SocketAddr, tokio::task::JoinHandle<(usize, usize, usize)>) {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut alloc, mut refresh0, mut other) = (0, 0, 0);
            let mut buf = [0u8; 2048];
            let relayed: SocketAddr = "127.0.0.1:40000".parse().unwrap();
            while let Ok(Ok((n, from))) =
                tokio::time::timeout(Duration::from_millis(1500), sock.recv_from(&mut buf)).await
            {
                match u16::from_be_bytes([buf[0], buf[1]]) {
                    turn_client::M_ALLOCATE => alloc += 1,
                    turn_client::M_REFRESH => refresh0 += 1,
                    _ => other += 1,
                }
                let reply = turn_client::test_success_for(&buf[..n], relayed);
                sock.send_to(&reply, from).await.unwrap();
            }
            (alloc, refresh0, other)
        });
        (addr, task)
    }

    fn params(n: usize, channel: bool) -> HoldParams {
        HoldParams {
            allocations: n,
            parallel: 4,
            settle: Duration::from_millis(10),
            channel,
            rtt_ms: 1000,
        }
    }

    #[tokio::test]
    async fn establishes_holds_and_releases_every_allocation() {
        let (server, mock) = mock_server().await;
        let creds = Creds::Static {
            user: "u".into(),
            pass: "p".into(),
        };
        let r = run_hold(server, &creds, params(10, true)).await;
        assert_eq!(r.established, 10, "{r:?}");
        assert_eq!(r.errs, 0);
        let (alloc, refresh, other) = mock.await.unwrap();
        assert_eq!(alloc, 10);
        assert_eq!(refresh, 10, "every allocation is released with a Refresh");
        assert_eq!(other, 20, "one CreatePermission and one ChannelBind each");
    }

    #[tokio::test]
    async fn unreachable_server_reports_the_failure() {
        // Bound and immediately dropped: nothing answers on this port.
        let dead = UdpSocket::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let creds = Creds::Static {
            user: "u".into(),
            pass: "p".into(),
        };
        let mut p = params(3, false);
        p.rtt_ms = 200;
        let r = run_hold(dead, &creds, p).await;
        assert_eq!(r.established, 0);
        assert_eq!(r.errs, 3);
        assert!(r.first_error.is_some());
        assert_eq!(r.rss_bytes_per_allocation(), None);
    }

    #[test]
    fn json_is_one_object_with_nulls_for_missing_samples() {
        let r = HoldReport {
            requested: 5,
            established: 4,
            errs: 1,
            first_error: Some("alloc: \"quoted\"".into()),
            ..HoldReport::default()
        };
        let j = r.to_json("coturn|hold|r1");
        assert!(j.starts_with('{') && j.ends_with('}'));
        assert!(j.contains("\"mode\":\"hold\""));
        assert!(j.contains("\"rss_bytes_per_allocation\":null"));
        assert!(j.contains("\"first_error\":\"alloc: \\\"quoted\\\"\""));
        assert!(!j.contains('\n'));
    }

    #[test]
    fn per_allocation_uses_established_not_requested() {
        let r = HoldReport {
            requested: 100,
            established: 50,
            rss_kb_before: Some(10_000),
            rss_kb_held: Some(10_100),
            ..HoldReport::default()
        };
        // 100 KiB over 50 allocations = 2048 bytes each.
        assert_eq!(r.rss_bytes_per_allocation(), Some(2048.0));
    }
}
