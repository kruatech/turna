//! Server-side resource sampling from Linux procfs, for `--server-pid`.
//!
//! The comparison harness (`bench/matrix.sh`) needs two numbers the client cannot
//! observe on the wire: how much CPU the server burned while relaying, and how much
//! resident memory an active allocation costs it. Both come from `/proc/<pid>`, and
//! both are read *here* rather than by the script around this tool, because only
//! this process knows where the measured window starts and ends — after the
//! allocations are set up and the warm-up is discarded, not when the command was
//! launched. A script sampling around the whole invocation would fold allocation
//! setup and teardown into "CPU during relay".
//!
//! Scope, stated so a number is not read as more than it is:
//!
//! - one process: the PID given. coturn and turna are single-process
//!   multi-threaded, so their threads are included. A server that forks workers
//!   would be under-counted;
//! - CPU is `utime + stime` from `/proc/<pid>/stat`, in clock ticks, divided by
//!   `--clk-tck` (USER_HZ — 100 on every mainstream Linux ABI; the harness passes
//!   `getconf CLK_TCK`). 100 % is one core fully busy, so a multi-threaded server
//!   can exceed it;
//! - memory is `VmRSS` from `/proc/<pid>/status`: resident pages, including what
//!   the allocator holds on to after a free. It is not "live heap".
//!
//! Off Linux every sample is `None` and the JSON fields read `null`.

use std::sync::OnceLock;
use std::time::Instant;

/// The process to sample and its clock-tick rate. Set once from the CLI.
#[derive(Debug, Clone, Copy)]
pub struct Target {
    pub pid: u32,
    pub clk_tck: u64,
}

pub static TARGET: OnceLock<Target> = OnceLock::new();

/// One reading of the target process.
#[derive(Debug, Clone, Copy)]
pub struct ProcSample {
    pub at: Instant,
    /// `utime + stime`, clock ticks.
    pub cpu_ticks: u64,
    /// `VmRSS`, KiB.
    pub rss_kb: u64,
}

/// `utime + stime` from the contents of `/proc/<pid>/stat`.
///
/// Field 2 (`comm`) is the executable name in parentheses and may itself contain
/// spaces and `)`, so the remaining fields are counted from the **last** `)`.
/// After it, field 3 (`state`) is index 0, which puts `utime` (field 14) at index
/// 11 and `stime` (field 15) at index 12.
pub fn parse_stat_cpu_ticks(stat: &str) -> Option<u64> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let mut fields = rest.split_whitespace();
    let utime: u64 = fields.nth(11)?.parse().ok()?;
    let stime: u64 = fields.next()?.parse().ok()?;
    Some(utime + stime)
}

/// `VmRSS` in KiB from the contents of `/proc/<pid>/status`.
pub fn parse_status_rss_kb(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|n| n.parse().ok())
}

/// Read both values for `pid`. `None` if the process is gone or this is not Linux.
pub fn sample_pid(pid: u32) -> Option<ProcSample> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    Some(ProcSample {
        at: Instant::now(),
        cpu_ticks: parse_stat_cpu_ticks(&stat)?,
        rss_kb: parse_status_rss_kb(&status)?,
    })
}

/// Sample the configured target, if any.
pub fn sample() -> Option<ProcSample> {
    TARGET.get().and_then(|t| sample_pid(t.pid))
}

/// CPU use between two samples, percent of one core.
pub fn cpu_percent(start: &ProcSample, end: &ProcSample, clk_tck: u64) -> Option<f64> {
    let wall = end.at.checked_duration_since(start.at)?.as_secs_f64();
    if wall <= 0.0 || clk_tck == 0 {
        return None;
    }
    let ticks = end.cpu_ticks.checked_sub(start.cpu_ticks)?;
    Some(ticks as f64 / clk_tck as f64 / wall * 100.0)
}

/// Resident bytes attributable to each of `n` allocations, from the RSS before
/// they were created and while they were all held.
///
/// Signed on purpose: an allocator that returned memory between the two samples
/// produces a negative delta, and hiding that behind a zero would make a
/// meaningless run look like a very good one.
pub fn bytes_per_allocation(before_kb: u64, held_kb: u64, n: usize) -> Option<f64> {
    if n == 0 {
        return None;
    }
    Some((held_kb as f64 - before_kb as f64) * 1024.0 / n as f64)
}

/// Render an optional number as JSON (`null` when absent).
pub fn json_opt<T: std::fmt::Display>(v: Option<T>) -> String {
    v.map_or_else(|| "null".to_string(), |v| v.to_string())
}

/// Same, with a fixed number of decimals for floats.
pub fn json_opt_f(v: Option<f64>, decimals: usize) -> String {
    match v {
        Some(v) if v.is_finite() => format!("{v:.decimals$}"),
        _ => "null".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // A real /proc/<pid>/stat line (kernel 6.x), with a comm that contains a space
    // and a closing parenthesis — the case a naive split gets wrong.
    const STAT: &str = "4242 (turna node) x) S 1 4242 4242 0 -1 4194560 12345 0 0 0 \
                        731 269 0 0 20 0 9 0 123456 1234567890 5432 18446744073709551615 \
                        1 1 0 0 0 0 0 4096 0 0 0 0 17 3 0 0 0 0 0";

    #[test]
    fn stat_ticks_are_counted_from_the_last_paren() {
        assert_eq!(parse_stat_cpu_ticks(STAT), Some(731 + 269));
    }

    #[test]
    fn stat_rejects_truncated_input() {
        assert_eq!(parse_stat_cpu_ticks("4242 (x) S 1 2 3"), None);
        assert_eq!(parse_stat_cpu_ticks("no parenthesis at all"), None);
    }

    #[test]
    fn status_rss_parses_kib() {
        let status = "Name:\tturna-node\nVmPeak:\t  999 kB\nVmRSS:\t   51234 kB\nThreads:\t9\n";
        assert_eq!(parse_status_rss_kb(status), Some(51_234));
        assert_eq!(parse_status_rss_kb("Name:\tx\n"), None);
    }

    #[test]
    fn cpu_percent_is_ticks_over_wall_time() {
        let t0 = Instant::now();
        let a = ProcSample {
            at: t0,
            cpu_ticks: 1_000,
            rss_kb: 0,
        };
        let b = ProcSample {
            at: t0 + Duration::from_secs(10),
            cpu_ticks: 1_000 + 1_500,
            rss_kb: 0,
        };
        // 1500 ticks at 100 Hz = 15 s of CPU in 10 s of wall = 150 % (1.5 cores).
        let pct = cpu_percent(&a, &b, 100).unwrap();
        assert!((pct - 150.0).abs() < 1e-9, "{pct}");
        // Reversed samples are not a negative CPU figure, they are no figure.
        assert!(cpu_percent(&b, &a, 100).is_none());
        assert!(cpu_percent(&a, &b, 0).is_none());
    }

    #[test]
    fn per_allocation_bytes_keep_their_sign() {
        assert_eq!(bytes_per_allocation(1_000, 2_000, 1_024), Some(1_000.0));
        assert_eq!(bytes_per_allocation(2_000, 1_000, 1_024), Some(-1_000.0));
        assert_eq!(bytes_per_allocation(1_000, 2_000, 0), None);
    }

    #[test]
    fn json_helpers_emit_null() {
        assert_eq!(json_opt::<u64>(None), "null");
        assert_eq!(json_opt(Some(7u64)), "7");
        assert_eq!(json_opt_f(Some(1.23456), 2), "1.23");
        assert_eq!(json_opt_f(Some(f64::NAN), 2), "null");
        assert_eq!(json_opt_f(None, 2), "null");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn samples_this_process() {
        let s = sample_pid(std::process::id()).expect("own /proc entry");
        assert!(s.rss_kb > 0);
    }
}
