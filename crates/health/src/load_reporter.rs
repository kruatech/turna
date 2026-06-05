//! Load Reporter — сбор метрик ноды и reporting в gossip/control-plane
//!
//! Собирает: CPU, allocations, bandwidth, ports → composite load %.
//! Публикует через watch channel (gossip, gRPC, Prometheus подписываются).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::watch;
use tracing::{debug, info};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LoadReporterConfig {
    pub collect_interval: Duration,
    pub max_allocations: u32,
    pub max_bandwidth_bps: u64,
    pub relay_port_range: (u16, u16),
}

impl Default for LoadReporterConfig {
    fn default() -> Self {
        Self {
            collect_interval: Duration::from_secs(5),
            max_allocations: 50_000,
            max_bandwidth_bps: 10_000_000_000,
            relay_port_range: (49152, 65535),
        }
    }
}

// ---------------------------------------------------------------------------
// Node Load Snapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NodeLoad {
    pub load_percent: u8,
    pub active_allocations: u32,
    pub max_allocations: u32,
    pub allocation_percent: f64,
    pub bandwidth_bps: u64,
    pub max_bandwidth_bps: u64,
    pub bandwidth_percent: f64,
    pub ports_used: u32,
    pub ports_total: u32,
    pub ports_percent: f64,
    pub cpu_usage: f64,
    pub collected_at: Instant,
}

impl NodeLoad {
    fn compute_load_percent(alloc_pct: f64, bw_pct: f64, cpu: f64, port_pct: f64) -> u8 {
        let weighted = alloc_pct * 0.35 + cpu * 100.0 * 0.30 + bw_pct * 0.20 + port_pct * 0.15;
        weighted.clamp(0.0, 100.0) as u8
    }
}

// ---------------------------------------------------------------------------
// Source trait
// ---------------------------------------------------------------------------

pub trait MetricsSource: Send + Sync {
    fn active_allocations(&self) -> u32;
    fn used_relay_ports(&self) -> u32;
    fn bandwidth_bytes_per_sec(&self) -> u64;
}

/// Простая реализация на атомиках.
pub struct AtomicMetrics {
    pub allocations: AtomicU32,
    pub relay_ports: AtomicU32,
    pub bandwidth_bps: AtomicU64,
}

impl AtomicMetrics {
    pub fn new() -> Self {
        Self {
            allocations: AtomicU32::new(0),
            relay_ports: AtomicU32::new(0),
            bandwidth_bps: AtomicU64::new(0),
        }
    }
}

impl MetricsSource for AtomicMetrics {
    fn active_allocations(&self) -> u32 { self.allocations.load(Ordering::Relaxed) }
    fn used_relay_ports(&self) -> u32 { self.relay_ports.load(Ordering::Relaxed) }
    fn bandwidth_bytes_per_sec(&self) -> u64 { self.bandwidth_bps.load(Ordering::Relaxed) }
}

// ---------------------------------------------------------------------------
// Reporter
// ---------------------------------------------------------------------------

pub struct LoadReporter {
    config: LoadReporterConfig,
    source: Arc<dyn MetricsSource>,
    tx: watch::Sender<NodeLoad>,
    rx: watch::Receiver<NodeLoad>,
}

impl LoadReporter {
    pub fn new(config: LoadReporterConfig, source: Arc<dyn MetricsSource>) -> Self {
        let ports_total = (config.relay_port_range.1 as u32).saturating_sub(config.relay_port_range.0 as u32);

        let initial = NodeLoad {
            load_percent: 0,
            active_allocations: 0,
            max_allocations: config.max_allocations,
            allocation_percent: 0.0,
            bandwidth_bps: 0,
            max_bandwidth_bps: config.max_bandwidth_bps,
            bandwidth_percent: 0.0,
            ports_used: 0,
            ports_total,
            ports_percent: 0.0,
            cpu_usage: 0.0,
            collected_at: Instant::now(),
        };

        let (tx, rx) = watch::channel(initial);
        Self { config, source, tx, rx }
    }

    pub fn subscribe(&self) -> watch::Receiver<NodeLoad> {
        self.rx.clone()
    }

    pub fn current(&self) -> NodeLoad {
        self.rx.borrow().clone()
    }

    pub async fn run(self) {
        let interval = self.config.collect_interval;
        let ports_total = (self.config.relay_port_range.1 as u32)
            .saturating_sub(self.config.relay_port_range.0 as u32);

        info!(interval_secs = interval.as_secs(), "load reporter started");

        loop {
            tokio::time::sleep(interval).await;

            let allocs = self.source.active_allocations();
            let ports = self.source.used_relay_ports();
            let bw_bps = self.source.bandwidth_bytes_per_sec() * 8;
            let cpu = read_cpu_usage();

            let alloc_pct = if self.config.max_allocations > 0 {
                allocs as f64 / self.config.max_allocations as f64 * 100.0
            } else { 0.0 };

            let bw_pct = if self.config.max_bandwidth_bps > 0 {
                bw_bps as f64 / self.config.max_bandwidth_bps as f64 * 100.0
            } else { 0.0 };

            let port_pct = if ports_total > 0 {
                ports as f64 / ports_total as f64 * 100.0
            } else { 0.0 };

            let load_pct = NodeLoad::compute_load_percent(alloc_pct, bw_pct, cpu, port_pct);

            let load = NodeLoad {
                load_percent: load_pct,
                active_allocations: allocs,
                max_allocations: self.config.max_allocations,
                allocation_percent: alloc_pct,
                bandwidth_bps: bw_bps,
                max_bandwidth_bps: self.config.max_bandwidth_bps,
                bandwidth_percent: bw_pct,
                ports_used: ports,
                ports_total,
                ports_percent: port_pct,
                cpu_usage: cpu,
                collected_at: Instant::now(),
            };

            debug!(
                load = load_pct,
                allocs,
                bw_mbps = bw_bps / 1_000_000,
                cpu_pct = format!("{:.1}", cpu * 100.0),
                "load collected"
            );

            let _ = self.tx.send(load);
        }
    }
}

// ---------------------------------------------------------------------------
// CPU (platform-specific)
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn read_cpu_usage() -> f64 {
    let loadavg = std::fs::read_to_string("/proc/loadavg").unwrap_or_default();
    let load1: f64 = loadavg
        .split_whitespace()
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0);
    let ncpu = std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count()
        .max(1);
    (load1 / ncpu as f64).clamp(0.0, 1.0)
}

#[cfg(target_os = "macos")]
fn read_cpu_usage() -> f64 {
    let output = std::process::Command::new("sysctl")
        .args(["-n", "vm.loadavg"])
        .output()
        .ok();
    if let Some(out) = output {
        let s = String::from_utf8_lossy(&out.stdout);
        let load1: f64 = s
            .trim_matches(|c: char| c == '{' || c == '}' || c.is_whitespace())
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        let ncpu = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
        return (load1 / ncpu as f64).clamp(0.0, 1.0);
    }
    0.0
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn read_cpu_usage() -> f64 { 0.0 }

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_empty() {
        assert_eq!(NodeLoad::compute_load_percent(0.0, 0.0, 0.0, 0.0), 0);
    }

    #[test]
    fn load_full() {
        assert_eq!(NodeLoad::compute_load_percent(100.0, 100.0, 1.0, 100.0), 100);
    }

    #[test]
    fn load_mixed() {
        let pct = NodeLoad::compute_load_percent(50.0, 0.0, 0.5, 20.0);
        assert!(pct >= 35 && pct <= 36);
    }

    #[test]
    fn cpu_no_panic() {
        let cpu = read_cpu_usage();
        assert!(cpu >= 0.0 && cpu <= 1.0);
    }

    #[test]
    fn atomic_metrics_works() {
        let m = AtomicMetrics::new();
        m.allocations.store(100, Ordering::Relaxed);
        assert_eq!(m.active_allocations(), 100);
    }

    #[test]
    fn reporter_initial() {
        let source = Arc::new(AtomicMetrics::new());
        let reporter = LoadReporter::new(LoadReporterConfig::default(), source);
        let load = reporter.current();
        assert_eq!(load.load_percent, 0);
        assert_eq!(load.ports_total, 65535 - 49152);
    }
}