//! NUMA-aware worker placement and memory binding.
//!
//! On multi-socket servers, cross-NUMA memory access is 2-3x slower.
//! This module:
//! - Detects NUMA topology (nodes, CPUs per node)
//! - Pins worker threads to specific NUMA nodes
//! - Allocates buffers on local NUMA memory
//! - Assigns port ranges per NUMA node to avoid cross-node contention

#![cfg(target_os = "linux")]

use std::collections::HashMap;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// NUMA Topology
// ---------------------------------------------------------------------------

/// Detected NUMA topology.
#[derive(Debug, Clone)]
pub struct NumaTopology {
    /// node_id → list of CPU core IDs.
    pub nodes: HashMap<u32, Vec<u32>>,
    /// Total number of NUMA nodes.
    pub node_count: usize,
    /// Total number of CPU cores.
    pub total_cores: usize,
}

impl NumaTopology {
    /// Detect NUMA topology from sysfs.
    pub fn detect() -> Self {
        let nodes = parse_numa_topology();
        let node_count = nodes.len().max(1);
        let total_cores: usize = nodes.values().map(|v| v.len()).sum();
        info!(
            nodes = node_count,
            cores = total_cores,
            "NUMA topology detected"
        );
        for (node, cpus) in &nodes {
            debug!(node, cpus = ?cpus, "NUMA node");
        }
        Self {
            nodes,
            node_count,
            total_cores,
        }
    }

    /// Get CPUs for a NUMA node.
    pub fn cpus_for_node(&self, node: u32) -> &[u32] {
        self.nodes.get(&node).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Determine which NUMA node a CPU belongs to.
    pub fn node_for_cpu(&self, cpu: u32) -> Option<u32> {
        for (&node, cpus) in &self.nodes {
            if cpus.contains(&cpu) {
                return Some(node);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// Worker Placement
// ---------------------------------------------------------------------------

/// Placement strategy for worker threads.
#[derive(Debug, Clone)]
pub struct WorkerPlacement {
    /// worker_id → (numa_node, cpu_id, port_range)
    pub assignments: Vec<WorkerAssignment>,
}

#[derive(Debug, Clone)]
pub struct WorkerAssignment {
    pub worker_id: usize,
    pub numa_node: u32,
    pub cpu_id: u32,
    pub port_range: (u16, u16),
}

impl WorkerPlacement {
    /// Generate worker placements distributed across NUMA nodes.
    ///
    /// Strategy: round-robin workers across NUMA nodes,
    /// then pin to specific CPUs within each node.
    /// Port ranges split evenly across workers.
    pub fn plan(topology: &NumaTopology, num_workers: usize, port_range: (u16, u16)) -> Self {
        let total_ports = (port_range.1 - port_range.0) as usize;
        let ports_per_worker = total_ports / num_workers.max(1);

        let mut assignments = Vec::with_capacity(num_workers);
        let mut cpu_index_per_node: HashMap<u32, usize> = HashMap::new();

        // Sorted node IDs for deterministic assignment
        let mut node_ids: Vec<u32> = topology.nodes.keys().copied().collect();
        node_ids.sort();

        if node_ids.is_empty() {
            // No NUMA info: simple sequential assignment
            for i in 0..num_workers {
                let start = port_range.0 + (i * ports_per_worker) as u16;
                let end = if i == num_workers - 1 {
                    port_range.1
                } else {
                    start + ports_per_worker as u16
                };
                assignments.push(WorkerAssignment {
                    worker_id: i,
                    numa_node: 0,
                    cpu_id: i as u32,
                    port_range: (start, end),
                });
            }
        } else {
            for i in 0..num_workers {
                let node = node_ids[i % node_ids.len()];
                let cpus = topology.cpus_for_node(node);
                let idx = cpu_index_per_node.entry(node).or_insert(0);
                let cpu = cpus.get(*idx % cpus.len()).copied().unwrap_or(i as u32);
                *idx += 1;

                let start = port_range.0 + (i * ports_per_worker) as u16;
                let end = if i == num_workers - 1 {
                    port_range.1
                } else {
                    start + ports_per_worker as u16
                };

                assignments.push(WorkerAssignment {
                    worker_id: i,
                    numa_node: node,
                    cpu_id: cpu,
                    port_range: (start, end),
                });
            }
        }

        info!(workers = num_workers, "worker placement planned");
        for a in &assignments {
            debug!(
                worker = a.worker_id,
                node = a.numa_node,
                cpu = a.cpu_id,
                ports = ?(a.port_range.0, a.port_range.1),
                "assignment"
            );
        }

        Self { assignments }
    }
}

// ---------------------------------------------------------------------------
// NUMA Memory Binding
// ---------------------------------------------------------------------------

/// Bind current thread's memory allocations to a NUMA node.
///
/// Uses mbind(2) / set_mempolicy(2) to ensure all future allocations
/// on this thread come from local NUMA memory.
pub fn bind_memory_to_node(node: u32) -> bool {
    let mask: u64 = 1u64 << node;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_set_mempolicy,
            1i64, // MPOL_BIND
            &mask as *const u64,
            64u64, // max nodes
        )
    };
    if ret < 0 {
        warn!(node, err = %std::io::Error::last_os_error(), "set_mempolicy failed");
        false
    } else {
        debug!(node, "memory bound to NUMA node");
        true
    }
}

/// Pin current thread to a specific CPU core.
pub fn pin_to_cpu(cpu: u32) -> bool {
    unsafe {
        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu as usize, &mut cpuset);
        let ret = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset);
        if ret == 0 {
            debug!(cpu, "pinned to CPU");
            true
        } else {
            warn!(cpu, "CPU pin failed");
            false
        }
    }
}

/// Full NUMA setup for a worker thread.
///
/// Call at the beginning of each worker thread:
/// 1. Pin to CPU
/// 2. Bind memory to local NUMA node
pub fn setup_worker_numa(assignment: &WorkerAssignment) {
    pin_to_cpu(assignment.cpu_id);
    bind_memory_to_node(assignment.numa_node);
    info!(
        worker = assignment.worker_id,
        cpu = assignment.cpu_id,
        node = assignment.numa_node,
        "NUMA worker setup complete"
    );
}

// ---------------------------------------------------------------------------
// Topology Parsing
// ---------------------------------------------------------------------------

fn parse_numa_topology() -> HashMap<u32, Vec<u32>> {
    let mut nodes = HashMap::new();

    // Parse from /sys/devices/system/node/
    let node_dir = "/sys/devices/system/node";
    let Ok(entries) = std::fs::read_dir(node_dir) else {
        // No NUMA sysfs — single node system
        let ncpu = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        nodes.insert(0, (0..ncpu as u32).collect());
        return nodes;
    };

    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with("node") {
            continue;
        }
        let Ok(node_id) = name[4..].parse::<u32>() else {
            continue;
        };

        // Read cpulist: e.g., "0-7,16-23"
        let cpulist_path = format!("{node_dir}/{name}/cpulist");
        if let Ok(cpulist) = std::fs::read_to_string(&cpulist_path) {
            let cpus = parse_cpu_list(cpulist.trim());
            nodes.insert(node_id, cpus);
        }
    }

    if nodes.is_empty() {
        let ncpu = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        nodes.insert(0, (0..ncpu as u32).collect());
    }

    nodes
}

/// Parse Linux CPU list format: "0-3,8-11" → [0,1,2,3,8,9,10,11]
fn parse_cpu_list(s: &str) -> Vec<u32> {
    let mut result = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<u32>(), end.parse::<u32>()) {
                result.extend(s..=e);
            }
        } else if let Ok(n) = part.parse::<u32>() {
            result.push(n);
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cpu_list_simple() {
        assert_eq!(parse_cpu_list("0-3"), vec![0, 1, 2, 3]);
    }

    #[test]
    fn parse_cpu_list_mixed() {
        assert_eq!(parse_cpu_list("0-2,8-9"), vec![0, 1, 2, 8, 9]);
    }

    #[test]
    fn parse_cpu_list_single() {
        assert_eq!(parse_cpu_list("5"), vec![5]);
    }

    #[test]
    fn placement_even_distribution() {
        let mut topo = NumaTopology {
            nodes: HashMap::new(),
            node_count: 2,
            total_cores: 8,
        };
        topo.nodes.insert(0, vec![0, 1, 2, 3]);
        topo.nodes.insert(1, vec![4, 5, 6, 7]);

        let placement = WorkerPlacement::plan(&topo, 4, (49152, 65535));
        assert_eq!(placement.assignments.len(), 4);
        // Workers alternate between nodes
        assert_eq!(placement.assignments[0].numa_node, 0);
        assert_eq!(placement.assignments[1].numa_node, 1);
        assert_eq!(placement.assignments[2].numa_node, 0);
        assert_eq!(placement.assignments[3].numa_node, 1);
    }

    #[test]
    fn detect_no_panic() {
        let _ = NumaTopology::detect();
    }
}
