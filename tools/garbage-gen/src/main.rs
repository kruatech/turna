//! High-throughput UDP garbage generator for BPF filter benchmarking.
//! Sends random bytes (no valid STUN magic cookie) at target PPS.
//!
//! Usage: garbage-gen --target 127.0.0.1:3478 --pps 200000 --duration 30

use clap::Parser;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "127.0.0.1:3478")]
    target: String,
    #[arg(long, default_value = "50000")]
    pps: u64,
    #[arg(long, default_value = "30")]
    duration: u64,
    #[arg(long, default_value = "200")]
    size: usize,
}

fn main() {
    let cli = Cli::parse();
    let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
    sock.connect(&cli.target).unwrap();

    // Pre-generate 64 random-looking payloads (no STUN magic cookie)
    let payloads: Vec<Vec<u8>> = (0..64)
        .map(|i| {
            let mut p = vec![0xAAu8; cli.size];
            p[0] = (i * 7 + 1) as u8; // ensure no STUN magic cookie
            p
        })
        .collect();

    let interval_ns = 1_000_000_000u64 / cli.pps;
    let deadline = Instant::now() + Duration::from_secs(cli.duration);
    let mut sent = 0u64;
    let mut next = Instant::now();

    eprintln!(
        "[garbage] → {} @ {} pps, {}B, {}s",
        cli.target, cli.pps, cli.size, cli.duration
    );

    while Instant::now() < deadline {
        let now = Instant::now();
        if now >= next {
            let _ = sock.send(&payloads[sent as usize % 64]);
            sent += 1;
            next += Duration::from_nanos(interval_ns);
        } else {
            // Spin-wait для точного timing (не sleep — слишком грубо)
            std::hint::spin_loop();
        }
    }

    eprintln!(
        "[garbage] sent={sent} actual_pps={:.0}",
        sent as f64 / cli.duration as f64
    );
}
