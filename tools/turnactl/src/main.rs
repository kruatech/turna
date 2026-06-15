//! turnactl — CLI for Turna server management.
//!
//! Usage:
//!   turnactl status                     # node status
//!   turnactl failover status            # failover takeover counters
//!   turnactl allocations list           # list allocations
//!   turnactl allocations count          # count allocations
//!   turnactl allocations get 50000      # get allocation by relay port
//!   turnactl allocations kill 50000     # force-remove allocation
//!   turnactl drain                      # enable drain mode
//!   turnactl undrain                    # disable drain mode
//!   turnactl ping                       # health check
//!   turnactl rooms list                 # list rooms
//!
//! Options:
//!   --addr HOST:PORT    management API address (default: 127.0.0.1:9090)
//!   --json              output raw JSON

use std::net::SocketAddr;
use turna_management::ManagementClient;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();
    let mut json_output = false;
    let mut cmd_args: Vec<String> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                i += 1;
                addr = args[i].parse().expect("invalid addr");
            }
            "--json" => {
                json_output = true;
            }
            "--help" | "-h" => {
                print_help();
                return;
            }
            _ => {
                cmd_args.push(args[i].clone());
            }
        }
        i += 1;
    }

    if cmd_args.is_empty() {
        print_help();
        return;
    }

    let client = ManagementClient::new(addr);
    let (command, params) = parse_command(&cmd_args);

    match client.send(&command, params).await {
        Ok(resp) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&resp).unwrap());
            } else if resp.ok {
                print_formatted(&command, &resp.data);
            } else {
                eprintln!("Error: {}", resp.error.unwrap_or_default());
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Connection failed: {e}");
            eprintln!("Is turna-node running with management API on {addr}?");
            std::process::exit(1);
        }
    }
}

fn parse_command(args: &[String]) -> (String, serde_json::Value) {
    match args.first().map(|s| s.as_str()) {
        Some("ping") => ("ping".into(), serde_json::json!({})),
        Some("status") => ("node.status".into(), serde_json::json!({})),
        Some("failover") => match args.get(1).map(|s| s.as_str()) {
            Some("status") | None => ("failover.status".into(), serde_json::json!({})),
            other => {
                eprintln!("Unknown: failover {}", other.unwrap_or(""));
                std::process::exit(1);
            }
        },
        Some("drain") => ("node.drain".into(), serde_json::json!({})),
        Some("undrain") => ("node.undrain".into(), serde_json::json!({})),
        Some("allocations") => match args.get(1).map(|s| s.as_str()) {
            Some("list") => ("allocations.list".into(), serde_json::json!({"limit": 50})),
            Some("count") => ("allocations.count".into(), serde_json::json!({})),
            Some("get") => {
                let port: u16 = args
                    .get(2)
                    .and_then(|s| s.parse().ok())
                    .expect("usage: turnactl allocations get <relay_port>");
                (
                    "allocations.get".into(),
                    serde_json::json!({"relay_port": port}),
                )
            }
            Some("kill") => {
                let port: u16 = args
                    .get(2)
                    .and_then(|s| s.parse().ok())
                    .expect("usage: turnactl allocations kill <relay_port>");
                (
                    "allocations.kill".into(),
                    serde_json::json!({"relay_port": port}),
                )
            }
            _ => {
                eprintln!(
                    "Unknown: allocations {}",
                    args.get(1).unwrap_or(&String::new())
                );
                std::process::exit(1);
            }
        },
        Some("rooms") => match args.get(1).map(|s| s.as_str()) {
            Some("list") => ("rooms.list".into(), serde_json::json!({"limit": 50})),
            _ => ("rooms.list".into(), serde_json::json!({"limit": 50})),
        },
        Some("cluster") => match args.get(1).map(|s| s.as_str()) {
            Some("nodes") | None => ("cluster.nodes".into(), serde_json::json!({})),
            other => {
                eprintln!("Unknown: cluster {}", other.unwrap_or(""));
                std::process::exit(1);
            }
        },
        _ => {
            eprintln!(
                "Unknown command: {}",
                args.first().unwrap_or(&String::new())
            );
            std::process::exit(1);
        }
    }
}

fn print_formatted(command: &str, data: &Option<serde_json::Value>) {
    let Some(data) = data else {
        println!("OK");
        return;
    };

    match command {
        "ping" => println!("pong"),
        "node.status" => {
            println!("Node:        {}", data["node_id"].as_str().unwrap_or("?"));
            println!(
                "Uptime:      {}s",
                data["uptime_secs"].as_u64().unwrap_or(0)
            );
            println!(
                "Allocations: {}",
                data["active_allocations"].as_u64().unwrap_or(0)
            );
            println!(
                "Draining:    {}",
                data["draining"].as_bool().unwrap_or(false)
            );
        }
        "node.drain" => println!("Drain mode enabled"),
        "node.undrain" => println!("Drain mode disabled"),
        "failover.status" => {
            println!("Failover (this node):");
            println!(
                "  Allocations claimed: {}",
                data["claimed_total"].as_u64().unwrap_or(0)
            );
            println!(
                "  Races lost:          {}",
                data["lost_race_total"].as_u64().unwrap_or(0)
            );
            println!(
                "  Errors:              {}",
                data["errors_total"].as_u64().unwrap_or(0)
            );
            println!(
                "  Last sweep:          {} us",
                data["last_sweep_us"].as_u64().unwrap_or(0)
            );
            println!(
                "  Draining:            {}",
                data["draining"].as_bool().unwrap_or(false)
            );
        }
        "allocations.count" => println!("{}", data["count"].as_u64().unwrap_or(0)),
        "allocations.kill" => println!("Killed allocation on port {}", data["killed"]),
        "cluster.nodes" => {
            if let Some(nodes) = data.as_array() {
                println!("{:<28} {:<24} SELF", "NODE_ID", "TURN_ADDR");
                for n in nodes {
                    println!(
                        "{:<28} {:<24} {}",
                        n["node_id"].as_str().unwrap_or("?"),
                        n["turn_addr"].as_str().unwrap_or("?"),
                        if n["is_self"].as_bool().unwrap_or(false) { "*" } else { "" }
                    );
                }
                println!("({} node(s))", nodes.len());
            } else {
                println!("{}", serde_json::to_string_pretty(data).unwrap());
            }
        }
        _ => println!("{}", serde_json::to_string_pretty(data).unwrap()),
    }
}

fn print_help() {
    println!("turnactl — Turna server management CLI\n");
    println!("Usage: turnactl [--addr HOST:PORT] [--json] <command>\n");
    println!("Commands:");
    println!("  ping                     Health check");
    println!("  status                   Node status");
    println!("  failover status          Failover takeover counters (this node)");
    println!("  drain                    Enable drain mode");
    println!("  undrain                  Disable drain mode");
    println!("  allocations list         List allocations");
    println!("  allocations count        Count allocations");
    println!("  allocations get <port>   Get allocation details");
    println!("  allocations kill <port>  Force-remove allocation");
    println!("  rooms list               List active rooms");
    println!("  cluster nodes            List live cluster nodes (gossip ring)");
}
