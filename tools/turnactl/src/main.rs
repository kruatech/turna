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

use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

mod proto {
    tonic::include_proto!("turna.management.v1");
}
use proto::turna_management_client::TurnaManagementClient;
use proto::{AddUserRequest, RemoveUserRequest};

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut addr: SocketAddr = "127.0.0.1:9090".parse().unwrap();
    let mut grpc_addr: String = "http://127.0.0.1:5350".to_string();
    let mut tls_ca: Option<String> = None;
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;
    let mut org: Option<String> = None;
    let mut force = false;
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
            "--grpc-addr" => {
                i += 1;
                grpc_addr = args[i].clone();
            }
            "--tls-ca" => {
                i += 1;
                tls_ca = Some(args[i].clone());
            }
            "--tls-cert" => {
                i += 1;
                tls_cert = Some(args[i].clone());
            }
            "--tls-key" => {
                i += 1;
                tls_key = Some(args[i].clone());
            }
            "--org" => {
                i += 1;
                org = Some(args[i].clone());
            }
            "--force" => {
                force = true;
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

    // User management is served over gRPC by the control-plane (not the node's
    // HTTP management API), so it uses a separate transport and address.
    if cmd_args.first().map(|s| s.as_str()) == Some("user") {
        handle_user_command(
            &grpc_addr,
            TlsArgs {
                ca: tls_ca,
                cert: tls_cert,
                key: tls_key,
            },
            &cmd_args,
            org,
            force,
            json_output,
        )
        .await;
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

struct TlsArgs {
    ca: Option<String>,
    cert: Option<String>,
    key: Option<String>,
}

impl TlsArgs {
    fn enabled(&self) -> bool {
        self.ca.is_some() || self.cert.is_some() || self.key.is_some()
    }
}

async fn connect_grpc(
    addr: &str,
    tls: &TlsArgs,
) -> Result<TurnaManagementClient<Channel>, Box<dyn std::error::Error>> {
    let mut endpoint = Channel::from_shared(addr.to_string())?;
    if tls.enabled() {
        let mut cfg = ClientTlsConfig::new();
        if let Some(ca) = &tls.ca {
            cfg = cfg.ca_certificate(Certificate::from_pem(std::fs::read(ca)?));
        }
        match (&tls.cert, &tls.key) {
            (Some(cert), Some(key)) => {
                cfg = cfg.identity(Identity::from_pem(
                    std::fs::read(cert)?,
                    std::fs::read(key)?,
                ));
            }
            (None, None) => {}
            _ => return Err("both --tls-cert and --tls-key are required for mTLS".into()),
        }
        endpoint = endpoint.tls_config(cfg)?;
    }
    let channel = endpoint.connect().await?;
    Ok(TurnaManagementClient::new(channel))
}

async fn handle_user_command(
    grpc_addr: &str,
    tls: TlsArgs,
    args: &[String],
    org: Option<String>,
    force: bool,
    json_output: bool,
) {
    let mut client = match connect_grpc(grpc_addr, &tls).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("gRPC connect failed: {e}");
            eprintln!("Is turna-control-plane running with management gRPC on {grpc_addr}?");
            std::process::exit(1);
        }
    };

    match args.get(1).map(|s| s.as_str()) {
        Some("add") => {
            let (Some(username), Some(password)) = (args.get(2).cloned(), args.get(3).cloned())
            else {
                eprintln!("usage: turnactl user add <username> <password> [--org ORG]");
                std::process::exit(1);
            };
            let req = AddUserRequest {
                username: username.clone(),
                password,
                organization: org.unwrap_or_default(),
            };
            match client.add_user(req).await {
                Ok(resp) => {
                    let ok = resp.into_inner().success;
                    if json_output {
                        println!("{}", serde_json::json!({ "success": ok }));
                    } else if ok {
                        // Name omitted: the operator typed it in the command
                        // they just ran, and CodeQL reads any username in output
                        // as a disclosure.
                        println!("User added");
                    } else {
                        eprintln!("Server reported failure adding user");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("AddUser failed: {}", e.message());
                    std::process::exit(1);
                }
            }
        }
        Some("remove") => {
            let Some(username) = args.get(2).cloned() else {
                eprintln!("usage: turnactl user remove <username> [--force]");
                std::process::exit(1);
            };
            let req = RemoveUserRequest {
                username: username.clone(),
                force_delete_allocations: force,
            };
            match client.remove_user(req).await {
                Ok(resp) => {
                    let r = resp.into_inner();
                    if json_output {
                        println!(
                            "{}",
                            serde_json::json!({
                                "success": r.success,
                                "allocations_deleted": r.allocations_deleted,
                            })
                        );
                    } else if r.success {
                        println!(
                            "User removed ({} allocation(s) dropped)",
                            r.allocations_deleted
                        );
                    } else {
                        eprintln!("Server reported failure removing user");
                        std::process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!("RemoveUser failed: {}", e.message());
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("Unknown: user {}", other.unwrap_or(""));
            eprintln!("usage: turnactl user add <username> <password> [--org ORG]");
            eprintln!("       turnactl user remove <username> [--force]");
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
                        if n["is_self"].as_bool().unwrap_or(false) {
                            "*"
                        } else {
                            ""
                        }
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
    println!("  user add <u> <p> [--org O]  Add a long-term user (gRPC → control-plane)");
    println!("  user remove <u> [--force]   Remove a long-term user (gRPC → control-plane)");
    println!();
    println!("gRPC options (user commands):");
    println!("  --grpc-addr URL          control-plane gRPC (default: http://127.0.0.1:5350)");
    println!("  --tls-ca FILE            CA cert (PEM) to verify the server");
    println!("  --tls-cert FILE          client cert (PEM) for mTLS");
    println!("  --tls-key FILE           client key (PEM) for mTLS");
}
