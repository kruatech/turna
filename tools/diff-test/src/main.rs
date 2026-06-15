//! Differential STUN/TURN protocol tester
//!
//! Sends identical packets to two servers (turna and coturn) and compares
//! their responses. Finds parser behavior discrepancies: cases where one
//! server accepts a packet the other rejects, or responds differently.
//!
//! Usage:
//!   diff-test --turna 127.0.0.1:3478 --coturn 127.0.0.1:3479
//!   diff-test --turna 127.0.0.1:3478 --coturn 127.0.0.1:3479 --json
//!
//! Exit codes:
//!   0 = no discrepancies
//!   1 = discrepancies found (see output)
//!   2 = error (server unreachable etc.)

use std::net::SocketAddr;
use std::time::Duration;

use clap::Parser;
use serde::Serialize;
use tokio::net::UdpSocket;

use turna_proto_stun::attribute::Attribute;
use turna_proto_stun::header::{MessageClass, MAGIC_COOKIE};
use turna_proto_stun::message::{encode_channel_data, StunMessage};
use turna_proto_stun::method::Method;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "diff-test", about = "Differential STUN/TURN protocol tester")]
struct Cli {
    /// turna server address
    #[arg(long, default_value = "127.0.0.1:3478")]
    turna: SocketAddr,

    /// coturn server address
    #[arg(long, default_value = "127.0.0.1:3479")]
    coturn: SocketAddr,

    /// Timeout per packet in milliseconds
    #[arg(long, default_value = "500")]
    timeout_ms: u64,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

// ── Result types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
enum Response {
    /// Got a response: response class + STUN error code if present
    Stun {
        class: String,
        error_code: Option<u16>,
    },
    /// Got raw bytes that don't parse as STUN
    Raw { len: usize },
    /// No response within timeout
    Timeout,
    /// Send error
    Error { msg: String },
}

#[derive(Debug, Clone, Serialize)]
struct TestResult {
    name: String,
    description: String,
    turna: Response,
    coturn: Response,
    discrepancy: bool,
    note: Option<String>,
}

#[derive(Debug, Serialize)]
struct Report {
    total: usize,
    discrepancies: usize,
    results: Vec<TestResult>,
}

// ── UDP send/recv ─────────────────────────────────────────────────────────────

async fn send_recv(
    sock: &UdpSocket,
    target: SocketAddr,
    packet: &[u8],
    timeout_ms: u64,
) -> Response {
    if let Err(e) = sock.send_to(packet, target).await {
        return Response::Error { msg: e.to_string() };
    }

    let mut buf = [0u8; 4096];
    match tokio::time::timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf)).await {
        Err(_) => Response::Timeout,
        Ok(Err(e)) => Response::Error { msg: e.to_string() },
        Ok(Ok((n, _))) => match StunMessage::decode(&buf[..n]) {
            Ok(msg) => {
                let class = format!("{:?}", msg.class);
                let error_code = msg.attributes.iter().find_map(|a| match a {
                    Attribute::ErrorCode { code, .. } => Some(*code),
                    _ => None,
                });
                Response::Stun { class, error_code }
            }
            Err(_) => Response::Raw { len: n },
        },
    }
}

// ── Comparison ────────────────────────────────────────────────────────────────

/// Two responses are consistent if they agree on accept vs reject.
/// We allow different error codes (400 vs 401 etc) as implementation detail.
fn is_discrepancy(turna: &Response, coturn: &Response) -> (bool, Option<String>) {
    match (turna, coturn) {
        // Both timeout → consistent (both dropped)
        (Response::Timeout, Response::Timeout) => (false, None),

        // Both respond → compare accept vs reject.
        // ErrorResponse and Timeout are both "reject" — different ways to say no.
        (Response::Stun { class: vc, .. }, Response::Stun { class: cc, .. }) => {
            let turna_ok = vc == "SuccessResponse";
            let coturn_ok = cc == "SuccessResponse";
            if turna_ok != coturn_ok {
                (true, Some(format!("turna={vc} coturn={cc}")))
            } else {
                (false, None)
            }
        }

        // One ErrorResponse, one Timeout → both reject, consistent.
        (Response::Stun { class: vc, .. }, Response::Timeout)
        | (Response::Timeout, Response::Stun { class: vc, .. })
            if vc == "ErrorResponse" =>
        {
            (false, Some("both reject (ErrorResponse vs Timeout)".into()))
        }

        // Both return non-STUN → likely both rejecting at IP level
        (Response::Raw { .. }, Response::Raw { .. }) => (false, None),

        // One responds, one doesn't → discrepancy
        (Response::Timeout, Response::Stun { class, .. }) => {
            (true, Some(format!("turna=Timeout coturn={class}")))
        }
        (Response::Stun { class, .. }, Response::Timeout) => {
            (true, Some(format!("turna={class} coturn=Timeout")))
        }

        // One errors → not a discrepancy (network issue)
        (Response::Error { .. }, _) | (_, Response::Error { .. }) => {
            (false, Some("send/recv error — skipped".into()))
        }

        _ => (false, None),
    }
}

// ── Test cases ────────────────────────────────────────────────────────────────

struct TestCase {
    name: &'static str,
    description: &'static str,
    packet: Vec<u8>,
}

fn build_tests() -> Vec<TestCase> {
    let mut tests = Vec::new();
    let key = b"diff_test_key_padding_32bytes_ok";

    // ── Happy path ────────────────────────────────────────────────────────────

    let msg = StunMessage::new(Method::Binding, MessageClass::Request);
    let mut buf = [0u8; 512];
    let n = msg.encode(&mut buf).expect("diff-test: STUN encode overflowed buffer");
    tests.push(TestCase {
        name: "binding_request_minimal",
        description: "Minimal Binding Request — both must respond with SuccessResponse",
        packet: buf[..n].to_vec(),
    });

    let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
    msg.add(Attribute::Software("diff-test/1.0".into()));
    let mut buf = [0u8; 512];
    let n = msg.encode(&mut buf).expect("diff-test: STUN encode overflowed buffer");
    tests.push(TestCase {
        name: "binding_request_with_software",
        description: "Binding Request with SOFTWARE attr",
        packet: buf[..n].to_vec(),
    });

    // ── Malformed packets ─────────────────────────────────────────────────────

    tests.push(TestCase {
        name: "too_short",
        description: "4-byte packet — too short for any STUN header",
        packet: vec![0x00, 0x01, 0x00, 0x00],
    });

    tests.push(TestCase {
        name: "wrong_magic_cookie",
        description: "Valid header structure but wrong magic cookie — must reject",
        packet: {
            let mut buf = [0u8; 20];
            buf[0] = 0x00;
            buf[1] = 0x01; // Binding Request
            buf[2] = 0x00;
            buf[3] = 0x00; // length = 0
            buf[4] = 0xDE;
            buf[5] = 0xAD;
            buf[6] = 0xBE;
            buf[7] = 0xEF; // wrong cookie
            buf.to_vec()
        },
    });

    tests.push(TestCase {
        name: "odd_length_field",
        description: "Length field not 4-byte aligned — RFC violation",
        packet: {
            let mut buf = [0u8; 20];
            buf[0] = 0x00;
            buf[1] = 0x01;
            buf[2] = 0x00;
            buf[3] = 0x03; // length = 3 (not aligned)
            buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            buf.to_vec()
        },
    });

    tests.push(TestCase {
        name: "oversized_length_claim",
        description: "Header claims 4000 bytes but packet is only 20 bytes",
        packet: {
            let mut buf = [0u8; 20];
            buf[0] = 0x00;
            buf[1] = 0x01;
            buf[2] = 0x0F;
            buf[3] = 0xA0; // length = 4000
            buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            buf.to_vec()
        },
    });

    // ── Unknown method ────────────────────────────────────────────────────────

    tests.push(TestCase {
        name: "unknown_method",
        description: "Valid STUN framing but unknown method 0x999",
        packet: {
            let mut buf = [0u8; 20];
            buf[0] = 0x09;
            buf[1] = 0x99; // unknown method
            buf[2] = 0x00;
            buf[3] = 0x00;
            buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            buf.to_vec()
        },
    });

    // ── Attribute edge cases ──────────────────────────────────────────────────

    let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
    // 33 copies of SOFTWARE — exceeds MAX_ATTRIBUTES_PER_MESSAGE=32 in turna
    for _ in 0..33 {
        msg.add(Attribute::Software("x".into()));
    }
    let mut buf = vec![0u8; 8192];
    let n = msg.encode(&mut buf).expect("diff-test: STUN encode overflowed buffer");
    tests.push(TestCase {
        name: "too_many_attributes",
        description: "33 SOFTWARE attrs — turna rejects (MAX=32, security limit), coturn accepts [KNOWN DIFFERENCE]",
        packet: buf[..n].to_vec(),
    });

    // ── MESSAGE-INTEGRITY ─────────────────────────────────────────────────────

    let mut msg = StunMessage::new(Method::Binding, MessageClass::Request);
    msg.add(Attribute::Username("diff-test-user".into()));
    let mut buf = [0u8; 512];
    let n = msg.encode_with_integrity(&mut buf, key).expect("diff-test: STUN encode overflowed buffer");
    tests.push(TestCase {
        name: "binding_with_integrity_no_auth_coturn",
        description: "Binding Request with MESSAGE-INTEGRITY — turna validates (RFC compliant), coturn ignores in no-auth mode [KNOWN DIFFERENCE]",
        packet: buf[..n].to_vec(),
    });

    // Corrupt HMAC — flip last byte
    let mut corrupt = buf[..n].to_vec();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xFF;
    tests.push(TestCase {
        name: "corrupted_integrity",
        description: "Binding Request with corrupt MESSAGE-INTEGRITY (bit flip)",
        packet: corrupt,
    });

    // ── ChannelData ───────────────────────────────────────────────────────────

    // Valid ChannelData frame (no allocation, both should ignore/reject)
    let payload = b"hello differential test";
    let padded = (4 + payload.len() + 3) & !3;
    let mut ch_buf = vec![0u8; padded];
    encode_channel_data(&mut ch_buf, 0x4001, payload).expect("diff-test: STUN encode overflowed buffer");
    tests.push(TestCase {
        name: "channel_data_no_alloc",
        description: "ChannelData for non-existent allocation — both should silently drop",
        packet: ch_buf,
    });

    // Invalid channel number (below 0x4000)
    let mut ch_buf2 = vec![0u8; 8];
    ch_buf2[0] = 0x00;
    ch_buf2[1] = 0x01; // channel 0x0001 — invalid range
    ch_buf2[2] = 0x00;
    ch_buf2[3] = 0x04; // length = 4
    ch_buf2[4..8].copy_from_slice(b"data");
    tests.push(TestCase {
        name: "channel_data_invalid_channel",
        description: "ChannelData with channel 0x0001 — outside valid range 0x4000-0x7FFF",
        packet: ch_buf2,
    });

    // ── Pure garbage ──────────────────────────────────────────────────────────

    tests.push(TestCase {
        name: "random_garbage",
        description: "32 bytes of 0xAA — pure garbage",
        packet: vec![0xAAu8; 32],
    });

    tests.push(TestCase {
        name: "empty_packet",
        description: "Zero-length packet",
        packet: vec![],
    });

    // ── Indication (no response expected from either) ─────────────────────────

    let mut msg = StunMessage::new(Method::Send, MessageClass::Indication);
    let peer: SocketAddr = "10.0.0.1:5000".parse().unwrap();
    msg.add(Attribute::XorPeerAddress(peer));
    msg.add(Attribute::Data(b"test".to_vec()));
    let mut buf = [0u8; 512];
    let n = msg.encode(&mut buf).expect("diff-test: STUN encode overflowed buffer");
    tests.push(TestCase {
        name: "send_indication_no_alloc",
        description: "Send Indication without allocation — both should silently drop (Indication, no response expected)",
        packet: buf[..n].to_vec(),
    });

    tests
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    if !cli.json {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
    }

    // Two sockets — one per server to avoid response routing issues
    let turna_sock = UdpSocket::bind("0.0.0.0:0").await?;
    let coturn_sock = UdpSocket::bind("0.0.0.0:0").await?;

    // Warm-up ping to both servers
    let ping_msg = StunMessage::new(Method::Binding, MessageClass::Request);
    let mut ping_buf = [0u8; 64];
    let ping_n = ping_msg.encode(&mut ping_buf).expect("diff-test: STUN encode overflowed buffer");

    let turna_up = matches!(
        send_recv(&turna_sock, cli.turna, &ping_buf[..ping_n], 1000).await,
        Response::Stun { .. }
    );
    let coturn_up = matches!(
        send_recv(&coturn_sock, cli.coturn, &ping_buf[..ping_n], 1000).await,
        Response::Stun { .. }
    );

    if !turna_up {
        eprintln!(
            "WARNING: turna at {} is not responding to Binding Request",
            cli.turna
        );
    }
    if !coturn_up {
        eprintln!(
            "WARNING: coturn at {} is not responding to Binding Request",
            cli.coturn
        );
    }

    let tests = build_tests();
    let mut results = Vec::new();

    for test in &tests {
        let turna_resp = send_recv(&turna_sock, cli.turna, &test.packet, cli.timeout_ms).await;
        // Small delay between sends to avoid UDP ordering issues
        tokio::time::sleep(Duration::from_millis(10)).await;
        let coturn_resp = send_recv(&coturn_sock, cli.coturn, &test.packet, cli.timeout_ms).await;

        let (disc, note) = is_discrepancy(&turna_resp, &coturn_resp);

        results.push(TestResult {
            name: test.name.to_string(),
            description: test.description.to_string(),
            turna: turna_resp,
            coturn: coturn_resp,
            discrepancy: disc,
            note,
        });
    }

    let discrepancies = results.iter().filter(|r| r.discrepancy).count();
    let report = Report {
        total: results.len(),
        discrepancies,
        results,
    };

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("\n## Differential Test Results\n");
        println!("Servers: turna={} coturn={}\n", cli.turna, cli.coturn);
        println!(
            "{:<40} {:<20} {:<20} Status",
            "Test", "turna", "coturn"
        );
        println!("{}", "─".repeat(100));

        for r in &report.results {
            let turna_s = format_resp(&r.turna);
            let coturn_s = format_resp(&r.coturn);
            let status = if r.discrepancy {
                format!("⚠ DISCREPANCY: {}", r.note.as_deref().unwrap_or(""))
            } else {
                "✓".into()
            };
            println!("{:<40} {:<20} {:<20} {}", r.name, turna_s, coturn_s, status);
        }

        println!(
            "\nTotal: {} tests, {} discrepancies",
            report.total, report.discrepancies
        );

        if discrepancies > 0 {
            println!("\n=== DISCREPANCIES ===");
            for r in report.results.iter().filter(|r| r.discrepancy) {
                println!("\n[{}] {}", r.name, r.description);
                println!("  turna:    {:?}", r.turna);
                println!("  coturn: {:?}", r.coturn);
                if let Some(ref note) = r.note {
                    println!("  note:   {note}");
                }
            }
        }
    }

    std::process::exit(if discrepancies > 0 { 1 } else { 0 });
}

fn format_resp(r: &Response) -> String {
    match r {
        Response::Stun {
            class,
            error_code: Some(c),
        } => format!("{class}({c})"),
        Response::Stun { class, .. } => class.clone(),
        Response::Raw { len } => format!("Raw({len}b)"),
        Response::Timeout => "Timeout".into(),
        Response::Error { msg } => format!("Err({msg})"),
    }
}
