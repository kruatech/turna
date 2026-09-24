# QUIC and WebTransport support — 2026-09-18

Both transports are **supported on Linux/macOS with the tokio backend**, opt-in
via `quic` or `web-transport`. This is a support decision for Turna's implemented
TURN mappings, not a new standardized TURN transport or a guarantee of lossless
DATAGRAM delivery. Other platform/backend combinations are outside this record.

## Product scope

Raw QUIC carries TURN control and media using Turna's framing. WebTransport uses
HTTP/3 sessions with a custom client such as the browser probe, not the standard
WebRTC ICE `turn:`/`turns:` configuration. Peer-side media relay is UDP. Raw QUIC
independent TURN-client interoperability has not been demonstrated. WebTransport
browser evidence covers the tested Chrome versions, not every browser.

Both paths implement bounded stream/datagram handling, per-stream responses,
global/per-IP admission and handshake rate limits, certificate reload, migration
handling, metrics, readiness, drain and allocation cleanup. WebTransport uses
`h3` ALPN; the configurable ALPN list applies only to raw QUIC. See
[configuration](../CONFIGURATION.md) and [design](../design/quic-webtransport.md).

## Recorded verification

The following are operator-provided results from the implementation/hardening
session. They are not independent reruns by the documentation change and do not
identify a new release commit (cloud source copies have no git metadata).

| Check | QUIC | WebTransport |
|---|---|---|
| macOS and Linux functional checks | PASS, relayed media and 128-stream routing/half-close/credit checks | PASS, relayed media and 128-stream checks |
| Nonce recovery | PASS, forced 438 on Refresh/CreatePermission/ChannelBind | PASS, same operations |
| Linux lifecycle and limits | PASS, reconnect, crash, global cap, per-IP cap, pressure | PASS, same five cases |
| Linux 1200-second load, 10 sessions, 10 pps | 120000/120000, zero errors | 120000/120000, zero errors |
| Latest kz-to-cloud 60-second WAN check, 10 sessions, 10 pps | 6000/6000, zero missing/deadlines/errors; monitoring/cleanup PASS | 6000/6000, zero missing/deadlines/errors; monitoring/cleanup PASS |
| Independent browser protocol/media check | Not established | Chrome 152 on macOS: session, control stream, independent JS authentication, permission/channel, 10/10 echoes (5 stream ingress, 5 datagram ingress) |

Latest cloud result directories: `network-quic-cloud-acceptance-20260918-233310`
and `network-wt-cloud-acceptance-20260918-233050`. The latest client runs selected
transport acceptance but also passed every strict delivery gate. Historical
browser evidence is in [the earlier browser record](../interop/webtransport-browser-2026-08-20.md).

## WAN loss and evidence limits

Earlier WAN runs remain strict delivery FAIL. The 30-minute WebTransport run
sent 179507 and verified 178964 echoes; all sessions passed stability and offered
rate, but 543 echoes were missing. Its cloud echo count was 179505. This is not
relabelled as a clean 30-minute run. Earlier QUIC WAN checks also encountered
missing echoes and, on the unstable local route, control timeouts.

Paired captures from a later WT minute check locate two missing media-sized
packets between the cloud and kz capture points, with zero capture drops:
[analysis](webtransport-wan-2026-09-18.md). This does not prove the cause of every
previous loss, nor guarantee that the route is repaired. QUIC/WT DATAGRAMs are
unreliable; support does not promise their retransmission or zero WAN loss.

The explicit transport acceptance policy checks session operation and reports
strict delivery separately. It is not sufficient by itself for support promotion
and is not a network-quality threshold. Server monitoring/cleanup must pass too.
See [network verification](transports-network.md) for policies and commands.

No 24-hour/72-hour QUIC or WT endurance result is claimed. The WAN Rust clients
bypass certificate verification for the test certificate; these runs do not
prove PKI validation. Earlier browser certificate evidence is a separate test.
No universal browser support, independent raw-QUIC TURN interop or production
capacity benchmark is claimed. Lifecycle tests are bounded resource checks, not
proof that every deployment is leak-free under arbitrary load.
