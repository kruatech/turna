# WebTransport WAN capture evidence — 2026-09-18 UTC

Operator supplied `turna-wt-cloud-diag.tar.gz` and `turna-wt-kz-diag.tar.gz`.
The 60-second run used ten sessions at 10 payloads/s/session, 160-byte verified
payloads. Cloud 45.88.174.72:3484; client 176.12.76.60. The UDP echo peer stayed
on cloud. Test certificate validation was bypassed; this is not PKI evidence.

- Sent 6000; verified 5998; two missing echoes and two deadline violations.
- All sessions completed with zero operational/protocol errors.
- Server echo count 6000; server monitoring/cleanup PASS.
- Server application DATAGRAM receive/send counters both 6000; send errors zero.
- Both capture logs report zero kernel capture drops; no truncated IPv4/UDP
  records or IP fragments were found in the parsed captures.

Encrypted UDP payloads were compared across captures, allowing a payload to be
contained in a larger captured payload to account for offload coalescing.
All client outgoing payloads were found on cloud. In the reverse direction,
two 194-byte payloads and one 33-byte payload were absent from the client capture.
The two 194-byte payloads were at positions 120 and 432 (zero based) among the
600 media-sized responses on their respective flows. These match the reported
missing sequence numbers in sessions 4 and 5. Payloads were not decrypted.

| Cloud source | Client destination | Cloud capture timestamp UTC | Media-sized response position |
|---|---|---|---|
| 45.88.174.72:3484 | 176.12.76.60:48943 | 21:08:56.176436 | 120 |
| 45.88.174.72:3484 | 176.12.76.60:41249 | 21:09:27.352118 | 432 |

The evidence locates these missing packets between capture points, including
possible host egress/ingress or virtual-network losses. It does not identify a
particular provider, router or NIC, nor prove every previous WAN loss has the
same cause. No application forwarding loss was identified in this run.

The original strict delivery verdict remains FAIL (5998/6000). This document
neither promotes WebTransport to supported nor claims day-long endurance,
independent client interoperability, or a successful PKI validation test.
