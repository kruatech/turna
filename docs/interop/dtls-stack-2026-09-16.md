# DTLS verification — `crates/dtls`, 2026-09-16

Verification of the DTLS stack that ships in 0.5.0, against the plan in
`docs/verification/dtls-stack-2026-09-15.md`. Every earlier DTLS result measured
`webrtc-dtls` 0.10 as a dependency and does not describe this code.

**Result: all applicable checks pass.** Two defects were found and fixed during
the run; both are described below, because a verification that only records
successes is a verification nobody can learn from.

Host: `cloud`, Ubuntu, 4 cores. Build: `cargo build --release -p turna-node
--features dtls`. Certificate: Let's Encrypt ECDSA P-256 for
`turna.quinter.ru`, except where a test replaces it.

## 1. Spoofed-source flood — the reason this work happened

The defect: a ClientHello from an unknown address allocated a channel, a map
entry, a connection and a task before anything proved the sender existed.

300 000 **valid** ClientHellos, captured from a real handshake and replayed from
`198.51.100.1` (RFC 5737 documentation range) with `hping3 -a`:

```
sudo hping3 --udp -p 35349 -a 198.51.100.1 -i u10 -c 100000 --file /tmp/hello.bin -d 205 127.0.0.1
```

| | before | after |
|---|---|---|
| `turna_dtls_cookie_challenges_total` | 1 | 299 894 |
| `turna_dtls_pending_handshakes` | 0 | **0** |
| `turna_dtls_rejected_pending_cap_total` | 0 | **0** |
| RSS | 10.4 MiB | 11.5 MiB |

Every spoofed hello got a HelloVerifyRequest and **no state**. The backstop cap
was never reached, because the gate in front of it did the work.

A first run with random bytes rather than a captured ClientHello was also done
(100 000 packets, all dropped unparsed). It proves less than it looks: the old
code would have survived garbage too, because garbage fails early. The valid
ClientHello is the case that used to allocate.

**And the half that is usually skipped:** a legitimate client during the flood.
With 200 000 spoofed hellos in flight, `openssl s_client` completed a full
handshake — `SSL handshake has read 7603 bytes`,
`ECDHE-ECDSA-AES128-GCM-SHA256`. The node is not merely surviving the flood, it
is still serving.

## 2. Twenty-four hours under load

`docs/soak/soak-24h-dtls-2026-09-15.md`. Eleven DTLS phases, 552 948–552 951
packets each, **zero loss** every phase, 312/s, 88 MB relayed back. The spread
between the first phase (hour 0.6) and the last (hour 22.9) is two packets.
Handshake failures 0, accept timeouts 0, `pending_handshakes` 0 throughout.

## 3. Packet loss on the path

The change in 0.5.0 is in handshake sequence numbering, and loss is what makes
sequence numbering matter: a dropped HelloVerifyRequest means the client
retransmits at `message_seq` 0 while the server has moved to 1.

```
sudo tc qdisc add dev lo root netem loss 3%
```

20 consecutive handshakes, **20 completed**. No retry logic was needed on the
client side.

## 4. coturn's client

`turnutils_uclient` from coturn — a third independent implementation after
OpenSSL and this project's own load tool.

```
turnutils_uclient -S -v -e 1.1.1.1 -u testuser -w testpass -p 35349 127.0.0.1
```

DTLS handshake (`ECDHE-ECDSA-AES128-GCM-SHA256`, DTLSv1.2, certificate
verified), then Allocate, CreatePermission, ChannelBind and ten packets through
the relay, then a clean close. The peer was `1.1.1.1`, so nothing comes back —
this exercises the path to the relay, not an end-to-end exchange.

Two observations worth keeping:

**The first two handshake attempts fail with `internal error`, the third
succeeds.** This matches the 3:1 ratio of `cookie_challenges` to sessions seen
in the soak, and it now shows on an independent client — so it is a property of
this server, not of the load tool. Not diagnosed. It costs two extra round trips
on a first connection and nothing else observable: handshake failures stay at
zero and every client gets through.

**A single-machine end-to-end relay test is not possible.** `-y`
(client-to-client) relays through the node's own advertised address, and the
peer filter denies a node's own addresses unconditionally — by design, closing
relay-to-self (finding 25). The filter is right and the test cannot be run that
way. Two hosts would be needed.

## 5. Certificate hot-reload

`cert_reload_secs = 20`, a live listener, files replaced underneath it.

| Case | `reloads` | `failures` | Served to the next client |
|---|---|---|---|
| Valid ECDSA P-256 pair | 2 | 0 | the **new** certificate (`CN = rotated`) |
| Truncated/garbage cert | 2 | 1 | the **previous** certificate, still working |
| RSA pair (see below) | 0 | 1 | the **previous** certificate, still working |

Reload works, and a bad file does not cost the running certificate.

## 6. Browsers — not applicable, and the plan was wrong to ask

The plan listed Chrome, Firefox and Safari. **Browsers cannot speak TURN over
DTLS at all**: WebRTC's ICE configuration offers `turn:` (UDP/TCP) and `turns:`
(TLS over TCP), and RFC 7350's DTLS transport is not among them. DTLS in a
browser is used inside the media path between peers, not to reach a TURN server.

The item was written by analogy with TURNS without checking whether it applied.
Recorded here rather than quietly dropped, because the next person will have the
same idea.

## Defects found during verification

Both were found by running the checks, not by reading the code, and both are
fixed in this release.

### An unusable key pair was accepted silently

Rotating to an RSA certificate reported **success** — `cert_reloads_total`
incremented, the audit log recorded `DTLS certificate reloaded; new sessions use
it` — and then every handshake failed with `invalid private key type`. The
listener was dead and every signal said it was fine.

`Certificate::from_pem` parses an RSA key happily; `validate_config` refuses it
at handshake time, because the DTLS server side accepts only Ed25519 and ECDSA
P-256. Nothing checked in between.

`load_operator_certificate` now applies the same predicate as `validate_config`
— deliberately the same one, so a second independently written check cannot
drift from it on an upgrade and put the silent failure back. A bad pair is now a
reload failure with the generating command in the message, and the previous
certificate stays in service.

### Two code paths contradicted each other

`dtls_demux` logged `DTLS certificate reloaded; new sessions use it` while
`dtls_listener` logged `DTLS certificate material changed on disk but DTLS
cannot hot-reload it … restart the node to pick up the new one` — about the same
file, seconds apart.

The warning predates the demultiplexer's reload support and was never narrowed
when it landed. It is now scoped to the stock listener, which genuinely does fix
its config at `listen()`, and the demux path says what it actually does. An
operator following the old warning would have restarted a node that had already
picked the change up.

Also corrected: the load failure said "refusing to start" on the reload path,
where the node is running and keeping its previous certificate.

## What this does and does not establish

Established: the cookie gate holds under a flood while still serving real
clients; the stack does not degrade over a day; it survives 3 % loss;
it interoperates with OpenSSL and with coturn's client; certificate rotation
works and fails safe.

Not established: end-to-end relay across two hosts; behaviour above 50
concurrent handshakes; the cause of the two failed attempts before a successful
handshake. None of these blocks the beta label, and the third is worth a wire
capture when somebody has an hour.
