#!/usr/bin/env python3
"""RFC 6062 §5.3 end-to-end probe.

A peer-initiated TCP connection to a relayed address must be closed at once,
with no ConnectionAttempt sent to the client, unless the allocation holds a
permission for the peer's IP.

Needs a node with [tls] and [turn.tcp_relay] enabled, a static user
testuser/testpass, and `[turn.peer_filter] allow_loopback_peers = true` (the
peers are 127.0.0.2 and 127.0.0.3). Usage:

    python3 scripts/verify/rfc6062_peer_permission.py [HOST:TURNS_PORT]

Exits non-zero if the unpermitted peer is announced or left open, or if the
permitted peer is not announced. Standard library only; certificate checking
is off because the target is a test node.
"""
import hashlib
import hmac
import os
import socket
import ssl
import struct
import sys

MAGIC = 0x2112A442
ALLOCATE, CREATE_PERMISSION = 0x0003, 0x0008
ALLOCATE_OK, CREATE_PERMISSION_OK, CONNECTION_ATTEMPT = 0x0103, 0x0108, 0x001C
USERNAME, MESSAGE_INTEGRITY, ERROR_CODE, REALM, NONCE = 0x0006, 0x0008, 0x0009, 0x0014, 0x0015
XOR_PEER, XOR_RELAYED, REQ_TRANSPORT, CONNECTION_ID = 0x0012, 0x0016, 0x0019, 0x002A


def attr(t, v):
    return struct.pack("!HH", t, len(v)) + v + b"\0" * ((4 - len(v) % 4) % 4)


def message(method, attrs, key=None):
    tid = os.urandom(12)
    body = b"".join(attrs)
    if key:
        hdr = struct.pack("!HHI", method, len(body) + 24, MAGIC) + tid
        body += attr(MESSAGE_INTEGRITY, hmac.new(key, hdr + body, hashlib.sha1).digest())
    return struct.pack("!HHI", method, len(body), MAGIC) + tid + body


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("control connection closed")
        buf += chunk
    return buf


def recv_message(sock):
    hdr = recv_exact(sock, 20)
    typ, length, _ = struct.unpack("!HHI", hdr[:8])
    body = recv_exact(sock, length)
    attrs, i = {}, 0
    while i < length:
        at, al = struct.unpack("!HH", body[i:i + 4])
        attrs.setdefault(at, body[i + 4:i + 4 + al])
        i += 4 + al + ((4 - al % 4) % 4)
    return typ, attrs


def xor_addr(v):
    port = struct.unpack("!H", v[2:4])[0] ^ (MAGIC >> 16)
    ip = struct.unpack("!I", v[4:8])[0] ^ MAGIC
    return socket.inet_ntoa(struct.pack("!I", ip)), port


def xor_peer(ip, port):
    x_ip = struct.unpack("!I", socket.inet_aton(ip))[0] ^ MAGIC
    return attr(XOR_PEER, struct.pack("!BBHI", 0, 1, port ^ (MAGIC >> 16), x_ip))


def main():
    host, port = (sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1:5349").rsplit(":", 1)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctl = ctx.wrap_socket(socket.create_connection((host, int(port))))
    ctl.settimeout(3)

    tcp = attr(REQ_TRANSPORT, bytes([6, 0, 0, 0]))
    ctl.sendall(message(ALLOCATE, [tcp]))
    _, a = recv_message(ctl)
    realm, nonce = a[REALM], a[NONCE]
    key = hashlib.md5(b"testuser:" + realm + b":testpass").digest()
    auth = [attr(USERNAME, b"testuser"), attr(REALM, realm), attr(NONCE, nonce)]

    ctl.sendall(message(ALLOCATE, [tcp] + auth, key))
    typ, a = recv_message(ctl)
    if typ != ALLOCATE_OK:
        sys.exit(f"TCP Allocate failed: {typ:#06x} {a.get(ERROR_CODE)}")
    relay_ip, relay_port = xor_addr(a[XOR_RELAYED])
    print(f"relayed {relay_ip}:{relay_port}")

    ctl.sendall(message(CREATE_PERMISSION, [xor_peer("127.0.0.2", 0)] + auth, key))
    typ, _ = recv_message(ctl)
    if typ != CREATE_PERMISSION_OK:
        sys.exit(f"CreatePermission failed: {typ:#06x}")
    print("permission installed for 127.0.0.2 only")

    def connect_from(src):
        c = socket.socket()
        c.bind((src, 0))
        c.connect((host, relay_port))
        c.settimeout(2)
        return c

    failed = False
    stranger = connect_from("127.0.0.3")
    try:
        closed = stranger.recv(1) == b""
    except ConnectionResetError:
        closed = True
    except socket.timeout:
        closed = False
    print("unpermitted peer:", "closed by server" if closed else "LEFT OPEN (FAIL)")
    failed |= not closed

    ctl.settimeout(1.5)
    try:
        typ, _ = recv_message(ctl)
        print(f"unpermitted peer: control connection received {typ:#06x} (FAIL)")
        failed = True
    except socket.timeout:
        print("unpermitted peer: no ConnectionAttempt")

    friend = connect_from("127.0.0.2")
    ctl.settimeout(3)
    typ, a = recv_message(ctl)
    if typ == CONNECTION_ATTEMPT:
        conn_id = struct.unpack("!I", a[CONNECTION_ID])[0]
        print(f"permitted peer: ConnectionAttempt from {xor_addr(a[XOR_PEER])}, id {conn_id}")
    else:
        print(f"permitted peer: expected ConnectionAttempt, got {typ:#06x} (FAIL)")
        failed = True
    friend.close()
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
