#!/usr/bin/env python3
"""Two-host transport check. Echo is loopback on cloud; all client media crosses WAN.
Rust clients deliberately accept the stand's self-signed certificate. This is not
PKI validation or an independent browser interoperability check.
"""
import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from transport_network_result import assess

ROOT = Path(__file__).resolve().parents[2]
os.chdir(ROOT)
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('mode', choices=['init', 'serve', 'client'])
p.add_argument('--transport', choices=['quic', 'wt', 'sctp'], default='quic')
p.add_argument('--server', default='45.88.174.72')
p.add_argument('--seconds', type=int, default=300)
p.add_argument('--sessions', type=int, default=10)
p.add_argument('--pps', type=int, default=10)
p.add_argument('--acceptance', choices=['strict', 'transport'], default='strict',
               help='strict: zero-loss delivery; transport: QUIC/WT session operation, with delivery reported separately')
p.add_argument('--credentials', type=Path, default=Path('/tmp/turna-network-credentials.json'))
p.add_argument('--out', type=Path)
a = p.parse_args()
if not 1 <= a.seconds <= 86400 or not 1 <= a.sessions <= 16 or not 1 <= a.pps <= 1000:
    p.error('seconds: 1..86400; sessions: 1..16; pps: 1..1000')
port = 3485 if a.transport == 'sctp' else 3484
health = 19097
observer = ROOT / 'scripts/verify/transport-observe.py'


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')


def stop(proc):
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def probe_port(kind, host, number, protocol=0):
    with socket.socket(socket.AF_INET, kind, protocol) as sock:
        if kind == socket.SOCK_STREAM and protocol == 0:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, number))
        if kind == socket.SOCK_STREAM:
            sock.listen(1)


if a.mode == 'init':
    # Exclusive create prevents accidental replacement of credentials already copied.
    fd = os.open(a.credentials, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump({'secret': secrets.token_hex(32)}, f)
    print('Created ' + str(a.credentials))
    sys.exit(0)

secret = json.loads(a.credentials.read_text())['secret']
if not isinstance(secret, str) or len(secret) != 64 or any(c not in '0123456789abcdef' for c in secret):
    sys.exit('Invalid test credentials; use init')
out = a.out or Path(f'transport-network-{a.mode}-{a.transport}-{time.strftime("%Y%m%d-%H%M%S")}')
out.mkdir(parents=True, exist_ok=False)
os.chmod(out, 0o700)
profile = os.environ.get('BUILD_PROFILE', 'release')
if profile not in ('release', 'debug'):
    sys.exit('BUILD_PROFILE must be release or debug')
binary = ROOT / 'target' / profile / ('turna-node' if a.mode == 'serve' else 'turna-load-test')
if not binary.is_file():
    sys.exit(f'Missing binary: {binary}; build it first')
write_json(out / 'manifest.json', {
    'mode': a.mode, 'transport': a.transport, 'server': a.server, 'port': port,
    'seconds': a.seconds, 'sessions': a.sessions, 'pps': a.pps,
    'binary_sha256': hashlib.file_digest(binary.open('rb'), 'sha256').hexdigest()
        if hasattr(hashlib, 'file_digest') else hashlib.sha256(binary.read_bytes()).hexdigest(),
    'kernel': os.uname().release, 'hostname': socket.gethostname(),
    'utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'scope': 'WAN client transport; loopback UDP echo on node host; test certificate not verified',
})

if a.mode == 'client':
    # Resolve explicitly to IPv4. No SSH connection or reverse port forwarding needed.
    address = socket.gethostbyname(a.server)
    processes = []
    lock = threading.Lock()

    def client(i):
        cmd = [str(binary), '--server', f'{address}:{port}', '--secret', secret,
               '--uid', f'network-{i}', '--duration', str(a.seconds), '--json',
               'transport-network', '--transport', a.transport, '--pps', str(a.pps)]
        with (out / f'session-{i}.json').open('w') as stdout, (out / f'session-{i}.err').open('w') as stderr:
            proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, env={**os.environ, 'TOKIO_WORKER_THREADS': '2'})
            with lock:
                processes.append(proc)
            try:
                rc = proc.wait(timeout=a.seconds + 40)
            except subprocess.TimeoutExpired:
                stop(proc)
                rc = 124
        try:
            result = json.loads((out / f'session-{i}.json').read_text().strip().splitlines()[-1])
        except (ValueError, IndexError):
            result = {'sent': 0, 'recv': 0, 'errs': 1, 'error': 'No JSON result; inspect session stderr'}
        result['exit_code'] = rc
        result['session'] = i
        result.update(assess(result, a.seconds, a.pps, a.transport, a.acceptance))
        print(f"session {i}: {'PASS' if result['pass'] else 'FAIL'} {result['sent']}/{result['recv']}"
              f"; stability={'PASS' if result['stability_pass'] else 'FAIL'}"
              f"; missing={result.get('missing_echoes', '?')} deadlines={result.get('echo_timeouts', '?')}", flush=True)
        return result

    pool = concurrent.futures.ThreadPoolExecutor(max_workers=a.sessions)
    try:
        results = list(pool.map(client, range(a.sessions)))
    finally:
        with lock:
            for proc in processes:
                stop(proc)
        pool.shutdown(wait=True, cancel_futures=True)
    passed = all(r['pass'] for r in results)
    write_json(out / 'results.json', results)
    summary = f"# Network {a.transport} ({a.acceptance} acceptance): {'PASS' if passed else 'FAIL'}\n\n"
    summary += f"- Destination: {address}:{port}\n- {a.seconds}s per session; {a.sessions} sessions; {a.pps} round trips/s target\n"
    summary += '- Paced sends with up to 128 packets in flight per session; verified 160-byte echoes; no warmup.\n'
    summary += ('- Native SCTP without TLS. UDP echo stays on cloud.\n\n' if a.transport == 'sctp' else '- Test certificate accepted without PKI validation. UDP echo stays on cloud.\n\n')
    summary += f'- Acceptance policy: {a.acceptance}; SCTP always requires strict delivery.\n'
    summary += '- Transport acceptance checks completion, zero protocol/operational errors, offered volume and some verified media; it does not certify network quality or supported status.\n'
    summary += '- Server monitoring/cleanup must also pass separately.\n'
    summary += '- Strict delivery gate: zero missing echoes and zero 5-second deadline violations.\n'
    summary += '- QUIC/WT continue after individual media deadlines; SCTP remains fail-fast.\n'
    summary += '- Selected-policy PASS requires at least 99% of target send volume. Delivery FAIL remains visible even when transport acceptance passes.\n\n'
    summary += '| Session | Sent | Verified | Missing | Deadlines | Late | Errors | Stability | Rate | Delivery | Selected policy |\n|---|---|---|---|---|---|---|---|---|---|---|\n'
    for r in results:
        gates = ' | '.join('PASS' if r[k] else 'FAIL' for k in ('stability_pass', 'rate_pass', 'delivery_pass', 'pass'))
        summary += f"| {r['session']} | {r['sent']} | {r['recv']} | {r.get('missing_echoes', '?')} | {r.get('echo_timeouts', '?')} | {r.get('late_echoes', '?')} | {r['errs']} | {gates} |\n"
    for r in results:
        if r['failure_reasons']:
            summary += f"\n- Session {r['session']}: " + '; '.join(r['failure_reasons']) + '.\n'
    (out / 'summary.md').write_text(summary)
    print(summary)
    sys.exit(0 if passed else 1)

# Server side: all preflights happen before the test node starts.
probe_port(socket.SOCK_STREAM, '127.0.0.1', health)
probe_port(socket.SOCK_DGRAM, '127.0.0.1', 3476)
probe_port(socket.SOCK_STREAM if a.transport == 'sctp' else socket.SOCK_DGRAM,
           '0.0.0.0', port, 132 if a.transport == 'sctp' else 0)
echo = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
echo.bind(('127.0.0.1', 39001))
echo.settimeout(.5)
ending = threading.Event()
echo_count = [0]
echo_errors = []


def echo_loop():
    while not ending.is_set():
        try:
            data, source = echo.recvfrom(2048)
            if source[0] == '127.0.0.1' and 22000 <= source[1] <= 22847 and len(data) == 160:
                echo.sendto(data, source)
                echo_count[0] += 1
        except socket.timeout:
            pass
        except OSError as e:
            echo_errors.append(str(e))
            ending.set()


subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                '-nodes', '-keyout', str(out / 'key.pem'), '-out', str(out / 'cert.pem'),
                '-days', '2', '-subj', '/CN=localhost'], check=True, capture_output=True)
section = (f'[turn.sctp]\nenabled = true\nlisten = "0.0.0.0:{port}"\nmax_connections_per_ip = 32\n'
           if a.transport == 'sctp' else
           f'[turn.quic]\nenabled = true\nlisten = "0.0.0.0:{port}"\n'
           f'cert_path = "{(out / "cert.pem").resolve()}"\nkey_path = "{(out / "key.pem").resolve()}"\n'
           f'web_transport = {str(a.transport == "wt").lower()}\n')
config = f'''production = false
[turn]
listen = "127.0.0.1:3476"
external_ip = "127.0.0.1"
realm = "network-test"
transport = "tokio"
[turn.auth]
shared_secret = "{secret}"
[turn.peer_filter]
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = 22000
max_port = 22847
max_allocations = 64
[turn.relay.quota]
max_per_user = 0
[health]
listen = "127.0.0.1:{health}"
{section}'''
(out / 'node.toml').write_text(config)
node = sampler = None
worker = threading.Thread(target=echo_loop)
worker.start()
for sig in (signal.SIGTERM, signal.SIGINT):
    signal.signal(sig, lambda *_: ending.set())
ok = False
try:
    with (out / 'node.log').open('w') as log:
        node = subprocess.Popen([str(binary), str(out / 'node.toml')], stdout=log, stderr=log, start_new_session=True)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for _ in range(60):
        if node.poll() is not None:
            raise RuntimeError('Node stopped; see node.log')
        try:
            with opener.open(f'http://127.0.0.1:{health}/ready', timeout=1) as r:
                if r.status == 200:
                    break
        except OSError:
            time.sleep(.25)
    else:
        raise RuntimeError('Node readiness timeout')
    sampler = subprocess.Popen([sys.executable, str(observer), 'sample', '--pid', str(node.pid),
                                '--port', str(health), '--out', str(out / 'resources.jsonl')],
                                start_new_session=True)
    print(f'READY {a.transport} port={port}; run client on server. After client finishes press Ctrl+C here.', flush=True)
    while not ending.wait(.5):
        if node.poll() is not None or sampler.poll() is not None:
            raise RuntimeError('Node or monitoring stopped unexpectedly')
    with (out / 'cleanup.log').open('w') as log:
        cleanup = subprocess.run([sys.executable, str(observer), 'cleanup', '--transport', a.transport,
                                  '--port', str(health)], stdout=log, stderr=log)
    stop(sampler)
    with (out / 'monitoring.log').open('w') as log:
        report = subprocess.run([sys.executable, str(observer), 'report', '--out', str(out / 'resources.jsonl')],
                                stdout=log, stderr=log)
    ok = cleanup.returncode == 0 and report.returncode == 0 and echo_count[0] > 0 and not echo_errors
finally:
    ending.set()
    stop(sampler)
    stop(node)
    worker.join(timeout=2)
    echo.close()
    write_json(out / 'server-result.json', {'pass': ok, 'echoes': echo_count[0], 'echo_errors': echo_errors})
print(f"Server monitoring/cleanup: {'PASS' if ok else 'FAIL'}; echoes={echo_count[0]}; {out}")
sys.exit(0 if ok else 1)
