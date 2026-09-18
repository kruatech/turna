#!/usr/bin/env python3
"""Lifecycle, admission and backpressure checks. Isolated loopback nodes only."""
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time
import urllib.request

REPO = Path(__file__).resolve().parents[2]
os.chdir(REPO)
OUT = Path(os.environ.get('OUT', 'transport-lifecycle-' + time.strftime('%Y%m%d-%H%M%S'))).resolve()
PHASES = os.environ.get('PHASES', 'quic wt').split()
CASES = os.environ.get('CASES', 'reconnect crash global-cap ip-cap pressure').split()
CYCLES = int(os.environ.get('CYCLES', '10'))
CRASH_ROUNDS = int(os.environ.get('CRASH_ROUNDS', '3'))
HEALTH = int(os.environ.get('HEALTH_PORT', '19096'))
PORT = int(os.environ.get('TRANSPORT_PORT', '3484'))
CONTROL = int(os.environ.get('TURN_PORT', '3476'))
RSS_LIMIT = int(os.environ.get('MAX_RSS_GROWTH_MIB', '64')) * 1024
FD_SLACK = int(os.environ.get('FD_SLACK', '2'))
if not PHASES or any(p not in ('quic', 'wt', 'sctp') for p in PHASES):
    sys.exit('PHASES must select quic wt sctp')
if not CASES or any(c not in ('reconnect', 'crash', 'global-cap', 'ip-cap', 'pressure') for c in CASES):
    sys.exit('Unknown or empty CASES selection')
if len(PHASES) != len(set(PHASES)) or len(CASES) != len(set(CASES)):
    sys.exit('PHASES and CASES must not contain duplicates')
if min(CYCLES, CRASH_ROUNDS, RSS_LIMIT) <= 0 or FD_SLACK < 0:
    sys.exit('CYCLES, CRASH_ROUNDS and RSS limit must be positive; FD_SLACK nonnegative')
OUT.mkdir(parents=True, exist_ok=True)
PROFILE = os.environ.get('BUILD_PROFILE', 'release')
if PROFILE not in ('release', 'dev'):
    sys.exit('BUILD_PROFILE must be release or dev')
BIN = REPO / 'target' / ('release' if PROFILE == 'release' else 'debug')
SECRET = secrets.token_hex(24)
children = []
results = []


def announce(message):
    print(time.strftime('[%H:%M:%S] ') + message, flush=True)


def metrics():
    with urllib.request.urlopen(f'http://127.0.0.1:{HEALTH}/metrics', timeout=2) as r:
        body = r.read().decode()
    values = {}
    for line in body.splitlines():
        fields = line.split()
        if len(fields) == 2 and not line.startswith('#') and '{' not in fields[0]:
            values[fields[0]] = float(fields[1])
    return values


def terminate(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def shutdown(*_):
    raise KeyboardInterrupt


signal.signal(signal.SIGTERM, shutdown)


class Probe:
    def __init__(self, phase, label, action='hold', hold=0):
        self.path = OUT / (label + '.client.log')
        self.log = self.path.open('w')
        self.proc = subprocess.Popen([
            str(BIN / 'turna-load-test'), '--server', f'127.0.0.1:{PORT}',
            '--secret', SECRET, 'transport-probe', '--transport', phase,
            '--action', action, '--hold-secs', str(hold),
        ], stdout=self.log, stderr=subprocess.STDOUT)
        children.append(self.proc)

    def events(self):
        values = []
        for line in self.path.read_text().splitlines():
            try:
                value = json.loads(line)
                if isinstance(value, dict):
                    values.append(value)
            except ValueError:
                pass
        return values

    def count(self, event):
        return sum(e.get('event') == event for e in self.events())

    def ready(self):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if self.count('ready'):
                return
            if self.proc.poll() is not None:
                break
            time.sleep(.05)
        raise RuntimeError(f'client did not establish verified media: {self.path.name}')

    def finish(self):
        try:
            rc = self.proc.wait(timeout=15)
        except subprocess.TimeoutExpired as e:
            raise RuntimeError(f'client timed out: {self.path.name}') from e
        if rc != 0 or not self.count('closed'):
            raise RuntimeError(f'client failed: {self.path.name} (exit {rc})')

    def graceful(self):
        if self.proc.poll() is not None:
            raise RuntimeError(f'client exited before graceful close: {self.path.name}')
        self.proc.send_signal(signal.SIGUSR1)
        self.finish()

    def kill(self):
        if self.proc.poll() is not None:
            raise RuntimeError(f'client exited before deliberate SIGKILL: {self.path.name}')
        self.proc.kill()
        self.proc.wait(timeout=5)


class Node:
    def __init__(self, phase, case, cap=4, per_ip=0):
        self.phase, self.label = phase, phase + '-' + case
        self.session_key = 'turna_sctp_active_associations' if phase == 'sctp' else 'turna_quic_active_sessions'
        self.prefix = 'turna_sctp_' if phase == 'sctp' else 'turna_quic_'
        # Fail if the selected health port is already occupied; never inspect
        # another process or shut it down as part of these tests.
        with socket.socket() as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('127.0.0.1', HEALTH))
            s.listen(1)
        section = f'''[turn.sctp]
enabled = true
listen = "127.0.0.1:{PORT}"
max_connections = {cap}
max_connections_per_ip = {per_ip}
read_timeout_secs = 60
''' if phase == 'sctp' else f'''[turn.quic]
enabled = true
listen = "127.0.0.1:{PORT}"
web_transport = {str(phase == 'wt').lower()}
cert_path = "{OUT}/cert.pem"
key_path = "{OUT}/key.pem"
max_sessions = {cap}
max_sessions_per_ip = {per_ip}
max_handshakes_per_sec_per_ip = 0
idle_timeout_secs = 10
keep_alive_secs = 1
max_bi_streams = 8
'''
        # Pressure must close the offender before the 60s idle deadline.
        if case == 'pressure':
            section = section.replace('idle_timeout_secs = 10', 'idle_timeout_secs = 60')
        config = OUT / (self.label + '.toml')
        config.write_text(f'''production = false
[turn]
listen = "127.0.0.1:{CONTROL}"
external_ip = "127.0.0.1"
realm = "lifecycle"
transport = "tokio"
[turn.auth]
shared_secret = "{SECRET}"
[turn.peer_filter]
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = 21000
max_port = 21847
max_allocations = 800
[health]
listen = "127.0.0.1:{HEALTH}"
{section}''')
        self.log = (OUT / (self.label + '.node.log')).open('w')
        self.samples = (OUT / (self.label + '.resources.jsonl')).open('w', buffering=1)
        self.proc = subprocess.Popen([str(BIN / 'turna-node'), str(config)], stdout=self.log, stderr=subprocess.STDOUT)
        children.append(self.proc)
        self.start = time.monotonic()
        self.baseline = None
        self.probes = []
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f'node exited: {self.label}.node.log')
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{HEALTH}/ready', timeout=1):
                    break
            except OSError:
                time.sleep(.2)
        else:
            raise RuntimeError('node readiness timeout')
        self.zero()
        self.normal('warmup')
        self.zero()
        self.baseline = self.sample()

    def sample(self):
        if self.proc.poll() is not None:
            raise RuntimeError('node exited during test')
        m = metrics()
        ps = subprocess.check_output(['ps', '-p', str(self.proc.pid), '-o', 'rss=,pcpu='], text=True, timeout=2).split()
        row = {'elapsed_s': round(time.monotonic() - self.start, 3), 'rss_kib': int(ps[0]),
               'cpu_percent': float(ps[1]), 'fds': m.get('turna_process_open_fds'), 'metrics': m}
        self.samples.write(json.dumps(row) + '\n')
        required = ['turna_active_allocations', self.session_key]
        if sys.platform.startswith('linux'):
            required.append('turna_process_open_fds')
        if any(k not in m for k in required):
            raise RuntimeError('required metrics missing: rebuild node with monitoring patch')
        if self.baseline and row['rss_kib'] > self.baseline['rss_kib'] + RSS_LIMIT:
            raise RuntimeError('RSS growth exceeded configured bound')
        return row

    def wait(self, predicate, label, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = self.sample()
            if predicate(row):
                return row
            time.sleep(.25)
        raise RuntimeError(label + ' timed out')

    def zero(self):
        self.wait(lambda r: r['metrics']['turna_active_allocations'] == 0 and
                  r['metrics'][self.session_key] == 0 and
                  (not self.baseline or r['fds'] is None or r['fds'] <= self.baseline['fds'] + FD_SLACK),
                  'allocation/session/FD cleanup')

    def probe(self, suffix, action='hold', hold=0):
        p = Probe(self.phase, self.label + '-' + suffix, action, hold)
        self.probes.append(p)
        return p

    def normal(self, suffix):
        p = self.probe(suffix)
        p.ready()
        p.finish()

    def live(self, suffix):
        p = self.probe(suffix, hold=120)
        p.ready()
        return p

    def healthy(self, p, previous):
        self.wait(lambda _: p.count('healthy') >= previous + 2, 'unaffected client media', timeout=5)
        if p.proc.poll() is not None:
            raise RuntimeError('unaffected client exited')

    def close(self):
        for p in self.probes:
            terminate(p.proc)
            p.log.close()
        terminate(self.proc)
        self.samples.close()
        self.log.close()


def run_case(phase, case):
    node = None
    try:
        node = Node(phase, case, cap=2 if case == 'global-cap' else 4, per_ip=1 if case == 'ip-cap' else 0)
        if case == 'reconnect':
            for i in range(CYCLES):
                node.normal(str(i))
                node.zero()
        elif case == 'crash':
            survivor = node.live('survivor')
            for i in range(CRASH_ROUNDS):
                victim = node.live('victim-' + str(i))
                node.wait(lambda r: r['metrics'][node.session_key] == 2 and r['metrics']['turna_active_allocations'] == 2, 'two live clients')
                heartbeat = survivor.count('healthy')
                victim.kill()
                node.wait(lambda r: r['metrics'][node.session_key] == 1 and r['metrics']['turna_active_allocations'] == 1, 'crash cleanup')
                node.healthy(survivor, heartbeat)
            survivor.graceful()
            node.zero()
            node.normal('recovery')
            node.zero()
        elif case in ('global-cap', 'ip-cap'):
            survivor = node.live('survivor')
            other = node.live('second-slot') if case == 'global-cap' else None
            key = node.prefix + ('rejected_over_cap_total' if case == 'global-cap' else 'rejected_per_ip_total')
            before = node.sample()['metrics'][key]
            heartbeat = survivor.count('healthy')
            refused = node.probe('refused')
            rc = refused.proc.wait(timeout=15)
            if rc == 0 or refused.count('ready'):
                raise RuntimeError('over-limit client unexpectedly admitted')
            node.wait(lambda r: r['metrics'][key] > before, 'admission rejection counter')
            node.healthy(survivor, heartbeat)
            if other:
                other.kill()
                node.wait(lambda r: r['metrics'][node.session_key] == 1 and r['metrics']['turna_active_allocations'] == 1, 'slot release')
                node.normal('slot-reused')
            survivor.graceful()
            node.zero()
            node.normal('recovery')
            node.zero()
        else:
            survivor = node.live('survivor')
            key = node.prefix + ('send_dropped_total' if phase == 'sctp' else 'send_errors_total')
            before = node.sample()['metrics'][key]
            offender = node.probe('nonreader', action='pressure', hold=30)
            offender.ready()
            heartbeat = survivor.count('healthy')
            node.wait(lambda r: offender.count('pressure_started') and
                      r['metrics'][key] > before and r['metrics'][node.session_key] == 1 and
                      r['metrics']['turna_active_allocations'] == 1, 'backpressure close and cleanup', timeout=20)
            if offender.proc.poll() is not None:
                raise RuntimeError('offender exited before server cleanup was observed')
            node.healthy(survivor, heartbeat)
            offender.kill()
            survivor.graceful()
            node.zero()
            node.normal('recovery')
            node.zero()
        return True, 'verified'
    except Exception as e:
        return False, str(e)
    finally:
        if node:
            node.close()
        # Also cover constructors that fail before returning a Node instance.
        for p in children:
            terminate(p)
        children.clear()


def summary():
    text = ['# Transport lifecycle and limits', '',
            f'- cycles: {CYCLES}; crash rounds: {CRASH_ROUNDS}',
            f'- RSS growth bound: {RSS_LIMIT // 1024} MiB; post-cleanup FD slack: {FD_SLACK}',
            '- Independent node per case; two-way payload checks; native SCTP requires Linux.',
            '- Pressure combines a non-reading peer and bounded authenticated request flooding.',
            '- This is not a throughput benchmark or independent interoperability test.', '',
            '| Transport | Case | Result | Detail |', '|---|---|---|---|']
    for phase, case, ok, detail in results:
        text.append(f'| {phase} | {case} | {"PASS" if ok else "FAIL"} | {detail.replace("|", "/")} |')
    text += ['', f'{sum(r[2] for r in results)} passed, {sum(not r[2] for r in results)} failed.']
    (OUT / 'summary.md').write_text('\n'.join(text) + '\n')


try:
    if 'sctp' in PHASES:
        subprocess.run(['python3', 'scripts/verify/transport-observe.py', 'sctp'], check=True)
    features = 'quic,web-transport' + (',sctp' if 'sctp' in PHASES else '')
    announce('building node and probe client')
    with (OUT / 'build.log').open('w') as log:
        subprocess.run(['cargo', 'build', '--locked', '-p', 'turna-node', '-p', 'turna-load-test',
                        '--features', features] + (['--release'] if PROFILE == 'release' else []),
                       check=True, stdout=log, stderr=subprocess.STDOUT)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
                    '-nodes', '-keyout', str(OUT/'key.pem'), '-out', str(OUT/'cert.pem'), '-days', '2',
                    '-subj', '/CN=localhost'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for phase in PHASES:
        for case in CASES:
            announce(phase + ': ' + case)
            ok, detail = run_case(phase, case)
            results.append((phase, case, ok, detail))
            summary()
            announce(('PASS ' if ok else 'FAIL ') + detail)
    sys.exit(0 if all(r[2] for r in results) else 1)
except KeyboardInterrupt:
    announce('interrupted; stopping only test-owned processes')
    sys.exit(130)
finally:
    for p in children:
        terminate(p)
