#!/usr/bin/env python3
"""Two-terminal AF_XDP WAN probe. Python 3.11+, run from repository root."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import statistics
from decimal import Decimal
import subprocess as sp
import sys
import time
import tomllib
import urllib.request


def command(*args):
    return sp.check_output(args, text=True)


def metrics():
    with urllib.request.urlopen('http://127.0.0.1:19100/metrics', timeout=2) as r:
        return r.read().decode()


def queue_gate(log, queues):
    last = {}
    for line in log.splitlines():
        if 'AF_XDP queue stats' not in line or 'final_snapshot=true' not in line:
            continue
        fields = dict(re.findall(r'\b(queue|rx|tx|parse_drops|tx_drops)=(\d+)', line))
        if len(fields) == 5:
            last[int(fields['queue'])] = {k: int(v) for k, v in fields.items()}
    return bool(queues) and all(q in last and last[q]['rx'] > 0 and last[q]['tx'] > 0
        and last[q]['parse_drops'] == last[q]['tx_drops'] == 0 for q in queues), last


def client_gate(data, rc, seconds, workload, min_delivery):
    sent, recv = data['sent'], data['recv']
    consistent = (isinstance(sent, int) and isinstance(recv, int) and sent > 0
                  and 0 <= recv <= sent and data['loss'] == sent - recv)
    delivery = Decimal(recv) * 100 / Decimal(sent) if sent > 0 else Decimal(0)
    volume = sent >= (seconds * 100 * .99 if workload == 'media' else 1000)
    duration = data.get('duration_s', 0) >= seconds * .99
    strict = consistent and sent == recv
    selected = strict if workload == 'churn' else consistent and delivery >= Decimal(str(min_delivery))
    return {'pass': rc == 0 and data['errs'] == 0 and volume and duration and selected,
            'client_exit': rc, 'workload': workload, 'strict_delivery': strict,
            'delivery_percent': float(delivery), 'min_delivery_percent': 100 if workload == 'churn' else min_delivery,
            'volume_pass': volume, 'duration_pass': duration}


def resource_gate(samples):
    if len(samples) < 12:
        return {'pass': False, 'error': 'fewer than 12 resource samples'}
    rss = [int(re.search(r'^VmRSS:\s+(\d+)', x['status'], re.M)[1]) for x in samples]
    floor = statistics.median(rss[:12])
    end = statistics.median(rss[-12:])
    fd_start, fd_end = samples[0]['fds'], samples[-1]['fds']
    return {'pass': end - floor <= 65536 and fd_end <= fd_start + 2,
            'rss_start_window_kib': floor, 'rss_end_window_kib': end,
            'rss_peak_kib': max(rss), 'rss_growth_limit_kib': 65536,
            'fds_start': fd_start, 'fds_end': fd_end, 'fd_slack': 2}


def stop(proc):
    if proc.poll() is None:
        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=60)
        except sp.TimeoutExpired:
            proc.kill()
            proc.wait()
    return proc.returncode


def server(a, out):
    source = Path(a.config).read_text()
    cfg = tomllib.loads(source)
    af = cfg['turn']['af_xdp']
    if a.workload == 'churn':
        rate = cfg['turn'].get('rate_limit', {})
        trusted = rate.get('trusted', {})
        if ('176.12.76.60/32' not in rate.get('trusted_prefixes', [])
                or trusted.get('allocate_rps', 0) < 256
                or trusted.get('allocate_burst', 0) < 256):
            raise ValueError('Churn requires the isolated kz trusted tier: 176.12.76.60/32, allocate_rps/burst >= 256; use afxdp-churn-ratefix.toml')
    iface = af['interface']
    if cfg['health']['listen'] != '127.0.0.1:19100':
        raise ValueError('This runner requires health.listen=127.0.0.1:19100')
    for kind, addr in [(socket.SOCK_STREAM, ('127.0.0.1', 19100)),
                       (socket.SOCK_DGRAM, ('45.88.174.72', 13478))]:
        with socket.socket(socket.AF_INET, kind) as probe:
            probe.bind(addr)
    before = json.loads(command('ip', '-j', '-details', 'link', 'show', 'dev', iface))[0]
    if before.get('xdp'):
        raise ValueError('Interface already has XDP attached; refusing to replace it')
    if len(re.findall(r'^attach_mode\s*=.*$', source, re.M)) != 1:
        raise ValueError('Expected exactly one attach_mode assignment')
    source = re.sub(r'^attach_mode\s*=.*$', f'attach_mode = "{a.mode}"', source, flags=re.M)
    if af.get('zero_copy', False):
        raise ValueError('This runner tests copy mode; zero_copy must be false')
    config = out / 'turn.toml'
    config.write_text(source)
    config.chmod(0o600)
    with (out / 'config-resolved.txt').open('w') as f:
        sp.run(['target/release/turna-node', '--dump-config', str(config)], stdout=f, check=True)
    (out / 'environment.txt').write_text(command('uname', '-a') + command('ip', '-details', 'link', 'show', 'dev', iface))
    proc = None
    samples = []
    final_metrics = ''
    try:
        with (out / 'node.log').open('w') as log:
            proc = sp.Popen(['target/release/turna-node', str(config)], stdout=log, stderr=sp.STDOUT,
                            env={**os.environ, 'RUST_LOG': 'info', 'NO_COLOR': '1',
                                 'TURNA_AFXDP_TRACE': '1' if a.trace else '0'})
            for _ in range(80):
                if proc.poll() is not None:
                    raise RuntimeError('Node failed to start; see node.log')
                try:
                    with urllib.request.urlopen('http://127.0.0.1:19100/ready', timeout=1):
                        break
                except OSError:
                    time.sleep(.5)
            else:
                raise RuntimeError('Readiness timeout')
            print(f'READY {a.mode}/copy — start kz now; automatic stop in {a.seconds}s', flush=True)
            end = time.monotonic() + a.seconds
            while time.monotonic() < end:
                if proc.poll() is not None:
                    raise RuntimeError('Node exited early')
                final_metrics = metrics()
                (out / 'metrics-final.txt').write_text(final_metrics)
                status = Path(f'/proc/{proc.pid}/status').read_text()
                samples.append({'time': time.time(), 'status': status,
                    'fds': len(list(Path(f'/proc/{proc.pid}/fd').iterdir()))})
                with (out / 'resources.jsonl').open('a') as f:
                    f.write(json.dumps(samples[-1]) + '\n')
                time.sleep(min(5, max(0, end - time.monotonic())))
            final_metrics = metrics()
            (out / 'metrics-final.txt').write_text(final_metrics)
            rc = stop(proc)
    finally:
        if proc is not None:
            stop(proc)
        (out / 'link-after.json').write_text(command('ip', '-j', '-details', 'link', 'show', 'dev', iface))
    log = re.sub(r'\x1b\[[0-9;]*m', '', (out / 'node.log').read_text())
    covered, queues = queue_gate(log, af.get('queue_ids') or [af.get('queue_id', 0)])
    values = dict(re.findall(r'^(turna_\w+)\s+([0-9.eE+-]+)$', final_metrics, re.M))
    required_zero = ['turna_afxdp_parse_drops_total', 'turna_afxdp_tx_drops_total',
        'turna_send_queue_dropped_total', 'turna_active_allocations', 'turna_processor_panics_total', 'turna_afxdp_relay_ports_registered', 'turna_afxdp_tx_inflight']
    zero = all(k in values and float(values[k]) == 0 for k in required_zero)
    detached = not json.loads((out / 'link-after.json').read_text())[0].get('xdp')
    resources = resource_gate(samples)
    result = {'pass': rc == 0 and covered and zero and detached and resources['pass'],
        'resources': resources, 'node_exit': rc,
        'queue_coverage': covered, 'queues': queues, 'cleanup_and_drop_counters': zero,
        'cleanup_values': {k: float(values[k]) if k in values else None for k in required_zero},
        'xdp_detached': detached,
        'scope': 'Server and bounded resource growth; client result required separately.'}
    return result


def client(a, out):
    rule = ['INPUT', '-s', '45.88.174.72/32', '-p', 'udp', '--sport', '23000:23255',
        '-m', 'comment', '--comment', f'turna-afxdp-{os.getpid()}', '-j', 'ACCEPT']
    proc = None
    if a.workload == 'media':
        sp.run(['iptables', '-I', 'INPUT', '1', *rule[1:]], check=True)
    try:
        with (out / 'result.json').open('w') as stdout, (out / 'client.err').open('w') as stderr:
            proc = sp.Popen(['target/release/turna-load-test', '--server', '45.88.174.72:13478',
                '--bind-ip', '176.12.76.60', '--secret', 'afxdp-wan-test-20260920', '--uid', 'afxdp-wan',
                '--duration', str(a.seconds), '--warmup', '0', '--json',
                *(['allocate', '--concurrency', '10'] if a.workload == 'churn' else
                  ['channel-data', '--channels', '10', '--pps', '10', '--payload', '160'])],
                stdout=stdout, stderr=stderr)
            print(f'Client running for {a.seconds}s; wait for automatic completion', flush=True)
            try:
                rc = proc.wait(timeout=a.seconds + 60)
            except sp.TimeoutExpired:
                stop(proc)
                rc = 124
    finally:
        if proc is not None:
            stop(proc)
        if a.workload == 'media':
            sp.run(['iptables', '-D', *rule], check=True)
    (out / 'client.exit').write_text(str(rc) + '\n')
    raw = (out / 'result.json').read_text()
    print(raw, flush=True)
    print((out / 'client.err').read_text(), flush=True)
    data = json.loads(raw)
    return client_gate(data, rc, a.seconds, a.workload, a.min_delivery_percent)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('role', choices=['serve', 'client'])
    p.add_argument('--mode', choices=['skb', 'native'], default='native')
    p.add_argument('--config')
    p.add_argument('--trace', action='store_true', help='Bounded STUN RX/TX/completion metadata and UMEM readback (server only)')
    p.add_argument('--workload', choices=['media', 'churn'], default='media')
    p.add_argument('--min-delivery-percent', type=float, default=99.99)
    p.add_argument('--seconds', type=int)
    p.add_argument('--out', required=True)
    a = p.parse_args()
    if not 0 < a.min_delivery_percent <= 100:
        p.error('--min-delivery-percent must be in (0, 100]')
    if os.geteuid() != 0:
        p.error('Run as root (cloud: sudo python3; kz root: python3)')
    if a.role == 'serve' and not a.config:
        p.error('serve requires --config')
    a.seconds = a.seconds if a.seconds is not None else (480 if a.role == 'serve' else 300)
    if a.seconds < 1:
        p.error('--seconds must be positive')
    os.umask(0o077)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=False)
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f'signal {signum}')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        result = server(a, out) if a.role == 'serve' else client(a, out)
    except (Exception, KeyboardInterrupt) as e:
        result = {'pass': False, 'error': str(e)}
    (out / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2), flush=True)
    print(f'Results: {out}', flush=True)
    return 0 if result['pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
