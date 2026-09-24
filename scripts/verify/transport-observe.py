#!/usr/bin/env python3
"""Kernel preflight, resource samples and post-run allocation/session cleanup."""
import argparse
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import time
import urllib.request

p = argparse.ArgumentParser()
p.add_argument('mode', choices=['sctp', 'sample', 'cleanup', 'report'])
p.add_argument('--pid', type=int)
p.add_argument('--port', type=int, default=9091)
p.add_argument('--transport', default='quic')
p.add_argument('--out')
a = p.parse_args()

def metrics():
    with urllib.request.urlopen(f'http://127.0.0.1:{a.port}/metrics', timeout=2) as r:
        text = r.read().decode()
    values = {}
    for line in text.splitlines():
        if line.startswith('#'):
            continue
        fields = line.split()
        if len(fields) == 2 and '{' not in fields[0]:
            try:
                values[fields[0]] = float(fields[1])
            except ValueError:
                pass
    return values

if a.mode == 'sctp':
    if not sys.platform.startswith('linux'):
        sys.exit('Native SCTP checks require Linux')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 132) as s:
            s.bind(('127.0.0.1', 0))
            s.listen(1)
    except OSError as e:
        sys.exit(f'SCTP unavailable: {e}; on the Linux test host run sudo modprobe sctp')
    print('SCTP kernel socket: OK')
elif a.mode == 'report':
    try:
        rows = [json.loads(line) for line in pathlib.Path(a.out).read_text().splitlines() if line.strip()]
        required = ['rss_kib', 'cpu_percent', 'metrics']
        if sys.platform.startswith('linux'):
            required.append('fds')
        missing = {key: sum(row.get(key) is None or (key == 'metrics' and not row[key]) for row in rows)
                   for key in required}
        bad = not rows or any(missing.values()) or any(row.get('errors') or row.get('error') for row in rows)
        print(('INCOMPLETE' if bad else 'COMPLETE') + f': {len(rows)} samples; missing={missing}')
        if not sys.platform.startswith('linux'):
            print('FD monitoring is available only on Linux')
        sys.exit(1 if bad else 0)
    except (OSError, ValueError) as e:
        sys.exit('INCOMPLETE monitoring: ' + str(e))
elif a.mode == 'cleanup':
    session = 'turna_sctp_active_associations' if a.transport == 'sctp' else 'turna_quic_active_sessions'
    required = ('turna_active_allocations', session)
    last = {}
    for _ in range(20):
        try:
            last = metrics()
            if all(k in last and last[k] == 0 for k in required):
                print('cleanup: allocations=0, sessions=0')
                sys.exit(0)
        except Exception as e:
            last = {'error': str(e)}
        time.sleep(.5)
    sys.exit('cleanup failed: ' + repr({k: last.get(k, 'missing') for k in required}))
else:
    stopping = False
    def stop(*_):
        global stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    start = time.monotonic()
    with open(a.out, 'w', buffering=1) as out:
        while not stopping:
            record = {'elapsed_s': round(time.monotonic() - start, 3), 'pid': a.pid}
            errors = {}
            try:
                ps = subprocess.check_output(['ps', '-p', str(a.pid), '-o', 'rss=,pcpu='], text=True, timeout=2).split()
                record.update(rss_kib=int(ps[0]), cpu_percent=float(ps[1]))
            except Exception as e:
                errors['process'] = str(e)
            try:
                record['metrics'] = metrics()
            except Exception as e:
                errors['metrics'] = str(e)
            try:
                own_count = record.get('metrics', {}).get('turna_process_open_fds')
                if own_count is not None:
                    record['fds'] = int(own_count)
                    record['fds_source'] = 'node_metrics'
                elif sys.platform.startswith('linux'):
                    record['fds'] = len(list(pathlib.Path(f'/proc/{a.pid}/fd').iterdir()))
                    record['fds_source'] = 'proc'
                else:
                    record['fds'] = None
                    record['fds_source'] = 'unsupported'
            except Exception as e:
                errors['fds'] = str(e)
            if errors:
                record['errors'] = errors
            out.write(json.dumps(record) + '\n')
            for _ in range(10):
                if stopping:
                    break
                time.sleep(.5)
