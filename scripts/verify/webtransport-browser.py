#!/usr/bin/env python3
"""Local browser probe with a pinned certificate and a real UDP echo peer.
Run from any directory. Stop with Ctrl-C after downloading the browser report.
"""
import functools
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import threading
import time
import urllib.request

repo = Path(__file__).resolve().parents[2]
os.chdir(repo)
out = (repo / os.environ.get('OUT', 'transports-browser-local')).resolve()
out.mkdir(parents=True, exist_ok=True)
profile = os.environ.get('BUILD_PROFILE', 'release')
cmd = ['cargo', 'build', '--locked', '-p', 'turna-node', '--features', 'web-transport']
if profile != 'dev':
    cmd.append('--release')
with (out / 'build.log').open('w') as log:
    subprocess.run(cmd, check=True, stdout=log, stderr=subprocess.STDOUT)
subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
    'ec_paramgen_curve:prime256v1', '-nodes', '-keyout', str(out / 'key.pem'),
    '-out', str(out / 'cert.pem'), '-days', '2', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1'],
    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
der = subprocess.check_output(['openssl', 'x509', '-in', str(out/'cert.pem'), '-outform', 'DER'])
secret = secrets.token_hex(24)
config = f'''production = false
[turn]
listen = "127.0.0.1:3477"
external_ip = "127.0.0.1"
realm = "browser-probe"
transport = "tokio"
[turn.auth]
shared_secret = "{secret}"
[turn.peer_filter]
profile = "lan"
allow_loopback_peers = true
[turn.relay]
min_port = 20000
max_port = 20847
max_allocations = 800
[health]
listen = "127.0.0.1:19095"
[turn.quic]
enabled = true
web_transport = true
listen = "[::]:3482"
cert_path = "{out}/cert.pem"
key_path = "{out}/key.pem"
'''
(out/'turn.toml').write_text(config)
html = (repo/'tools/browser-probes/wt-browser-probe.html').read_text()
preset = {'url':'https://localhost:3482/', 'pin':hashlib.sha256(der).hexdigest(),
          'peer':'127.0.0.1', 'peerport':'39000', 'pass':secret}
init = 'for (const [k,v] of Object.entries(' + json.dumps(preset) + ')) document.getElementById(k).value=v;'
html = html.replace('</body>', '<script>'+init+'</script></body>')
# Serve only the page, never the node config or certificate private key.
page = out/'page'; page.mkdir(exist_ok=True); (page/'index.html').write_text(html)
peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
peer.bind(('127.0.0.1',39000)); peer.settimeout(.5)
stopping = threading.Event()
def echo():
    with (out/'echo.jsonl').open('w', buffering=1) as log:
        while not stopping.is_set():
            try:
                data, addr = peer.recvfrom(65535)
                peer.sendto(data, addr)
                log.write(json.dumps({'bytes':len(data), 'relay':addr})+'\n')
            except socket.timeout:
                pass
            except OSError:
                if stopping.is_set():
                    break
                raise
server = http.server.ThreadingHTTPServer(('127.0.0.1',8765),
    functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(page)))
node = None
def terminate(*_):
    raise KeyboardInterrupt
signal.signal(signal.SIGTERM, terminate)
try:
    with (out/'node.log').open('w') as log:
        node = subprocess.Popen([str(repo/('target/debug' if profile=='dev' else 'target/release')/'turna-node'),
            str(out/'turn.toml')], stdout=log, stderr=subprocess.STDOUT)
        for _ in range(40):
            if node.poll() is not None:
                raise RuntimeError('node exited; see '+str(out/'node.log'))
            try:
                urllib.request.urlopen('http://127.0.0.1:19095/ready', timeout=1).close()
                break
            except Exception:
                time.sleep(.25)
        else:
            raise RuntimeError('node not ready')
        threading.Thread(target=echo, daemon=True).start()
        print('Open Chrome/Chromium: http://127.0.0.1:8765/ — press Run, then Download log', flush=True)
        print('Stop this terminal with Ctrl-C after the browser check.', flush=True)
        server.serve_forever()
except KeyboardInterrupt:
    pass
finally:
    stopping.set()
    server.server_close()
    peer.close()
    if node is not None:
        node.terminate()
        try:
            node.wait(timeout=10)
        except subprocess.TimeoutExpired:
            node.kill(); node.wait()
