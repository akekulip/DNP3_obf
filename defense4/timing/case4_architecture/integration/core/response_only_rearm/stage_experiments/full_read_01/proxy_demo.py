#!/usr/bin/env python3
"""Software demonstration of both request cases with the real OpenDNP3 master and outstation.

master --(port 20001, the attacker's observation point: master-facing link)--> proxy
proxy  --(port 20000, outstation-facing link)--> outstation

The proxy stands in for the switch at the DNP3 layer only (each leg is its own kernel TCP connection;
the P4 sequence mapping is tested separately). It applies pad_oracle:
  --targets 292         Case B: pad every READ response to the smallest reachable target
  --expand G:V:F:L,...  Case A: append range headers for configured points to every READ request
Both legs are captured with dumpcap inside a private user+network namespace.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import threading

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / 'endpoint'))
import pad_oracle as po  # noqa: E402
import dnp3_std as std  # noqa: E402
from run_full_read import to_microsecond_pcap, sha256  # noqa: E402

FIRST_PAD_INDEX = 16   # binary inputs 0..15 are configured; padding indices start after them


def consume(buf):
    out = []
    while len(buf) >= 3 and buf[:2] == b'\x05\x64':
        n = std.frame_length(buf[2] - 5)
        if len(buf) < n:
            break
        out.append(bytes(buf[:n]))
        del buf[:n]
    return out


class Proxy:
    def __init__(self, targets, expand, log):
        self.targets, self.expand, self.log = targets, expand, log
        self.lock = threading.Lock()

    def record(self, **kw):
        with self.lock:
            self.log.write(json.dumps(kw) + '\n'); self.log.flush()

    def requests(self, src, dst):
        buf = bytearray()
        while True:
            data = src.recv(65536)
            if not data:
                break
            buf += data
            for f in consume(buf):
                out = f
                _, user = std.deframe(f)
                if self.expand and len(user) > 2 and user[2] == 0x01:
                    out = po.expand_request(f, self.expand)
                dst.sendall(out)
                self.record(dir='request', native=f.hex(), sent=out.hex())
        dst.close()

    def responses(self, src, dst):
        buf, pending = bytearray(), []
        while True:
            data = src.recv(65536)
            if not data:
                break
            buf += data
            for f in consume(buf):
                _, user = std.deframe(f)
                pending.append(f)
                if not user or user[0] & std.FIN:
                    native = b''.join(pending)
                    pending = []
                    out, info = native, None
                    if self.targets and user:
                        t = po.choose_target(len(native), self.targets)
                        if t is not None and t != len(native):
                            out, info = po.pad_response(native, t, FIRST_PAD_INDEX)
                    dst.sendall(out)
                    self.record(dir='response', native=native.hex(), sent=out.hex(), pad=info)
        dst.close()


def serve(listen, upstream, targets, expand, log_path):
    ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(('127.0.0.1', listen)); ls.listen(1)
    print('READY', flush=True)
    m, _ = ls.accept()
    o = socket.create_connection(('127.0.0.1', upstream))
    with open(log_path, 'w') as log:
        p = Proxy(targets, expand, log)
        a = threading.Thread(target=p.requests, args=(m, o)); b = threading.Thread(target=p.responses, args=(o, m))
        a.start(); b.start(); a.join(); b.join()


def parse_expand(text):
    if not text:
        return []
    out = []
    for item in text.split(','):
        g, v, f, l = (int(x) for x in item.split(':'))
        out.append(po.range_header(g, v, f, l))
    return out


def run(binary, output, mode, db, reads, targets, expand, gap_ms=10):
    output = Path(output).resolve(); output.mkdir(parents=True, exist_ok=False)
    q = shlex.quote
    stop = output / 'stop'
    lifetime = int(10 + reads * (0.5 + gap_ms / 1000)) + 5
    proxy_cmd = [sys.executable, '-B', str(Path(__file__).resolve()), 'serve', '--log', str(output / 'proxy.jsonl')]
    if targets:
        proxy_cmd += ['--targets', ','.join(map(str, targets))]
    if expand:
        proxy_cmd += ['--expand', expand]
    script = f"""ip link set lo up
dumpcap -q -i lo -F pcap -f 'tcp port 20000 or tcp port 20001' -w - > {q(str(output / 'capture_ns.pcap'))} 2> {q(str(output / 'dumpcap.log'))} &
TD=$!
sleep 0.5
{q(str(binary))} outstation 127.0.0.1 20000 {q(str(stop))} {lifetime} {db} > {q(str(output / 'outstation.log'))} 2>&1 &
OS=$!
for i in $(seq 100); do grep -q READY {q(str(output / 'outstation.log'))} && break; sleep 0.05; done
{' '.join(q(c) for c in proxy_cmd)} > {q(str(output / 'proxy.log'))} 2>&1 &
PX=$!
for i in $(seq 100); do grep -q READY {q(str(output / 'proxy.log'))} && break; sleep 0.05; done
{q(str(binary))} master 127.0.0.1 20001 {q(str(stop))} {reads} {mode} {gap_ms} > {q(str(output / 'master.log'))} 2>&1
MRC=$?
touch {q(str(stop))}
wait $OS; wait $PX
sleep 0.3; kill -INT $TD || true; wait $TD || true
exit $MRC
"""
    rc = subprocess.run(['unshare', '-rn', 'bash', '-c', script], env=dict(os.environ, FULL_READ_GATE='1')).returncode
    to_microsecond_pcap(output / 'capture_ns.pcap', output / 'capture.pcap')
    (output / 'run.json').write_text(json.dumps({
        'binary_sha256': sha256(binary), 'mode': mode, 'db': db, 'reads': reads, 'targets': targets,
        'expand': expand, 'gap_ms': gap_ms, 'master_rc': rc, 'proxy_sha256': sha256(__file__),
        'oracle_sha256': sha256(HERE / 'pad_oracle.py'),
        'observation_point': 'port 20001 (master-facing link)'}, indent=2) + '\n')
    return rc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('serve')
    s.add_argument('--listen', type=int, default=20001); s.add_argument('--upstream', type=int, default=20000)
    s.add_argument('--targets', default=''); s.add_argument('--expand', default=''); s.add_argument('--log', required=True)
    r = sub.add_parser('run')
    r.add_argument('--binary', required=True); r.add_argument('--output', required=True)
    r.add_argument('--mode', required=True); r.add_argument('--db', default='base')
    r.add_argument('--reads', type=int, default=200); r.add_argument('--targets', default='')
    r.add_argument('--expand', default='')
    a = ap.parse_args(argv)
    targets = [int(t) for t in a.targets.split(',') if t]
    if a.cmd == 'serve':
        serve(a.listen, a.upstream, targets, parse_expand(a.expand), a.log)
        return 0
    return run(a.binary, a.output, a.mode, a.db, a.reads, targets, a.expand)


if __name__ == '__main__':
    sys.exit(main())
