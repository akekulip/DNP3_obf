#!/usr/bin/env python3
"""Build FullReadGate at the pinned OpenDNP3 commit and capture native READs on loopback.

Build: the same pinned-archive flow as framework/size/endpoint_gate/run_sockets_pad58b.py
(git archive of 4648fcb, one added executable, dependency cache for asio/exe4cpp/ser4cpp).
Run: outstation and master in one private user+network namespace (unshare -rn), so tcpdump can
capture the loopback interface without host privileges (dumpcap; tcpdump cannot drop privileges in a
user namespace); the capture holds the real TCP segments. The nanosecond pcap is kept and a
microsecond copy is written for read_reencode_01/capture.py.

  run_full_read.py build --work DIR
  run_full_read.py run --binary BIN --output DIR --mode integrity --db base --reads 200
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import struct
import subprocess
import sys
import tarfile

PIN = '4648fcb898456d1cb70b5baecc38cc256c859c2e'
HERE = Path(__file__).resolve().parent
SOURCES = ['FullReadGate.cpp', 'DecoyGateCommandHandler.h']
DEFAULT_SOURCE = Path('/home/philip/Projects/opendnp3-community')
DEFAULT_DEPS = Path('/tmp/dnp3-case4-endpoint-gate/build/_deps')


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(work, source=DEFAULT_SOURCE, deps=DEFAULT_DEPS, jobs=4):
    work = Path(work).resolve()
    work.mkdir(parents=True, exist_ok=False)
    archive = subprocess.check_output(['git', '-C', str(source), 'archive', PIN])
    src = work / 'source'
    src.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(src)
    for name in SOURCES:
        (src / name).write_bytes((HERE / name).read_bytes())
    cmake = src / 'CMakeLists.txt'
    cmake.write_text(cmake.read_text() + '\nadd_executable(full_read_gate FullReadGate.cpp)\n'
                     'target_link_libraries(full_read_gate PRIVATE opendnp3)\n')
    bld = work / 'build'
    configure = ['cmake', '-S', str(src), '-B', str(bld), '-DDNP3_TESTS=OFF', '-DCMAKE_BUILD_TYPE=Release']
    for name in ('asio', 'exe4cpp', 'ser4cpp'):
        configure.append('-DFETCHCONTENT_SOURCE_DIR_%s=%s' % (name.upper(), deps / (name + '-src')))
    with (work / 'build.log').open('w') as log:
        for cmd in (configure, ['cmake', '--build', str(bld), '--target', 'full_read_gate', '-j%d' % jobs]):
            log.write('$ ' + ' '.join(cmd) + '\n'); log.flush()
            rc = subprocess.run(cmd, stdout=log, stderr=subprocess.STDOUT).returncode
            if rc:
                raise SystemExit('build failed, see %s' % (work / 'build.log'))
    binary = bld / 'full_read_gate'
    manifest = {'opendnp3_commit': PIN, 'archive_sha256': hashlib.sha256(archive).hexdigest(),
                'binary': str(binary), 'binary_sha256': sha256(binary),
                'library_sha256': sha256(bld / 'cpp/lib/libopendnp3.so'),
                'sources': {n: sha256(HERE / n) for n in SOURCES}}
    (work / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


def to_microsecond_pcap(src, dst):
    """Rewrite a little-endian nanosecond pcap as a microsecond pcap (timestamps truncated)."""
    data = Path(src).read_bytes()
    if data[:4] != b'\x4d\x3c\xb2\xa1':
        raise ValueError('expected a little-endian nanosecond pcap')
    out, p = bytearray(b'\xd4\xc3\xb2\xa1' + data[4:24]), 24
    while p + 16 <= len(data):
        sec, nsec, incl, orig = struct.unpack('<IIII', data[p:p + 16])
        out += struct.pack('<IIII', sec, nsec // 1000, incl, orig) + data[p + 16:p + 16 + incl]
        p += 16 + incl
    Path(dst).write_bytes(bytes(out))


def run(binary, output, mode, db, reads, gap_ms=25, port=20000):
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    binary = Path(binary).resolve()
    lifetime = int(10 + reads * (0.5 + gap_ms / 1000)) + 5
    stop = output / 'stop'
    q = shlex.quote
    script = f"""set -e
ip link set lo up
dumpcap -q -i lo -F pcap -f 'tcp port {port}' -w - > {q(str(output / 'capture_ns.pcap'))} 2> {q(str(output / 'dumpcap.log'))} &
TD=$!
sleep 0.5
{q(str(binary))} outstation 127.0.0.1 {port} {q(str(stop))} {lifetime} {db} > {q(str(output / 'outstation.log'))} 2>&1 &
OS=$!
for i in $(seq 100); do grep -q READY {q(str(output / 'outstation.log'))} && break; sleep 0.05; done
{q(str(binary))} master 127.0.0.1 {port} {q(str(stop))} {reads} {mode} {gap_ms} > {q(str(output / 'master.log'))} 2>&1
MRC=$?
touch {q(str(stop))}
wait $OS
sleep 0.3
sleep 0.3; kill -INT $TD || true; wait $TD || true
exit $MRC
"""
    env = dict(os.environ, FULL_READ_GATE='1')
    rc = subprocess.run(['unshare', '-rn', 'bash', '-c', script], env=env).returncode
    to_microsecond_pcap(output / 'capture_ns.pcap', output / 'capture.pcap')
    meta = {'binary': str(binary), 'binary_sha256': sha256(binary), 'mode': mode, 'db': db, 'reads': reads,
            'gap_ms': gap_ms, 'port': port, 'master_rc': rc, 'runner_sha256': sha256(__file__),
            'capture': 'dumpcap on lo inside unshare -rn; real kernel TCP segments'}
    (output / 'run.json').write_text(json.dumps(meta, indent=2) + '\n')
    return rc


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    b = sub.add_parser('build'); b.add_argument('--work', required=True)
    r = sub.add_parser('run')
    r.add_argument('--binary', required=True); r.add_argument('--output', required=True)
    r.add_argument('--mode', choices=['range', 'class0', 'integrity', 'analog'], required=True)
    r.add_argument('--db', choices=['base', 'large'], default='base')
    r.add_argument('--reads', type=int, default=200); r.add_argument('--gap-ms', type=int, default=25)
    a = ap.parse_args(argv)
    if a.cmd == 'build':
        print(json.dumps(build(a.work), indent=2))
        return 0
    return run(a.binary, a.output, a.mode, a.db, a.reads, a.gap_ms)


if __name__ == '__main__':
    sys.exit(main())
