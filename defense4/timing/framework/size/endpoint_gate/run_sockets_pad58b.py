#!/usr/bin/env python3
"""Real-TCP-socket OpenDNP3 workload runner for Option B' (case4_pad58b.py).

Repeated READ exchanges plus one full SELECT -> OPERATE exchange, all over
two real, independent, kernel-backed TCP connections (master <-> proxy <->
outstation), with the proxy (pad58b_proxy.py) applying case4_pad58b's exact
response-padding transform to the live wire bytes in transit.

Sibling of run.py --sockets: it reuses that path's pinned-build approach and
the shared `runner.evidence` reservation/snapshot/hash machinery, but drives
a different production binary (SocketGatePad58B.cpp, not SocketGate.cpp,
because SocketGate.cpp configures no measurement points and only runs one
SELECT/OPERATE pair -- it cannot serve READ) through a real padding proxy
instead of socket_lab.py's raw-packet RRC/size bridge. That bridge exists to
study a different transform: it preserves one continuous TCP byte stream
end to end (raw AF_PACKET sockets bridging two network-namespace veth ends)
so it can study mid-stream, byte-preserving insertion visible to a single
TCP endpoint pair, which requires it to translate seq/ack/window itself.
Option B' only needs the DNP3-level codec and endpoint behaviour validated
over real sockets -- a separate concern from the P4 transport mapper
(case4_response_path.p4 / response_path_cp.py), which this runner does not
exercise -- so a plain two-connection application-level proxy is the correct,
not merely simpler, tool: each leg's TCP sequencing is the kernel's problem.
It also needs neither a private network namespace nor raw AF_PACKET sockets,
both of which require privilege this host does not have (no sudo, no
CAP_NET_RAW); a packet capture is therefore replaced with the proxy's own
byte-level JSONL tee, an alternative the task explicitly allows.

Every invocation requires a fresh output directory, exactly like run.py.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tarfile
import time

PIN = '4648fcb898456d1cb70b5baecc38cc256c859c2e'
HERE = Path(__file__).resolve().parent
FRAMEWORK = HERE.parents[1]
REPO = HERE.parents[4]
sys.path.insert(0, str(FRAMEWORK))
from runner.evidence import reserve_run, sha256  # noqa: E402

BINARY_SOURCES = ['SocketGatePad58B.cpp', 'DecoyGateCommandHandler.h']
PROFILE_SOURCES = ['case4_padding.py', 'case4_pad58b.py', 'rrc.py']
PROXY_SOURCE = 'pad58b_proxy.py'
READS = 3


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def build_gate(run, source_repo, work, dependency_cache=None, jobs=2):
    source_repo, work = Path(source_repo).resolve(), Path(work).resolve()
    for protected in (REPO.resolve(), source_repo):
        if work == protected or protected in work.parents:
            raise ValueError('build work must be outside both source trees')
    work.mkdir(parents=True, exist_ok=False)
    run.write_json('build_work.json', {'path': str(work), 'retained': True})
    status_before = subprocess.check_output(['git', '-C', str(source_repo), 'status', '--porcelain'])
    archive = subprocess.check_output(['git', '-C', str(source_repo), 'archive', PIN])
    run.record('pinned_archive', commit=PIN, sha256=hashlib.sha256(archive).hexdigest())
    source = work / 'source'; source.mkdir()
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(source)
    snapshots = {name: run.snapshot(HERE / name) for name in BINARY_SOURCES + [PROXY_SOURCE]}
    for name in PROFILE_SOURCES:
        run.snapshot(HERE.parent / name)
    (source / 'SocketGatePad58B.cpp').write_bytes(snapshots['SocketGatePad58B.cpp'].read_bytes())
    (source / 'DecoyGateCommandHandler.h').write_bytes(snapshots['DecoyGateCommandHandler.h'].read_bytes())
    cmake = source / 'CMakeLists.txt'
    cmake.write_text(cmake.read_text() + '\nadd_executable(case4_socket_gate_pad58b SocketGatePad58B.cpp)\n'
                      'target_link_libraries(case4_socket_gate_pad58b PRIVATE opendnp3)\n')
    target, binary_relative = 'case4_socket_gate_pad58b', 'case4_socket_gate_pad58b'
    build = work / 'build'
    build.mkdir()
    configure = ['cmake', '-S', str(source), '-B', str(build), '-DDNP3_TESTS=OFF', '-DCMAKE_BUILD_TYPE=Release']
    if dependency_cache:
        for name in ('asio', 'exe4cpp', 'ser4cpp'):
            dep = Path(dependency_cache).resolve() / (name + '-src')
            if not dep.is_dir(): raise ValueError('missing declared dependency cache: ' + str(dep))
            configure.append('-DFETCHCONTENT_SOURCE_DIR_' + name.upper() + '=' + str(dep))
    steps = [(configure, 'configure.log'), (['cmake', '--build', str(build), '--target', target, '-j' + str(jobs)], 'build.log')]
    binary = build / binary_relative
    result = 0
    for command, filename in steps:
        run.record('command', argv=command, log=filename)
        with (run.path / filename).open('x') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT).returncode
        if result: break
    manifest = {'opendnp3_commit': PIN, 'archive_sha256': hashlib.sha256(archive).hexdigest(),
                'archive_model': 'git archive pinned clean commit; dirty sibling excluded',
                'software_only': True, 'scope': 'production TCP sockets + real response-padding proxy',
                'result': result, 'binary_path': str(binary), 'binary_sha256': sha256(binary) if binary.exists() else None,
                'production_library_sha256': sha256(build / 'cpp/lib/libopendnp3.so') if (build / 'cpp/lib/libopendnp3.so').exists() else None,
                'files': {name: sha256(path) for name, path in snapshots.items()},
                'wire_transform_sha256': sha256(run.path / 'sources/case4_padding.py'),
                'pad58b_sha256': sha256(run.path / 'sources/case4_pad58b.py'),
                'crc_model_sha256': sha256(run.path / 'sources/rrc.py'),
                'compiler': subprocess.check_output(['c++', '--version'], text=True).splitlines()[0],
                'cmake': subprocess.check_output(['cmake', '--version'], text=True).splitlines()[0],
                'sibling_status_unchanged': status_before == subprocess.check_output(['git', '-C', str(source_repo), 'status', '--porcelain'])}
    run.write_json('manifest.json', manifest)
    return manifest


def _wait_ready(log_path, proc, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError('process exited before READY: ' + log_path.read_text()[-2000:])
        if 'READY' in log_path.read_text():
            return
        time.sleep(0.01)
    raise RuntimeError('process never printed READY: ' + log_path.read_text()[-2000:])


def _last_json(path):
    rows = [line for line in path.read_text().splitlines() if line.startswith('{')]
    if not rows:
        raise RuntimeError('no JSON output line found in ' + str(path))
    return json.loads(rows[-1])


def _check_transforms(run, tee_path, reads):
    """Independent byte-exact check: recompute case4_pad58b fresh on every
    captured native response frame and assert it equals the bytes the proxy
    actually put on the wire to the master -- not a re-check of the proxy's
    own in-memory decision, a brand new call against the raw tee bytes.
    """
    sys.path.insert(0, str(HERE.parent))
    import case4_pad58b as pad58b
    control_points = (pad58b.AnalogFloatPoint(301, 10.0, 0), pad58b.AnalogFloatPoint(302, 20.0, 0))
    failures = []
    counts = {'read': 0, 'control': 0, 'passthrough': 0, 'request_forwarded': 0}
    mismatches = []
    for line in tee_path.read_text().splitlines():
        event = json.loads(line)
        if event['direction'] == 'master_to_outstation':
            counts['request_forwarded'] += 1
            continue
        counts[event['kind']] += 1
        native = bytes.fromhex(event['native_frame_hex'])
        sent = bytes.fromhex(event['sent_frame_hex'])
        if event['kind'] == 'read':
            expected, delta = pad58b.pad_read_response(native)
        elif event['kind'] == 'control':
            expected, delta = pad58b.pad_control_response(native, control_points)
        else:
            expected, delta = native, 0
        if expected != sent:
            mismatches.append(event)
        if event['kind'] != 'passthrough' and delta == 0:
            failures.append('tee claims a transform but the independent recompute found none: ' + event['sent_frame_hex'])
    if mismatches:
        failures.append('%d response frame(s) do not match the independently recomputed codec output' % len(mismatches))
    if counts['read'] != reads:
        failures.append('expected %d READ-padded response frames, tee shows %d' % (reads, counts['read']))
    if counts['control'] != 2:
        failures.append('expected exactly 2 CONTROL-padded response frames (SELECT echo + OPERATE echo), tee shows %d' % counts['control'])
    run.write_json('independent_wire_check.json', {'counts': counts, 'mismatches': mismatches, 'failures': failures})
    return failures


def launch(run, manifest, reads, listen_port, outstation_port):
    binary = Path(manifest['binary_path'])
    env = dict(os.environ, CASE4_PAD58B_SOCKET_GATE='1')
    stop = run.path / 'endpoint_stop'
    outstation_log, master_log, tee_path = run.path / 'outstation.log', run.path / 'master.log', run.path / 'tee.jsonl'
    procs = []
    try:
        with outstation_log.open('x') as log:
            outstation = subprocess.Popen([str(binary), 'outstation', '127.0.0.1', str(outstation_port), str(stop)],
                                          stdout=log, stderr=subprocess.STDOUT, env=env)
        procs.append(outstation)
        _wait_ready(outstation_log, outstation, 5)
        proxy_log = run.path / 'proxy.log'
        with proxy_log.open('x') as log:
            proxy = subprocess.Popen([sys.executable, '-B', str(HERE / 'pad58b_proxy.py'),
                                      '--listen-port', str(listen_port), '--outstation-host', '127.0.0.1',
                                      '--outstation-port', str(outstation_port), '--tee', str(tee_path),
                                      '--stop-file', str(stop)], stdout=log, stderr=subprocess.STDOUT)
        procs.append(proxy)
        _wait_ready(proxy_log, proxy, 5)
        run.record('socket_launch', binary_sha256=manifest['binary_sha256'], listen_port=listen_port, outstation_port=outstation_port)
        with master_log.open('x') as log:
            master = subprocess.Popen([str(binary), 'master', '127.0.0.1', str(listen_port), str(stop), str(reads)],
                                      stdout=log, stderr=subprocess.STDOUT, env=env)
        procs.append(master)
        try:
            master_rc = master.wait(timeout=15)
        except subprocess.TimeoutExpired:
            master.kill(); master.wait()
            raise RuntimeError('master binary timed out: ' + master_log.read_text()[-2000:])
        stop.touch(exist_ok=False)
        outstation_rc = outstation.wait(timeout=5)
        proxy_rc = proxy.wait(timeout=5)
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
    master_result = _last_json(master_log)
    outstation_result = _last_json(outstation_log)
    data = dict(master=master_result, outstation=outstation_result,
                master_exit_code=master_rc, outstation_exit_code=outstation_rc, proxy_exit_code=proxy_rc,
                scope='production OpenDNP3 TCP sockets (two real connections) + real response-padding proxy; no P4 or physical endpoint',
                endpoint_binary_sha256=manifest['binary_sha256'], opendnp3_commit=manifest['opendnp3_commit'],
                pad58b_sha256=manifest['pad58b_sha256'])
    failures = []
    if master_rc != 0: failures.append('master exit code %r' % master_rc)
    if outstation_rc != 0: failures.append('outstation exit code %r' % outstation_rc)
    if master_result.get('success') is not True: failures.append('master SELECT/OPERATE task status')
    if master_result.get('application_calls') != 1: failures.append('application resend')
    if master_result.get('reads_completed') != reads: failures.append('reads_completed != %d' % reads)
    if master_result.get('all_reads_match_seed') is not True: failures.append('a READ did not deliver all 23 seeded points')
    for key in ('select_real', 'operate_real'):
        if outstation_result.get(key) != 1: failures.append('endpoint callback ' + key)
    for key in ('select_decoy', 'operate_decoy'):
        if outstation_result.get(key) != 0: failures.append('decoy point touched: ' + key)
    if outstation_result.get('opens') != 1: failures.append('outstation connection count (expected 1: only the proxy connects to it)')
    failures += _check_transforms(run, tee_path, reads)
    return dict(passed=not failures, failures=failures, **data)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path, help='fresh exclusive evidence directory')
    parser.add_argument('--source', type=Path, default=Path(os.environ.get('OPENDNP3_SRC', str(REPO.parent / 'opendnp3-community'))))
    parser.add_argument('--work', type=Path, help='fresh external build directory, retained on failure')
    parser.add_argument('--dependency-cache', type=Path, help='existing pinned build header dependency cache; production library is rebuilt')
    parser.add_argument('--jobs', type=int, choices=range(1, 5), default=2)
    parser.add_argument('--reads', type=int, default=READS, help='number of repeated READ (ScanRange) exchanges before the SELECT/OPERATE pair')
    args = parser.parse_args(argv)
    run = reserve_run(args.output, {'scope': 'OpenDNP3 Option B\' socket-proxy gate', 'commit': PIN, 'reads': args.reads})
    with run:
        manifest = build_gate(run, args.source, args.work or Path('/tmp') / ('case4-pad58b-sockets-' + run.token), args.dependency_cache, args.jobs)
        if manifest['result']:
            run.finish('failed', {'reason': 'pinned build failed', 'exit_code': manifest['result']})
            return manifest['result']
        listen_port, outstation_port = _free_port(), _free_port()
        while outstation_port == listen_port:
            outstation_port = _free_port()
        result = launch(run, manifest, args.reads, listen_port, outstation_port)
        run.finish('passed' if result['passed'] else 'failed', result)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
