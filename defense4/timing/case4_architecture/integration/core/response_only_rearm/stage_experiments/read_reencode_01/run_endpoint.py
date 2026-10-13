#!/usr/bin/env python3
"""Gate 1 step 2: the pinned OpenDNP3 master/outstation pair through the strict-response proxy.

One persistent master connection: N READs (ScanRange G10V2 0-22) whose responses the proxy
re-encodes to 58 octets, then one native SELECT -> OPERATE on the same connection. Builds the
pinned binary through run_sockets_pad58b.build_gate (fresh archive, fresh work directory) and
checks the tee independently with dnp3_std.py.

  python3 -B run_endpoint.py --output FRESH_DIR --work FRESH_BUILD_DIR \
      --dependency-cache /tmp/dnp3-case4-endpoint-gate/build/_deps --reads 20
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
GATE = HERE.parents[5] / 'framework/size/endpoint_gate'
sys.path[:0] = [str(HERE), str(GATE)]
import run_sockets_pad58b as base  # noqa: E402
import dnp3_std as std  # noqa: E402
import reencode  # noqa: E402

OWN_SOURCES = ['dnp3_std.py', 'reencode.py', 'endpoint_proxy.py', 'run_endpoint.py']


def check_tee(tee_path, reads):
    """Recompute every decision from the raw tee bytes and apply the standards checks."""
    failures, counts = [], {'read': 0, 'passthrough': 0, 'requests': 0}
    requests, responses = [], []
    for line in Path(tee_path).read_text().splitlines():
        ev = json.loads(line)
        if ev['direction'] == 'master_to_outstation':
            counts['requests'] += 1
            requests.append(bytes.fromhex(ev['frame_hex']))
            continue
        native, sent = bytes.fromhex(ev['native_frame_hex']), bytes.fromhex(ev['sent_frame_hex'])
        counts[ev['kind']] += 1
        expected = reencode.reencode_frame(native) or native
        if sent != expected:
            failures.append('sent frame differs from independent recompute: ' + ev['sent_frame_hex'])
        if ev['kind'] == 'read':
            if len(sent) != 58:
                failures.append('re-encoded READ frame is %d octets' % len(sent))
            try:
                if not reencode.semantically_equal(native, sent):
                    failures.append('re-encoded READ lost a point: ' + ev['sent_frame_hex'])
            except std.StdError as error:
                failures.append('re-encoded READ fails a standards check: %s' % error)
        responses.append(sent)
    if counts['read'] != reads:
        failures.append('expected %d re-encoded READ frames, tee shows %d' % (reads, counts['read']))
    # SELECT and OPERATE: the last two request/response pairs; Rule 8 echo on the wire bytes.
    controls = [(q, r) for q, r in zip(requests, responses) if std.deframe(q)[1][2] in (0x03, 0x04)]
    if [std.deframe(q)[1][2] for q, _ in controls] != [0x03, 0x04]:
        failures.append('expected one SELECT then one OPERATE, saw functions %s'
                        % [std.deframe(q)[1][2] for q, _ in controls])
    for q, r in controls:
        try:
            std.check_control_echo(std.deframe(q)[1], std.deframe(r)[1])
        except std.StdError as error:
            failures.append('control echo: %s' % error)
    return counts, failures


def launch(run, manifest, reads, listen_port, outstation_port):
    """base.launch with this directory's proxy and checker."""
    binary = Path(manifest['binary_path'])
    env = dict(os.environ, CASE4_PAD58B_SOCKET_GATE='1', CASE4_RUN_SBO='1')
    stop = run.path / 'endpoint_stop'
    logs = {k: run.path / (k + '.log') for k in ('outstation', 'proxy', 'master')}
    tee = run.path / 'tee.jsonl'
    timeout = 10 + reads * 3.025 + 3
    procs = []
    try:
        with logs['outstation'].open('x') as log:
            procs.append(subprocess.Popen([str(binary), 'outstation', '127.0.0.1', str(outstation_port), str(stop),
                                           str(int(timeout) + 5)], stdout=log, stderr=subprocess.STDOUT, env=env))
        base._wait_ready(logs['outstation'], procs[0], 5)
        with logs['proxy'].open('x') as log:
            procs.append(subprocess.Popen([sys.executable, '-B', str(HERE / 'endpoint_proxy.py'),
                                           '--listen-port', str(listen_port), '--outstation-port', str(outstation_port),
                                           '--tee', str(tee), '--stop-file', str(stop)],
                                          stdout=log, stderr=subprocess.STDOUT))
        base._wait_ready(logs['proxy'], procs[1], 5)
        run.record('socket_launch', binary_sha256=manifest['binary_sha256'], listen_port=listen_port,
                   outstation_port=outstation_port)
        with logs['master'].open('x') as log:
            procs.append(subprocess.Popen([str(binary), 'master', '127.0.0.1', str(listen_port), str(stop), str(reads)],
                                          stdout=log, stderr=subprocess.STDOUT, env=env))
        master_rc = procs[2].wait(timeout=timeout)
        stop.touch(exist_ok=False)
        outstation_rc = procs[0].wait(timeout=5)
        proxy_rc = procs[1].wait(timeout=5)
    finally:
        for proc in procs:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    master, outstation = base._last_json(logs['master']), base._last_json(logs['outstation'])
    failures = []
    for name, rc in (('master', master_rc), ('outstation', outstation_rc), ('proxy', proxy_rc)):
        if rc != 0:
            failures.append('%s exit code %r' % (name, rc))
    if master.get('success') is not True:
        failures.append('master task status')
    if master.get('reads_completed') != reads or master.get('all_reads_match_seed') is not True:
        failures.append('a READ did not deliver all 23 seeded points')
    if master.get('application_calls') != 1:
        failures.append('application SBO count')
    for key in ('select_real', 'operate_real'):
        if outstation.get(key) != 1:
            failures.append('endpoint callback ' + key)
    for key in ('select_decoy', 'operate_decoy'):
        if outstation.get(key) != 0:
            failures.append('decoy point touched: ' + key)
    if outstation.get('opens') != 1:
        failures.append('outstation saw %r connections, expected one persistent connection' % outstation.get('opens'))
    counts, tee_failures = check_tee(tee, reads)
    failures += tee_failures
    run.write_json('independent_standards_check.json', {'counts': counts, 'failures': tee_failures})
    return dict(passed=not failures, failures=failures, master=master, outstation=outstation, counts=counts,
                scope='pinned OpenDNP3 over two loopback TCP connections; software re-encoding proxy; no P4, '
                      'no switch, no physical endpoint',
                endpoint_binary_sha256=manifest['binary_sha256'], opendnp3_commit=manifest['opendnp3_commit'])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--source', type=Path, default=Path(os.environ.get('OPENDNP3_SRC', str(base.REPO.parent / 'opendnp3-community'))))
    parser.add_argument('--work', required=True, type=Path)
    parser.add_argument('--dependency-cache', type=Path)
    parser.add_argument('--jobs', type=int, choices=range(1, 5), default=2)
    parser.add_argument('--reads', type=int, default=20)
    args = parser.parse_args(argv)
    run = base.reserve_run(args.output, {'scope': 'READ re-encoding strict-response endpoint gate', 'commit': base.PIN,
                                         'reads': args.reads})
    with run:
        for name in OWN_SOURCES:
            run.snapshot(HERE / name)
        manifest = base.build_gate(run, args.source, args.work, args.dependency_cache, args.jobs)
        if manifest['result']:
            run.finish('failed', {'reason': 'pinned build failed', 'exit_code': manifest['result']})
            return manifest['result']
        ports = (base._free_port(), base._free_port())
        while ports[0] == ports[1]:
            ports = (ports[0], base._free_port())
        result = launch(run, manifest, args.reads, *ports)
        run.finish('passed' if result['passed'] else 'failed', result)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
