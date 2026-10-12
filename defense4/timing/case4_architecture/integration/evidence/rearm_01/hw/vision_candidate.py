#!/usr/bin/env python3
"""Three consecutive connections on one externally installed software tuple.

Default prints an offline plan. On Vision (already set up and installed):
  sudo env DEFENSE4_HW_AUTHORIZED=1 python3 vision_candidate.py LABEL \
    --master-port PORT --padding 1 --close-mode graceful|rst --apply

--rst-grace-ms accepts 500..5000 (default5000); --reads accepts 1..20 (default20).
--pre-read-grace-ms accepts 0..5000 (default0). Nonzero uses the isolated
pre-READ endpoint binary deployed by the hardware owner; each connection writes
its own pre_read_ready.json before the pause. Existing master timeout budgets
(at least34s for one READ) already accommodate the bounded additional5s pause.

Deploy beside the pinned controls endpoint's vision_run.py, loss.py, wire_check.py,
clrt_check.py and checks.py. This helper never installs rows, changes the fixture,
or restores global setup. The hardware owner supplies and restores that setup.
RST uses the actual kernel's ss -K after an observed OPERATE response; no packets
are constructed. ss --help documents -K; the installed ss(8) manual documents the
state/filter grammar. The exact read-only filter was parsed by installed ss.
The pinned endpoint retries after 60s, outside the bounded grace. opens != 1
still fails so extra reconnects cannot be reported as exactly three incarnations.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
LIBRARY = HERE if (HERE / 'vision_run.py').is_file() else HERE.parents[3] / 'protocol/hw_vepa'
sys.path.insert(0, str(LIBRARY))
import vision_run as vr
import wire_check as wc
import clrt_check as clrt
import checks

MASTER, OUTSTATION, SERVER_PORT = '192.168.10.61', '192.168.10.62', 20000
NAMESPACE_M, NAMESPACE_O, NIC = 'ns_vepa_a', 'ns_vepa_b', 'enp59s0f0np0'
EXPECT = {'common': {'read_points': 23}, 'padding': {
    '0': {'read_resp_len': [49], 'sbo_resp_len': [37]},
    '1': {'read_resp_len': [58], 'sbo_resp_len': [58]}}}


def guard(port, apply=False):
    if type(port) is not int or not 1024 <= port <= 65535 or port == SERVER_PORT:
        raise ValueError('unsafe master source port')
    if (vr.IP_M, vr.IP_O, vr.PORT_O, vr.NS_M, vr.NS_O, vr.PARENT) != (
            MASTER, OUTSTATION, SERVER_PORT, NAMESPACE_M, NAMESPACE_O, NIC):
        raise ValueError('only the fixed software tuple, namespaces and parent NIC are allowed')
    if apply and os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        raise ValueError('--apply requires DEFENSE4_HW_AUTHORIZED=1')


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')


@contextmanager
def pre_read_controls(dest, grace):
    keys = ('CASE4_PRE_READ_GRACE_MS', 'CASE4_PRE_READ_MARKER')
    prior = {key: os.environ.get(key) for key in keys}
    os.environ[keys[0]] = str(grace)
    if grace:
        os.environ[keys[1]] = str(Path(dest) / 'pre_read_ready.json')
    else:
        os.environ.pop(keys[1], None)
    try:
        yield
    finally:
        for key, value in prior.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def pre_read_evidence(dest, grace):
    failures, master = [], {}
    try:
        value = json.loads((Path(dest) / 'master.json').read_text())
        master = value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        pass
    observed = dict(requested_pre_read_grace_ms=grace, supported='pre_read_grace_ms' in master,
                    observed_pre_read_grace_ms=master.get('pre_read_grace_ms'),
                    pre_read_ready_ns=master.get('pre_read_ready_ns'), first_read_issued_ns=master.get('first_read_issued_ns'),
                    marker_path=str(Path(dest) / 'pre_read_ready.json') if grace else None, marker_sha256=None)
    if (grace or 'pre_read_grace_ms' in master) and (
            type(master.get('pre_read_grace_ms')) is not int or master.get('pre_read_grace_ms') != grace):
        failures.append('missing or wrong effective pre-READ grace')
    if grace:
        ready, issued = master.get('pre_read_ready_ns'), master.get('first_read_issued_ns')
        if type(ready) is not int or type(issued) is not int or ready <= 0 or issued - ready < grace * 1_000_000:
            failures.append('missing or premature first READ timestamp')
        else:
            observed['elapsed_ns'] = issued - ready
        try:
            raw = Path(observed['marker_path']).read_bytes()
            observed['marker_sha256'] = hashlib.sha256(raw).hexdigest()
            marker = json.loads(raw)
            expected = dict(pre_read_grace_ms=grace, pre_read_ready_ns=ready, first_read_issued_ns=0, opens=1)
            if not isinstance(marker, dict) or marker.get('tcp_open') is not True or any(
                    type(marker.get(key)) is not int or marker.get(key) != value for key, value in expected.items()):
                failures.append('pre-READ marker does not match final master readiness')
        except (OSError, ValueError):
            failures.append('missing or malformed pre-READ marker')
    return failures, observed


def preflight(mode):
    commands = []
    def checked(args, namespace=None):
        result = vr.nsx(namespace, *args, timeout=5) if namespace else vr.sh(*args, timeout=5)
        commands.append(dict(namespace=namespace, argv=list(args), rc=result.returncode,
                             stdout=result.stdout, stderr=result.stderr))
        if result.returncode:
            raise RuntimeError('Vision preflight command failed: ' + ' '.join(args))
        return result.stdout
    link = json.loads(checked(('ip', '-j', 'link', 'show', 'dev', NIC)))
    if len(link) != 1 or link[0].get('ifname') != NIC:
        raise RuntimeError('parent NIC identity not observed')
    for namespace, device, address in ((NAMESPACE_M, 'mvA', MASTER), (NAMESPACE_O, 'mvB', OUTSTATION)):
        rows = json.loads(checked(('ip', '-j', 'address', 'show', 'dev', device), namespace))
        ips = [addr.get('local') for row in rows for addr in row.get('addr_info', []) if addr.get('family') == 'inet']
        if len(rows) != 1 or rows[0].get('ifname') != device or ips != [address]:
            raise RuntimeError('software namespace address not observed: ' + namespace)
    if mode == 'rst' and '--kill' not in checked(('ss', '--help')):
        raise RuntimeError('installed ss does not advertise --kill')
    return commands


def segments(path):
    return wc.parse(path)[0] if Path(path).is_file() else []


def exact(seg, port, reverse=False):
    wanted = (OUTSTATION, MASTER, SERVER_PORT, port) if reverse else (MASTER, OUTSTATION, port, SERVER_PORT)
    return tuple(seg[key] for key in ('src', 'dst', 'sport', 'dport')) == wanted


def operate_response(dest, port):
    requests = [s for s in segments(Path(dest) / 'out.pcap') if exact(s, port)
                and clrt.func_of(s['payload']) == 4 and wc.dnp3_ok(s['payload'])[0]]
    for response in segments(Path(dest) / 'in.pcap'):
        if not exact(response, port, True) or clrt.func_of(response['payload']) != 0x81 or \
                not wc.dnp3_ok(response['payload'])[0] or not all(wc.ip_tcp_checksum(response)[:2]):
            continue
        for request in requests:
            if response['t_us'] >= request['t_us'] and clrt.app_seq(response['payload']) == clrt.app_seq(request['payload']) and \
                    response['flags'] & wc.ACK and clrt.after(response['ack'], (request['seq'] + request['len']) & 0xffffffff):
                return dict(response_index=response['index'], t_us=response['t_us'], app_seq=clrt.app_seq(response['payload']),
                            frame_sha256=hashlib.sha256(response['frame']).hexdigest(), checksum_valid=True, dnp3_crc_valid=True)
    return None


def ss_args(port, kill=False):
    expression = '( src %s and sport = :%d and dst %s and dport = :%d )' % (MASTER, port, OUTSTATION, SERVER_PORT)
    return ['ss', '-H', '-4', '-t', '-n'] + (['-K'] if kill else []) + ['state', 'established', expression]


def observe(dest, port, done, timeout=198):
    """Bounded live-capture observer. Failure never broadens the socket filter."""
    record = dict(ok=False, response=None, error=None, commands=[])
    logs = {'ss_probe.log': 'not attempted\n', 'ss_kill.log': 'not attempted\n'}
    try:
        guard(port, apply=True)
        deadline = time.monotonic() + timeout
        while not done.is_set() and time.monotonic() < deadline:
            response = operate_response(dest, port)
            if response:
                record['response'] = response
                if done.wait(0.2):
                    break                        # callback settling window inside the bounded endpoint grace
                for kill, name in ((False, 'ss_probe.log'), (True, 'ss_kill.log')):
                    if done.is_set():
                        raise RuntimeError('connection ended before kernel socket kill')
                    guard(port, apply=True)       # recheck authority at the destructive boundary
                    args = ss_args(port, kill)
                    result = vr.nsx(NAMESPACE_M, *args, timeout=2)
                    record['commands'].append(dict(argv=args, namespace=NAMESPACE_M, rc=result.returncode,
                                                   stdout=result.stdout, stderr=result.stderr))
                    logs[name] = result.stdout + '\n--- stderr ---\n' + result.stderr
                    if result.returncode:
                        raise RuntimeError(name + ' failed')
                    if not kill:
                        rows = [line.split() for line in result.stdout.splitlines() if line.strip()]
                        endpoints = ['%s:%d' % (MASTER, port), '%s:%d' % (OUTSTATION, SERVER_PORT)]
                        if len(rows) != 1 or rows[0][-2:] != endpoints:
                            raise RuntimeError('exact established socket probe is missing or ambiguous')
                record['ok'] = True
                return record
            done.wait(0.05)
        raise RuntimeError('OPERATE response monitoring timed out or connection ended')
    except Exception as error:
        record['error'] = str(error)
        return record
    finally:
        if Path(dest).is_dir():
            for name, text in logs.items():
                (Path(dest) / name).write_text(text)
            write_json(Path(dest) / 'observer.json', record)


def close_proof(dest, port, mode):
    returned = [s for s in segments(Path(dest) / 'in.pcap') if all(wc.ip_tcp_checksum(s)[:2])]
    if mode == 'rst':
        sent = [s for s in segments(Path(dest) / 'out.pcap') if exact(s, port) and s['flags'] & wc.RST]
        return bool(sent and any(exact(s, port) and s['flags'] & wc.RST for s in returned))
    return all(any(exact(s, port, reverse) and s['flags'] & wc.FIN for s in returned) for reverse in (False, True))


def evaluate(dest, port, mode, padding, result, rst_grace_ms=5000, reads=20, pre_read_grace_ms=0):
    failures, ev = [], {}
    required = ('out.pcap', 'in.pcap', 'master.json', 'outstation.json', 'result.json', 'state.txt')
    for name in required:
        path = Path(dest) / name
        if not path.is_file() or not path.stat().st_size:
            failures.append('missing or empty evidence: ' + name)
    try:
        for name in ('master', 'outstation'):
            data = json.loads((Path(dest) / (name + '.json')).read_text())
            ev[name] = data if isinstance(data, dict) else None
        ev['wire'] = wc.analyze(Path(dest) / 'out.pcap', Path(dest) / 'in.pcap')
        ev['timing'] = clrt.analyze(Path(dest) / 'out.pcap', Path(dest) / 'in.pcap')
        write_json(Path(dest) / 'wire.json', ev['wire']); write_json(Path(dest) / 'timing.json', ev['timing'])
        failures += checks.application_checks(EXPECT, padding, reads, ev, run_sbo=True)
        master = ev['master'] or {}
        controls = dict(read_pause_ms=25, run_sbo=True, close_grace_ms=rst_grace_ms if mode == 'rst' else 0)
        if any(type(master.get(key)) is not type(value) or master.get(key) != value for key, value in controls.items()):
            failures.append('missing or wrong master effective controls')
        failures += pre_read_evidence(dest, pre_read_grace_ms)[0]
        if master.get('application_calls') != 1:
            failures.append('master application_calls must equal 1')
        if type(master.get('opens')) is not int or master.get('opens') != 1:
            failures.append('master must report exactly one connection open')
        if result.get('ok') is not True or result.get('master_rc') != 0 or result.get('endpoint_controls') != controls:
            failures.append('connection result or effective controls failed')
        for key in ('unmatched_sent', 'unmatched_returned', 'duplicate_returned'):
            if ev['wire'].get(key) != []:
                failures.append('wire mapping failure: ' + key)
        for direction in ('out', 'in'):
            stats = result.get('tcpdump', {}).get(direction, {})
            if stats.get('dropped_kernel') != 0 or not stats.get('captured', 0) or stats.get('dropped_interface', 0):
                failures.append('missing or lossy capture statistics: ' + direction)
        if not close_proof(dest, port, mode):
            failures.append('captured close proof missing: ' + mode)
    except Exception as error:
        failures.append('evidence extraction failed: ' + str(error))
    return failures


def scenario(label, port, mode, padding, apply=False, rst_grace_ms=5000, reads=20, pre_read_grace_ms=0):
    guard(port, apply)
    if not re.fullmatch('[A-Za-z0-9_]+', label) or mode not in ('graceful', 'rst') or padding not in (0, 1):
        raise ValueError('invalid label, close mode or padding')
    if type(rst_grace_ms) is not int or not 500 <= rst_grace_ms <= 5000:
        raise ValueError('RST grace must be an integer in 500..5000 ms')
    if type(reads) is not int or not 1 <= reads <= 20:
        raise ValueError('READ count must be an integer in 1..20')
    if type(pre_read_grace_ms) is not int or not 0 <= pre_read_grace_ms <= 5000:
        raise ValueError('pre-READ grace must be an integer in 0..5000 ms')
    parent = Path(vr.RUNS) / label
    record = dict(scenario='candidate_same_tuple', label=label, close_mode=mode, master_port=port,
                  tuple=[MASTER, port, OUTSTATION, SERVER_PORT], namespaces=[NAMESPACE_M, NAMESPACE_O], nic=NIC,
                  padding=padding, reads=reads, read_pause_ms=25, close_grace_ms=rst_grace_ms if mode == 'rst' else 0,
                  pre_read_grace_ms=pre_read_grace_ms,
                  switch_mutations=False, applied=apply, connections=[], ok=False)
    if not apply:
        record['plan'] = [dict(name='c%d' % index, master_port=port, start_seed=12344 + index,
                             marker_path=str(parent / ('c%d' % index) / 'pre_read_ready.json') if pre_read_grace_ms else None)
                          for index in range(1, 4)]
        record['ok'] = True
        return record
    parent.mkdir()                                # refuse retained evidence reuse
    try:
        record['preflight'] = preflight(mode)
        for index in range(1, 4):
            dest = parent / ('c%d' % index)
            done, observer, worker = threading.Event(), {}, None
            connection = dict(name=dest.name, master_port=port, ok=False, failures=[])
            record['connections'].append(connection)
            if mode == 'rst':
                def watch():
                    observer.update(observe(dest, port, done))
                worker = threading.Thread(target=watch, daemon=True); worker.start()
            try:
                with pre_read_controls(dest, pre_read_grace_ms):
                    result = vr.run_connection(str(dest), label + '_' + dest.name, port, reads, 8, 0, 0, 12344 + index,
                                               read_pause_ms=25, run_sbo=True, close_grace_ms=record['close_grace_ms'],
                                               capture_immediate=mode == 'rst')
                connection['result'] = result
            except Exception as error:
                result = {}; connection['failures'].append(str(error))
            finally:
                done.set()
                dest.mkdir(exist_ok=True)
                if worker:
                    worker.join(timeout=5)
                    if worker.is_alive():
                        connection['failures'].append('observer did not stop within 5 seconds')
                    connection['observer'] = observer
                    write_json(dest / 'observer.json', observer)
                    if observer.get('ok') is not True:
                        connection['failures'].append('kernel RST observer failed')
            connection['failures'] += evaluate(dest, port, mode, padding, result, rst_grace_ms=rst_grace_ms,
                                               reads=reads, pre_read_grace_ms=pre_read_grace_ms)
            connection['pre_read_hook'] = pre_read_evidence(dest, pre_read_grace_ms)[1]
            connection['ok'] = not connection['failures']
            write_json(dest / 'verdict.json', connection)
            if not connection['ok']:
                break                            # a later incarnation needs a valid previous close
        record['ok'] = len(record['connections']) == 3 and all(c['ok'] for c in record['connections'])
    except Exception as error:
        record['error'] = str(error)
    finally:
        record['source_sha256'] = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in
                                  (Path(__file__), Path(vr.__file__), Path(wc.__file__), Path(clrt.__file__), Path(checks.__file__))}
        record['hashes'] = {str(path.relative_to(parent)): hashlib.sha256(path.read_bytes()).hexdigest()
                            for path in parent.rglob('*') if path.is_file()}
        write_json(parent / 'scenario.json', record)
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('label')
    parser.add_argument('--master-port', type=int, required=True)
    parser.add_argument('--close-mode', choices=('graceful', 'rst'), default='graceful')
    parser.add_argument('--padding', type=int, choices=(0, 1), default=1)
    parser.add_argument('--rst-grace-ms', type=int, default=5000)
    parser.add_argument('--reads', type=int, default=20)
    parser.add_argument('--pre-read-grace-ms', type=int, default=0)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    result = scenario(args.label, args.master_port, args.close_mode, args.padding, args.apply,
                      rst_grace_ms=args.rst_grace_ms, reads=args.reads, pre_read_grace_ms=args.pre_read_grace_ms)
    print(json.dumps(result, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        sys.stderr.write('Vision candidate refused: %s\n' % error)
        sys.exit(2)
