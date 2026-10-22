#!/usr/bin/env python3
"""Three consecutive connections on one externally installed software tuple.

Default prints an offline plan. On Vision (already set up and installed):
  sudo env DEFENSE4_HW_AUTHORIZED=1 python3 vision_candidate.py LABEL \
    --master-port PORT --padding 1 --close-mode graceful|rst --apply

--rst-grace-ms accepts 500..5000 (default5000); --reads accepts 1..20 (default20).
--pre-read-grace-ms accepts 0..10000 (default0). Nonzero uses the isolated
pre-READ endpoint binary deployed by the hardware owner; each connection writes
its own pre_read_ready.json before the pause. Existing master timeout budgets
(at least34s for one READ) already accommodate the bounded additional10s pause.

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
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(LIBRARY))
import vision_run as vr
import wire_check as wc
import clrt_check as clrt
import checks
from token_window import PRE_READ_GRACE_MS

MASTER, OUTSTATION, SERVER_PORT = '192.168.10.61', '192.168.10.62', 20000
NAMESPACE_M, NAMESPACE_O, NIC = 'ns_vepa_a', 'ns_vepa_b', 'enp59s0f0np0'
EXPECT = {'common': {'read_points': 23}, 'padding': {
    '0': {'read_resp_len': [49], 'sbo_resp_len': [37]},
    '1': {'read_resp_len': [58], 'sbo_resp_len': [58]}}}
# Strict-response builds (control_padding 0): READ still 58, SELECT/OPERATE responses stay native.
EXPECT_STRICT = {'common': {'read_points': 23}, 'padding': {
    '0': {'read_resp_len': [49], 'sbo_resp_len': [37]},
    '1': {'read_resp_len': [58], 'sbo_resp_len': [37]}}}


def expect(control_padding=1, image_len=58, read_image_len=None):
    """Per-connection length expectations for a build: padded READ = read_image_len (default image_len); padded
    SELECT/OPERATE = image_len, or native 37 under the strict policy. image_len 58 reproduces EXPECT /
    EXPECT_STRICT exactly; read_image_len differs only on builds whose READ image is not the control image
    (read_complete_01 policy: READ 141, SELECT/OPERATE 61)."""
    return {'common': {'read_points': 23}, 'padding': {
        '0': {'read_resp_len': [49], 'sbo_resp_len': [37]},
        '1': {'read_resp_len': [read_image_len or image_len], 'sbo_resp_len': [image_len if control_padding else 37]}}}


def read_controls(padding, reads, read_schedule=None, db=None, endpoint_binary=None, pad_expect=None,
                  read_classes=None):
    """Validate the optional READ-schedule declaration; returns the parsed per-class expectation (or None).
    --read-schedule needs --db and --read-classes (the workstation-computed read_classes.expectations dict);
    --db, --pad-expect and --read-classes need --read-schedule; --pad-expect is a padded-arm declaration only."""
    if read_schedule is None:
        if db is not None or pad_expect is not None or read_classes is not None:
            raise ValueError('--db, --pad-expect and --read-classes require --read-schedule')
    else:
        if read_schedule not in vr.READ_SCHEDULES:
            raise ValueError('--read-schedule must be one of %s' % (vr.READ_SCHEDULES,))
        if db is None or read_classes is None:
            raise ValueError('--read-schedule requires --db and --read-classes')
        if db not in vr.DBS:
            raise ValueError('--db must be one of %s' % (vr.DBS,))
    if pad_expect is not None:
        if not vr.PAD_EXPECT_RE.fullmatch(str(pad_expect)):
            raise ValueError('--pad-expect must be <class>=<n>[,...], got %r' % (pad_expect,))
        if padding != 1:
            raise ValueError('--pad-expect is a padded-arm declaration; padding 0 must declare none')
    if endpoint_binary is not None and (not re.fullmatch(r'[A-Za-z0-9_.-]+', str(endpoint_binary)) or
                                        endpoint_binary in ('.', '..')):
        raise ValueError('--endpoint-binary must be a file name beside vision_run.py, got %r' % (endpoint_binary,))
    if read_classes is None:
        return None
    if isinstance(read_classes, str):
        read_classes = json.loads(read_classes)
    classes = read_classes.get('classes') if isinstance(read_classes, dict) else None
    if not isinstance(classes, dict) or not classes or not isinstance(read_classes.get('order'), list) or any(
            not isinstance(e, dict) or type(e.get('count')) is not int for e in classes.values()):
        raise ValueError('--read-classes must be a per-class READ expectation with classes and order')
    if (read_classes.get('schedule'), read_classes.get('db')) != (read_schedule, db):
        raise ValueError('--read-classes schedule/db %r/%r disagree with --read-schedule/--db %r/%r'
                         % (read_classes.get('schedule'), read_classes.get('db'), read_schedule, db))
    if sum(e['count'] for e in classes.values()) != reads:
        raise ValueError('--read-classes counts must sum to --reads %d' % reads)
    return read_classes


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


def held_operate_duplicates(out_pcap, unmatched):
    """Split unmatched sent frames into (excused, remaining). Excused: a master 35-octet segment that repeats an
    earlier sent master segment's sequence number and payload, i.e. a TCP retransmission of the held OPERATE that
    dup_hold_01 drops while the original is held. Anything else stays a wire-mapping failure."""
    segs = wc.parse(out_pcap)[0]
    by_index = {s['index']: s for s in segs}
    excused, remaining = [], []
    for u in unmatched:
        s = by_index.get(u.get('sent_index'))
        earlier = s is not None and any(e['src'] == s['src'] and e['seq'] == s['seq'] and e['payload'] == s['payload']
                                        and e['t_us'] < s['t_us'] for e in segs)
        if s is not None and s['src'] == MASTER and s['len'] == 35 and earlier:
            excused.append(dict(u, seq=s['seq'], t_us=s['t_us']))
        else:
            remaining.append(u)
    return excused, remaining


def evaluate(dest, port, mode, padding, result, rst_grace_ms=5000, reads=20, pre_read_grace_ms=0, control_padding=1,
             image_len=58,
             expect_held_operate_dup=0, read_image_len=None, read_schedule=None, db=None, pad_expect=None,
             read_classes=None):
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
        ev['timing'] = clrt.analyze(Path(dest) / 'out.pcap', Path(dest) / 'in.pcap',
                                    **({'read_policy': {'classes': read_classes['classes']}} if read_classes else {}))
        write_json(Path(dest) / 'wire.json', ev['wire']); write_json(Path(dest) / 'timing.json', ev['timing'])
        failures += checks.application_checks(expect(control_padding, image_len, read_image_len), padding, reads, ev,
                                              run_sbo=True, read_classes=read_classes)
        master = ev['master'] or {}
        controls = dict(read_pause_ms=25, run_sbo=True, close_grace_ms=rst_grace_ms if mode == 'rst' else 0)
        endpoint_controls = dict(controls)
        if read_schedule is not None:
            controls.update(read_schedule=read_schedule, db=db)
            endpoint_controls.update(read_schedule=read_schedule, db=db)
            if pad_expect:
                endpoint_controls['pad_expect'] = pad_expect
            padding_decl = {k: int(v) for k, v in (kv.split('=') for kv in pad_expect.split(','))} if pad_expect else {}
            failures += checks.read_padding_record_checks(master, padding_decl)
        if any(type(master.get(key)) is not type(value) or master.get(key) != value for key, value in controls.items()):
            failures.append('missing or wrong master effective controls')
        failures += pre_read_evidence(dest, pre_read_grace_ms)[0]
        if master.get('application_calls') != 1:
            failures.append('master application_calls must equal 1')
        if type(master.get('opens')) is not int or master.get('opens') != 1:
            failures.append('master must report exactly one connection open')
        if result.get('ok') is not True or result.get('master_rc') != 0 or result.get('endpoint_controls') != endpoint_controls:
            failures.append('connection result or effective controls failed')
        unmatched_sent = ev['wire'].get('unmatched_sent')
        if expect_held_operate_dup and unmatched_sent:
            excused, unmatched_sent = held_operate_duplicates(Path(dest) / 'out.pcap', unmatched_sent)
            write_json(Path(dest) / 'held_operate_duplicates.json', {'excused': excused, 'remaining': unmatched_sent})
        for key, value in (('unmatched_sent', unmatched_sent), ('unmatched_returned', ev['wire'].get('unmatched_returned')),
                           ('duplicate_returned', ev['wire'].get('duplicate_returned'))):
            if value != []:
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


def scenario(label, port, mode, padding, apply=False, rst_grace_ms=5000, reads=20, pre_read_grace_ms=0,
             control_padding=1, expect_held_operate_dup=0, image_len=58, qualify_capture=False, read_image_len=None,
             read_schedule=None, db=None, endpoint_binary=None, pad_expect=None, read_classes=None):
    guard(port, apply)
    if not re.fullmatch('[A-Za-z0-9_]+', label) or mode not in ('graceful', 'rst') or padding not in (0, 1):
        raise ValueError('invalid label, close mode or padding')
    if type(rst_grace_ms) is not int or not 500 <= rst_grace_ms <= 5000:
        raise ValueError('RST grace must be an integer in 500..5000 ms')
    if type(reads) is not int or not 1 <= reads <= 20:
        raise ValueError('READ count must be an integer in 1..20')
    if type(pre_read_grace_ms) is not int or not 0 <= pre_read_grace_ms <= PRE_READ_GRACE_MS:
        raise ValueError('pre-READ grace must be an integer in 0..%d ms' % PRE_READ_GRACE_MS)
    if type(qualify_capture) is not bool:
        raise ValueError('qualify_capture must be a boolean')
    read_classes = read_controls(padding, reads, read_schedule, db, endpoint_binary, pad_expect, read_classes)
    endpoint_kwargs, gate_kwargs = {}, {}
    if read_schedule is not None:
        endpoint_kwargs.update(read_schedule=read_schedule, db=db, pad_expect=pad_expect)
        gate_kwargs.update(read_schedule=read_schedule, db=db, pad_expect=pad_expect, read_classes=read_classes)
    if endpoint_binary is not None:
        endpoint_kwargs['endpoint_binary_name'] = endpoint_binary
    parent = Path(vr.RUNS) / label
    record = dict(scenario='candidate_same_tuple', label=label, close_mode=mode, master_port=port,
                  tuple=[MASTER, port, OUTSTATION, SERVER_PORT], namespaces=[NAMESPACE_M, NAMESPACE_O], nic=NIC,
                  padding=padding, reads=reads, read_pause_ms=25, close_grace_ms=rst_grace_ms if mode == 'rst' else 0,
                  pre_read_grace_ms=pre_read_grace_ms,
                  qualify_capture=qualify_capture,
                  switch_mutations=False, applied=apply, connections=[], ok=False)
    if read_schedule is not None or endpoint_binary is not None:
        record.update(read_schedule=read_schedule, db=db, pad_expect=pad_expect, read_classes=read_classes,
                      endpoint_binary=endpoint_binary)
    if not apply:
        record['plan'] = [dict(name='c%d' % index, master_port=port, start_seed=12344 + index,
                             marker_path=str(parent / ('c%d' % index) / 'pre_read_ready.json') if pre_read_grace_ms else None)
                          for index in range(1, 4)]
        record['ok'] = True
        return record
    parent.mkdir(parents=True)                    # refuse retained evidence reuse
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
                    kwargs = dict(read_pause_ms=25, run_sbo=True, close_grace_ms=record['close_grace_ms'],
                                  capture_immediate=mode == 'rst')
                    if qualify_capture:
                        kwargs['qualify_capture'] = True
                    kwargs.update(endpoint_kwargs)
                    result = vr.run_connection(str(dest), label + '_' + dest.name, port, reads, 8, 0, 0, 12344 + index,
                                               **kwargs)
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
                                               reads=reads, pre_read_grace_ms=pre_read_grace_ms,
                                               control_padding=control_padding, image_len=image_len,
                                               expect_held_operate_dup=expect_held_operate_dup,
                                               **({'read_image_len': read_image_len} if read_image_len else {}),
                                               **gate_kwargs)
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
                                  (Path(__file__), Path(vr.__file__), Path(wc.__file__), Path(clrt.__file__), Path(checks.__file__),
                                   HERE / 'token_window.py', HERE / 'snapshot_lifecycle.py')}
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
    parser.add_argument('--read-image-len', type=int, default=None,
                        help='padded READ length when it differs from --image-len (read_complete_01 policy builds)')
    parser.add_argument('--image-len', type=int, default=58,
                        help='padded response length of the build (58 default; 61 for the transport-segmented profile)')
    parser.add_argument('--expect-held-operate-dup', type=int, choices=(0, 1), default=0,
                        help='1 when the fixture makes the master retransmit a held OPERATE (dup_hold_01 drops it)')
    parser.add_argument('--control-padding', type=int, choices=(0, 1), default=1,
                        help='0 for strict-response builds: SELECT/OPERATE responses stay native (37 B)')
    parser.add_argument('--rst-grace-ms', type=int, default=5000)
    parser.add_argument('--reads', type=int, default=20)
    parser.add_argument('--pre-read-grace-ms', type=int, default=0)
    parser.add_argument('--qualify-capture', action='store_true',
                        help='opt-in physical packet-boundary qualification evidence for each connection')
    parser.add_argument('--read-schedule', choices=vr.READ_SCHEDULES, default=None,
                        help='read-schedule endpoint READ schedule (needs --db and --read-classes)')
    parser.add_argument('--db', choices=vr.DBS, default=None, help='read-schedule endpoint database')
    parser.add_argument('--endpoint-binary', default=None, help='endpoint file beside vision_run.py')
    parser.add_argument('--pad-expect', default=None,
                        help='padded arm: the declared per-class READ padding, <class>=<n>[,...] (needs --read-schedule)')
    parser.add_argument('--read-classes', default=None,
                        help='JSON per-class READ expectation computed on the workstation (needs --read-schedule)')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    result = scenario(args.label, args.master_port, args.close_mode, args.padding, args.apply,
                      rst_grace_ms=args.rst_grace_ms, reads=args.reads, pre_read_grace_ms=args.pre_read_grace_ms,
                      control_padding=args.control_padding, expect_held_operate_dup=args.expect_held_operate_dup,
                      image_len=args.image_len, qualify_capture=args.qualify_capture,
                      read_image_len=args.read_image_len, read_schedule=args.read_schedule, db=args.db,
                      endpoint_binary=args.endpoint_binary, pad_expect=args.pad_expect, read_classes=args.read_classes)
    print(json.dumps(result, indent=2))
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError) as error:
        sys.stderr.write('Vision candidate refused: %s\n' % error)
        sys.exit(2)
