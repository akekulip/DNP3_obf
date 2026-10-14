#!/usr/bin/env python3
"""Physical capture-boundary qualification helpers for Vision runs.

This module is opt-in. It snapshots and temporarily disables receive aggregation
on the physical capture interface, runs a small unbound calibration flow through
the switch, and leaves file-backed evidence for the acceptance validator to
recompute from the pcaps and JSON files.
"""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import re
import socket
import struct
import subprocess
import time

import wire_check

PARENT = 'enp59s0f0np0'
NS_M, NS_O = 'ns_vepa_a', 'ns_vepa_b'
DEV_M, DEV_O = 'mvA', 'mvB'
IP_M, IP_O = '192.168.10.61', '192.168.10.62'
CAL_SRC_PORT, CAL_DST_PORT = 20001, 61998
CAL_PAYLOAD_LEN = 256
MANAGED_OFFLOADS = ('gro', 'lro', 'rx-gro-hw', 'rx-gro-list')
CAL_EXIT_POLLS = 50                   # up to 5 s for the -c bounded calibration captures to exit
CAL_READY_POLLS = 60                  # up to 3 s for both calibration captures to become active
FEATURE_ALIASES = {
    'generic-receive-offload': 'gro',
    'large-receive-offload': 'lro',
    'rx-gro-hw': 'rx-gro-hw',
    'rx-gro-list': 'rx-gro-list',
}


def sh(argv, **kw):
    return subprocess.run(list(argv), capture_output=True, text=True, **kw)


def parse_tcpdump_stats(stderr):
    out = {}
    for label, key in (('captured', 'captured'), ('received by filter', 'received'),
                       ('dropped by kernel', 'dropped_kernel'), ('dropped by interface', 'dropped_interface')):
        match = re.search(r'(\d+)\s+packets?\s+' + re.escape(label), stderr or '')
        if match:
            out[key] = int(match.group(1))
    return out


def _bool(value):
    if value == 'on':
        return True
    if value == 'off':
        return False
    return value


def parse_ethtool_features(raw):
    features = {}
    for line in (raw or '').splitlines():
        if ':' not in line:
            continue
        name, value = line.split(':', 1)
        name = name.strip()
        token = value.strip().split()[0].lower() if value.strip() else ''
        if token not in ('on', 'off'):
            continue
        key = FEATURE_ALIASES.get(name, name)
        features[key] = _bool(token)
    return features


def _run_checked(run, argv, commands):
    result = run(list(argv))
    commands.append(list(argv))
    if getattr(result, 'returncode', 0):
        raise RuntimeError('command failed: %s\n%s' % (' '.join(argv), getattr(result, 'stderr', '').strip()))
    return result


def snapshot_features(interface, run=sh):
    command = ['ethtool', '-k', interface]
    result = run(command)
    if result.returncode:
        raise RuntimeError('ethtool feature snapshot failed: ' + result.stderr.strip())
    return {'features': parse_ethtool_features(result.stdout), 'raw': result.stdout, 'command': command}


def receive_aggregation_failures(features):
    failures = []
    if features.get('gro') is not False:
        failures.append('GRO is not disabled on physical capture interface')
    for key in ('lro', 'rx-gro-hw', 'rx-gro-list'):
        if key in features and features[key] is not False:
            failures.append('%s is not disabled on physical capture interface' % key)
    return failures


def record_offload_baseline(path, interface=PARENT, run=sh):
    """Campaign-level receive-offload baseline, written once. An existing file means an earlier campaign never
    completed its restore, so the state now on the NIC may be that campaign's and is not taken as the baseline."""
    path = Path(path)
    if path.exists():
        return json.loads(path.read_text())
    snap = snapshot_features(interface, run=run)
    baseline = {'interface': interface, 'features': {k: v for k, v in snap['features'].items() if k in MANAGED_OFFLOADS},
                'raw': snap['raw']}
    path.write_text(json.dumps(baseline, indent=2) + '\n')
    return baseline


def restore_offload_baseline(path, interface=PARENT, run=sh):
    """Re-apply and verify the campaign baseline independently of any per-run context. Returns the errors; the
    baseline file is removed only after the NIC is verified equal to it."""
    path = Path(path)
    if not path.exists():
        return ['no receive-offload baseline recorded at %s' % path]
    baseline = json.loads(path.read_text())
    errors = []
    try:
        current = snapshot_features(interface, run=run)['features']
    except Exception as error:
        return [str(error)]
    for key, value in baseline['features'].items():
        if current.get(key) == value:       # never write a key already at baseline ([fixed] features refuse -K)
            continue
        result = run(['ethtool', '-K', interface, key, 'on' if value else 'off'])
        if getattr(result, 'returncode', 0):
            errors.append('ethtool -K %s %s failed: %s' % (key, value, getattr(result, 'stderr', '').strip()))
    try:
        after = snapshot_features(interface, run=run)['features']
    except Exception as error:
        return errors + [str(error)]
    errors += ['receive offload %s is %r, baseline %r' % (key, after.get(key), value)
               for key, value in baseline['features'].items() if after.get(key) != value]
    if not errors:
        path.unlink()
    return errors


@contextmanager
def offload_capture_context(evidence_dir, interface=PARENT, run=sh):
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    commands, restore_errors = [], []
    before = snapshot_features(interface, run=run)
    during = {}
    after = {}
    block_error = None
    try:
        for key in MANAGED_OFFLOADS:
            if before['features'].get(key) is True:
                _run_checked(run, ['ethtool', '-K', interface, key, 'off'], commands)
        during = snapshot_features(interface, run=run)
        failures = receive_aggregation_failures(during['features'])
        if failures:
            raise RuntimeError('; '.join(failures))
        yield {'interface': interface, 'before': before, 'during': during, 'commands': commands}
    except Exception as error:
        block_error = error
        raise
    finally:
        for key in MANAGED_OFFLOADS:
            if before['features'].get(key) is not True:
                continue
            try:
                _run_checked(run, ['ethtool', '-K', interface, key, 'on' if before['features'][key] else 'off'], commands)
            except Exception as error:
                restore_errors.append(str(error))
        try:
            after = snapshot_features(interface, run=run)
        except Exception as error:
            restore_errors.append(str(error))
        restore_ok = not restore_errors
        if after:
            for key in MANAGED_OFFLOADS:
                if key in before['features'] and after['features'].get(key) != before['features'][key]:
                    restore_ok = False
                    restore_errors.append('restore mismatch for %s' % key)
        evidence = {
            'interface': interface,
            'before': before,
            'during': during,
            'after': after,
            'restore_ok': restore_ok,
            'restore_errors': restore_errors,
            'commands': commands,
        }
        if block_error is not None:
            evidence['block_error'] = str(block_error)
        (evidence_dir / 'capture_offloads.json').write_text(json.dumps(evidence, indent=2) + '\n')
        if not restore_ok and block_error is None:
            raise RuntimeError('receive offload restore failed: ' + '; '.join(restore_errors))


def _sum16(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def tcp_frame(src_mac, dst_mac, src_ip, dst_ip, sport, dport, seq, ack, payload, ip_id=0):
    src = bytes(int(part) for part in src_ip.split('.'))
    dst = bytes(int(part) for part in dst_ip.split('.'))
    tcp = bytearray(struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                                0x50, 0x10, 64240, 0, 0)) + payload
    ip = bytearray(struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), ip_id, 0x4000, 64, 6, 0, src, dst))
    ip[10:12] = struct.pack('!H', _sum16(bytes(ip)))
    pseudo = src + dst + struct.pack('!BBH', 0, 6, len(tcp))
    tcp[16:18] = struct.pack('!H', _sum16(pseudo + bytes(tcp)))
    return bytes.fromhex(dst_mac.replace(':', '')) + bytes.fromhex(src_mac.replace(':', '')) + b'\x08\x00' + bytes(ip) + bytes(tcp)


def _json_command(run, argv):
    result = run(list(argv))
    if result.returncode:
        raise RuntimeError('command failed: %s\n%s' % (' '.join(argv), result.stderr.strip()))
    return json.loads(result.stdout)


def namespace_mac(namespace, device, run=sh):
    rows = _json_command(run, ['ip', 'netns', 'exec', namespace, 'ip', '-j', 'link', 'show', 'dev', device])
    if len(rows) != 1 or not rows[0].get('address'):
        raise RuntimeError('could not read namespace MAC: %s/%s' % (namespace, device))
    return rows[0]['address']


def calibration_expected(interface=PARENT, run=sh):
    src_mac = namespace_mac(NS_O, DEV_O, run=run)
    dst_mac = namespace_mac(NS_M, DEV_M, run=run)
    payloads = [bytes([0x41]) * CAL_PAYLOAD_LEN, bytes([0x42]) * CAL_PAYLOAD_LEN]
    frames = [tcp_frame(src_mac, dst_mac, IP_O, IP_M, CAL_SRC_PORT, CAL_DST_PORT, 1000 + i * CAL_PAYLOAD_LEN,
                        7000, payload, ip_id=2000 + i) for i, payload in enumerate(payloads)]
    send_command = ['ip', 'netns', 'exec', NS_O, 'python3', str(Path(__file__).resolve()), 'send-calibration',
                    '--device', DEV_O] + sum((['--frame-hex', frame.hex()] for frame in frames), [])
    return {
        'interface': interface,
        'source_namespace': NS_O,
        'send_command': send_command,
        'tuple': {'src': IP_O, 'dst': IP_M, 'sport': CAL_SRC_PORT, 'dport': CAL_DST_PORT},
        'direction': 'in',
        'source_mac': src_mac,
        'destination_mac': dst_mac,
        'payloads': [payload.hex() for payload in payloads],
        'frames': [frame.hex() for frame in frames],
    }


def send_calibration_frames(frames, device=DEV_O):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    try:
        sock.bind((device, 0))
        for frame in frames:
            sock.send(bytes.fromhex(frame))
    finally:
        sock.close()


def _start_tcpdump(popen, command):
    proc = popen(command, stderr=subprocess.PIPE, text=True)
    return proc


def _pcap_header_written(command):
    path = Path(command[command.index('-w') + 1])
    return path.is_file() and path.stat().st_size >= 24


def run_calibration(evidence_dir, interface=PARENT, run=sh, popen=subprocess.Popen,
                    send_calibration=None, sleep=time.sleep):
    evidence_dir = Path(evidence_dir)
    expected = calibration_expected(interface, run=run)
    (evidence_dir / 'calibration_expected.json').write_text(json.dumps(expected, indent=2) + '\n')
    flt = 'tcp and src host %s and dst host %s and src port %d and dst port %d' % (
        IP_O, IP_M, CAL_SRC_PORT, CAL_DST_PORT)
    commands = {}
    procs = {}
    for direction in ('out', 'in'):
        # --immediate-mode: TPACKET_V3 otherwise holds packets in a ring block until it retires, and a
        # terminate before that loses them (smoke_02 combined: received 4, captured 0)
        command = ['tcpdump', '--immediate-mode', '-i', interface, '-Q', direction, '-s0', '-U', '-n', '-c',
                   str(len(expected['payloads'])), '-w', str(evidence_dir / ('calibration_%s.pcap' % direction)), flt]
        commands[direction] = command
        procs[direction] = _start_tcpdump(popen, command)
    try:
        # tcpdump writes the 24-octet pcap header once its capture is active; send only after both have
        # (fixed 1 s sleeps here delayed the next connection past candidate61_stale_tokens' old tokens)
        for _ in range(CAL_READY_POLLS):
            if all(_pcap_header_written(command) for command in commands.values()):
                break
            sleep(0.05)
        if send_calibration is None:
            _run_checked(run, expected['send_command'], [])
        else:
            send_calibration(expected)
        for _ in range(CAL_EXIT_POLLS):        # each capture is bounded by -c: let it finish its count
            if all(proc.poll() is not None for proc in procs.values()):
                break
            sleep(0.1)
    finally:
        stats = {}
        for direction, proc in procs.items():
            if proc.poll() is None:
                proc.terminate()
            try:
                _, err = proc.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                _, err = proc.communicate()
            stats[direction] = parse_tcpdump_stats(err or '')
    result = {'capture_commands': commands, 'tcpdump': stats}
    (evidence_dir / 'calibration_result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def _payloads(path):
    segs, _ = wire_check.parse(path)
    return [seg['payload'] for seg in segs if seg.get('len', 0)]


def validate_calibration_files(evidence_dir):
    evidence_dir = Path(evidence_dir)
    failures = []
    paths = {name: evidence_dir / name for name in (
        'calibration_expected.json', 'calibration_result.json', 'calibration_in.pcap', 'calibration_out.pcap')}
    for name, path in paths.items():
        if not path.is_file():
            failures.append('missing calibration evidence: ' + name)
    if failures:
        return failures
    try:
        expected = json.loads(paths['calibration_expected.json'].read_text())
        payloads = [bytes.fromhex(value) for value in expected.get('payloads', [])]
        if expected.get('direction') != 'in' or len(payloads) < 2:
            failures.append('malformed calibration expected tuple or payloads')
    except (OSError, ValueError, TypeError) as error:
        return ['malformed calibration expected: %s' % error]
    try:
        result = json.loads(paths['calibration_result.json'].read_text())
    except (OSError, ValueError) as error:
        return ['malformed calibration result: %s' % error]
    for direction in ('out', 'in'):
        stats = (result.get('tcpdump') or {}).get(direction, {})
        if stats.get('captured', 0) <= 0 or stats.get('dropped_kernel', 0) or stats.get('dropped_interface', 0):
            failures.append('calibration %s capture statistics missing or lossy' % direction)
        try:
            got = _payloads(paths['calibration_%s.pcap' % direction])
        except Exception as error:
            failures.append('calibration %s parse failed: %s' % (direction, error))
            continue
        if len(got) != len(payloads):
            failures.append('calibration_%s payload count %d, expected %d' % (direction, len(got), len(payloads)))
            continue
        for index, (actual, wanted) in enumerate(zip(got, payloads)):
            if actual != wanted:
                failures.append('calibration_%s payload[%d] does not match expected boundary frame' % (direction, index))
    return failures


def run_with_qualified_capture(evidence_dir, main, interface=PARENT, run=sh, popen=subprocess.Popen,
                               send_calibration=None, sleep=time.sleep):
    evidence_dir = Path(evidence_dir)
    with offload_capture_context(evidence_dir, interface, run=run):
        run_calibration(evidence_dir, interface=interface, run=run, popen=popen,
                        send_calibration=send_calibration, sleep=sleep)
        return main()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='mode', required=True)
    send = sub.add_parser('send-calibration')
    send.add_argument('--device', default=DEV_O)
    send.add_argument('--frame-hex', action='append', required=True)
    args = parser.parse_args(argv)
    if args.mode == 'send-calibration':
        send_calibration_frames(args.frame_hex, args.device)
        return 0
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
