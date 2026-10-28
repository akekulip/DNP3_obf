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
import os
import signal
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'checks'))
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


def snapshot_rx_coalesce(interface=PARENT, run=sh):
    """{'adaptive_rx': 'on'|'off', 'rx_usecs': int, 'raw': text} from `ethtool -c` (RX moderation only)."""
    result = run(['ethtool', '-c', interface])
    if getattr(result, 'returncode', 0):
        raise RuntimeError('ethtool -c %s failed: %s' % (interface, getattr(result, 'stderr', '').strip()))
    text = result.stdout
    adaptive = re.search(r'^Adaptive RX:\s*(on|off)\b', text, re.M)
    usecs = re.search(r'^rx-usecs:\s*(\d+)\s*$', text, re.M)
    if not adaptive or not usecs:
        raise RuntimeError('ethtool -c %s: adaptive RX or rx-usecs not reported' % interface)
    return {'adaptive_rx': adaptive.group(1), 'rx_usecs': int(usecs.group(1)), 'raw': text}


def rx_coalesce_diagnostic(path, interface=PARENT, run=sh):
    """Host diagnostic (Philip, 2026-10-22): record the RX interrupt-moderation baseline once (an existing file means
    an earlier diagnostic was never restored, so the NIC state is not taken as the baseline), then set adaptive RX
    off and rx-usecs 0 -- RX only; TX, offloads, IRQ affinity and CPU power are not touched -- and read back.
    Returns (baseline, effective); raises if the NIC did not take the setting."""
    path = Path(path)
    if path.exists():
        baseline = json.loads(path.read_text())
    else:
        snap = snapshot_rx_coalesce(interface, run=run)
        baseline = {'interface': interface, 'adaptive_rx': snap['adaptive_rx'], 'rx_usecs': snap['rx_usecs'],
                    'raw': snap['raw']}
        path.write_text(json.dumps(baseline, indent=2) + '\n')
    result = run(['ethtool', '-C', interface, 'adaptive-rx', 'off', 'rx-usecs', '0'])
    effective = snapshot_rx_coalesce(interface, run=run)
    if (effective['adaptive_rx'], effective['rx_usecs']) != ('off', 0):
        raise RuntimeError('RX coalescing diagnostic not effective (ethtool -C rc %s): adaptive RX %s, rx-usecs %d'
                           % (getattr(result, 'returncode', None), effective['adaptive_rx'], effective['rx_usecs']))
    return baseline, effective


def restore_rx_coalesce(path, interface=PARENT, run=sh):
    """Re-apply and verify a recorded RX-moderation baseline. No baseline file: the diagnostic was never applied,
    nothing to restore (returns []). The file is removed only after the NIC reads back equal to it."""
    path = Path(path)
    if not path.exists():
        return []
    baseline = json.loads(path.read_text())
    errors = []
    # two writes: i40e rejects rx-usecs in the same ethtool -C call that turns adaptive RX on ("netlink error:
    # Invalid argument", rc01_hw_c25_20261022_04), so the static interval is set first with adaptive off, then the mode
    for args in (['rx-usecs', str(baseline['rx_usecs'])], ['adaptive-rx', baseline['adaptive_rx']]):
        result = run(['ethtool', '-C', interface] + args)
        if getattr(result, 'returncode', 0):
            errors.append('ethtool -C %s rc %s: %s' % (' '.join(args), result.returncode,
                                                       getattr(result, 'stderr', '').strip()))
    try:
        after = snapshot_rx_coalesce(interface, run=run)
    except Exception as error:
        return errors + [str(error)]
    # with adaptive RX on, the driver reports its own rx-usecs; the recorded value is compared all the same
    if (after['adaptive_rx'], after['rx_usecs']) != (baseline['adaptive_rx'], baseline['rx_usecs']):
        errors.append('RX coalescing is adaptive %s rx-usecs %d, baseline adaptive %s rx-usecs %d'
                      % (after['adaptive_rx'], after['rx_usecs'], baseline['adaptive_rx'], baseline['rx_usecs']))
    if not errors:
        path.unlink()
    return errors


CPU_DMA_LATENCY = '/dev/cpu_dma_latency'
CPU_LATENCY_UNCONSTRAINED = 2000000000      # the kernel default (no request): Vision's recorded baseline
# The supervised helper (argv: helper_file, device): holds one signed 32-bit zero request open on the PM QoS device
# until SIGTERM, then closes the descriptor (which withdraws the request) and exits. The marker in its command line
# identifies it, together with its pid and start time.
CPU_LATENCY_HOLD = r"""
import json, os, signal, struct, sys, time  # cpu_latency_hold
fd = os.open(sys.argv[2], os.O_WRONLY)
os.write(fd, struct.pack('i', 0))
def stop(*_):
    os.close(fd)
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
open(sys.argv[1], 'w').write(json.dumps({'pid': os.getpid(), 'holding': True}))
while True:
    time.sleep(3600)
"""


def read_cpu_latency(device=CPU_DMA_LATENCY):
    """The effective PM QoS CPU latency constraint in microseconds (4-byte signed int read from the device)."""
    fd = os.open(device, os.O_RDONLY)
    try:
        raw = os.read(fd, 4)
    finally:
        os.close(fd)
    if len(raw) != 4:
        raise RuntimeError('%s returned %d bytes' % (device, len(raw)))
    return struct.unpack('i', raw)[0]


def cpuidle_usage(root='/sys/devices/system/cpu'):
    """{state name: summed entry count over all CPUs} from cpuidle (read-only). Under a zero latency request the
    deep states (C1E, C6) should not be entered, so their counts should not grow between setup and release."""
    totals = {}
    for usage in sorted(Path(root).glob('cpu[0-9]*/cpuidle/state*/usage')):
        try:
            name = (usage.parent / 'name').read_text().strip()
            totals[name] = totals.get(name, 0) + int(usage.read_text())
        except (OSError, ValueError):
            continue
    return totals


def device_held(device=CPU_DMA_LATENCY):
    """True when any process holds the device open (fuser -s exit 0)."""
    return subprocess.run(['fuser', '-s', device]).returncode == 0


def process_identity(pid):
    """(start time in clock ticks, command line) of a live pid, or None."""
    try:
        stat = Path('/proc/%d/stat' % pid).read_text()
        cmdline = Path('/proc/%d/cmdline' % pid).read_bytes().replace(b'\0', b' ').decode(errors='replace')
    except (OSError, ValueError):
        return None
    fields = stat[stat.rindex(')') + 2:].split()
    if fields[0] == 'Z':
        return None
    return int(fields[19]), cmdline          # field 22 overall = index 19 after "(comm) state"


def _is_helper(state):
    ident = process_identity(state.get('pid', -1)) if isinstance(state.get('pid'), int) else None
    return bool(ident and ident[0] == state.get('start_time') and 'cpu_latency_hold' in ident[1])


def _stop(pid, timeout):
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.time() + timeout
    while time.time() < deadline and process_identity(pid) is not None:
        try:
            os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            pass
        time.sleep(0.05)


def cpu_latency_hold(state_path, device=CPU_DMA_LATENCY, expected_baseline=CPU_LATENCY_UNCONSTRAINED,
                     read=None, held=None, spawn=None, timeout=5.0):
    """Host diagnostic (Philip, 2026-10-22). Refuses unless no diagnostic state exists, the effective constraint is
    the expected baseline and no process holds the device; then starts the supervised zero-request helper, records
    its pid and start time, and verifies the effective constraint reads 0. On ANY failure after the spawn the helper
    is stopped and the state removed before re-raising. Nothing else on the host is changed."""
    read = read or (lambda: read_cpu_latency(device))
    held = held or (lambda: device_held(device))
    state_path = Path(state_path)
    if state_path.exists():
        raise RuntimeError('a CPU-latency diagnostic state already exists at %s: restore first' % state_path)
    baseline = read()
    if expected_baseline is not None and baseline != expected_baseline:
        raise RuntimeError('effective CPU latency %r is not the expected baseline %r' % (baseline, expected_baseline))
    if held():
        raise RuntimeError('another process already holds %s' % device)
    helper_file = Path(str(state_path) + '.helper')
    if helper_file.exists():
        helper_file.unlink()
    spawn = spawn or (lambda: subprocess.Popen([sys.executable, '-c', CPU_LATENCY_HOLD, str(helper_file), device],
                                               start_new_session=True, stdin=subprocess.DEVNULL,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
    proc = spawn()
    try:
        ident = process_identity(proc.pid)
        if ident is None:
            raise RuntimeError('helper %d has no readable identity' % proc.pid)
        state = {'baseline': baseline, 'pid': proc.pid, 'start_time': ident[0],
                 'helper_file': str(helper_file), 'device': device}
        state_path.write_text(json.dumps(state) + '\n')
        deadline = time.time() + timeout
        effective = None
        while time.time() < deadline:
            if helper_file.exists():
                effective = read()
                if effective == 0:
                    state['effective'] = 0
                    state['cpuidle_usage_at_setup'] = cpuidle_usage()
                    state_path.write_text(json.dumps(state) + '\n')
                    return state
            time.sleep(0.05)
        raise RuntimeError('CPU-latency request not effective (effective %r)' % (effective,))
    except BaseException:
        _stop(proc.pid, timeout)
        for path in (state_path, helper_file):
            if path.exists():
                path.unlink()
        raise


def cpu_latency_release(state_path, read=None, timeout=5.0, held=None):
    """Release the diagnostic. Returns (host_errors, evidence). evidence['held_at_release'] is True only when the
    recorded helper (pid + start time + marker) was still running AND the effective constraint read 0 just before
    the release -- otherwise the diagnostic was not in force for the whole block (evidence['diagnostic_valid'] False).
    host_errors (the restoration verdict) are only: the helper still running afterwards, or the effective constraint
    not back at the recorded baseline. A pid that is no longer the helper is never signalled. The state files are
    removed only when the host is verified restored. No state: ([], {'applied': False})."""
    state_path = Path(state_path)
    if not state_path.exists():
        # no recorded diagnostic: the device itself must still be unconstrained and unheld (an orphaned helper from a
        # setup killed before it wrote its state would otherwise survive a restore that exits 0)
        errors = []
        try:
            effective = (read or read_cpu_latency)()
            holder = (held or device_held)()
        except Exception as error:      # noqa: BLE001
            return ['CPU latency unreadable with no diagnostic state: %s' % error], {'applied': False}
        if effective != CPU_LATENCY_UNCONSTRAINED or holder:
            errors.append('no CPU-latency diagnostic state, but effective constraint %r and device held %s'
                          % (effective, holder))
        return errors, {'applied': False, 'effective': effective, 'device_held': holder}
    try:
        state = json.loads(state_path.read_text())
        if not isinstance(state, dict):
            raise ValueError('not an object')
        device = state.get('device', CPU_DMA_LATENCY)
        baseline = state['baseline']
    except (ValueError, KeyError, TypeError) as error:
        stopped = None
        if isinstance(locals().get('state'), dict) and _is_helper(state):       # identity still checkable: stop it
            _stop(state['pid'], timeout)
            stopped = state['pid']
        return ['CPU-latency state unreadable: %s' % error], {'applied': True, 'stopped_helper': stopped}
    read = read or (lambda: read_cpu_latency(device))
    alive = _is_helper(state)
    try:
        effective_before = read()       # a failed read must never prevent the stop below
    except Exception as error:          # noqa: BLE001
        effective_before = 'unreadable: %s' % error
    evidence = {'applied': True, 'helper_alive_at_release': alive, 'effective_before_release': effective_before,
                'held_at_release': alive and effective_before == 0}
    try:
        before, after = state.get('cpuidle_usage_at_setup') or {}, cpuidle_usage()
        evidence['cpuidle_entries_during_hold'] = ({name: after.get(name, 0) - before.get(name, 0)
                                                    for name in sorted(set(before) | set(after))}
                                                   if before and after else 'cpuidle usage not available')
    except Exception as error:          # noqa: BLE001 - informational, never blocks the release
        evidence['cpuidle_entries_during_hold'] = 'unreadable: %s' % error
    evidence['diagnostic_valid'] = evidence['held_at_release']
    if alive:
        _stop(state['pid'], timeout)
    host_errors = []
    if _is_helper(state):
        host_errors.append('helper %d still running after SIGTERM' % state['pid'])
    try:
        effective = read()
    except Exception as error:          # noqa: BLE001 - keep the evidence already collected
        effective = 'unreadable: %s' % error
    evidence['effective_after_release'] = effective
    if effective != baseline:
        host_errors.append('effective CPU latency constraint %r, baseline %r' % (effective, baseline))
    if not host_errors:
        for path in (Path(state.get('helper_file', str(state_path) + '.helper')), state_path):
            if path.exists():
                path.unlink()
    return host_errors, evidence


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
    capture_ready, ready_polls = False, 0
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
        for ready_polls in range(1, CAL_READY_POLLS + 1):
            capture_ready = all(_pcap_header_written(command) for command in commands.values())
            if capture_ready:
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
    result = {'capture_commands': commands, 'tcpdump': stats, 'capture_ready': capture_ready,
              'ready_polls': ready_polls}
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
