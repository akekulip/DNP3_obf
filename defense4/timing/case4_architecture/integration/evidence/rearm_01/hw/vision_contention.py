#!/usr/bin/env python3
"""Vision-side injector and capture for the ACK/response contention probe. Executed later by the hardware
owner; never run now, and never from a test.

Default is an offline plan: it prints the schedule and the exact capture commands and touches nothing.
`--apply` (requires DEFENSE4_HW_AUTHORIZED=1 and the explicit parent interface) injects every scheduled
frame from one AF_PACKET raw socket and records both capture directions with tcpdump.

Design (directive 2026-10-16). Both the master side and the outstation side of a configured protected
connection are emitted by this one raw socket, so neither side is a real kernel socket: the probe tuple
must use IP addresses that no Vision interface or namespace owns, or an unanswered segment would draw a
kernel RST. This helper refuses to apply if either probe IP is locally assigned -- it will not install a
route, an iptables rule, a namespace, or change any NIC/sysctl setting to suppress a RST; those are out of
scope. The switch control plane must already hold N/E connection rows for the probe tuple (installed by the
candidate campaign from a probe config); this helper neither installs rows nor contacts the switch.

On NIC state: this helper makes no persistent NIC change. The one transient exception is that the capture
command (`tcpdump`) puts the parent NIC into promiscuous mode for the duration of the run and restores it on
exit; nothing else touches the NIC's configuration.

The ACK and the response are spaced by a busy-wait on the monotonic clock, not sleep(), but the recorded
independent variable is the spacing measured in the capture, which `contention_probe.judge` reads.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

INTERFACE = 'enp59s0f0np0'                       # Vision parent NIC, external switch dev 9


def local_addresses():
    """Every IPv4 address assigned on the host and in every listed namespace, so a probe IP can be checked
    unowned. Fails CLOSED (M2): if the host-namespace query, the namespace listing, or any listed namespace's
    address query fails, raise -- a silently skipped namespace could own a probe IP and draw a kernel RST."""
    found = set()
    namespaces = ['']
    listing = subprocess.run(['ip', '-j', 'netns', 'list'], capture_output=True, text=True)
    if listing.returncode:
        raise RuntimeError('cannot list namespaces (ip netns list rc=%d): %s'
                           % (listing.returncode, (listing.stderr or '').strip()))
    if listing.stdout.strip():
        try:
            namespaces += [row['name'] for row in json.loads(listing.stdout)]
        except (ValueError, KeyError) as error:
            raise RuntimeError('cannot parse namespace listing: %s' % error)
    for namespace in namespaces:
        prefix = ['ip', 'netns', 'exec', namespace] if namespace else []
        result = subprocess.run(prefix + ['ip', '-j', 'address', 'show'], capture_output=True, text=True)
        if result.returncode:
            where = 'namespace %s' % namespace if namespace else 'the host namespace'
            raise RuntimeError('cannot read addresses in %s (rc=%d): %s'
                               % (where, result.returncode, (result.stderr or '').strip()))
        if not result.stdout.strip():
            continue
        for row in json.loads(result.stdout):
            for addr in row.get('addr_info', []):
                if addr.get('family') == 'inet':
                    found.add(addr.get('local'))
    return found


def guard(plan, interface, apply):
    master_ip, outstation_ip = plan['tuple'][0], plan['tuple'][1]
    if apply:
        if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
            raise ValueError('--apply requires DEFENSE4_HW_AUTHORIZED=1')
        if interface != INTERFACE:
            raise ValueError('--apply requires the explicit parent interface %s' % INTERFACE)
        owned = local_addresses()
        clash = owned & {master_ip, outstation_ip}
        if clash:
            raise ValueError('probe IP(s) %s are locally assigned; a kernel would RST. Use a synthetic '
                             'tuple no interface/namespace owns (this helper will not add a route, iptables '
                             'rule or namespace to suppress a RST).' % ', '.join(sorted(clash)))


def validate_schedule(plan):
    """M3: parse every scheduled frame before anything is sent and refuse the whole run if any frame is not
    IPv4/TCP, is not exactly the probe tuple in one direction, or is not addressed to the configured next
    hop. An open raw socket will send whatever bytes it is handed, so this is the only check that a mangled
    schedule cannot put an unexpected frame on the wire."""
    master_ip, outstation_ip, master_port, outstation_port = plan['tuple']
    forward = (master_ip, outstation_ip, master_port, outstation_port)
    reverse = (outstation_ip, master_ip, outstation_port, master_port)
    next_hop = plan.get('next_hop_mac')
    if not next_hop:
        raise ValueError('plan has no next_hop_mac; cannot verify the frames are sent to the configured next hop')
    expected_dst = bytes(int(b, 16) for b in next_hop.split(':'))
    for event in plan['schedule']:
        frame = bytes.fromhex(event['bytes'])
        where = '%s/%s' % (event.get('tag'), event.get('frame'))
        if len(frame) < 34 or frame[12:14] != b'\x08\x00':
            raise ValueError('scheduled frame %s is not IPv4' % where)
        if frame[:6] != expected_dst:
            raise ValueError('scheduled frame %s destination MAC %s != next hop %s'
                             % (where, ':'.join('%02x' % b for b in frame[:6]), next_hop))
        ihl = (frame[14] & 0x0f) * 4
        if frame[14 + 9] != 6:
            raise ValueError('scheduled frame %s is not TCP' % where)
        tcp_off = 14 + ihl
        src = '.'.join(str(b) for b in frame[26:30])
        dst = '.'.join(str(b) for b in frame[30:34])
        sport = int.from_bytes(frame[tcp_off:tcp_off + 2], 'big')
        dport = int.from_bytes(frame[tcp_off + 2:tcp_off + 4], 'big')
        if (src, dst, sport, dport) not in (forward, reverse):
            raise ValueError('scheduled frame %s tuple %s is not the probe tuple in either direction'
                             % (where, (src, dst, sport, dport)))


def capture_commands(run_dir, master_ip, outstation_ip):
    flt = 'tcp and host %s and host %s' % (master_ip, outstation_ip)
    return {d: ['tcpdump', '-i', INTERFACE, '--immediate-mode', '-Q', d, '-s0', '-U', '-n',
                '-w', str(Path(run_dir) / (d + '.pcap')), flt] for d in ('out', 'in')}


def inject(schedule, interface):
    """Send every scheduled frame from one AF_PACKET raw socket, busy-waiting to each target offset."""
    import socket
    events = sorted(schedule, key=lambda e: e['t_ns'])
    base_ns = events[0]['t_ns']
    sent = 0
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as raw:
        raw.bind((interface, 0))
        t0 = time.monotonic_ns()
        for event in events:
            target = t0 + (event['t_ns'] - base_ns)
            while time.monotonic_ns() < target:        # busy-wait: microsecond spacing, not sleep()
                pass
            buf = bytes.fromhex(event['bytes'])
            if raw.send(buf) != len(buf):
                raise OSError('short raw frame send for ' + event['tag'] + '/' + event['frame'])
            sent += 1
    return sent


def run(args):
    plan = json.loads(Path(args.plan).read_text())
    validate_schedule(plan)
    if args.apply and args.interface is None:
        raise ValueError('--apply requires an explicit --interface (no default is assumed when sending)')
    interface = args.interface if args.interface is not None else INTERFACE
    guard(plan, interface, args.apply)
    master_ip, outstation_ip = plan['tuple'][0], plan['tuple'][1]
    record = dict(interface=interface, applied=False, tuple=plan['tuple'], events=len(plan['schedule']),
                  capture_commands=capture_commands(args.run_dir, master_ip, outstation_ip))
    if not args.apply:
        record['note'] = 'offline plan only; nothing was sent or captured'
        print(json.dumps(record, indent=2))
        return 0
    run_dir = Path(args.run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    captures = {}
    try:
        for d, command in record['capture_commands'].items():
            captures[d] = subprocess.Popen(command, stderr=subprocess.PIPE, text=True)
        time.sleep(2.0)
        for d, proc in captures.items():
            if proc.poll() is not None:
                raise RuntimeError('tcpdump -Q %s exited early: %s' % (d, (proc.stderr.read() or '').strip()))
        record['sent'] = inject(plan['schedule'], interface)
        time.sleep(1.0)
        record['applied'] = True
    finally:
        for proc in captures.values():
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
    (run_dir / 'inject.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, help='plan JSON from contention_probe.py plan')
    parser.add_argument('--run-dir', required=True)
    parser.add_argument('--interface', default=None,
                        help='parent NIC; REQUIRED with --apply (offline plan prints for %s by default)' % INTERFACE)
    parser.add_argument('--apply', action='store_true')
    return run(parser.parse_args(argv))


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError, RuntimeError) as error:
        sys.stderr.write('contention injector refused: %s\n' % error)
        sys.exit(2)
