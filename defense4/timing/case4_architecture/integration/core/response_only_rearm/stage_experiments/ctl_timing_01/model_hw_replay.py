"""Diagnostic: replay the exact physical rc01_hw_c51_20261024_09 smoke frames through the model.

On silicon the master's first READ after a completed handshake never reached the relay
(port 64 TX: SYN and ACK only) and N ended in owner phase 5. This replays the captured
SYN, relay SYN-ACK, final ACK and READ bytes on the hardware tuple (master port 60000)
and records what N forwards plus its state after each frame. Model only; NOT a
qualification driver.
"""
import hashlib
import json
import os
import struct
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'seg61_02'))
import model_packets as mp

# Captured on the master NIC (out.pcap / in.pcap of the trial below); the SYN-ACK is the
# relay's frame as delivered to the master by the switch (forwarded unchanged).
TRIAL = ('read_complete_01/evidence/hw_blocks/rc01_hw_c51_20261024_09_smoke/physical_relay/size_only/'
         'rc01_hw_c51_20261024_09_smoke_physical_relay_size_only_t0')
FRAMES = (
    ('SYN', 'master', '0030a7024ca23cfdfecc5dc008004500003ce4c440004006c09ec0a80a01c0a80a07ea604e20035e80d7'
                      '00000000a002faf095870000020405b40402080a3bfb0d070000000001030307'),
    ('SYNACK', 'relay', '3cfdfecc5dc00030a7024ca2080045000040095d00004006dc02c0a80a07c0a80a014e20ea6016317a27'
                        '035e80d8b01221f090de0000020405b401030300010104020101080a4e3709803bfb0d07'),
    ('ACK', 'master', '0030a7024ca23cfdfecc5dc0080045000034e4c540004006c0a5c0a80a01c0a80a07ea604e20035e80d8'
                      '16317a28801001f6957f00000101080a3bfb0d124e370980'),
    ('READ', 'master', '0030a7024ca23cfdfecc5dc008004500004de4c640004006c08bc0a80a01c0a80a07ea604e20035e80d8'
                       '16317a28801801f6959800000101080a3bfb0d124e370980056412c400000100d0bbc0c001010200000f1e01000007fb5c'),
)

# The master's actual retransmissions (out.pcap frames 3 and 4): new IP ID and TSval, same segment.
RETRANSMISSIONS = (
    '0030a7024ca23cfdfecc5dc008004500004de4c740004006c08ac0a80a01c0a80a07ea604e20035e80d816317a28801801f6'
    '959800000101080a3bfb0deb4e370980056412c400000100d0bbc0c001010200000f1e01000007fb5c',
    '0030a7024ca23cfdfecc5dc008004500004de4c840004006c089c0a80a01c0a80a07ea604e20035e80d816317a28801801f6'
    '959800000101080a3bfb0ec34e370980056412c400000100d0bbc0c001010200000f1e01000007fb5c',
)


def wire_checksum(frame):
    """The master NIC offloads TX checksums: its TX capture holds only the pseudo-header partial sum.
    Return the frame with the TCP checksum the NIC put on the wire."""
    frame = bytearray(frame)
    ihl = (frame[14] & 15) * 4
    end = 14 + int.from_bytes(frame[16:18], 'big')
    tcp = 14 + ihl
    frame[tcp + 16:tcp + 18] = b'\0\0'
    data = bytes(frame[26:34]) + struct.pack('!BBH', 0, 6, end - tcp) + bytes(frame[tcp:end])
    data += b'\0' * (len(data) & 1)
    value = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while value >> 16:
        value = (value & 0xffff) + (value >> 16)
    frame[tcp + 16:tcp + 18] = struct.pack('!H', ~value & 0xffff)
    return bytes(frame)


def main():
    h = mp.load('_hw_replay_helpers', HERE.parents[2] / 'response_only/model_drive_composite.py')
    cp = mp.load('_hw_replay_cp', HERE.parents[1] / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False, qualification_driver=False,
                      scope='diagnostic: exact silicon smoke frames replayed on the model', source_trial=TRIAL,
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    try:
        gate = mp.PacketGate(report, h.Model(ports=[], enable=False), h, cp)
        gate.master = h.rp.Endpoint('192.168.10.1', 60000, 9)   # the hardware tuple
        gate.configure()
        states = report.record['meta']['n_state'] = {}
        # HW_REPLAY_TIGHT=1: send the final ACK and the READ back to back as on silicon (READ 0.575 ms
        # after the ACK), then the master's first retransmission; record N's busy counters.
        tight = os.environ.get('HW_REPLAY_TIGHT') == '1'
        report.record['meta']['tight'] = tight
        for name, side, frame in (FRAMES[:2] if tight else FRAMES):
            captured = bytes.fromhex(frame)
            sent = wire_checksum(captured) if side == 'master' else captured
            report.record['meta'].setdefault('checksum_restored', {})[name] = captured != sent
            port = gate.master.dev_port if side == 'master' else gate.relay.dev_port
            got = gate.m.exchange(port, sent, gate.ports, timeout=3, quiet=.3)
            states[name] = gate.n_state()
            forward = gate.relay.dev_port if side == 'master' else gate.master.dev_port
            report.add('replay_%s_forwarded' % name, 1, len(got.get(forward, [])),
                       sent=sent, received={str(p): fs for p, fs in got.items()})
        if tight:
            ack, read = (wire_checksum(bytes.fromhex(f)) for _n, _s, f in FRAMES[2:])
            gate.m.drain(gate.ports)
            gate.m.send(gate.master.dev_port, ack)
            gate.m.send(gate.master.dev_port, read)
            got = gate.m.capture(gate.ports, timeout=3, quiet=.5)
            states['tight_ACK_READ'] = gate.n_state()
            relay = got.get(gate.relay.dev_port, [])
            report.add('tight_ACK_then_READ_forwarded', 2, len(relay), received={str(p): fs for p, fs in got.items()})
            for index, retx in enumerate(RETRANSMISSIONS, 1):
                got = gate.m.exchange(gate.master.dev_port, wire_checksum(bytes.fromhex(retx)), gate.ports,
                                      timeout=3, quiet=.5)
                states['tight_READ_retransmission_%d' % index] = gate.n_state()
                report.add('tight_READ_retransmission_%d_forwarded' % index, 1, len(got.get(gate.relay.dev_port, [])),
                           received={str(p): fs for p, fs in got.items()})
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    return 0 if report.finish(out / 'hw_replay_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())
