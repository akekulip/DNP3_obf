"""Deterministic synthetic tests for vision_candidate.overtaken_handshake_acks (review 6.2).

The real-capture tests (test_overtaken_ack.py) prove the positive case on the c28 run. These build small
synthetic pcaps to prove the tightened binding refuses the cases the earlier form wrongly excused:
  * a following segment that is NOT a DNP3 READ,
  * the overtaking READ not returned by the switch,
  * a matching READ returned on a DIFFERENT connection (flow), not this incarnation.
No hardware, no socket.
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

HW = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HW))
sys.path.insert(0, str(HW.parents[3] / 'protocol/hw_vepa'))
sys.path.insert(0, str(HW.parents[3] / 'protocol/hw_vepa/tests'))
import pcaptk as tk            # noqa: E402
import read_classes as rc      # noqa: E402
import vision_candidate as vc  # noqa: E402

M, O = vc.MASTER, vc.OUTSTATION
SYN, ACK, PSH, FIN = tk.SYN, tk.ACK, tk.PSH, tk.FIN


def _crc(data):
    c = 0
    for b in data:
        c ^= b
        for _ in range(8):
            c = (c >> 1) ^ 0xA6BC if c & 1 else c >> 1
    return bytes([(~c) & 0xFF, ((~c) >> 8) & 0xFF])


def mixed_read_payload(seq=0):
    """A DNP3 link frame carrying the mixed READ (G1V2 0..15 + G30V1 0..7); classify_request_frames -> 'mixed'."""
    app = bytes([0xC0, 0xC0 | (seq & 0x0F), 0x01, 0x01, 0x02, 0x00, 0, 15, 0x1E, 0x01, 0x00, 0, 7])
    hdr = bytes([0x05, 0x64, 5 + len(app), 0xC4, 0x00, 0x00, 0x01, 0x00])
    out = bytearray(hdr + _crc(hdr))
    for i in range(0, len(app), 16):
        blk = app[i:i + 16]
        out += blk + _crc(blk)
    return bytes(out)


def flow(sport, read_payload, *, return_read=True, return_flow_sport=None):
    """Build (out, in) record lists for one connection: SYN/SYN-ACK/pure-ACK then the overtaking READ.
    The pure ACK (index 2) is the unmatched candidate; the READ (index 3) is returned unless return_read is False.
    return_flow_sport lets the returned READ appear on a different flow (wrong incarnation binding)."""
    rsport = return_flow_sport or sport
    out = [
        (0,    tk.frame(M, O, sport, 20000, 1000, 0,    SYN)),
        (200,  tk.frame(O, M, 20000, sport, 5000, 1001, SYN | ACK)),
        (400,  tk.frame(M, O, sport, 20000, 1001, 5001, ACK)),                          # idx2: pure ACK (overtaken)
        (410,  tk.frame(M, O, sport, 20000, 1001, 5001, PSH | ACK, read_payload)),      # idx3: overtaking READ
    ]
    ret = [
        (50,   tk.frame(M, O, sport, 20000, 1000, 0,    SYN)),
        (250,  tk.frame(O, M, 20000, sport, 5000, 1001, SYN | ACK)),
    ]
    if return_read:
        ret.append((460, tk.frame(M, O, rsport, 20000, 1001, 5001, PSH | ACK, read_payload)))
    return out, ret


def run(out, ret):
    with tempfile.TemporaryDirectory() as t:
        op, ip = os.path.join(t, 'out.pcap'), os.path.join(t, 'in.pcap')
        tk.write_pcap(op, out)
        tk.write_pcap(ip, ret)
        unmatched = [{'sent_index': 2, 'dir': 'M->O', 'flags': ACK, 'len': 0}]
        return vc.overtaken_handshake_acks(op, ip, unmatched)


class OvertakenAckBinding(unittest.TestCase):
    def test_payload_classifies_as_read(self):
        self.assertEqual(rc.classify_request_frames(mixed_read_payload()), 'mixed')

    def test_genuine_overtake_is_excused(self):
        excused, remaining = run(*flow(40000, mixed_read_payload()))
        self.assertEqual([e['sent_index'] for e in excused], [2])
        self.assertEqual(excused[0]['read_class'], 'mixed')
        self.assertEqual(remaining, [])

    def test_following_not_a_read_is_not_excused(self):
        excused, remaining = run(*flow(40000, b'not-a-dnp3-read-payload'))
        self.assertEqual(excused, [])
        self.assertEqual([r['sent_index'] for r in remaining], [2])

    def test_read_not_returned_is_not_excused(self):
        excused, remaining = run(*flow(40000, mixed_read_payload(), return_read=False))
        self.assertEqual(excused, [])
        self.assertEqual([r['sent_index'] for r in remaining], [2])

    def test_read_returned_on_a_different_flow_is_not_excused(self):
        # the matching READ comes back on another connection (different source port) -- not this incarnation
        excused, remaining = run(*flow(40000, mixed_read_payload(), return_flow_sport=40001))
        self.assertEqual(excused, [])
        self.assertEqual([r['sent_index'] for r in remaining], [2])


if __name__ == '__main__':
    unittest.main(verbosity=2)
