"""wire_check pairs returned to sent segments robustly under loss, reordering and duplication, and never
samples latency from an unmatched pair. Synthetic pcap pair, no scapy.

The returned (switch) side translates the outstation->master sequence space by a constant +100 and the
master->outstation ack space by +100, so a correct pairing cannot rely on raw sequence equality."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))
import pcaptk as tk  # noqa: E402
import wire_check as wc  # noqa: E402

M, O = '192.168.10.61', '192.168.10.62'
SYN, ACK, PSH = tk.SYN, tk.ACK, tk.PSH


def build(tmp):
    req, resp = tk.read_request(0), tk.read_response(0)   # 20-byte request, 49-byte response
    out = [
        (0,     tk.frame(M, O, 40000, 20000, 1000, 0,    SYN,       ip_id=1)),
        (200,   tk.frame(O, M, 20000, 40000, 5000, 1001, SYN | ACK, ip_id=2)),
        (400,   tk.frame(M, O, 40000, 20000, 1001, 5001, ACK,       ip_id=3)),
        (1000,  tk.frame(M, O, 40000, 20000, 1001, 5001, PSH | ACK, req, ip_id=4, offload=True)),
        (1200,  tk.frame(O, M, 20000, 40000, 5001, 1021, ACK,       ip_id=5)),        # relay ACK: DROPPED on return
        (26000, tk.frame(O, M, 20000, 40000, 5001, 1021, PSH | ACK, resp, ip_id=6)),  # response
        (26200, tk.frame(M, O, 40000, 20000, 1021, 5050, ACK,       ip_id=7, offload=True)),
    ]
    # returned: +50us reflect latency; O->M seq +100, M->O ack +100; relay ACK dropped; response duplicated;
    # request's reflection reordered to arrive (in capture time) after the master ACK's reflection.
    ret = [
        (50,    tk.frame(M, O, 40000, 20000, 1000, 0,    SYN,       ip_id=1)),
        (250,   tk.frame(O, M, 20000, 40000, 5100, 1001, SYN | ACK, ip_id=2)),
        (450,   tk.frame(M, O, 40000, 20000, 1001, 5101, ACK,       ip_id=3)),
        (26050, tk.frame(O, M, 20000, 40000, 5101, 1021, PSH | ACK, resp, ip_id=6)),  # response
        (26060, tk.frame(O, M, 20000, 40000, 5101, 1021, PSH | ACK, resp, ip_id=60)),  # DUPLICATE response
        (26100, tk.frame(M, O, 40000, 20000, 1021, 5150, ACK,       ip_id=7)),        # master ACK
        (30000, tk.frame(M, O, 40000, 20000, 1001, 5101, PSH | ACK, req, ip_id=4, offload=True)),  # REORDERED request
    ]
    op, ip = os.path.join(tmp, 'out.pcap'), os.path.join(tmp, 'in.pcap')
    tk.write_pcap(op, out)
    tk.write_pcap(ip, ret)
    return op, ip


class WireCheck(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.out, self.in_ = build(self.tmp)
        self.rep = wc.analyze(self.out, self.in_)

    def test_drop_is_an_unmatched_sent_not_a_silent_truncation(self):
        self.assertEqual(len(self.rep['unmatched_sent']), 1)
        lost = self.rep['unmatched_sent'][0]
        self.assertEqual((lost['dir'], lost['flags'], lost['len']), ('O->M', ACK, 0))

    def test_reorder_still_pairs_every_other_frame(self):
        # 7 sent, one dropped -> 6 real reflections pair; the duplicate does not count as a match
        self.assertEqual(self.rep['matched'], 6)
        self.assertTrue(self.rep['reordered_returned_indices'], 'the time-reordered request must be flagged')

    def test_duplicate_is_its_own_category(self):
        self.assertEqual(len(self.rep['duplicate_returned']), 1)
        self.assertEqual(self.rep['duplicate_returned'][0]['len'], 49)
        self.assertEqual(self.rep['unmatched_returned'], [])

    def test_no_latency_from_unmatched(self):
        matched = [v for v in self.rep['reference_mapping'].values() if v is not None]
        self.assertEqual(len(matched), self.rep['matched'])
        self.assertIsNotNone(self.rep['reflect latency us min/median/max'])
        # the dropped sent segment (index 4) is referenced by no returned packet
        self.assertNotIn(4, self.rep['reference_mapping'].values())

    def test_translation_is_recovered_not_a_mismatch(self):
        self.assertEqual(self.rep['O->M seq delta set'], [100])
        self.assertEqual(self.rep['M->O ack delta set'], [100])

    def test_offloaded_sent_is_not_called_corrupt(self):
        si = self.rep['sent_integrity']
        self.assertEqual(si['tcp_checksum_bad'], 'not validated (sender capture)')
        self.assertEqual(sorted(si['tcp_checksum_offloaded']), [3, 6])   # the request and master ACK
        self.assertEqual(self.rep['returned_integrity']['tcp_checksum_bad'], [])
        self.assertEqual(self.rep['returned_integrity']['dnp3_crc_bad'], [])


class SpuriousReturned(unittest.TestCase):
    def test_spurious_returned_frame_is_flagged_and_exits_nonzero(self):
        tmp = tempfile.mkdtemp()
        out = [(0, tk.frame(M, O, 1, 20000, 1000, 0, SYN, ip_id=1))]
        ret = [(50, tk.frame(M, O, 1, 20000, 1000, 0, SYN, ip_id=1)),
               (60, tk.frame(O, M, 20000, 1, 9999, 1, PSH | ACK, tk.read_response(0), ip_id=9))]
        op, ipth = os.path.join(tmp, 'out.pcap'), os.path.join(tmp, 'in.pcap')
        tk.write_pcap(op, out)
        tk.write_pcap(ipth, ret)
        rep = wc.analyze(op, ipth)
        self.assertEqual(len(rep['unmatched_returned']), 1)
        r = subprocess.run([sys.executable, str(HERE.parent / 'wire_check.py'), op, ipth],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, r.stdout)


if __name__ == '__main__':
    unittest.main()
