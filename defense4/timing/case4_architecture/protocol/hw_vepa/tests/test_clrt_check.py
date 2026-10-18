"""clrt_check associates each logical request with its covering ACK and its application-sequence-matched
response, keeps a TCP retransmission as an attempt (not a new request), reports incomplete and piggyback
exchanges, and verifies DNP3 CRCs. Synthetic exchange, no scapy."""
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
import clrt_check as cc  # noqa: E402

M, O = '192.168.10.61', '192.168.10.62'
SP, DP = 40000, 20000
SYN, ACK, PSH = tk.SYN, tk.ACK, tk.PSH


def mreq(t, seq, ack, app_seq):
    return (t, tk.frame(M, O, SP, DP, seq, ack, PSH | ACK, tk.read_request(app_seq), offload=True))


def build(tmp, corrupt_resp0=False):
    resp0 = tk.read_response(0)
    if corrupt_resp0:
        resp0 = bytearray(resp0)
        resp0[20] ^= 1          # flip a data byte; its block CRC no longer matches
        resp0 = bytes(resp0)
    out = [
        (0,       tk.frame(M, O, SP, DP, 1000, 0, SYN)),
        mreq(1000,    1001, 5001, 0),
        mreq(1300,    1001, 5001, 0),                    # TCP retransmission of READ0 (same seq/bytes)
        (26200,   tk.frame(M, O, SP, DP, 1021, 5050, ACK)),
        mreq(1000000, 1021, 5050, 1),                    # READ1
        mreq(2000000, 1041, 5099, 2),                    # READ2 -> no response (incomplete)
        mreq(3000000, 1061, 5148, 3),                    # READ3 -> piggyback (no separate ACK)
    ]
    inp = [
        (1550,    tk.frame(O, M, DP, SP, 5001, 1021, ACK)),                       # READ0 relay ACK
        (26050,   tk.frame(O, M, DP, SP, 5001, 1021, PSH | ACK, resp0)),          # READ0 response
        (1000250, tk.frame(O, M, DP, SP, 5050, 1041, ACK)),                       # READ1 relay ACK
        (1025050, tk.frame(O, M, DP, SP, 5050, 1041, PSH | ACK, tk.read_response(1))),  # READ1 response
        (3025000, tk.frame(O, M, DP, SP, 5099, 1081, PSH | ACK, tk.read_response(3))),  # READ3 piggyback response
    ]
    op, ip = os.path.join(tmp, 'out.pcap'), os.path.join(tmp, 'in.pcap')
    tk.write_pcap(op, out)
    tk.write_pcap(ip, inp)
    return op, ip


class ClrtCheck(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = td.name
        self.out, self.in_ = build(self.tmp)
        self.rep = cc.analyze(self.out, self.in_)
        self.read = self.rep['summary']['READ']

    def test_retransmission_is_an_attempt_not_a_new_request(self):
        self.assertEqual(self.read['logical_requests'], 4)   # 5 request segments, 4 logical requests
        self.assertEqual(self.read['attempts'], 5)
        self.assertEqual(self.read['retransmitted'], 1)

    def test_exchange_identity_and_capture_provenance_survive_extraction(self):
        rows = self.rep['exchanges']
        self.assertEqual(len({row['exchange_id'] for row in rows}), 4)
        self.assertEqual(rows[0]['attempts'], 2)
        self.assertEqual(rows[0]['request_key']['seq'], 1001)
        self.assertIsInstance(rows[0]['request_packet_index'], int)
        self.assertIsInstance(rows[0]['response_packet_index'], int)
        self.assertEqual(len(self.rep['capture_sha256']['out']), 64)
        self.assertEqual(len(self.rep['capture_sha256']['in']), 64)
        self.assertEqual(len(self.rep['extractor_sha256']), 64)

    def test_incomplete_and_piggyback_are_distinguished_and_counted(self):
        self.assertEqual(self.read['complete'], 3)
        self.assertEqual(self.read['incomplete'], 1)         # READ2, failed, still reported
        self.assertEqual(self.read['piggyback'], 1)          # READ3

    def test_latency_subset_is_declared_and_excludes_retx_and_piggyback(self):
        # eligible = complete, single-attempt, non-piggyback -> only READ1
        self.assertEqual(self.read['eligible_for_latency'], 1)
        self.assertEqual(self.read['clrt_us']['n'], 1)
        self.assertEqual(self.read['clrt_us']['median'], 24800)   # 1025050 - 1000250

    def test_application_sequence_association_picks_the_right_response(self):
        read1 = [r for r in self.rep['exchanges'] if r['app_seq'] == 1][0]
        self.assertTrue(read1['complete'])
        self.assertEqual(read1['rt_us'], 25050)                   # 1025050 - 1000000
        self.assertEqual(read1['clrt_us'], 24800)

    def test_timestamps_are_integers(self):
        for r in self.rep['exchanges']:
            for k in ('t_req', 'ack_lat_us', 'clrt_us', 'rt_us'):
                if r.get(k) is not None:
                    self.assertIsInstance(r[k], int, k)

    def test_crcs_clean_on_the_good_capture(self):
        self.assertEqual(self.read['req_crc_bad'], 0)
        self.assertEqual(self.read['resp_crc_bad'], 0)


class SdConvention(unittest.TestCase):
    """The SD convention is explicit in the output: both population (divide by n) and sample (n-1) values are
    reported under unambiguous keys, and the report names the convention. A bare `sd` key is ambiguous."""
    def test_stats_reports_both_conventions_and_no_bare_sd(self):
        s = cc.stats([2, 4, 4, 4, 5, 5, 7, 9])          # classic: population SD exactly 2.0
        self.assertEqual(s['sd_population'], 2.0)
        self.assertEqual(s['sd_sample'], 2.1)           # 2.138 at the report's 0.1 us rounding
        self.assertNotIn('sd', s)

    def test_single_value_has_zero_sd(self):
        s = cc.stats([7])
        self.assertEqual((s['sd_population'], s['sd_sample']), (0.0, 0.0))

    def test_report_declares_the_convention(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        rep = cc.analyze(*build(td.name))
        self.assertIn('population', rep['sd_convention'])
        self.assertIn('sample', rep['sd_convention'])


class CrcFailure(unittest.TestCase):
    def test_bad_response_crc_is_reported_and_exits_nonzero(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        tmp = td.name
        op, ip = build(tmp, corrupt_resp0=True)
        rep = cc.analyze(op, ip)
        self.assertEqual(rep['summary']['READ']['resp_crc_bad'], 1)
        r = subprocess.run([sys.executable, str(HERE.parent / 'clrt_check.py'), op, ip],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, r.stdout)


if __name__ == '__main__':
    unittest.main()
