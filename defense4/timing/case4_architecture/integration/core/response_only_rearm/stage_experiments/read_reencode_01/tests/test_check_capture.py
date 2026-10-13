"""check_capture.py: the IEEE verifier for hardware captures, on the retained candidate56r run (negative)
and on synthetic runs built from that run's native frames (positive, and a misplaced octet)."""
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.dont_write_bytecode = True
sys.path[:0] = [str(HERE), str(HERE.parents[5] / 'case4_architecture/protocol/hw_vepa/tests')]
import capture  # noqa: E402
import check_capture  # noqa: E402
import pcaptk as tk  # noqa: E402
import reencode  # noqa: E402
from test_standards import RUN, directed  # noqa: E402

M, O, MP, OP = '192.168.10.61', '192.168.10.62', 59440, 20000


def synthetic(tmp, transform):
    """out.pcap = the retained native exchange; in.pcap = the same with each response passed through
    transform(i, frame). Requests and responses alternate, as in the retained run."""
    reqs = directed(RUN / 'out.pcap', MP, OP)
    rsps = directed(RUN / 'out.pcap', OP, MP)
    out, inn = [], []
    for side, conv in ((out, lambda i, f: f), (inn, transform)):
        sseq, rseq, t = 1000, 5000, 0
        for i, (q, r) in enumerate(zip(reqs, rsps)):
            r = conv(i, r)
            side.append((t, tk.frame(M, O, MP, OP, sseq, rseq, tk.PSH | tk.ACK, q)))
            sseq += len(q)
            side.append((t + 100, tk.frame(O, M, OP, MP, rseq, sseq, tk.PSH | tk.ACK, r)))
            rseq += len(r)
            t += 1000
    tk.write_pcap(str(Path(tmp) / 'out.pcap'), out)
    tk.write_pcap(str(Path(tmp) / 'in.pcap'), inn)
    return tmp


@unittest.skipUnless((RUN / 'out.pcap').exists(), 'retained candidate56r capture absent')
class CheckCapture(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = td.name

    def test_retained_all58_run_is_flagged(self):
        res = check_capture.check(RUN)
        kinds = [v['kind'] for v in res['verdicts'] if not v['ok']]
        self.assertEqual(kinds, ['READ'] * 20 + ['SELECT', 'OPERATE'])
        self.assertFalse(res['conformant'])

    def test_reencoded_reads_and_native_controls_pass(self):
        run = synthetic(self.tmp, lambda i, f: reencode.reencode_frame(f) or f)
        res = check_capture.check(run)
        self.assertEqual(res['failures'], [])
        self.assertEqual([v['wire_len'] for v in res['verdicts']], [58] * 20 + [37, 37])
        self.assertEqual([v['kind'] for v in res['verdicts']], ['READ'] * 20 + ['SELECT', 'OPERATE'])

    def test_misplaced_status_octet_fails(self):
        def bad(i, f):
            enc = reencode.reencode_frame(f)
            if i != 3 or enc is None:
                return enc or f
            import dnp3_std as std
            h, u = std.deframe(enc)
            u = bytearray(u)
            u[12] ^= 0x80                       # P0's state bit
            return std.frame(h, bytes(u))
        res = check_capture.check(synthetic(self.tmp, bad))
        self.assertEqual([v['index'] for v in res['verdicts'] if not v['ok']], [3])


if __name__ == '__main__':
    unittest.main()
