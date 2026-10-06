import json
import struct
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "analysis"))
import master_rto_analyze as an  # noqa: E402
import master_rto_probe as pr    # noqa: E402

OLD = HERE.parents[1] / "audit_current/master_rto_20260916/master_rto.pcap"


class Analysis(unittest.TestCase):
    @unittest.skipUnless(OLD.exists(), "2026-09-16 capture not present")
    def test_reproduces_the_recorded_2026_09_16_repeat_threshold(self):
        a = an.analyze(str(OLD))
        self.assertGreaterEqual(a["transmissions"], 4)
        self.assertAlmostEqual(a["first_repeat_ms"], 200.8, delta=1.0)        # the figure in RESULT.md
        self.assertTrue(all(g > 0 for g in a["gaps_ms"]))

    def test_tcp_info_offsets_parse_a_synthetic_struct(self):
        b = bytearray(232)
        b[0], b[2], b[4] = 1, 2, 3
        struct.pack_into("<I", b, 8, 204000)
        struct.pack_into("<I", b, 68, 350)
        struct.pack_into("<I", b, 72, 120)

        class S:
            def getsockopt(self, *a):
                return bytes(b)
        d = pr.tcp_info(S())
        self.assertEqual((d["state"], d["retransmits"], d["backoff"], d["rto_us"], d["rtt_us"], d["rttvar_us"]), (1, 2, 3, 204000, 350, 120))

    def test_probe_refuses_when_a_stale_rule_exists(self):
        import subprocess
        orig = subprocess.run
        subprocess.run = lambda *a, **k: type("R", (), {"stdout": "-A INPUT -m comment --comment master-rto-probe -j DROP\n", "returncode": 0})()
        try:
            self.assertEqual(pr.main(["/tmp/x.json", "/tmp/x.pcap"]), 2)
        finally:
            subprocess.run = orig


if __name__ == "__main__":
    unittest.main()
