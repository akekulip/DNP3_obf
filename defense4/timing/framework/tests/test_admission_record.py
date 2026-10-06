"""The admission record for the candidate, assembled from the committed evidence, must keep saying what is and is not established."""
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "analysis"))
RES = HERE.parent / "results"


@unittest.skipUnless((RES / "master_rto_20261006/master_rto_cand_20261006.json").exists(), "measurement evidence not present")
class Admission(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import admission_record as ar
        cls.ar = ar
        cls.inp = ar.build(18000 * 1711 / 1e6)
        cls.v = ar.da.evaluate(cls.inp)

    def test_verdict_is_provisional_and_names_exactly_what_is_missing(self):
        self.assertEqual(self.v["verdict"], "provisional")
        missing = set()
        for c in self.v["checks"]:
            missing |= set(c.get("missing", []))
        self.assertEqual(missing, {"outstation_feedback_path_ms", "detect_ms", "release_tail_ms"})

    def test_the_master_timer_is_the_measured_one_and_the_cap_holds(self):
        self.assertEqual(self.inp.master_rto_ms.value_ms, 201.0)
        self.assertEqual(self.inp.master_rto_ms.provenance, self.ar.P.MEASURED_THIS_CONNECTION)
        self.assertTrue(self.v["policy_cap"]["ok"])

    def test_a_provisional_verdict_does_not_authorise_the_profile(self):
        sys.path.insert(0, str(HERE.parent / "control"))
        import profiles as pf
        prof = pf.Profile("combined", 10.0, 1.0, connection_id=self.ar.CONN, build_id=self.ar.BUILD)
        self.assertIn("not one of", pf.admission_problem(prof, self.v))

    def test_measured_rto_evidence_is_internally_consistent(self):
        rec = json.loads((RES / "master_rto_20261006/master_rto_cand_20261006.json").read_text())
        self.assertTrue(rec["cleanup_verified"])
        import master_rto_analyze as an
        a = an.analyze(str(RES / "master_rto_20261006/master_rto_cand_20261006.pcap"), rec)
        self.assertAlmostEqual(a["first_repeat_ms"], rec["tcp_info_idle"]["rto_us"] / 1000, delta=10.0)
        self.assertEqual(a["kernel_rto_ms_over_time"][:3], [201.0, 402.0, 804.0])        # the kernel doubles from there


if __name__ == "__main__":
    unittest.main()
