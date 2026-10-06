"""The admission record for the candidate, assembled from the committed evidence, must keep saying what is and is not established."""
import json
import sys
import tempfile
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
        cls.inp = ar.build(10)
        cls.v = ar.da.evaluate(cls.inp)

    def test_verdict_is_provisional_and_names_exactly_what_is_missing(self):
        self.assertEqual(self.v["verdict"], "provisional")
        missing = set()
        for c in self.v["checks"]:
            missing |= set(c.get("missing", []))
        self.assertEqual(missing, {"master_feedback_path_ms", "outstation_feedback_path_ms", "ack_latency_bound_ms",
                                   "detect_ms", "release_tail_ms", "ack_hold_ms", "response_hold_ms", "recovery_hold_bound_ms"})

    def test_historical_master_timer_does_not_authorise_current_recovery_cap(self):
        self.assertEqual(self.inp.master_rto_ms.value_ms, 201.0)
        self.assertEqual(self.inp.master_rto_ms.provenance, self.ar.P.INHERITED_EARLIER_BUILD)
        self.assertIsNone(self.v["policy_cap"]["ok"])
        self.assertIsNone(self.v["recovery_hold_bound_ms"])

    def test_control_record_exports_distinct_unavailable_retention_budget(self):
        inp = self.ar.build(10, operation='SBO', operation_profile_sha256='a' * 64)
        verdict = self.ar.da.evaluate(inp)
        self.assertEqual(verdict['policy']['context']['operation'], 'SBO')
        self.assertEqual(verdict['verdict'], 'provisional')
        self.assertIn('sbo_budget_ms', verdict['unknown_inputs'])
        self.assertIn('sbo_native_cycle_ms', verdict['unknown_inputs'])
        self.assertIn('sbo_operate_added_ms', verdict['unknown_inputs'])
        self.assertIsNone(inp.sbo.budget_ms.value_ms)

    def test_record_output_refuses_overwriting_retained_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'admission.json'
            self.ar.write_record(path,self.v)
            original=path.read_bytes()
            with self.assertRaises(FileExistsError):self.ar.write_record(path,{'verdict':'other'})
            self.assertEqual(path.read_bytes(),original)

    def test_internal_observation_import_does_not_fill_physical_bounds(self):
        from test_observations import IDENTITY,sample
        import copy
        import hashlib
        baseline=self.ar.da.evaluate(self.ar.build(10,operation='SBO',operation_profile_sha256='d'*64))
        verdict=copy.deepcopy(baseline)
        identity=dict(IDENTITY,source_sha256=hashlib.sha256(self.ar.SOURCE.read_bytes()).hexdigest(),
            build_id=self.ar.BUILD,connection_id=self.ar.CONN,operation_profile_sha256='d'*64)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'observations.json'
            path.write_text(json.dumps(dict(version=1,identity=identity,observed_at='2026-10-06T00:00:00Z',
                samples=[sample('request_ingress',1),sample('ack_ingress',513)])))
            self.ar.attach_observations(verdict,path,identity)
        self.assertEqual(verdict['verdict'],'provisional')
        self.assertEqual(verdict['unknown_inputs'],baseline['unknown_inputs'])
        self.assertIsNone(verdict['recovery_hold_bound_ms'])
        physical=[row for row in verdict['observation_intervals'] if row['endpoints'][1].endswith('wire_departure')]
        self.assertTrue(all(row['value_ns'] is None for row in physical))

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
