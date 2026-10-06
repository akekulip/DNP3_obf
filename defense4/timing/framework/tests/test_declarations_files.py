"""The committed experiment declarations must pass the fail-closed validator and match the retained build evidence."""
import hashlib
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMING = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / "runner"))
import declaration as d  # noqa: E402


class Files(unittest.TestCase):
    def load(self, n):
        return json.loads((HERE.parent / "declarations" / (n + ".json")).read_text())

    def test_both_declarations_validate(self):
        for n in ("smoke", "main"):
            self.assertEqual(d.validate(self.load(n)), [], n)

    def test_source_hash_matches_the_recorded_baseline_file(self):
        for n in ("smoke", "main", "case4_attended_sbo", "case4_instrumentation"):
            record = self.load(n)["source"]
            src = TIMING.parents[1] / record["path"]
            self.assertEqual(record["sha256"], hashlib.sha256(src.read_bytes()).hexdigest(), n)

    def test_build_identity_matches_the_9_13_2_manifest(self):
        man = json.loads((TIMING / "response_ready/evidence/sde_9_13_2_build_03/manifest.json").read_text())
        for n in ("smoke", "main"):
            b = self.load(n)["build"]
            self.assertEqual(b["sha256"], man["artifact_sha256"]["pipe/tofino.bin"])
            self.assertEqual(b["program_source_sha256"], man["source_sha256"])

    def test_no_operate_and_restore_is_required(self):
        for n in ("smoke", "main"):
            x = self.load(n)
            self.assertNotIn("OPERATE", x["workload"]["ops"])
            self.assertTrue(x["termination"]["restore_required"])

    def test_the_refused_points_are_declared_not_silently_dropped(self):
        self.assertIn("rejected", self.load("main")["failure_outcomes"])




class CampaignFiles(unittest.TestCase):
    load = Files.load
    def test_case4_campaign_is_bounded_explicit_and_separately_attended(self):
        campaign = self.load('case4_campaign')
        declarations = [self.load(Path(p).stem) for p in campaign['declarations']]
        self.assertEqual(d.validate_campaign(declarations,
            max_total_attempts=campaign['max_total_attempts'],
            max_duration_ms=campaign['max_duration_ms']), [])
        self.assertEqual(sum(d.budget_summary(x)['attempted_transactions'] for x in declarations), 16168)
        self.assertEqual(sum(d.budget_summary(x)['blocks'] for x in declarations), 44)
        self.assertEqual(sum(d.budget_summary(x)['state_read_transactions'] for x in declarations), 88)
        # Instrumentation's 8 blocks account for 16 state reads separately from
        # the main/smoke/SBO 36 blocks and their 72 state READs.
        self.assertEqual(d.budget_summary(self.load('main'))['attempted_transactions'], 15660)
        self.assertEqual(d.budget_summary(self.load('smoke'))['attempted_transactions'], 128)
        self.assertEqual(d.budget_summary(self.load('case4_attended_sbo'))['attempted_transactions'], 124)
        self.assertEqual(d.budget_summary(self.load('case4_instrumentation'))['attempted_transactions'], 256)
        for x in declarations:
            self.assertFalse(x['collection']['hardware_authorized'])
            self.assertTrue(x['termination']['warmup_raw_retained'])
            self.assertTrue(x['termination']['precheck_raw_retained'])
            self.assertTrue(x['termination']['state_read_raw_retained'])
            self.assertIn('run_list', x['workload'])

    def test_joint_campaign_retains_baseline_identity_without_claiming_joint_build(self):
        for n in ('main', 'smoke', 'case4_attended_sbo', 'case4_instrumentation'):
            x = self.load(n)
            self.assertEqual(x['build']['evidence_role'], 'timing_baseline_not_joint')
            self.assertEqual(x['collection']['status'], 'blocked_pending_joint_build_and_admission')


if __name__ == "__main__":
    unittest.main()
