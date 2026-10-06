import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runner"))
import declaration as d  # noqa: E402

GOOD = {
    "id": "rr-read-d4-20261006", "declared_on": "2026-10-06",
    "source": {"path": "defense4/timing/response_ready/src/defense4_response_ready.p4", "sha256": "a" * 64},
    "build": {"sde": "9.13.2", "sha256": "b" * 64, "stages_ingress": 7, "stages_egress": 0},
    "policy": {"arms": ["OFF", "RESPONSE_READY"], "da_ms": [5, 10, 15, 20], "gap_ms": 1, "anchor": "request"},
    "workload": {"ops": ["READ"], "attempted_per_block": 1000, "blocks": 3, "interval_ms": 400,
                 "warmup_exchanges": 0, "seed": 20261006, "order": "counterbalanced"},
    "endpoints": {"master": "vision", "outstation": "sel-751"},
    "observation_points": ["master-facing pcap"],
    "tolerances": {"median_abs_gap_error_us": 10},
    "failure_outcomes": ["late", "fallback", "missing", "rejected", "bypassed", "malformed"],
    "termination": {"max_total_attempts": 6000, "abort_on": ["unexplained loss"]},
}


class Declaration(unittest.TestCase):
    def test_good_declaration_passes(self):
        self.assertEqual(d.validate(GOOD), [])

    def test_missing_section_fails(self):
        for key in d.REQUIRED:
            bad = copy.deepcopy(GOOD); del bad[key]
            self.assertTrue(d.validate(bad), key)

    def test_operate_is_rejected(self):
        bad = copy.deepcopy(GOOD); bad["workload"]["ops"] = ["READ", "OPERATE"]
        self.assertTrue(any("OPERATE" in p for p in d.validate(bad)))

    def test_unrecorded_seed_and_bad_hash_rejected(self):
        bad = copy.deepcopy(GOOD); bad["workload"]["seed"] = None; bad["build"]["sha256"] = "xyz"
        probs = d.validate(bad)
        self.assertTrue(any("seed" in p for p in probs) and any("build.sha256" in p for p in probs))

    def test_stage_limit_enforced(self):
        bad = copy.deepcopy(GOOD); bad["build"]["stages_ingress"] = 13
        self.assertTrue(any("12-stage" in p for p in d.validate(bad)))

    def test_warmup_requires_retained_raw(self):
        bad = copy.deepcopy(GOOD); bad["workload"]["warmup_exchanges"] = 20
        self.assertTrue(any("warm-up" in p for p in d.validate(bad)))

    def test_every_failure_class_must_be_accounted(self):
        bad = copy.deepcopy(GOOD); bad["failure_outcomes"] = ["late"]
        self.assertEqual(len([p for p in d.validate(bad) if "failure_outcomes" in p]), 5)

    def test_digest_is_stable_and_sensitive(self):
        other = copy.deepcopy(GOOD); other["policy"]["gap_ms"] = 2
        self.assertEqual(d.digest(GOOD), d.digest(copy.deepcopy(GOOD)))
        self.assertNotEqual(d.digest(GOOD), d.digest(other))


if __name__ == "__main__":
    unittest.main()
