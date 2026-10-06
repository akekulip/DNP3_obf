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
    "workload": {"ops": ["READ"], "attempted_per_block": 200, "blocks": 3, "interval_ms": 400,
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




class RunList(unittest.TestCase):
    def explicit(self):
        x = copy.deepcopy(GOOD)
        x['workload'] = {
            'ops': ['READ'], 'seed': 20261006, 'order': 'counterbalanced',
            'run_list': [{'id': 'read-off', 'phase': 'main', 'op': 'READ', 'arm': 'OFF',
                          'da_ms': 10, 'blocks': 3, 'primary_per_block': 500,
                          'warmup_per_block': 20, 'precheck_per_block': 1,
                          'state_reads_per_block': 2, 'interval_ms': 400,
                          'transaction_timeout_ms': 500, 'setup_budget_ms': 1000}],
        }
        x['termination'].update(max_total_attempts=18360, max_duration_ms=2000000,
                                warmup_raw_retained=True, precheck_raw_retained=True,
                                state_read_raw_retained=True)
        return x

    def test_explicit_run_list_validates_without_cartesian_workload(self):
        self.assertEqual(d.validate(self.explicit()), [])

    def test_all_attempts_count_and_timeout_spacing_setup_are_charged(self):
        x = self.explicit()
        summary = d.budget_summary(x)
        self.assertEqual(summary['attempted_transactions'], 1569)
        self.assertEqual(summary['warmup_transactions'], 60)
        self.assertEqual(summary['precheck_transactions'], 3)
        self.assertEqual(summary['state_read_transactions'], 6)
        self.assertEqual(summary['max_duration_ms'], 1569 * 900 + 3000)

    def test_cartesian_counts_are_enforced_including_warmups(self):
        x = copy.deepcopy(GOOD)
        x['termination']['max_total_attempts'] = 1
        self.assertTrue(any('attempt' in p for p in d.validate(x)))

    def test_global_ceiling_and_duration_reject_oversized_lists(self):
        for field, value, reason in [('primary_per_block', 7000, '18,360'),
                                     ('transaction_timeout_ms', 10000, 'duration')]:
            x = self.explicit(); x['workload']['run_list'][0][field] = value
            self.assertTrue(any(reason in p for p in d.validate(x)), d.validate(x))

    def test_prechecks_and_state_reads_cannot_be_discarded(self):
        for field, reason in [('precheck_raw_retained', 'precheck'),
                              ('state_read_raw_retained', 'state')]:
            x = self.explicit(); x['termination'][field] = False
            self.assertTrue(any(reason in p for p in d.validate(x)))

    def test_sbo_counts_two_transactions_and_requires_separate_attended_declaration(self):
        x = self.explicit(); x['workload']['ops'] = ['SBO']
        row = x['workload']['run_list'][0]; row.update(op='SBO', blocks=1, primary_per_block=30,
            warmup_per_block=0, precheck_per_block=0, state_reads_per_block=2)
        self.assertTrue(any('attended' in p for p in d.validate(x)))
        x['collection'] = {'attended_only': True, 'scope': 'sbo_smoke', 'hardware_authorized': False}
        self.assertEqual(d.validate(x), [])
        self.assertEqual(d.budget_summary(x)['attempted_transactions'], 62)

    def test_campaign_enforces_combined_ceiling(self):
        x = self.explicit()
        x['workload']['run_list'][0]['primary_per_block'] = 4000
        x['termination']['max_duration_ms'] = 20000000
        self.assertEqual(d.validate(x), [])
        self.assertTrue(any('18,360' in p for p in d.validate_campaign([x, x])))

    def test_invalid_numeric_counts_do_not_crash_validator(self):
        for bad in [True, -1, 1.5, '500']:
            x = self.explicit(); x['workload']['run_list'][0]['primary_per_block'] = bad
            self.assertTrue(d.validate(x), bad)


class MalformedDeclarations(unittest.TestCase):
    def test_structured_values_fail_closed_without_type_errors(self):
        mutations = [lambda x: x['policy'].update(arms=[{}]),
                     lambda x: x['workload'].update(ops=[{}]),
                     lambda x: x['workload'].update(ops=None),
                     lambda x: x['policy'].update(da_ms=[10 ** 400]),
                     lambda x: x['termination'].update(max_duration_ms='unbounded')]
        for mutate in mutations:
            x = copy.deepcopy(GOOD); mutate(x)
            self.assertTrue(d.validate(x))

    def test_duplicate_cartesian_dimensions_are_rejected(self):
        x = copy.deepcopy(GOOD); x['policy']['arms'] = ['OFF', 'OFF']
        self.assertTrue(any('duplicate' in p for p in d.validate(x)))


if __name__ == "__main__":
    unittest.main()
