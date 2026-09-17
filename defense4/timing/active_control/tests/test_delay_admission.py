#!/usr/bin/env python3
"""Offline tests for delay admission. No hardware, no network, no device.

Each test targets one way the policy could mislead: a missing bound filled with a convenient
number, the master's and outstation's timers confused, the ACK hold left out of the response's
wait, an unusable number admitted as a duration, an inherited constant passed off as a current
measurement, and a duration read as a countdown.

    python3 tests/test_delay_admission.py
"""
from __future__ import annotations

import math
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from delay_admission import (AdmissionInputs, Applicability, Bound,       # noqa: E402
                             PolicyContext, Provenance, evaluate,
                             remaining_headroom_note, validate)

M = Provenance.MEASURED_THIS_CONNECTION
CTX = PolicyContext(connection_id="conn-1", build_id="frozen-7ce30494")

#: Applicability carrying the role the field expects. A bound must describe the timer and
#: direction of the field it occupies, not merely the right connection.
def applies(direction="", timer=""):
    return Applicability(connection_id="conn-1", build_id="frozen-7ce30494",
                         direction=direction, timer=timer)


APPLIES = applies()
ROLE = {"master_rto_ms": applies("master_to_outstation", "master_rto"),
        "outstation_rto_ms": applies("outstation_to_master", "outstation_rto"),
        "master_feedback_path_ms": applies("master_to_outstation"),
        "outstation_feedback_path_ms": applies("outstation_to_master")}


def b(name, value, prov=M, source="test", observed_at="2026-09-15T00:00:00Z",
      applies_to=None):
    return Bound(name=name, value_ms=value, provenance=prov, source=source,
                 observed_at=observed_at,
                 applies_to=applies_to if applies_to is not None else ROLE.get(name, APPLIES))


def inputs(**over):
    base = dict(
        d_a_ms=20.0, clrt_new_ms=4.0,
        master_rto_ms=b("master_rto_ms", 200.0),
        outstation_rto_ms=b("outstation_rto_ms", 3000.0),
        application_deadline_ms=b("application_deadline_ms", 1000.0,
                                  Provenance.OPERATOR_SUPPLIED),
        clrt_original_ms=b("clrt_original_ms", 1.0),
        master_feedback_path_ms=b("master_feedback_path_ms", 1.0),
        outstation_feedback_path_ms=b("outstation_feedback_path_ms", 1.0),
        native_request_to_response_ms=b("native_request_to_response_ms", 5.0),
        ack_latency_bound_ms=b("ack_latency_bound_ms", 3.0),
        detect_ms=b("detect_ms", 0.0012),
        release_tail_ms=b("release_tail_ms", 0.0017),
        safety_margin_ms=3.0,
        policy_cap_ms=40.0,
        context=CTX,
    )
    base.update(over)
    return AdmissionInputs(**base)


def check(v, prefix):
    return [c for c in v["checks"] if c["constraint"].startswith(prefix)][0]


class TestTheResponseHoldContainsTheAckHold(unittest.TestCase):
    """The defect that admitted an unsafe policy: the response's wait omitted D_A."""

    def test_the_reviewed_counterexample_is_now_refused(self):
        """D_A=20, CLRT_new=4, native 1 ms: the response waits 23 ms, not 4 ms.

        The earlier evaluator charged roughly 7.5 ms here and admitted the policy against a
        10 ms outstation budget.
        """
        v = evaluate(inputs(d_a_ms=20.0, clrt_new_ms=4.0,
                            clrt_original_ms=b("clrt_original_ms", 1.0),
                            outstation_rto_ms=b("outstation_rto_ms", 10.0),
                            policy_cap_ms=100.0))
        self.assertEqual(v["response_hold_ms"], 23.0)
        out = check(v, "outstation")
        self.assertGreaterEqual(out["consumed_ms"], 23.0)
        self.assertFalse(out["ok"])
        self.assertEqual(v["verdict"], "refused")

    def test_raising_the_ack_hold_raises_the_outstation_consumption(self):
        """The conclusion that was wrong: D_A did not move the outstation check at all."""
        small = check(evaluate(inputs(d_a_ms=5.0)), "outstation")["consumed_ms"]
        large = check(evaluate(inputs(d_a_ms=25.0)), "outstation")["consumed_ms"]
        self.assertAlmostEqual(large - small, 20.0, places=6)

    def test_hold_is_floored_at_zero_not_negative(self):
        v = evaluate(inputs(d_a_ms=0.0, clrt_new_ms=1.0,
                            clrt_original_ms=b("clrt_original_ms", 9.0),
                            native_request_to_response_ms=b("native_request_to_response_ms", 20.0)))
        self.assertEqual(v["response_hold_ms"], 0.0)

    def test_unknown_native_interval_is_conservative_not_ignored(self):
        known = evaluate(inputs(clrt_original_ms=b("clrt_original_ms", 1.0)))
        unknown = evaluate(inputs(clrt_original_ms=Bound(
            "clrt_original_ms", None, Provenance.UNAVAILABLE)))
        self.assertGreater(unknown["response_hold_ms"], known["response_hold_ms"])
        self.assertTrue(unknown["conservative_substitutions"])


class TestInvalidNumbersAreRejectedBeforeAnyVerdict(unittest.TestCase):

    def test_a_negative_ack_hold_is_rejected(self):
        v = evaluate(inputs(d_a_ms=-20.0))
        self.assertEqual(v["verdict"], "rejected")
        self.assertTrue(any("negative" in e for e in v["input_errors"]))
        self.assertEqual(v["checks"], [])

    def test_nonfinite_values_are_rejected(self):
        for bad in (float("nan"), float("inf")):
            v = evaluate(inputs(clrt_new_ms=bad))
            self.assertEqual(v["verdict"], "rejected", bad)
            self.assertTrue(any("finite" in e for e in v["input_errors"]))

    def test_a_zero_policy_cap_is_rejected(self):
        self.assertTrue(any("greater than zero" in e
                            for e in validate(inputs(policy_cap_ms=0.0))))

    def test_an_out_of_range_value_is_read_as_a_unit_error(self):
        v = evaluate(inputs(d_a_ms=5e7))
        self.assertTrue(any("units" in e for e in v["input_errors"]))

    def test_an_inconsistent_pair_is_rejected(self):
        errs = validate(inputs(clrt_original_ms=b("clrt_original_ms", 50.0),
                               native_request_to_response_ms=b(
                                   "native_request_to_response_ms", 5.0)))
        self.assertTrue(any("cannot be longer" in e for e in errs))

    def test_a_valid_policy_is_not_rejected(self):
        """Non-vacuity: the validator must not reject everything."""
        self.assertEqual(validate(inputs()), [])


class TestMissingTermsCannotBecomeZero(unittest.TestCase):

    def test_a_missing_detection_term_leaves_the_check_undecided(self):
        v = evaluate(inputs(detect_ms=Bound("detect_ms", None, Provenance.UNAVAILABLE)))
        for prefix in ("master", "outstation", "master application"):
            c = check(v, prefix)
            self.assertIsNone(c["ok"], "%s must not pass on a missing term" % prefix)
            self.assertIn("detect_ms", c["missing"])
        self.assertEqual(v["verdict"], "provisional")

    def test_an_undecided_check_never_reports_ok_true(self):
        v = evaluate(inputs(release_tail_ms=Bound(
            "release_tail_ms", None, Provenance.UNAVAILABLE)))
        self.assertNotIn(True, [c.get("ok") for c in v["checks"]])

    def test_a_missing_bound_is_not_silently_given_a_number(self):
        v = evaluate(inputs(master_rto_ms=Bound(
            "master_rto_ms", None, Provenance.UNAVAILABLE)))
        self.assertIsNone(v["inputs"]["master_rto_ms"]["value_ms"])
        self.assertIsNone(check(v, "master TCP")["ok"])


class TestProvenanceAndApplicability(unittest.TestCase):

    def test_inherited_constants_do_not_support_an_admitted_verdict(self):
        v = evaluate(inputs(detect_ms=b("detect_ms", 0.0012,
                                        Provenance.INHERITED_EARLIER_BUILD,
                                        "Defense 3, 2026-07-29")))
        self.assertEqual(v["verdict"], "provisional")
        self.assertIn("detect_ms", v["inputs_not_authoritative"])

    def test_a_measurement_from_another_connection_is_not_authoritative_here(self):
        v = evaluate(inputs(master_rto_ms=b(
            "master_rto_ms", 200.0, applies_to=Applicability(
                connection_id="conn-OTHER", build_id="frozen-7ce30494"))))
        self.assertIn("master_rto_ms", v["inputs_not_authoritative"])
        self.assertIn("conn-OTHER", v["inputs"]["master_rto_ms"]["applicability_problem"])
        self.assertEqual(v["verdict"], "provisional")

    def test_a_measurement_from_another_build_is_not_authoritative_here(self):
        v = evaluate(inputs(release_tail_ms=b(
            "release_tail_ms", 0.0017, applies_to=Applicability(
                connection_id="conn-1", build_id="candidate-7d175222"))))
        self.assertIn("release_tail_ms", v["inputs_not_authoritative"])

    def test_a_claim_of_being_measured_here_needs_an_observation_time(self):
        v = evaluate(inputs(detect_ms=b("detect_ms", 0.0012, observed_at="")))
        self.assertIn("observation time", v["inputs"]["detect_ms"]["applicability_problem"])

    def test_an_operator_supplied_deadline_is_authoritative_for_its_role(self):
        """A requirement does not have to masquerade as a measurement."""
        v = evaluate(inputs())
        self.assertTrue(v["inputs"]["application_deadline_ms"]["authoritative_for_role"])
        self.assertNotIn("application_deadline_ms", v["inputs_not_authoritative"])
        self.assertEqual(v["verdict"], "admitted_conditional")

    def test_an_operator_supplied_transport_timer_is_not_authoritative(self):
        v = evaluate(inputs(outstation_rto_ms=b("outstation_rto_ms", 3000.0,
                                                Provenance.OPERATOR_SUPPLIED)))
        self.assertIn("outstation_rto_ms", v["inputs_not_authoritative"])


class TestRoleIsNotDecidedByLabel(unittest.TestCase):
    """Counterexamples from the 2026-09-16 review: labels must not substitute for roles."""

    def test_an_outstation_measurement_cannot_fill_the_master_field(self):
        v = evaluate(inputs(master_rto_ms=b(
            "master_rto_ms", 3000.0,
            applies_to=Applicability(connection_id="conn-1", build_id="frozen-7ce30494",
                                     direction="outstation_to_master", timer="outstation_rto"))))
        self.assertIn("master_rto_ms", v["inputs_not_authoritative"])
        self.assertIn("timer", v["inputs"]["master_rto_ms"]["applicability_problem"])
        self.assertEqual(v["verdict"], "provisional")

    def test_an_empty_context_admits_nothing_authoritatively(self):
        v = evaluate(inputs(context=PolicyContext()))
        self.assertEqual(v["verdict"], "provisional")
        self.assertTrue(v["inputs_not_authoritative"])

    def test_a_bound_must_be_named_for_the_field_it_fills(self):
        v = evaluate(inputs(master_rto_ms=b("application_deadline_ms", 200.0)))
        self.assertIn("occupies the", v["inputs"]["master_rto_ms"]["applicability_problem"])
        self.assertIn("master_rto_ms", v["inputs_not_authoritative"])

    def test_the_verdict_names_the_policy_it_evaluated(self):
        v = evaluate(inputs(d_a_ms=20.0, clrt_new_ms=4.0))
        self.assertEqual(v["policy"]["d_a_ms"], 20.0)
        self.assertEqual(v["policy"]["clrt_new_ms"], 4.0)
        self.assertEqual(v["policy"]["context"]["build_id"], "frozen-7ce30494")

    def test_the_conservative_direction_of_the_native_interval_is_stated(self):
        v = evaluate(inputs())
        self.assertTrue(any("SMALLEST" in s for s in v["conservative_substitutions"]))


class TestMasterAndOutstationAreNotInterchangeable(unittest.TestCase):

    def test_the_two_timers_are_separate_named_inputs(self):
        names = set(evaluate(inputs())["inputs"])
        self.assertIn("master_rto_ms", names)
        self.assertIn("outstation_rto_ms", names)
        self.assertNotIn("tcp_rto", names, "one ambiguous field is what caused the confusion")

    def test_a_long_outstation_timer_does_not_rescue_a_master_violation(self):
        v = evaluate(inputs(d_a_ms=500.0, policy_cap_ms=1000.0))
        self.assertFalse(check(v, "master TCP")["ok"])
        self.assertEqual(v["verdict"], "refused")

    def test_the_master_check_does_not_move_with_the_response_hold_alone(self):
        a = check(evaluate(inputs(clrt_new_ms=4.0)), "master TCP")["consumed_ms"]
        c = check(evaluate(inputs(clrt_new_ms=400.0, policy_cap_ms=1000.0)),
                  "master TCP")["consumed_ms"]
        self.assertEqual(a, c)


class TestBudgetAccounting(unittest.TestCase):

    def test_each_check_charges_its_whole_interval_not_only_the_hold(self):
        out = check(evaluate(inputs()), "outstation")
        self.assertIn("network_round_trip", out["terms_ms"])
        self.assertGreater(out["consumed_ms"], evaluate(inputs())["response_hold_ms"])

    def test_the_consumed_total_is_the_sum_of_its_stated_terms(self):
        for prefix in ("master TCP", "outstation", "master application"):
            c = check(evaluate(inputs()), prefix)
            self.assertAlmostEqual(c["consumed_ms"], round(sum(c["terms_ms"].values()), 4),
                                   places=4, msg=prefix)

    def test_no_path_allowance_is_charged_twice_in_one_check(self):
        for prefix in ("master TCP", "outstation"):
            keys = [k for k in check(evaluate(inputs()), prefix)["terms_ms"] if "path" in k
                    or "round_trip" in k]
            self.assertEqual(len(keys), 1, prefix)


class TestThePolicyCapIsIndependent(unittest.TestCase):

    def test_cap_is_enforced_against_the_requested_holds(self):
        v = evaluate(inputs(d_a_ms=30.0, clrt_new_ms=20.0, policy_cap_ms=40.0))
        self.assertFalse(v["policy_cap"]["ok"])
        self.assertEqual(v["verdict"], "refused")

    def test_cap_does_not_move_when_the_measured_timers_grow(self):
        small = evaluate(inputs(master_rto_ms=b("master_rto_ms", 200.0)))
        large = evaluate(inputs(master_rto_ms=b("master_rto_ms", 20000.0)))
        self.assertEqual(small["policy_cap"]["cap_ms"], large["policy_cap"]["cap_ms"])

    def test_inflating_the_measured_paths_cannot_license_a_longer_hold(self):
        """The feedback loop grows, the cap does not, so the cap still binds."""
        v = evaluate(inputs(d_a_ms=39.0, clrt_new_ms=2.0,
                            outstation_feedback_path_ms=b("outstation_feedback_path_ms", 500.0)))
        self.assertFalse(v["policy_cap"]["ok"])


class TestWhatIsNotEstablished(unittest.TestCase):

    def test_there_is_no_unconditional_verified_flag(self):
        v = evaluate(inputs())
        self.assertNotIn("transport_safety_verified", v.get("claim", {}))
        self.assertNotIn("transport_safety_verified", v)

    def test_the_best_verdict_is_explicitly_conditional(self):
        claim = evaluate(inputs())["claim"]
        self.assertEqual(claim["kind"], "admitted_conditional")
        self.assertIn("universal property", claim["statement"])
        self.assertTrue(claim["conditions"])

    def test_the_statement_distinguishes_the_roles_of_its_inputs(self):
        """The 2026-09-17 review: the statement called every input an observed maximum.

        They are not the same kind of number. A latency term has to be a maximum, a timer or
        deadline budget has to be a value the connection will not beat, and CLRT_original has to
        be a lower bound, since a smaller native interval lengthens the implied response hold.
        """
        s = evaluate(inputs())["claim"]["statement"].lower()
        self.assertIn("observed maxima", s)
        self.assertIn("will not beat", s)
        self.assertIn("lower bound", s)
        self.assertIn("clrt_original", s)

    def test_hardware_execution_is_never_claimed(self):
        joined = " ".join(evaluate(inputs())["claim"]["not_established"]).lower()
        self.assertIn("hardware", joined)

    def test_the_unverified_cases_are_named_in_every_verdict(self):
        joined = " ".join(evaluate(inputs())["unverified_cases"]).lower()
        for case in ("first", "reconnect", "policy change"):
            self.assertIn(case, joined)

    def test_a_duration_is_not_presented_as_a_countdown(self):
        note = remaining_headroom_note().lower()
        self.assertIn("not the time remaining", note)
        self.assertIn("tcp_info", note)
        self.assertIn("instead of", note)


class TestNonVacuity(unittest.TestCase):

    def test_a_sound_policy_still_reaches_the_best_verdict(self):
        v = evaluate(inputs())
        self.assertEqual(v["verdict"], "admitted_conditional")
        self.assertEqual(v["unknown_inputs"], [])
        self.assertEqual(v["inputs_not_authoritative"], [])
        self.assertTrue(all(c["ok"] for c in v["checks"]))
        self.assertTrue(math.isfinite(v["response_hold_ms"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
