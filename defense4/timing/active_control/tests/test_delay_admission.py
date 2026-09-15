#!/usr/bin/env python3
"""Offline tests for delay admission. No hardware, no network, no device.

Each test targets one way the frozen policy could mislead: a missing bound filled with a
convenient number, the master's and outstation's timers confused, a margin counted twice,
inherited constants passed off as current measurements, and a duration read as a countdown.

    python3 tests/test_delay_admission.py
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from delay_admission import (AdmissionInputs, Bound, Provenance,          # noqa: E402
                             evaluate, remaining_headroom_note)

M = Provenance.MEASURED_THIS_CONNECTION


def b(name, value, prov=M, source="test"):
    return Bound(name=name, value_ms=value, provenance=prov, source=source)


def inputs(**over):
    base = dict(
        d_a_ms=20.0, clrt_new_ms=4.0,
        master_rto_ms=b("master_rto_ms", 200.0),
        outstation_rto_ms=b("outstation_rto_ms", 3000.0),
        application_deadline_ms=b("application_deadline_ms", 1000.0),
        ack_latency_bound_ms=b("ack_latency_bound_ms", 3.0),
        detect_ms=b("detect_ms", 0.0012),
        release_tail_ms=b("release_tail_ms", 0.0017),
        path_uncertainty_ms=b("path_uncertainty_ms", 0.5),
        safety_margin_ms=3.0,
        policy_cap_ms=40.0,
    )
    base.update(over)
    return AdmissionInputs(**base)


class TestUnknownInputsCannotBecomeAVerifiedClaim(unittest.TestCase):

    def test_a_missing_bound_downgrades_the_verdict(self):
        v = evaluate(inputs(application_deadline_ms=Bound(
            "application_deadline_ms", None, Provenance.UNAVAILABLE)))
        self.assertEqual(v["verdict"], "provisional")
        self.assertFalse(v["claim"]["transport_safety_verified"])
        self.assertIn("application_deadline_ms", v["unknown_inputs"])

    def test_a_missing_bound_is_not_silently_given_a_number(self):
        v = evaluate(inputs(master_rto_ms=Bound(
            "master_rto_ms", None, Provenance.UNAVAILABLE)))
        self.assertIsNone(v["inputs"]["master_rto_ms"]["value_ms"])
        master = [c for c in v["checks"] if c["constraint"].startswith("master")][0]
        self.assertIsNone(master["ok"], "an unknown bound must leave the check undecided")

    def test_inherited_constants_do_not_support_a_verified_claim(self):
        v = evaluate(inputs(detect_ms=b("detect_ms", 0.0012,
                                        Provenance.INHERITED_EARLIER_BUILD,
                                        "Defense 3, 2026-07-29")))
        self.assertEqual(v["verdict"], "provisional")
        self.assertIn("detect_ms", v["inputs_not_measured_here"])
        self.assertIn("earlier build", v["inputs"]["detect_ms"]["provenance"])

    def test_all_measured_here_and_passing_gives_a_verified_claim(self):
        """Non-vacuity: without this, every test above would pass on a broken evaluator."""
        v = evaluate(inputs())
        self.assertEqual(v["verdict"], "admitted")
        self.assertTrue(v["claim"]["transport_safety_verified"])
        self.assertEqual(v["unknown_inputs"], [])


class TestMasterAndOutstationAreNotInterchangeable(unittest.TestCase):

    def test_the_two_timers_are_separate_named_inputs(self):
        v = evaluate(inputs())
        names = set(v["inputs"])
        self.assertIn("master_rto_ms", names)
        self.assertIn("outstation_rto_ms", names)
        self.assertNotIn("tcp_rto", names, "one ambiguous field is what caused the confusion")

    def test_a_long_outstation_timer_does_not_rescue_a_master_violation(self):
        """The 3 s relay measurement must not license a 500 ms ACK hold."""
        v = evaluate(inputs(d_a_ms=500.0, policy_cap_ms=1000.0))
        master = [c for c in v["checks"] if c["constraint"].startswith("master")][0]
        self.assertFalse(master["ok"])
        self.assertEqual(v["verdict"], "refused")

    def test_the_response_hold_is_charged_to_the_outstation_not_the_master(self):
        """Raising only CLRT_new must not consume the master's budget."""
        a = evaluate(inputs(clrt_new_ms=4.0))
        c = evaluate(inputs(clrt_new_ms=400.0, policy_cap_ms=1000.0))
        m_a = [x for x in a["checks"] if x["constraint"].startswith("master")][0]
        m_c = [x for x in c["checks"] if x["constraint"].startswith("master")][0]
        self.assertEqual(m_a["consumed_ms"], m_c["consumed_ms"],
                         "the master's check must not move when only the response hold changes")
        o_c = [x for x in c["checks"] if x["constraint"].startswith("outstation")][0]
        self.assertGreater(o_c["consumed_ms"], 400.0)


class TestMarginAccounting(unittest.TestCase):

    def test_path_uncertainty_is_counted_once(self):
        v = evaluate(inputs(path_uncertainty_ms=b("path_uncertainty_ms", 0.5)))
        self.assertEqual(v["budget_terms_ms"]["path_uncertainty_counted_once"], 0.5)
        self.assertEqual(sum(1 for k in v["budget_terms_ms"] if "path" in k), 1)

    def test_the_total_is_the_sum_of_the_stated_terms(self):
        v = evaluate(inputs())
        self.assertAlmostEqual(v["budget_total_ms"],
                               round(sum(v["budget_terms_ms"].values()), 4), places=6)

    def test_ack_latency_is_charged_before_the_hold_not_inside_it(self):
        v = evaluate(inputs())
        self.assertIn("ack_latency_before_the_hold", v["budget_terms_ms"])
        master = [c for c in v["checks"] if c["constraint"].startswith("master")][0]
        self.assertGreater(master["consumed_ms"], 20.0 + 3.0)


class TestThePolicyCapIsIndependent(unittest.TestCase):

    def test_cap_is_enforced_against_the_requested_holds(self):
        v = evaluate(inputs(d_a_ms=30.0, clrt_new_ms=20.0, policy_cap_ms=40.0))
        self.assertFalse(v["policy_cap"]["ok"])
        self.assertEqual(v["verdict"], "refused")

    def test_cap_does_not_move_when_the_measured_timers_grow(self):
        """RTT inflation must not license a longer hold."""
        small = evaluate(inputs(master_rto_ms=b("master_rto_ms", 200.0)))
        large = evaluate(inputs(master_rto_ms=b("master_rto_ms", 20000.0)))
        self.assertEqual(small["policy_cap"]["cap_ms"], large["policy_cap"]["cap_ms"])


class TestWhatIsNotEstablished(unittest.TestCase):

    def test_the_unverified_cases_are_named_in_every_verdict(self):
        v = evaluate(inputs())
        joined = " ".join(v["unverified_cases"]).lower()
        for case in ("first", "reconnect", "policy change"):
            self.assertIn(case, joined)

    def test_a_duration_is_not_presented_as_a_countdown(self):
        note = remaining_headroom_note().lower()
        self.assertIn("not the time remaining", note)
        self.assertIn("tcp_info", note)


if __name__ == "__main__":
    unittest.main(verbosity=2)
