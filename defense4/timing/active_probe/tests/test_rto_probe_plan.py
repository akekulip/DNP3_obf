#!/usr/bin/env python3
"""Offline tests for the retransmission probe.

Nothing here touches a host, a socket or a firewall. The execution tests drive `run_steps`
with a scripted runner and a fake clock, so the lifecycle is exercised without any test setting
the hardware-authorisation flag, and without any real waiting.

    python3 tests/test_rto_probe_plan.py
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from rto_probe_plan import (GUARD_ENV, RULE_ABSENT_RC, Connection, Direction,   # noqa: E402
                            ProbeRefused, RunContext, apply, build_rule, plan,
                            payload_length_rule, run_steps)


def conn(**over):
    base = dict(src_ip="192.168.10.1", src_port=40001, dst_ip="192.168.10.7", dst_port=20000,
                interface="enp59s0f0np0", tcp_header_bytes=32)
    base.update(over)
    return Connection(**base)


def ctx(**over):
    base = dict(capture_host="master", capture_point="master-facing NIC",
                capture_precision="nanosecond", timing_mode="D4", shape_enable=0,
                loaded_program="defense4_rrc_bor_unified12.p4", loaded_program_sha256="7ce30494")
    base.update(over)
    return RunContext(**base)


class FakeClock:
    """A clock that only moves when the code under test sleeps."""

    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += max(0.0, seconds)


class Runner:
    """A scripted iptables. Tracks whether the rule is installed so -C can answer honestly."""

    def __init__(self, *, install_rc=0, remove_rc=0, verify_removed_rc=RULE_ABSENT_RC,
                 verify_installed_rc=0, raise_on=None):
        self.installed = False
        self.calls = []
        self.install_rc = install_rc
        self.remove_rc = remove_rc
        self.verify_removed_rc = verify_removed_rc
        self.verify_installed_rc = verify_installed_rc
        self.raise_on = raise_on

    def __call__(self, argv):
        self.calls.append(argv)
        flag = next((a for a in argv if a in ("-A", "-C", "-D")), "")
        if self.raise_on and self.raise_on in argv:
            raise OSError("scripted failure")
        if flag == "-A":
            if self.install_rc == 0:
                self.installed = True
            return (self.install_rc, "", "" if self.install_rc == 0 else "install failed")
        if flag == "-D":
            if self.remove_rc == 0:
                self.installed = False
            return (self.remove_rc, "", "" if self.remove_rc == 0 else "delete failed")
        if flag == "-C":
            if self.installed:
                return (self.verify_installed_rc, "", "")
            return (self.verify_removed_rc, "",
                    "" if self.verify_removed_rc == RULE_ABSENT_RC else "Permission denied")
        return (0, "", "")


def run(p, runner, **kw):
    clk = FakeClock()
    kw.setdefault("clock", clk)
    kw.setdefault("sleeper", clk.sleep)
    return run_steps(p, runner, **kw), clk


class TestTheHoldIsTakenNotRecorded(unittest.TestCase):

    def test_a_forty_second_hold_actually_advances_the_clock(self):
        """The defect: the record said 40 s and the call returned in 0.24 ms."""
        rec, clk = run(plan(conn(), ctx(), 40.0), Runner())
        self.assertEqual(rec["status"], "completed")
        self.assertGreaterEqual(rec["elapsed_seconds"], 40.0)
        self.assertGreaterEqual(clk.t - 1000.0, 40.0)

    def test_a_workload_that_returns_early_is_not_a_completed_hold(self):
        """The 2026-09-16 counterexample: status completed, elapsed 0 s, requested 40 s."""
        with self.assertRaises(ProbeRefused) as cm:
            run(plan(conn(), ctx(), 40.0), Runner(), workload=lambda s: None)
        rec = cm.exception.record
        self.assertEqual(rec["status"], "hold not served")
        self.assertEqual(rec["requested_hold_seconds"], 40.0)
        self.assertEqual(rec["elapsed_seconds"], 0.0)
        self.assertTrue(rec["cleanup_verified"], "cleanup must still run")

    def test_the_watchdog_bounds_a_workload_that_overruns(self):
        clk = FakeClock()

        def greedy(_seconds):
            clk.t += 10_000.0

        rec = None
        with self.assertRaises(ProbeRefused) as cm:
            run_steps(plan(conn(), ctx(), 40.0), Runner(), clock=clk, sleeper=clk.sleep,
                      workload=greedy)
        rec = cm.exception.record
        self.assertTrue(rec["watchdog_expired"])
        self.assertTrue(rec["cleanup_verified"], "cleanup must still run on the watchdog path")

    def test_a_workload_receives_the_requested_duration(self):
        seen = []
        with self.assertRaises(ProbeRefused):        # it returns at once, so it served nothing
            run(plan(conn(), ctx(), 12.5), Runner(), workload=seen.append)
        self.assertEqual(seen, [12.5])

    def test_a_workload_that_serves_the_hold_completes(self):
        """Non-vacuity: a workload that actually holds must still be able to succeed."""
        clk = FakeClock()

        def serve(seconds):
            clk.t += seconds

        rec = run_steps(plan(conn(), ctx(), 12.5), Runner(), clock=clk, sleeper=clk.sleep,
                        workload=serve)
        self.assertEqual(rec["status"], "completed")
        self.assertGreaterEqual(rec["elapsed_seconds"], 12.5)

    def test_a_blocked_workload_is_abandoned_rather_than_waited_on(self):
        """The watchdog must act while the workload is still running, not after it returns."""
        import threading
        release = threading.Event()
        clk = FakeClock()

        def blocked(_seconds):
            release.wait(5.0)

        def sleeper(seconds):
            clk.t += seconds                          # drive the fake clock past the watchdog

        try:
            with self.assertRaises(ProbeRefused) as cm:
                run_steps(plan(conn(), ctx(), 10.0), Runner(), clock=clk, sleeper=sleeper,
                          workload=blocked, slice_seconds=5.0)
            rec = cm.exception.record
            self.assertTrue(rec["watchdog_expired"])
            self.assertTrue(rec["workload_abandoned"])
            self.assertTrue(rec["cleanup_verified"], "the rule must be removed anyway")
        finally:
            release.set()


class TestCleanupProtection(unittest.TestCase):

    def test_a_failure_during_verification_still_removes_the_rule(self):
        """The defect: protection began after verification, so this path leaked a rule."""
        r = Runner(verify_installed_rc=1)
        with self.assertRaises(ProbeRefused) as cm:
            run(plan(conn(), ctx(), 5.0), r)
        self.assertFalse(r.installed, "the rule must not be left behind")
        self.assertIn("-D", [a for c in r.calls for a in c])
        self.assertTrue(cm.exception.record["rule_removed"])

    def test_an_exception_from_the_runner_still_removes_the_rule(self):
        r = Runner(raise_on="-C")
        with self.assertRaises(Exception):
            run(plan(conn(), ctx(), 5.0), r)
        self.assertIn("-D", [a for c in r.calls for a in c])

    def test_a_failed_install_does_not_attempt_removal(self):
        r = Runner(install_rc=1)
        with self.assertRaises(ProbeRefused) as cm:
            run(plan(conn(), ctx(), 5.0), r)
        self.assertNotIn("-D", [a for c in r.calls for a in c])
        self.assertFalse(cm.exception.record["rule_installed"])


class TestRemovalIsVerifiedHonestly(unittest.TestCase):

    def test_permission_denied_is_not_successful_removal(self):
        """The defect: any non-zero code counted as absence, including 'permission denied'."""
        r = Runner(verify_removed_rc=2)
        with self.assertRaises(ProbeRefused) as cm:
            run(plan(conn(), ctx(), 5.0), r)
        rec = cm.exception.record
        self.assertFalse(rec["cleanup_verified"])
        self.assertEqual(rec["status"], "cleanup unverified")
        self.assertTrue(any("Permission denied" in e for e in rec["errors"]))

    def test_only_the_absent_code_establishes_absence(self):
        rec, _ = run(plan(conn(), ctx(), 1.0), Runner(verify_removed_rc=RULE_ABSENT_RC))
        self.assertTrue(rec["cleanup_verified"])

    def test_a_failed_delete_is_reported(self):
        r = Runner(remove_rc=1)
        with self.assertRaises(ProbeRefused) as cm:
            run(plan(conn(), ctx(), 1.0), r)
        self.assertFalse(cm.exception.record["rule_removed"])


class TestErrorsCarryTheirEvidence(unittest.TestCase):

    def test_the_record_is_attached_to_the_raised_error(self):
        with self.assertRaises(ProbeRefused) as cm:
            run(plan(conn(), ctx(), 5.0), Runner(verify_removed_rc=2))
        rec = cm.exception.record
        self.assertTrue(rec["steps"], "the steps taken must survive the failure")
        self.assertEqual(rec["probe_id"], rec["probe_id"])
        self.assertIn("install", [s["step"] for s in rec["steps"]])

    def test_every_step_records_its_return_code(self):
        rec, _ = run(plan(conn(), ctx(), 1.0), Runner())
        for s in rec["steps"]:
            self.assertIn("returncode", s)
            self.assertIn("expected_returncode", s)


class TestOwnership(unittest.TestCase):

    def test_the_rule_carries_a_probe_specific_comment(self):
        p = plan(conn(), ctx(), 1.0)
        self.assertIn(p["probe_id"], p["commands"]["install"])
        self.assertIn("--comment", p["commands"]["install"])

    def test_two_plans_do_not_share_an_identity(self):
        self.assertNotEqual(plan(conn(), ctx(), 1.0)["probe_id"],
                            plan(conn(), ctx(), 1.0)["probe_id"])

    def test_removal_targets_this_probes_rule(self):
        p = plan(conn(), ctx(), 1.0)
        self.assertIn(p["probe_id"], p["commands"]["remove"])


class TestTheExecutedSelectionMatchesTheDocumentedOne(unittest.TestCase):

    def test_the_interface_is_actually_enforced(self):
        """The defect: the plan named an interface the rule never matched on."""
        p = plan(conn(interface="eth7"), ctx(), 1.0)
        self.assertIn("-o eth7", p["commands"]["install"])
        self.assertIn("eth7", p["selector"]["interface_enforced"])

    def test_the_inbound_experiment_matches_on_the_input_interface(self):
        p = plan(conn(interface="eth7"), ctx(), 1.0,
                 direction=Direction.DROP_OUTSTATION_RESPONSE)
        self.assertIn("-i eth7", p["commands"]["install"])
        self.assertTrue(p["commands"]["install"].startswith("iptables -A INPUT"))

    def test_the_two_directions_are_different_experiments(self):
        out = plan(conn(), ctx(), 1.0, direction=Direction.WITHHOLD_MASTER_ACK)
        inp = plan(conn(), ctx(), 1.0, direction=Direction.DROP_OUTSTATION_RESPONSE)
        self.assertEqual(out["selector"]["chain"], "OUTPUT")
        self.assertEqual(inp["selector"]["chain"], "INPUT")
        # Both carry a length bound, in opposite directions: the outbound one selects exactly a
        # header-only segment, the inbound one selects anything longer than that, so neither
        # experiment catches the other's packets.
        self.assertIn("--length 52:52", out["commands"]["install"])
        self.assertIn("--length 53:65535", inp["commands"]["install"])

    def test_the_inbound_rule_does_not_catch_pure_acknowledgments(self):
        """A rule with no length bound would also drop the outstation's own ACKs."""
        inp = plan(conn(), ctx(), 1.0, direction=Direction.DROP_OUTSTATION_RESPONSE)
        self.assertIn("53:65535", inp["commands"]["install"])
        self.assertIn("pure acknowledgments are not caught", inp["selector"]["implemented_as"])


class TestTheSelector(unittest.TestCase):

    def test_the_length_bound_is_computed_from_the_observed_header(self):
        self.assertIn("52:52", " ".join(payload_length_rule(conn(tcp_header_bytes=32))))
        self.assertIn("40:40", " ".join(payload_length_rule(conn(tcp_header_bytes=20))))

    def test_psh_is_not_used_as_a_payload_test(self):
        self.assertNotIn("PSH", " ".join(build_rule(conn(), Direction.WITHHOLD_MASTER_ACK, "x")))

    def test_an_unsupported_ip_header_is_refused(self):
        with self.assertRaises(ProbeRefused):
            plan(conn(ip_header_bytes=24), ctx(), 1.0)

    def test_an_illegal_tcp_header_length_is_refused(self):
        for bad in (19, 61, 33):
            with self.assertRaises(ProbeRefused):
                plan(conn(tcp_header_bytes=bad), ctx(), 1.0)

    def test_the_margin_to_the_smallest_data_segment_is_reported(self):
        sel = plan(conn(), ctx(), 1.0)["selector"]
        self.assertEqual(sel["smallest_data_segment_on_this_connection_B"], 52 + 20)
        self.assertEqual(sel["margin_B"], 20)


class TestIncompletePlansAreNotExecuted(unittest.TestCase):

    def test_an_unset_source_port_is_refused_at_execution(self):
        p = plan(conn(), ctx(), 1.0)
        p["connection"]["src_port"] = 0
        with self.assertRaises(ProbeRefused) as cm:
            run(p, Runner())
        self.assertIn("src_port", str(cm.exception))

    def test_an_unset_context_is_refused_at_execution(self):
        p = plan(conn(), ctx(), 1.0)
        p["context"]["loaded_program_sha256"] = "UNSET"
        with self.assertRaises(ProbeRefused) as cm:
            run(p, Runner())
        self.assertIn("loaded_program_sha256", str(cm.exception))

    def test_an_unread_shape_state_is_refused_at_execution(self):
        p = plan(conn(), ctx(), 1.0)
        p["context"]["shape_enable"] = -1
        with self.assertRaises(ProbeRefused) as cm:
            run(p, Runner())
        self.assertIn("shape_enable", str(cm.exception))

    def test_a_complete_plan_executes(self):
        """Non-vacuity: the refusals above must not reject every plan."""
        rec, _ = run(plan(conn(), ctx(), 1.0), Runner())
        self.assertEqual(rec["status"], "completed")


class TestTheGuard(unittest.TestCase):

    def test_apply_refuses_without_live(self):
        with self.assertRaises(ProbeRefused):
            apply(plan(conn(), ctx(), 1.0), Runner())

    def test_apply_refuses_without_the_environment_guard(self):
        self.assertNotEqual(os.environ.get(GUARD_ENV), "1",
                            "the offline test environment must never set this")
        with self.assertRaises(ProbeRefused) as cm:
            apply(plan(conn(), ctx(), 1.0), Runner(), live=True)
        self.assertIn(GUARD_ENV, str(cm.exception))

    def test_planning_is_pure(self):
        r = Runner()
        plan(conn(), ctx(), 40.0)
        self.assertEqual(r.calls, [])

    def test_a_nonpositive_or_nonfinite_hold_is_refused(self):
        """NaN fails every comparison, so `<= 0` alone let it through."""
        for bad in (0, -1, "40", float("nan"), float("inf")):
            with self.assertRaises(ProbeRefused, msg=repr(bad)):
                plan(conn(), ctx(), bad)

    def test_a_network_address_is_refused(self):
        """The probe is scoped to one connection; a prefix is not one connection."""
        for bad in ("192.168.10.0/24", "192.168.10", "not-an-ip"):
            with self.assertRaises(ProbeRefused, msg=bad):
                plan(conn(src_ip=bad), ctx(), 1.0)

    def test_a_nonfinite_slice_is_refused(self):
        with self.assertRaises(ProbeRefused):
            run_steps(plan(conn(), ctx(), 1.0), Runner(), slice_seconds=float("nan"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
