#!/usr/bin/env python3
"""Offline tests for the timing-only activation path. No socket, no device, no hardware.

These are adversarial on purpose. Most feed the activation something wrong and assert that it
refuses, because a suite that only feeds good input cannot show that a fail-closed path is
fail-closed. Every test states what it would take to make it pass spuriously.

    python3 tests/test_timing_only_profile.py
"""
from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import timing_only_profile as top                                           # noqa: E402
from timing_only_profile import (ActivationError, TimingOnlyProfile,        # noqa: E402
                                 activate, build_plan, quantize_ns, validate)


class RecordingDevice:
    """A scripted stand-in for a switch. Records every write; never touches anything."""

    def __init__(self, readback=None, fail_on=None):
        self.writes = []
        self._readback = readback or {}
        self._fail_on = fail_on

    def write(self, table, fields):
        if self._fail_on == table:
            raise OSError("simulated write failure on %s" % table)
        self.writes.append((table, dict(fields)))

    def read(self, table):
        return dict(self._readback.get(table, {}))


def _executable_source():
    """The module's source with its docstring and comment lines removed."""
    import ast
    with open(os.path.join(ROOT, "timing_only_profile.py")) as fh:
        src = fh.read()
    doc = ast.get_docstring(ast.parse(src))
    if doc:
        src = src.replace(doc, "", 1)
    return "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))


def good_readback(p=None):
    """Readbacks that agree with the plan, so activation should succeed."""
    p = p or TimingOnlyProfile()
    d_a, clrt = quantize_ns(p.d_a_ms), quantize_ns(p.clrt_new_ms)
    return {
        "$PORT": {"port_up": [p.port_loopback_rrc, p.port_loopback_bor,
                              p.port_master, p.port_relay]},
        "tm.queue.sched_cfg": {"strict_priority_descending": True},
        "tbl_params": {"mode": p.mode, "d_ticks": d_a, "da_dr": d_a + clrt,
                       "budget": p.budget, "shape_enable": 0},
        "pktgen.app_cfg": {"app_enable": True},
    }


class TestShapingNeverEnabled(unittest.TestCase):
    """The defect this module exists to prevent."""

    def test_no_write_ever_sets_shape_enable_to_one(self):
        dev = RecordingDevice(good_readback())
        rec = activate(TimingOnlyProfile(), dev, mock=True)
        self.assertEqual(rec["status"], "activated")
        shape_writes = [(t, f["shape_enable"]) for t, f in dev.writes if "shape_enable" in f]
        self.assertTrue(shape_writes, "no shape_enable was written at all; the path must "
                                      "positively write 0, not merely avoid the field")
        for table, value in shape_writes:
            self.assertEqual(value, 0, "%s wrote shape_enable=%r" % (table, value))

    def test_module_contains_no_code_that_enables_shaping(self):
        """Source-level check on EXECUTABLE lines only.

        The module docstring quotes the frozen defect verbatim, including `on=True`, so a naive
        whole-file scan would trip on the very explanation of what is being prevented. This
        strips the docstring and comments and scans what actually runs.
        """
        code = _executable_source()
        for forbidden in ('shape_enable": 1', "shape_enable': 1", "shape_enable=1",
                          "on=True", "shape_enable\", 1"):
            self.assertNotIn(forbidden, code,
                             "the timing-only path must not contain %r in code" % forbidden)

    def test_the_docstring_scan_would_actually_catch_a_real_violation(self):
        """Non-vacuity: prove the scan is not passing because it looks at nothing."""
        self.assertIn("shape_enable", _executable_source(),
                      "the executable source should still mention shape_enable, which it "
                      "writes as 0; an empty scan would make the test above meaningless")

    def test_activation_aborts_if_shaping_becomes_enabled_mid_sequence(self):
        """A step that turns shaping on as a side effect is caught at that step."""
        rb = good_readback()
        rb["tbl_params"] = dict(rb["tbl_params"], shape_enable=1)
        dev = RecordingDevice(rb)
        with self.assertRaises(ActivationError) as cm:
            activate(TimingOnlyProfile(), dev, mock=True)
        self.assertIn("shape", str(cm.exception).lower())

    def test_final_step_asserts_shaping_off(self):
        plan = build_plan(TimingOnlyProfile())
        last = plan["steps"][-1]
        self.assertEqual(last["expect"].get("shape_enable"), 0,
                         "the sequence must end by asserting shaping is still off")


class TestReadbackMismatch(unittest.TestCase):

    def test_wrong_timing_word_is_detected_and_aborts(self):
        rb = good_readback()
        rb["tbl_params"] = dict(rb["tbl_params"], d_ticks=123456)      # not what was written
        dev = RecordingDevice(rb)
        with self.assertRaises(ActivationError):
            activate(TimingOnlyProfile(), dev, mock=True)

    def test_mismatch_stops_the_sequence_rather_than_continuing(self):
        rb = good_readback()
        rb["tm.queue.sched_cfg"] = {"strict_priority_descending": False}
        dev = RecordingDevice(rb)
        with self.assertRaises(ActivationError):
            activate(TimingOnlyProfile(), dev, mock=True)
        tables = [t for t, _ in dev.writes]
        self.assertNotIn("pktgen.app_cfg", tables,
                         "pktgen was armed after an earlier step had already failed")

    def test_missing_field_counts_as_a_mismatch_not_a_pass(self):
        rb = good_readback()
        rb["tbl_params"] = {}                                          # empty read
        dev = RecordingDevice(rb)
        with self.assertRaises(ActivationError):
            activate(TimingOnlyProfile(), dev, mock=True)


class TestPrerequisiteFailure(unittest.TestCase):

    def test_invalid_profile_is_rejected_before_any_write(self):
        bad = TimingOnlyProfile(mode="NOT_A_MODE")
        dev = RecordingDevice(good_readback())
        with self.assertRaises(ActivationError):
            activate(bad, dev, mock=True)
        self.assertEqual(dev.writes, [], "a rejected profile still wrote to the device")

    def test_device_write_failure_aborts_and_does_not_arm_pktgen(self):
        dev = RecordingDevice(good_readback(), fail_on="tbl_params")
        with self.assertRaises(ActivationError):
            activate(TimingOnlyProfile(), dev, mock=True)
        self.assertNotIn("pktgen.app_cfg", [t for t, _ in dev.writes])

    def test_quantisation_residual_is_reported_not_absorbed(self):
        """A delay that does not land on a 256 ns tick must say so in the plan.

        20.0001 ms is 20,000,100 ns, which is 100 ns above the nearest whole tick. The written
        word is still tick-aligned, and the 100 ns the caller did not get is stated.
        """
        p = TimingOnlyProfile(d_a_ms=20.0001)
        word = quantize_ns(p.d_a_ms)
        self.assertEqual(word & 0xFF, 0, "the written word must stay tick-aligned")
        plan = build_plan(p)
        self.assertEqual(plan["quantisation"]["d_a_residual_ns"], 100)

    def test_an_exactly_aligned_delay_reports_no_residual(self):
        plan = build_plan(TimingOnlyProfile(d_a_ms=20.0))
        self.assertEqual(plan["quantisation"]["d_a_residual_ns"], 0)

    def test_duplicate_ports_and_queue_ids_are_rejected(self):
        self.assertTrue(validate(TimingOnlyProfile(port_relay=9)))
        broken = TimingOnlyProfile(queue_plan_rrc=(("A", 7, 6), ("B", 6, 6),
                                                   ("C", 5, 5), ("D", 4, 4)))
        self.assertTrue(validate(broken), "qid != priority must be rejected")

    def test_a_clean_profile_has_no_problems(self):
        """Non-vacuity: the negative tests above would be meaningless if nothing ever passed."""
        self.assertEqual(validate(TimingOnlyProfile()), [])


class TestMockIsNeverEvidence(unittest.TestCase):

    def test_mock_run_is_labelled_and_disclaims_switch_state(self):
        rec = activate(TimingOnlyProfile(), RecordingDevice(good_readback()), mock=True)
        self.assertEqual(rec["source"], "mock")
        self.assertFalse(rec["is_evidence_of_switch_state"])

    def test_live_label_is_only_set_when_the_caller_says_so(self):
        rec = activate(TimingOnlyProfile(), RecordingDevice(good_readback()), mock=False)
        self.assertEqual(rec["source"], "switch")
        self.assertTrue(rec["is_evidence_of_switch_state"])


class TestImportsResolveWhereIntended(unittest.TestCase):
    """§3: a wrapper must not silently resolve a module from another worktree or a user path."""

    def test_module_file_is_inside_this_repository(self):
        here = os.path.abspath(top.__file__)
        repo = os.path.abspath(os.path.join(ROOT, "..", "..", ".."))
        self.assertTrue(here.startswith(repo + os.sep),
                        "timing_only_profile resolved to %s, outside %s" % (here, repo))
        self.assertIn(os.path.join("defense4", "timing", "active_control"), here)

    def test_it_imports_nothing_from_the_frozen_implementation(self):
        src = open(os.path.join(ROOT, "timing_only_profile.py")).read()
        for frozen in ("implementation", "defense4_caseA_setup", "defense4_rrc_setup",
                       "defense4_rrc_bor_unified12_setup", "bfrt_grpc"):
            for line in src.splitlines():
                stripped = line.strip()
                if stripped.startswith(("import ", "from ")):
                    self.assertNotIn(frozen, stripped,
                                     "this path must not import %r: %s" % (frozen, stripped))

    def test_no_absolute_user_paths_are_baked_in(self):
        src = open(os.path.join(ROOT, "timing_only_profile.py")).read()
        for bad in ("/home/", "/Users/", "C:\\\\"):
            self.assertNotIn(bad, src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
