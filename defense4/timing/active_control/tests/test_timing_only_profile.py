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
from timing_only_profile import (ADAPTER_STATUS, ARMING_MODES,              # noqa: E402
                                 ActivationError, TimingOnlyProfile,
                                 activate, build_plan, quantize_ns, validate)


class RecordingDevice:
    """A stateful stand-in for a switch: reads reflect what was written.

    A static readback table cannot model this sequence, because `pktgen.app_cfg` is expected to
    read back disabled at step 6 and enabled at step 10. Modelling the state also stops a test
    passing because a fixed dict happened to contain the right answer.
    """

    def __init__(self, seed=None, fail_on=None, stuck=None):
        self.writes = []
        self._fail_on = fail_on
        self._stuck = stuck or {}          # table -> fields that ignore writes
        self.state = {
            "tbl_params": {"shape_enable": 0},
            "tm.port.sched_shaping": {},
            "$PORT": {},
            "registers": {},
            "tm.queue.sched_cfg": {},
            "pktgen.app_cfg": {},
            "tbl_session": {},
            "tbl_commit": {"map_complete": True},
        }
        for table, fields in (seed or {}).items():
            self.state.setdefault(table, {}).update(fields)

    def write(self, table, fields):
        if self._fail_on == table:
            raise OSError("simulated write failure on %s" % table)
        self.writes.append((table, dict(fields)))
        st = self.state.setdefault(table, {})
        if table == "tbl_params":
            st.update({k: v for k, v in fields.items()
                       if k in ("mode", "d_ticks", "da_dr", "budget", "shape_enable")})
        elif table == "tm.port.sched_shaping" and "disarm" in fields:
            st["shaper_armed"] = False
        elif table == "$PORT" and "bring_up" in fields:
            st["port_up"] = [p for p in fields["bring_up"] if p != 68]
        elif table == "registers" and "clear" in fields:
            st["cleared"] = True
        elif table == "tm.queue.sched_cfg":
            st["qid_priority_map"] = {q[0]: [q[1], q[2]]
                                      for q in fields.get("rrc", []) + fields.get("bor", [])}
        elif table == "pktgen.app_cfg":
            if "enable" in fields:
                st["app_enable"] = fields["enable"]
        elif table == "tbl_session" and "mirror_to" in fields:
            st["session_installed"] = True
        st.update(self._stuck.get(table, {}))

    def read(self, table):
        out = dict(self.state.get(table, {}))
        out.update(self._stuck.get(table, {}))
        return out


def _executable_source():
    """The module's source with its docstring and comment lines removed."""
    import ast
    with open(os.path.join(ROOT, "timing_only_profile.py")) as fh:
        src = fh.read()
    doc = ast.get_docstring(ast.parse(src))
    if doc:
        src = src.replace(doc, "", 1)
    return "\n".join(ln for ln in src.splitlines() if not ln.strip().startswith("#"))


def admitted():
    return {"verdict": "admitted_conditional"}


class TestShapingNeverEnabled(unittest.TestCase):
    """The defect this module exists to prevent."""

    def test_no_write_ever_sets_shape_enable_to_one(self):
        dev = RecordingDevice()
        rec = activate(TimingOnlyProfile(), dev, mock=True)
        self.assertEqual(rec["status"], "activated")
        shape_writes = [(t, f["shape_enable"]) for t, f in dev.writes if "shape_enable" in f]
        self.assertTrue(shape_writes, "no shape_enable was written at all; the path must "
                                      "positively write 0, not merely avoid the field")
        for table, value in shape_writes:
            self.assertEqual(value, 0, "%s wrote shape_enable=%r" % (table, value))

    def test_shaping_is_established_before_any_traffic_path(self):
        """Order matters: configuring forwarding first is how a run carries traffic unintended."""
        dev = RecordingDevice()
        activate(TimingOnlyProfile(), dev, mock=True)
        tables = [t for t, _ in dev.writes]
        first_shape = next(i for i, (t, f) in enumerate(dev.writes) if "shape_enable" in f)
        for traffic in ("$PORT", "pktgen.app_cfg", "tbl_session"):
            self.assertGreater(tables.index(traffic), first_shape,
                               "%s was configured before shaping was established" % traffic)

    def test_shaping_is_reread_from_its_own_table_after_every_step(self):
        dev = RecordingDevice()
        rec = activate(TimingOnlyProfile(), dev, mock=True)
        for entry in rec["steps"]:
            self.assertIn("shaping_probe", entry,
                          "step %r did not re-read shaping" % entry["name"])

    def test_shaping_turning_on_mid_sequence_is_caught_at_that_step(self):
        """A later step enabling shaping as a side effect is caught where it happened."""

        class FlipsOnPortBringUp(RecordingDevice):
            def write(self, table, fields):
                super().write(table, fields)
                if table == "$PORT":                     # a side effect nobody asked for
                    self.state["tbl_params"]["shape_enable"] = 1

        dev = FlipsOnPortBringUp()
        with self.assertRaises(ActivationError) as cm:
            activate(TimingOnlyProfile(), dev, mock=True)
        self.assertIn("shaping is enabled after ports", str(cm.exception).lower())
        self.assertEqual(cm.exception.record["failure"]["stage"], "ports")

    def test_an_unreadable_shape_field_is_not_treated_as_off(self):
        """Absence is not evidence of zero. The probe itself must refuse."""
        class Blind(RecordingDevice):
            def read(self, table):
                out = super().read(table)
                out.pop("shape_enable", None)
                return out

        rec = {}
        with self.assertRaises(ActivationError) as cm:
            top._assert_shaping_off(Blind(), rec, "a step")
        self.assertIn("could not be read", str(cm.exception))
        self.assertIn("could not be established", rec["failure"]["reason"])

    def test_module_contains_no_code_that_enables_shaping(self):
        """Source-level check on EXECUTABLE lines only.

        The module docstring quotes the frozen defect verbatim, including `on=True`, so a naive
        whole-file scan would trip on the very explanation of what is being prevented.
        """
        code = _executable_source()
        for forbidden in ('shape_enable": 1', "shape_enable': 1", "shape_enable=1",
                          "on=True", "shape_enable\", 1"):
            self.assertNotIn(forbidden, code,
                             "the timing-only path must not contain %r in code" % forbidden)

    def test_the_source_scan_would_actually_catch_a_real_violation(self):
        self.assertIn("shape_enable", _executable_source(),
                      "the executable source should still mention shape_enable, which it "
                      "writes as 0; an empty scan would make the test above meaningless")

    def test_no_step_enables_shaping_and_the_last_asserts_it_off(self):
        plan = build_plan(TimingOnlyProfile())
        for step in plan["steps"]:
            self.assertNotEqual(step["write"].get("shape_enable", 0), 1)
        self.assertEqual(plan["steps"][-1]["expect"].get("shape_enable"), 0)


class TestValidationDoesNotRaiseOrAdmitNonsense(unittest.TestCase):

    def test_a_positive_delay_that_truncates_to_zero_is_rejected(self):
        """0.0001 ms is 100 ns, below one 256 ns tick, so it is no hold at all."""
        self.assertEqual(quantize_ns(0.0001), 0)
        problems = validate(TimingOnlyProfile(d_a_ms=0.0001))
        self.assertTrue(any("no hold at all" in p for p in problems))

    def test_nan_and_infinity_are_reported_not_raised(self):
        for bad in (float("nan"), float("inf"), float("-inf")):
            problems = validate(TimingOnlyProfile(d_a_ms=bad))
            self.assertTrue(problems, "%r was accepted" % bad)

    def test_an_out_of_range_port_is_rejected(self):
        self.assertTrue(validate(TimingOnlyProfile(port_master=99999)))
        self.assertTrue(validate(TimingOnlyProfile(port_master=-1)))

    def test_an_out_of_range_queue_id_is_rejected(self):
        bad = TimingOnlyProfile(queue_plan_rrc=(("A", 99, 7), ("B", 6, 6),
                                                ("C", 5, 5), ("D", 4, 4)))
        self.assertTrue(validate(bad))

    def test_a_non_integer_budget_is_rejected(self):
        self.assertTrue(validate(TimingOnlyProfile(budget=1.5)))
        self.assertTrue(validate(TimingOnlyProfile(budget=0)))

    def test_queue_id_need_not_equal_priority(self):
        """They are separate numbers. Requiring identity was an assumption, not a constraint."""
        ok = TimingOnlyProfile(queue_plan_rrc=(("A", 7, 31), ("B", 6, 30),
                                               ("C", 5, 29), ("D", 4, 28)),
                               queue_plan_bor=(("E", 3, 27), ("F", 2, 26)))
        self.assertEqual(validate(ok), [])

    def test_duplicate_priorities_are_rejected(self):
        bad = TimingOnlyProfile(queue_plan_rrc=(("A", 7, 6), ("B", 6, 6),
                                                ("C", 5, 5), ("D", 4, 4)))
        self.assertTrue(any("priorities are not distinct" in p for p in validate(bad)))

    def test_a_ladder_out_of_descending_order_is_rejected(self):
        bad = TimingOnlyProfile(queue_plan_rrc=(("A", 7, 4), ("B", 6, 5),
                                                ("C", 5, 6), ("D", 4, 7)))
        self.assertTrue(any("descending" in p for p in validate(bad)))

    def test_duplicate_ports_are_rejected(self):
        self.assertTrue(validate(TimingOnlyProfile(port_relay=9)))

    def test_a_hold_above_the_enforced_clamp_is_rejected(self):
        """The control plane refuses above 40 ms; this must refuse before reaching it.

        Observed on hardware 2026-09-16: configure-all refused 2200 ms with
        "D = 2200.000000 ms exceeds the 40.0 ms clamp", while its own dry-run model accepted the
        same input.
        """
        self.assertEqual(validate(TimingOnlyProfile(d_a_ms=40.0)), [])
        for bad in (41.0, 100.0, 2200.0):
            problems = validate(TimingOnlyProfile(d_a_ms=bad))
            self.assertTrue(any("clamp" in p for p in problems), bad)

    def test_a_clean_profile_has_no_problems(self):
        """Non-vacuity: the negative tests above would be meaningless if nothing ever passed."""
        self.assertEqual(validate(TimingOnlyProfile()), [])


class TestModesMatchTheLoadedBuild(unittest.TestCase):

    def test_only_the_modes_that_arm_are_offered(self):
        self.assertEqual(set(ARMING_MODES), {"OFF", "D4"})

    def test_a_mode_that_never_arms_is_rejected_and_explained(self):
        problems = validate(TimingOnlyProfile(mode="D2"))
        self.assertTrue(problems)
        self.assertIn("never arms", problems[0])

    def test_the_plan_records_which_modes_never_arm(self):
        modes = build_plan(TimingOnlyProfile())["modes"]
        self.assertEqual(set(modes["accepted_but_never_arming"]), {"D1", "D2", "D3"})


class TestReadbackMismatch(unittest.TestCase):

    def test_wrong_timing_word_is_detected_and_aborts(self):
        dev = RecordingDevice(stuck={"tbl_params": {"d_ticks": 123456, "shape_enable": 0}})
        with self.assertRaises(ActivationError):
            activate(TimingOnlyProfile(), dev, mock=True)

    def test_mismatch_stops_the_sequence_rather_than_continuing(self):
        dev = RecordingDevice(stuck={"tm.queue.sched_cfg": {"qid_priority_map": {}}})
        with self.assertRaises(ActivationError):
            activate(TimingOnlyProfile(), dev, mock=True)
        self.assertNotIn("pktgen.app_cfg", [t for t, _ in dev.writes],
                         "pktgen was armed after an earlier step had already failed")

    def test_missing_field_counts_as_a_mismatch_not_a_pass(self):
        dev = RecordingDevice()
        dev.state["$PORT"] = {}
        real = dev.write

        def write(table, fields):
            real(table, fields)
            if table == "$PORT":
                dev.state["$PORT"].pop("port_up", None)

        dev.write = write
        with self.assertRaises(ActivationError):
            activate(TimingOnlyProfile(), dev, mock=True)

    def test_a_generic_success_flag_does_not_satisfy_a_field_expectation(self):
        """`{"ok": True}` is not evidence that d_ticks holds the intended value."""

        class OnlySaysOk(RecordingDevice):
            def read(self, table):
                if table == "tbl_params":
                    return {"ok": True, "shape_enable": 0}
                return super().read(table)

        with self.assertRaises(ActivationError) as cm:
            activate(TimingOnlyProfile(), OnlySaysOk(), mock=True)
        self.assertIn("timing params", cm.exception.record["failure"]["stage"])


class TestFailuresKeepTheirEvidence(unittest.TestCase):

    def test_the_partial_record_is_attached_to_the_error(self):
        """The docstring promised this and the code did not do it."""
        dev = RecordingDevice(fail_on="tbl_params")
        with self.assertRaises(ActivationError) as cm:
            activate(TimingOnlyProfile(), dev, mock=True)
        rec = cm.exception.record
        self.assertTrue(rec, "the error carried no record")
        self.assertEqual(rec["status"], "aborted")
        self.assertIn("failure", rec)

    def test_a_rejected_profile_attaches_its_problems(self):
        with self.assertRaises(ActivationError) as cm:
            activate(TimingOnlyProfile(mode="NOT_A_MODE"), RecordingDevice(), mock=True)
        self.assertEqual(cm.exception.record["failure"]["stage"], "validation")

    def test_invalid_profile_is_rejected_before_any_write(self):
        dev = RecordingDevice()
        with self.assertRaises(ActivationError):
            activate(TimingOnlyProfile(mode="NOT_A_MODE"), dev, mock=True)
        self.assertEqual(dev.writes, [], "a rejected profile still wrote to the device")

    def test_device_write_failure_aborts_and_does_not_arm_pktgen(self):
        dev = RecordingDevice(fail_on="tbl_params")
        with self.assertRaises(ActivationError):
            activate(TimingOnlyProfile(), dev, mock=True)
        armed = [f for t, f in dev.writes if t == "pktgen.app_cfg" and f.get("enable")]
        self.assertEqual(armed, [])


class TestQuantisation(unittest.TestCase):

    def test_quantisation_residual_is_reported_not_absorbed(self):
        p = TimingOnlyProfile(d_a_ms=20.0001)
        self.assertEqual(quantize_ns(p.d_a_ms) & 0xFF, 0)
        self.assertEqual(build_plan(p)["quantisation"]["d_a_residual_ns"], 100)

    def test_an_exactly_aligned_delay_reports_no_residual(self):
        self.assertEqual(build_plan(TimingOnlyProfile(d_a_ms=20.0))
                         ["quantisation"]["d_a_residual_ns"], 0)

    def test_quantize_refuses_a_nonfinite_duration(self):
        with self.assertRaises(ValueError):
            quantize_ns(float("nan"))


class TestAdmissionIsWiredIn(unittest.TestCase):

    def test_a_non_mock_activation_requires_an_admission_verdict(self):
        with self.assertRaises(ActivationError) as cm:
            activate(TimingOnlyProfile(), RecordingDevice(), mock=False)
        self.assertIn("admission verdict", str(cm.exception))

    def test_a_refused_policy_is_never_applied(self):
        dev = RecordingDevice()
        with self.assertRaises(ActivationError):
            activate(TimingOnlyProfile(), dev, mock=False, admission={"verdict": "refused"})
        self.assertEqual(dev.writes, [])

    def test_a_rejected_policy_is_never_applied(self):
        dev = RecordingDevice()
        with self.assertRaises(ActivationError):
            activate(TimingOnlyProfile(), dev, mock=False, admission={"verdict": "rejected"})
        self.assertEqual(dev.writes, [])

    def test_an_admitted_policy_proceeds(self):
        rec = activate(TimingOnlyProfile(), RecordingDevice(), mock=False,
                       admission=admitted())
        self.assertEqual(rec["status"], "activated")
        self.assertEqual(rec["admission"], admitted())


class TestMockIsNeverEvidence(unittest.TestCase):

    def test_mock_run_is_labelled_and_disclaims_switch_state(self):
        rec = activate(TimingOnlyProfile(), RecordingDevice(), mock=True)
        self.assertEqual(rec["source"], "mock")
        self.assertFalse(rec["is_evidence_of_switch_state"])

    def test_live_label_is_only_set_when_the_caller_says_so(self):
        rec = activate(TimingOnlyProfile(), RecordingDevice(), mock=False,
                       admission=admitted())
        self.assertEqual(rec["source"], "switch")
        self.assertTrue(rec["is_evidence_of_switch_state"])

    def test_every_record_states_that_no_adapter_is_implemented(self):
        rec = activate(TimingOnlyProfile(), RecordingDevice(), mock=True)
        self.assertEqual(rec["adapter_status"], ADAPTER_STATUS)
        self.assertIn("no device adapter", ADAPTER_STATUS)

    def test_the_plan_names_what_it_does_not_configure(self):
        plan = build_plan(TimingOnlyProfile())
        self.assertTrue(plan["not_configured_here"])
        self.assertTrue(any("bfrt_grpc" in x for x in plan["not_configured_here"]))


class TestImportsResolveWhereIntended(unittest.TestCase):
    """A wrapper must not silently resolve a module from another worktree or a user path."""

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
