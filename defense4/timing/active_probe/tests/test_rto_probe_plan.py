#!/usr/bin/env python3
"""Offline tests for the corrected probe. No firewall, no socket, no hardware.

Each test targets one of the four defects the 2026-09-15 review found in the original probe,
plus the guards that keep this one from running by accident.

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

import rto_probe_plan as rp                                                  # noqa: E402
from rto_probe_plan import (Connection, ProbeRefused, RunContext, apply,  # noqa: E402
                            run_steps)
from rto_probe_plan import plan                                             # noqa: E402


def conn(src_port=46636, tcp_hdr=32):
    return Connection(src_ip="192.168.10.1", src_port=src_port, dst_ip="192.168.10.7",
                      dst_port=20000, interface="enp59s0f0np0", tcp_header_bytes=tcp_hdr)


def ctx():
    return RunContext(capture_host="master", capture_point="master-facing NIC",
                      capture_precision="nanosecond", timing_mode="OFF", shape_enable=0,
                      loaded_program="defense4_rrc_bor_unified12",
                      loaded_program_sha256="7ce30494668df427")


class ScriptedRunner:
    """Returns a scripted return code per command, recording what it was asked to run."""

    def __init__(self, codes=None):
        self.calls = []
        self._codes = codes or {}

    def __call__(self, argv):
        key = argv[1] if len(argv) > 1 else argv[0]        # -A / -C / -D
        self.calls.append(argv)
        rc = self._codes.get(key, 0)
        if callable(rc):
            rc = rc(len([c for c in self.calls if c[1] == key]))
        return rc, "", ""


class TestSelectorIsAPayloadTestNotAFlagGuess(unittest.TestCase):

    def test_psh_is_not_used_to_infer_payload(self):
        cmd = plan(conn(), ctx(), 40.0)["commands"]["install"]
        self.assertNotIn("PSH", cmd,
                         "PSH-clear is not a payload-length test and must not be the selector")

    def test_selector_is_an_exact_length_derived_from_the_connection(self):
        p = plan(conn(tcp_hdr=32), ctx(), 40.0)
        self.assertIn("--length 52:52", p["commands"]["install"])     # 20 IPv4 + 32 TCP
        self.assertEqual(p["selector"]["smallest_data_segment_on_this_connection_B"], 72)

    def test_a_different_tcp_header_size_changes_the_bound(self):
        """Non-vacuity: the bound is computed, not hard-coded."""
        self.assertIn("--length 40:40", plan(conn(tcp_hdr=20), ctx(), 40.0)["commands"]["install"])

    def test_handshake_and_teardown_are_excluded(self):
        cmd = plan(conn(), ctx(), 40.0)["commands"]["install"]
        self.assertIn("SYN,RST,FIN,ACK ACK", cmd.replace("'", ""))


class TestScopedToOneConnection(unittest.TestCase):

    def test_rule_pins_all_four_tuple_elements(self):
        cmd = plan(conn(src_port=46636), ctx(), 40.0)["commands"]["install"]
        for token in ("-s 192.168.10.1", "--sport 46636",
                      "-d 192.168.10.7", "--dport 20000"):
            self.assertIn(token, cmd.replace("'", ""), "missing %r; the rule is too broad" % token)

    def test_two_connections_produce_different_rules(self):
        a = plan(conn(src_port=1111), ctx(), 40.0)["commands"]["install"]
        b = plan(conn(src_port=2222), ctx(), 40.0)["commands"]["install"]
        self.assertNotEqual(a, b, "the rule does not depend on the probe's own source port")


class TestFailuresAreNotSwallowed(unittest.TestCase):

    def test_failed_install_raises_and_does_not_claim_a_capture(self):
        r = ScriptedRunner({"-A": 1})
        with self.assertRaises(ProbeRefused):
            run_steps(plan(conn(), ctx(), 1.0), r)

    def test_failed_removal_is_reported_rather_than_announced_as_success(self):
        # -D succeeds but the rule is still present, so -C keeps returning 0
        r = ScriptedRunner({"-C": 0, "-D": 0})
        with self.assertRaises(ProbeRefused) as cm:
            run_steps(plan(conn(), ctx(), 1.0), r)
        self.assertIn("NOT confirmed removed", str(cm.exception))

    def test_clean_run_confirms_removal_by_checking_not_by_printing(self):
        # -C returns 0 while installed, then non-zero after removal
        state = {"n": 0}

        def codes(_):
            state["n"] += 1
            return 0 if state["n"] == 1 else 1
        r = ScriptedRunner({"-C": codes})
        rec = run_steps(plan(conn(), ctx(), 1.0), r)
        self.assertEqual(rec["status"], "completed")
        self.assertTrue(rec["rule_removed"])
        self.assertIn("-D", [c[1] for c in r.calls])


class TestGuards(unittest.TestCase):

    def test_default_is_a_dry_run(self):
        with self.assertRaises(ProbeRefused):
            apply(plan(conn(), ctx(), 1.0), ScriptedRunner(), live=False)

    def test_live_still_requires_the_environment_guard(self):
        old = os.environ.pop(rp.GUARD_ENV, None)
        try:
            with self.assertRaises(ProbeRefused) as cm:
                apply(plan(conn(), ctx(), 1.0), ScriptedRunner(), live=True)
            self.assertIn(rp.GUARD_ENV, str(cm.exception))
        finally:
            if old is not None:
                os.environ[rp.GUARD_ENV] = old

    def test_plan_touches_nothing(self):
        r = ScriptedRunner()
        plan(conn(), ctx(), 40.0)
        self.assertEqual(r.calls, [])

    def test_module_builds_no_dnp3_frame_at_all(self):
        """The probe must not construct protocol traffic of any kind, control or otherwise.

        Scans executable lines, not the docstring, which legitimately says the words SELECT and
        OPERATE while promising not to build them.
        """
        import ast
        with open(os.path.join(ROOT, "rto_probe_plan.py")) as fh:
            src = fh.read()
        doc = ast.get_docstring(ast.parse(src))
        code = "\n".join(ln for ln in src.replace(doc or "", "", 1).splitlines()
                          if not ln.strip().startswith("#"))
        for forbidden in ("fromhex", "0564", "crob", "sendall", "socket", "connect("):
            self.assertNotIn(forbidden, code.lower(),
                             "the probe must build no frames and open no socket (%r)" % forbidden)

    def test_that_scan_is_not_vacuous(self):
        import ast
        with open(os.path.join(ROOT, "rto_probe_plan.py")) as fh:
            src = fh.read()
        doc = ast.get_docstring(ast.parse(src))
        code = src.replace(doc or "", "", 1)
        self.assertIn("iptables", code, "the scan should still see the module's real content")


class TestContextIsRecorded(unittest.TestCase):

    def test_shape_state_and_build_identity_are_in_the_plan(self):
        p = plan(conn(), ctx(), 40.0)
        for k in ("timing_mode", "shape_enable", "loaded_program_sha256",
                  "capture_precision", "capture_point"):
            self.assertIn(k, p["context"],
                          "%r is exactly what was missing when the archived captures were "
                          "taken with shaping on without anyone noticing" % k)

    def test_a_negative_hold_is_refused(self):
        with self.assertRaises(ProbeRefused):
            plan(conn(), ctx(), 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
