#!/usr/bin/env python3
"""Offline tests for the latency-search hardware block runner."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("latency_run_block", ROOT / "run_block.py")
run_block = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = run_block
SPEC.loader.exec_module(run_block)


class FakeOutcome:
    def __init__(self, operation, outcome="OK", ok=True):
        self.operation = operation
        self.outcome = outcome
        self.ok = ok
        self.problems = [] if ok else [outcome.lower()]

    def as_dict(self):
        return {
            "operation": self.operation,
            "outcome": self.outcome,
            "ok": self.ok,
            "problems": list(self.problems),
        }


class FakeSession:
    def __init__(self, _host, _port, source_address=None):
        self.source_address = source_address

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def transaction(self, **kwargs):
        raise AssertionError("test did not install transaction behavior")


class FakeCapture:
    def __init__(self, command):
        self.command = command
        self.signals = []

    def poll(self):
        return None

    def send_signal(self, sig):
        self.signals.append(sig)

    def wait(self, timeout=None):
        self.wait_timeout = timeout
        return 0


class TestPlanning(unittest.TestCase):
    def test_duration_is_derived_from_read_and_sbo_transaction_budgets(self):
        plan = run_block.build_plan("D4_05_01", reads=100, sbo=100, gap_ms=400,
                                    budget_ms=500, root=Path("/tmp/root"),
                                    now=run_block.datetime(2026, 9, 26, 12, 13, 14, 123456,
                                                           tzinfo=run_block.timezone.utc))
        self.assertEqual(plan.duration_s, 256)
        self.assertEqual(plan.read_jsonl.name, "D4_05_01_20260926T121314123456Z_read.jsonl")
        self.assertEqual(plan.sbo_jsonl.name, "D4_05_01_20260926T121314123456Z_sbo.jsonl")
        self.assertEqual(plan.pcap.name, "D4_05_01_20260926T121314123456Z.pcapng")
        self.assertNotEqual(plan.read_jsonl.parent, plan.pcap.parent)

    def test_live_refuses_without_explicit_hardware_authorization(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ, {}, clear=True):
            rc = run_block.main(["case", "--root", td, "--reads", "1", "--sbo", "0"])
        self.assertEqual(rc, 2)

    def test_dry_run_writes_plan_without_hardware_authorization(self):
        with tempfile.TemporaryDirectory() as td, mock.patch.dict(os.environ, {}, clear=True):
            rc = run_block.main(["case", "--root", td, "--reads", "2", "--sbo", "1",
                                 "--dry-run"])
            status = json.loads(next(Path(td).glob("case/status.json")).read_text())
        self.assertEqual(rc, 0)
        self.assertTrue(status["dry_run"])
        self.assertEqual(status["read_count"], 2)
        self.assertEqual(status["sbo_count"], 1)
        self.assertGreaterEqual(status["capture_duration_s"], 6)


class TestExecution(unittest.TestCase):
    def run_with_fakes(self, tmp, *, read_outcomes, sbo_pairs=()):
        capture = FakeCapture([])
        output_checks = []
        read_iter = iter(read_outcomes)
        sbo_iter = iter(sbo_pairs)

        def fake_popen(command, stdout=None, stderr=None):
            capture.command = command
            return capture

        def fake_run(command, env=None, stdout=None, stderr=None, timeout=None, cwd=None):
            output_checks.append(Path(command[1]).name)
            if stdout is not None:
                stdout.write('{"points": 32, "all_open": true, "all_online": true}\\n')
            return subprocess.CompletedProcess(command, 0)

        def fake_build_read(seq):
            return b"read-%d" % seq

        def fake_one_sbo(session, seq_select, seq_operate, points, budget_ms, select_only):
            return next(sbo_iter)

        def fake_read_transaction(self, **kwargs):
            return next(read_iter)

        with mock.patch.dict(os.environ, {"DEFENSE4_HW_AUTHORIZED": "1"}), \
             mock.patch.object(run_block.subprocess, "Popen", fake_popen), \
             mock.patch.object(run_block.subprocess, "run", fake_run), \
             mock.patch.object(run_block, "Session", FakeSession), \
             mock.patch.object(run_block.read_driver, "build", fake_build_read), \
             mock.patch.object(run_block.sbo_driver, "one_sbo", fake_one_sbo), \
             mock.patch.object(FakeSession, "transaction", fake_read_transaction), \
             mock.patch.object(run_block.time, "sleep", lambda _seconds: None):
            rc = run_block.main(["case", "--root", tmp, "--reads", "3", "--sbo", "2",
                                 "--gap-ms", "400", "--budget-ms", "500"])
        return rc, capture, output_checks

    def test_read_failure_stops_block_and_preserves_partial_jsonl(self):
        with tempfile.TemporaryDirectory() as td:
            rc, capture, output_checks = self.run_with_fakes(
                td,
                read_outcomes=[
                    FakeOutcome("READ"),
                    FakeOutcome("READ", "TIMEOUT", ok=False),
                    FakeOutcome("READ"),
                ],
            )
            out = Path(td) / "case"
            read_rows = (out / "app_jsonl").glob("*_read.jsonl")
            rows = [json.loads(line) for line in next(read_rows).read_text().splitlines()]
            status = json.loads((out / "status.json").read_text())
        self.assertEqual(rc, 1)
        self.assertEqual([row["outcome"] for row in rows], ["OK", "TIMEOUT"])
        self.assertEqual(status["error"], "READ transaction 2 failed: TIMEOUT (timeout)")
        self.assertEqual(status["read_completed"], 2)
        self.assertEqual(status.get("sbo_completed", 0), 0)
        self.assertEqual(output_checks, ["read_outputs.py", "read_outputs.py"])
        self.assertIn("-a", capture.command)
        self.assertTrue(capture.signals)

    def test_sbo_failure_stops_without_more_operates_and_preserves_select_operate_pair(self):
        failed_pair = (
            FakeOutcome("SELECT"),
            FakeOutcome("OPERATE", "INVALID", ok=False),
        )
        unused_pair = (
            FakeOutcome("SELECT"),
            FakeOutcome("OPERATE"),
        )
        with tempfile.TemporaryDirectory() as td:
            rc, _capture, _output_checks = self.run_with_fakes(
                td,
                read_outcomes=[FakeOutcome("READ"), FakeOutcome("READ"), FakeOutcome("READ")],
                sbo_pairs=[failed_pair, unused_pair],
            )
            out = Path(td) / "case"
            rows = [json.loads(line) for line in
                    next((out / "app_jsonl").glob("*_sbo.jsonl")).read_text().splitlines()]
            status = json.loads((out / "status.json").read_text())
        self.assertEqual(rc, 1)
        self.assertEqual([row["operation"] for row in rows], ["SELECT", "OPERATE"])
        self.assertEqual(status["error"], "SBO transaction 1 failed at OPERATE: INVALID (invalid)")
        self.assertEqual(status["sbo_completed"], 1)

    def test_read_and_sbo_share_one_tcp_session_and_close_on_failure(self):
        events = []

        class SharedSession:
            opens = 0
            closes = 0

            def __init__(self, _host, _port, source_address=None):
                self.source_address = source_address
                self.id = SharedSession.opens + 1

            def __enter__(self):
                SharedSession.opens += 1
                events.append(("open", self.id))
                return self

            def __exit__(self, *exc):
                SharedSession.closes += 1
                events.append(("close", self.id, exc[0].__name__ if exc[0] else None))
                return False

            def transaction(self, **kwargs):
                events.append(("read", self.id, kwargs["app_seq"]))
                return FakeOutcome("READ")

        failed_pair = (
            FakeOutcome("SELECT"),
            FakeOutcome("OPERATE", "TIMEOUT", ok=False),
        )

        def fake_popen(command, stdout=None, stderr=None):
            return FakeCapture(command)

        def fake_run(command, env=None, stdout=None, stderr=None, timeout=None, cwd=None):
            if stdout is not None:
                stdout.write('{"points": 32, "all_open": true, "all_online": true}\n')
            return subprocess.CompletedProcess(command, 0)

        def fake_one_sbo(session, seq_select, seq_operate, points, budget_ms, select_only):
            events.append(("sbo", session.id, seq_select, seq_operate))
            return failed_pair

        with tempfile.TemporaryDirectory() as td, \
             mock.patch.dict(os.environ, {"DEFENSE4_HW_AUTHORIZED": "1"}), \
             mock.patch.object(run_block.subprocess, "Popen", fake_popen), \
             mock.patch.object(run_block.subprocess, "run", fake_run), \
             mock.patch.object(run_block, "Session", SharedSession), \
             mock.patch.object(run_block.read_driver, "build", lambda seq: b"read"), \
             mock.patch.object(run_block.sbo_driver, "one_sbo", fake_one_sbo), \
             mock.patch.object(run_block.time, "sleep", lambda _seconds: None):
            rc = run_block.main(["case", "--root", td, "--reads", "2", "--sbo", "2",
                                 "--gap-ms", "400", "--budget-ms", "500"])
            status = json.loads((Path(td) / "case" / "status.json").read_text())

        self.assertEqual(rc, 1)
        self.assertEqual(SharedSession.opens, 1)
        self.assertEqual(SharedSession.closes, 1)
        self.assertEqual([e for e in events if e[0] == "read"],
                         [("read", 1, 0), ("read", 1, 1)])
        self.assertEqual([e for e in events if e[0] == "sbo"],
                         [("sbo", 1, 0, 1)])
        self.assertEqual(events[-1][0], "close")
        self.assertEqual(status["session_mode"], "one TCP session for READ and SBO")
        self.assertEqual(status["read_completed"], 2)
        self.assertEqual(status["sbo_completed"], 1)
        self.assertEqual(status["error"], "SBO transaction 1 failed at OPERATE: TIMEOUT (timeout)")


if __name__ == "__main__":
    unittest.main()
