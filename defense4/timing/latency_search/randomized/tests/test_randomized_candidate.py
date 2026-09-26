#!/usr/bin/env python3
"""Offline checks for the randomized timing candidate."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "defense4_timing_randomized.p4"


def load_model():
    spec = importlib.util.spec_from_file_location("randomized_model", ROOT / "model.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestRandomizedTimingModel(unittest.TestCase):
    def test_default_no_action_preserves_fixed_parameters(self):
        m = load_model()
        fixed = m.DeadlineParams(seq_m=4_000_000, da_dr=8_000_000,
                                 a_ticks=4_000_000, r_ticks=8_000_000)
        book = m.RandomDeadlineTable(entries=())

        selected = book.select(bucket=17, current=fixed, fresh_role_arm=True)

        self.assertEqual(selected, fixed)

    def test_selection_is_class_independent_for_read_select_operate(self):
        m = load_model()
        fixed = m.DeadlineParams(seq_m=20_000_000, da_dr=24_000_000,
                                 a_ticks=20_000_000, r_ticks=24_000_000)
        randomized = m.DeadlineParams(seq_m=4_000_000, da_dr=8_000_000,
                                      a_ticks=4_000_000, r_ticks=8_000_000)
        book = m.RandomDeadlineTable(entries=(m.RandomDeadlineEntry(0, 255, randomized),))

        got = {
            op: book.begin_transaction(now_word=1000, bucket=7, current=fixed,
                                       operation=op).selected
            for op in ("READ", "SELECT", "OPERATE")
        }

        self.assertEqual(set(got.values()), {randomized})

    def test_selected_deadlines_persist_without_redraw(self):
        m = load_model()
        fixed = m.DeadlineParams(seq_m=20_000_000, da_dr=24_000_000,
                                 a_ticks=20_000_000, r_ticks=24_000_000)
        short = m.DeadlineParams(seq_m=4_000_000, da_dr=8_000_000,
                                 a_ticks=4_000_000, r_ticks=8_000_000)
        long = m.DeadlineParams(seq_m=8_000_000, da_dr=12_000_000,
                                a_ticks=8_000_000, r_ticks=12_000_000)
        book = m.RandomDeadlineTable(entries=(
            m.RandomDeadlineEntry(0, 127, short),
            m.RandomDeadlineEntry(128, 255, long),
        ))

        txn = book.begin_transaction(now_word=10_000, bucket=3, current=fixed,
                                     operation="READ")
        later = txn.observed_deadlines(later_bucket=250)

        self.assertEqual(txn.selected, short)
        self.assertEqual(later["ack_deadline"], 10_000 + short.seq_m)
        self.assertEqual(later["resp_deadline"], 10_000 + short.da_dr)
        self.assertEqual(later["operate_ack_deadline"], 10_000 + short.a_ticks)
        self.assertEqual(later["operate_resp_deadline"], 10_000 + short.r_ticks)

    def test_invalid_ranges_are_rejected(self):
        m = load_model()
        params = m.DeadlineParams(seq_m=4_000_000, da_dr=8_000_000,
                                  a_ticks=4_000_000, r_ticks=8_000_000)
        with self.assertRaises(ValueError):
            m.RandomDeadlineTable(entries=(
                m.RandomDeadlineEntry(0, 100, params),
                m.RandomDeadlineEntry(100, 255, params),
            ))


class TestP4RandomizedSurface(unittest.TestCase):
    def test_randomized_p4_has_optional_table_and_no_new_registers(self):
        text = SRC.read_text()
        random_block = text.split("/* RANDOMIZED DEADLINE CANDIDATE", 1)[1]
        random_block = random_block.split("/* END RANDOMIZED DEADLINE CANDIDATE", 1)[0]

        self.assertIn("table tbl_random_deadlines", text)
        self.assertIn("action set_random_deadlines", text)
        self.assertIn("NoAction", text)
        self.assertIn("meta.rand8 : range", text)
        self.assertIn("tbl_random_deadlines.apply()", text)
        self.assertIn("meta.role == ROLE_ARM", text)
        self.assertIn("meta.sess == SESS_MASTER", text)
        self.assertNotIn("hdr.dnp3_app.func_code", random_block)
        self.assertNotIn("Register<", random_block)
        self.assertIn("meta.dl_cand_op    = meta.now_word + meta.a_ticks", text)
        self.assertIn("action build_cand() { meta.dl_cand = meta.now_word + meta.seq_m; }", text)


class TestTelemetryListener(unittest.TestCase):
    def test_listener_uses_distinct_default_client_for_subscription(self):
        text = (ROOT / "telemetry_listener.py").read_text()
        self.assertIn('default=119', text)
        self.assertIn('gc.Notifications(enable_learn=True)', text)
        self.assertIn('interface.bind_pipeline_config(program)', text)
        self.assertIn('LEARN_NAME = "pipe.IgDeparser.random_deadline_digest"', text)

    def test_decode_digest_filters_by_generated_learn_id(self):
        spec = importlib.util.spec_from_file_location("telemetry_listener", ROOT / "telemetry_listener.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)

        class Info:
            def id_get(self):
                return 2388186329

        class Learn:
            info = Info()

            def make_data_list(self, digest):
                return [Data()]

        class Data:
            def to_dict(self):
                return {
                    "request_tcp_seq": 100,
                    "request_tcp_sport": 20000,
                    "ingress_ts32": 300,
                    "ingress_now_word": 257,
                    "dnp3_func": 1,
                    "rand8": 17,
                    "selected_d_ticks": 4_000_000,
                    "selected_da_dr_ticks": 8_000_000,
                    "selected_a_ticks": 4_000_000,
                    "selected_r_ticks": 8_000_000,
                    "ignored": 1,
                }

        class Target:
            device_id = 0
            pipe_id = 0

        class Digest:
            digest_id = 2388186329
            list_id = 7
            target = Target()
            data = [object()]

        rows = list(mod.decode_digest(Learn(), Digest()))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["digest_id"], 2388186329)
        self.assertEqual(rows[0]["list_id"], 7)
        self.assertEqual(rows[0]["selected_da_dr_ticks"], 8_000_000)
        self.assertNotIn("ignored", rows[0])

        Digest.digest_id = 1
        self.assertEqual(list(mod.decode_digest(Learn(), Digest())), [])


class TestRandomPolicyPlanner(unittest.TestCase):
    def test_plan_has_16_full_coverage_entries_and_class_equal_values(self):
        spec = importlib.util.spec_from_file_location("policy_planner", ROOT / "policy_planner.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)

        plan = mod.build_plan(center_da_ms=5, center_gap_ms=2, amplitude_ms=1, mode="joint")

        self.assertEqual(len(plan.entries), 16)
        buckets = []
        for entry in plan.entries:
            buckets.extend(range(entry.low, entry.high + 1))
            self.assertEqual(entry.d_ticks, entry.op_a_ticks)
            self.assertEqual(entry.da_dr_ticks, entry.op_r_ticks)
            self.assertEqual(entry.d_ticks & 0xFF, 0)
            self.assertEqual(entry.da_dr_ticks & 0xFF, 0)
            self.assertLess(entry.op_r_ticks, 30_000_000)
        self.assertEqual(sorted(buckets), list(range(256)))
        self.assertEqual(len({round(e.da_offset_ms, 6) for e in plan.entries}), 4)
        self.assertEqual(len({round(e.gap_offset_ms, 6) for e in plan.entries}), 4)

    def test_gap_mode_has_16_gap_levels_and_fixed_da(self):
        spec = importlib.util.spec_from_file_location("policy_planner", ROOT / "policy_planner.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)

        plan = mod.build_plan(center_da_ms=5, center_gap_ms=8, amplitude_ms=4, mode="gap")

        self.assertEqual(len(plan.entries), 16)
        self.assertEqual({e.da_offset_ms for e in plan.entries}, {0.0})
        self.assertEqual(len({round(e.gap_offset_ms, 6) for e in plan.entries}), 16)

    def test_plan_records_explicit_invalid_amplitude4_gap4_reason(self):
        spec = importlib.util.spec_from_file_location("policy_planner", ROOT / "policy_planner.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)

        result = mod.enumerate_plans()

        matches = [
            x for x in result["excluded_configs"]
            if x.center_da_ms == 5.0 and x.center_gap_ms == 1.0
            and x.amplitude_ms == 4.0 and x.mode == "joint"
        ]
        self.assertTrue(matches)
        self.assertTrue(any("gap must be positive" in r or "A > J_max + native_ACK failed" in r for r in matches[0].reasons))


class TestRandomBfrtSetter(unittest.TestCase):
    def test_setter_requires_authorization_gate(self):
        setter_spec = importlib.util.spec_from_file_location("bfrt_random_table", ROOT / "bfrt_random_table.py")
        setter = importlib.util.module_from_spec(setter_spec)
        sys.modules[setter_spec.name] = setter
        setter_spec.loader.exec_module(setter)

        old = setter.os.environ.pop(setter.AUTH_ENV, None)
        try:
            with self.assertRaises(RuntimeError):
                setter.require_authorized()
        finally:
            if old is not None:
                setter.os.environ[setter.AUTH_ENV] = old

    def test_apply_plan_live_programs_reads_back_and_clear_removes_entries(self):
        planner_spec = importlib.util.spec_from_file_location("policy_planner", ROOT / "policy_planner.py")
        planner = importlib.util.module_from_spec(planner_spec)
        sys.modules[planner_spec.name] = planner
        planner_spec.loader.exec_module(planner)
        setter_spec = importlib.util.spec_from_file_location("bfrt_random_table", ROOT / "bfrt_random_table.py")
        setter = importlib.util.module_from_spec(setter_spec)
        sys.modules[setter_spec.name] = setter
        setter_spec.loader.exec_module(setter)

        plan = planner.build_plan(center_da_ms=5, center_gap_ms=2, amplitude_ms=1, mode="joint")
        state = []

        class KeyTuple:
            def __init__(self, name, value=None, low=None, high=None):
                self.name = name; self.value = value; self.low = low; self.high = high

        class DataTuple:
            def __init__(self, name, value):
                self.name = name; self.value = value

        class Target:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        class Key:
            def __init__(self, fields):
                self.fields = fields
            def to_dict(self):
                out = {}
                for f in self.fields:
                    if f.low is not None or f.high is not None:
                        out[f.name] = {"low": f.low, "high": f.high}
                    else:
                        out[f.name] = {"value": f.value}
                return out

        class Data:
            def __init__(self, fields, action_name):
                self.fields = fields; self.action_name = action_name
            def to_dict(self):
                d = {f.name: f.value for f in self.fields}
                d["action_name"] = self.action_name
                return d

        class Table:
            def make_key(self, fields):
                return Key(fields)
            def make_data(self, fields, action_name):
                return Data(fields, "Ingress." + action_name if not action_name.startswith("Ingress.") else action_name)
            def entry_get(self, target, flags=None):
                return list(state)
            def entry_del(self, target, keys):
                remove = {id(k) for k in keys}
                state[:] = [(d, k) for d, k in state if id(k) not in remove]
            def entry_add(self, target, keys, data):
                state.append((data[0], keys[0]))
            def default_entry_get(self, target, flags=None):
                return [(Data([], "Ingress.NoAction"), None)]

        class BfrtInfo:
            def table_get(self, name):
                self.name = name
                return table

        class Interface:
            def bind_pipeline_config(self, program):
                self.program = program
            def bfrt_info_get(self, program):
                return BfrtInfo()
            def tear_down_stream(self):
                self.closed = True

        class GC:
            pass
        GC.KeyTuple = KeyTuple
        GC.DataTuple = DataTuple
        GC.Target = Target

        table = Table()
        setter.open_bfrt = lambda program="defense4_timing", client_id=0: (GC, Interface(), BfrtInfo(), Target())
        setter.require_authorized = lambda: None

        result = setter.apply_plan_live(plan)

        self.assertEqual(result["entry_count"], 16)
        self.assertEqual(len(state), 16)
        self.assertEqual(result["entries"][0]["low"], 0)

        cleared = setter.clear_table_live()
        self.assertEqual(cleared["deleted"], 16)
        self.assertEqual(cleared["default_action"], "Ingress.NoAction")
        self.assertEqual(state, [])


class TestTelemetryJoin(unittest.TestCase):
    def test_join_detects_missing_duplicate_and_wrong_selection(self):
        planner_spec = importlib.util.spec_from_file_location("policy_planner", ROOT / "policy_planner.py")
        planner = importlib.util.module_from_spec(planner_spec)
        sys.modules[planner_spec.name] = planner
        planner_spec.loader.exec_module(planner)
        join_spec = importlib.util.spec_from_file_location("telemetry_join", ROOT / "telemetry_join.py")
        joiner = importlib.util.module_from_spec(join_spec)
        sys.modules[join_spec.name] = joiner
        join_spec.loader.exec_module(joiner)

        plan = planner.plan_to_dict(planner.build_plan(center_da_ms=5, center_gap_ms=2, amplitude_ms=1, mode="joint"))
        entry = plan["entries"][0]
        good_req = {"sport": 20000, "seq": 10, "func": "READ"}
        good_digest = {
            "request_tcp_sport": 20000, "request_tcp_seq": 10, "dnp3_func": 1,
            "rand8": entry["low"], "selected_d_ticks": entry["d_ticks"],
            "selected_da_dr_ticks": entry["da_dr_ticks"],
            "selected_a_ticks": entry["op_a_ticks"],
            "selected_r_ticks": entry["op_r_ticks"],
        }
        missing_req = {"sport": 20000, "seq": 11, "func": "SELECT"}
        dup_req = {"sport": 20000, "seq": 12, "func": "OPERATE"}
        wrong_req = {"sport": 20000, "seq": 13, "func": "READ"}
        wrong_digest = dict(good_digest, request_tcp_seq=13, selected_d_ticks=entry["d_ticks"] + 256)
        extra_digest = dict(good_digest, request_tcp_seq=99)
        dup_digest = dict(good_digest, request_tcp_seq=12, dnp3_func=4)

        result = joiner.join(
            [good_req, missing_req, dup_req, dup_req, wrong_req],
            [good_digest, dup_digest, dup_digest, wrong_digest, extra_digest],
            plan,
        )

        self.assertEqual(len(result.joined), 1)
        self.assertEqual(len(result.missing_digest), 1)
        self.assertEqual(len(result.missing_request), 1)
        self.assertEqual(len(result.duplicate_requests), 2)
        self.assertEqual(len(result.duplicate_digests), 2)
        self.assertEqual(len(result.wrong_selection), 1)


if __name__ == "__main__":
    unittest.main()
