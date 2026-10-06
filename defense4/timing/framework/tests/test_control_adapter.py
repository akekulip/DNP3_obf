"""The BFRT adapter against a schema-faithful fake and the real compiled schema. No hardware."""
import copy
import sys
import unittest
from collections import namedtuple
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIMING = HERE.parents[1]
sys.path.insert(0, str(HERE.parent / "control"))
sys.path.insert(0, str(TIMING / "response_ready" / "tests"))
import bfrt_device as bd          # noqa: E402
import profiles as pf             # noqa: E402
from schema import Schema, SchemaError   # noqa: E402
from test_p4_release import SOURCE, sem  # noqa: E402

BFRT = TIMING / "response_ready/evidence/local_build_35/out/bfrt.json"
DT = namedtuple("DataTuple", "name value")
CONSTS = sem.extract_consts(SOURCE.read_text())


class FakeData:
    def __init__(self, action, fields):
        self.action, self.fields = action, fields

    def to_dict(self):
        return dict(self.fields, action_name=self.action, is_default_entry=True)


class FakeTable:
    """Enforces the schema itself, independently of the adapter, and records every device call."""
    def __init__(self, schema, name, calls):
        self.schema, self.name, self.calls, self.default = schema, name, calls, None

    def make_data(self, tuples, action):
        return FakeData(action, {t.name: t.value for t in tuples})

    def default_entry_set(self, target, data):
        self.calls.append(("set", self.name))
        spec = self.schema.actions(self.name)[data.action]
        assert set(data.fields) == set(spec), "device rejected the field set"
        for k, v in data.fields.items():
            assert 0 <= v < (1 << spec[k]), "device rejected an out-of-range value"
        self.default = data

    def default_entry_get(self, target, flags):
        return [(self.default,)] if self.default is not None else []


class FakeInfo:
    def __init__(self, schema, calls):
        self.schema, self.calls, self.tables = schema, calls, {}

    def table_get(self, name):
        return self.tables.setdefault(name, FakeTable(self.schema, name, self.calls))


class FakeGC:
    DataTuple = DT


def make(authorized=True, schema=None):
    schema = schema or Schema.from_file(BFRT)
    calls = []
    return bd.BfrtDevice(schema, FakeGC, FakeInfo(schema, calls), None, authorized=authorized), calls


@unittest.skipUnless(BFRT.exists(), "compiled schema for build 35 is not on this machine")
class Adapter(unittest.TestCase):
    def test_schema_has_no_shaping_field_and_the_expected_fields(self):
        s = Schema.from_file(BFRT)
        self.assertFalse(s.has_field("tbl_params", "shape_enable"))
        self.assertEqual(set(s.actions("tbl_params")["Ingress.set_params"]), {"d_ticks", "read_len", "budget", "mode", "da_dr"})
        self.assertEqual(s.actions("tbl_read_release_params")["Ingress.set_read_release"], {"enabled": 8, "gap_ticks": 32})

    def test_unknown_table_action_field_and_overflow_are_refused_before_any_device_call(self):
        dev, calls = make()
        bad = [("tbl_nope", dict(action_name="x")),
               ("tbl_params", dict(action_name="Ingress.nope")),
               ("tbl_params", dict(action_name="Ingress.set_params", d_ticks=1)),
               ("tbl_params", dict(action_name="Ingress.set_params", d_ticks=1, read_len=0, budget=1, mode=4, da_dr=1, shape_enable=0)),
               ("tbl_params", dict(action_name="Ingress.set_params", d_ticks=1, read_len=0, budget=1, mode=256, da_dr=1)),
               ("tbl_params", dict(action_name="Ingress.set_params", d_ticks=-1, read_len=0, budget=1, mode=4, da_dr=1)),
               ("tbl_params", dict(action_name="Ingress.set_params", d_ticks=True, read_len=0, budget=1, mode=4, da_dr=1)),
               ("tbl_params", dict(d_ticks=1))]
        for table, fields in bad:
            with self.assertRaises(SchemaError, msg=(table, fields)):
                dev.write(table, fields)
        self.assertEqual(calls, [])

    def test_unauthorised_write_is_refused_but_read_works(self):
        dev, calls = make(authorized=False)
        with self.assertRaises(bd.WriteRefused):
            dev.write("tbl_read_release_params", dict(action_name="Ingress.set_read_release", enabled=0, gap_ticks=0))
        self.assertEqual(dev.read("tbl_params"), {})
        self.assertEqual(calls, [])

    def test_write_then_read_round_trips_ints_without_the_default_flag(self):
        dev, _ = make()
        f = dict(action_name="Ingress.set_read_release", enabled=1, gap_ticks=3906 << 8)
        dev.write("tbl_read_release_params", f)
        self.assertEqual(dev.read("tbl_read_release_params"), f)


@unittest.skipUnless(BFRT.exists(), "compiled schema for build 35 is not on this machine")
class Profiles(unittest.TestCase):
    P = dict(connection_id="relay-sel751", build_id="rr-35")

    def test_combined_values_match_the_candidates_own_plan(self):
        sys.path.insert(0, str(TIMING.parents[1]))
        from defense4.timing.response_ready import control as cand
        want = cand.build_plan(10)["defaults"]
        got = pf.plan(pf.Profile("combined", 10.0, 1.0), CONSTS)["expect"]
        self.assertEqual({k: v for k, v in got["tbl_params"].items()},
                         {k: v for k, v in want[cand.PARAMS].items()})
        self.assertEqual(got["tbl_bor_params"], want[cand.BOR])
        self.assertEqual(got["tbl_read_release_params"], want[cand.RELEASE])

    def test_modes_come_from_the_source(self):
        self.assertEqual(pf.plan(pf.Profile("response_focused", 0, 1.0), CONSTS)["expect"]["tbl_params"]["mode"], CONSTS["MODE_D2_RESP"])
        self.assertEqual(pf.plan(pf.Profile("ack_focused", 0, 0.000256), CONSTS)["expect"]["tbl_params"]["mode"], CONSTS["MODE_D4_DUAL"])
        self.assertEqual(pf.plan(pf.Profile("off", 0, 1.0), CONSTS)["expect"]["tbl_read_release_params"]["enabled"], 0)

    def test_release_is_disarmed_first_and_enabled_last(self):
        w = pf.plan(pf.Profile("combined", 10.0, 1.0), CONSTS)["writes"]
        self.assertEqual((w[0][0], w[0][1]["enabled"]), ("tbl_read_release_params", 0))
        self.assertEqual((w[-1][0], w[-1][1]["enabled"]), ("tbl_read_release_params", 1))

    def test_invalid_profiles_are_rejected_before_any_write(self):
        for p in (pf.Profile("combined", 0.0, 1.0), pf.Profile("ack_focused", 5.0, 1.0),
                  pf.Profile("response_focused", 5.0, 1.0), pf.Profile("combined", 10.0, 0.0),
                  pf.Profile("combined", 10.0, 1.0, budget=30000), pf.Profile("nonsense")):
            with self.assertRaises(ValueError, msg=p):
                pf.plan(p, CONSTS)

    def test_ack_focused_guard_is_one_tick(self):
        pl = pf.plan(pf.Profile("ack_focused", 0, 0.000256), CONSTS)
        self.assertEqual(pl["quantised_ns"]["gap"], 256)

    def test_worst_case_hold_is_the_watchdog_horizon_not_d_a(self):
        self.assertAlmostEqual(pf.hold_bound_ms(pf.Profile("combined", 5.0, 1.0)), 18000 * 1711 / 1e6)

    def test_activation_without_admission_writes_nothing_on_a_real_run(self):
        dev, calls = make()
        with self.assertRaises(pf.ActivationError) as cm:
            pf.activate(dev, pf.Profile("combined", 10.0, 1.0, **self.P), CONSTS, mock=False)
        self.assertEqual([c for c in calls if c[0] == "set"], [])
        self.assertEqual(cm.exception.record["failure"]["stage"], "admission")

    def test_mock_run_is_labelled_and_verifies_every_table(self):
        dev, _ = make()
        rec = pf.activate(dev, pf.Profile("combined", 10.0, 1.0), CONSTS, mock=True)
        self.assertFalse(rec["is_evidence_of_switch_state"])
        self.assertTrue(all(s["match"] for s in rec["steps"]))
        self.assertEqual(rec["after"]["tbl_params"]["mode"], CONSTS["MODE_D4_DUAL"])

    def test_readback_mismatch_stops_activation_and_keeps_the_evidence(self):
        dev, _ = make()
        real_read = dev.read
        dev.read = lambda t: dict(real_read(t), gap_ticks=0) if t == "tbl_read_release_params" and real_read(t) else real_read(t)
        with self.assertRaises(pf.ActivationError) as cm:
            pf.activate(dev, pf.Profile("combined", 10.0, 1.0), CONSTS, mock=True)
        self.assertEqual(cm.exception.record["failure"]["stage"], "tbl_read_release_params")
        self.assertTrue(cm.exception.record["steps"])

    def test_restore_returns_the_saved_state_and_refuses_to_guess(self):
        dev, _ = make()
        pf.activate(dev, pf.Profile("combined", 10.0, 1.0), CONSTS, mock=True)
        saved = {t: dev.read(t) for t in ("tbl_params", "tbl_bor_params", "tbl_read_release_params")}
        pf.activate(dev, pf.Profile("response_focused", 0, 1.0), CONSTS, mock=True)
        self.assertNotEqual(dev.read("tbl_params"), saved["tbl_params"])
        pf.restore(dev, saved)
        self.assertEqual({t: dev.read(t) for t in saved}, saved)
        with self.assertRaises(pf.ActivationError):
            pf.restore(dev, {"tbl_params": {}, "tbl_bor_params": {}, "tbl_read_release_params": {}})

    def test_a_bound_admission_lets_the_writes_through(self):
        """Positive path against the fake device (so the record's `source` says switch only because mock=False)."""
        dev, calls = make()
        prof = pf.Profile("combined", 10.0, 1.0, **self.P)
        adm = {"verdict": "admitted_conditional", "claim": {"kind": "admitted_conditional"},
               "policy": {"d_a_ms": pf.hold_bound_ms(prof), "clrt_new_ms": 1.0,
                          "context": {"build_id": "rr-35", "connection_id": "relay-sel751"}},
               "checks": [{"constraint": n, "ok": True} for n in pf.top.REQUIRED_ADMISSION_CHECKS],
               "policy_cap": {"ok": True}}
        rec = pf.activate(dev, prof, CONSTS, mock=False, admission=adm)
        self.assertEqual(len([c for c in calls if c[0] == "set"]), 4)
        self.assertTrue(rec["is_evidence_of_switch_state"])

    def test_admission_for_another_policy_does_not_authorise_this_one(self):
        dev, calls = make()
        wrong = {"verdict": "admitted_conditional", "claim": {"kind": "admitted_conditional"},
                 "policy": {"d_a_ms": 9.0, "clrt_new_ms": 1.0, "context": {"build_id": "rr-35", "connection_id": "relay-sel751"}},
                 "checks": [], "policy_cap": {"ok": True}}
        with self.assertRaises(pf.ActivationError):
            pf.activate(dev, pf.Profile("combined", 10.0, 1.0, **self.P), CONSTS, mock=False, admission=wrong)
        self.assertEqual([c for c in calls if c[0] == "set"], [])


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(BFRT.exists(), "compiled schema for build 35 is not on this machine")
class Runner(unittest.TestCase):
    def setUp(self):
        sys.path.insert(0, str(HERE.parent / "runner"))
        import cli
        self.cli = cli
        import tempfile
        self.tmp = Path(tempfile.mkdtemp())
        self.dev, self.calls = make()

    def factory(self):
        return self.dev, None

    def test_plan_is_offline_and_reports_problems(self):
        self.assertEqual(self.cli.run(["plan", "--case", "combined", "--d-a-ms", "10"]), 0)
        self.assertEqual(self.cli.run(["plan", "--case", "combined", "--d-a-ms", "0"]), 1)
        self.assertEqual(self.calls, [])

    def test_execute_needs_signoff_and_backup_and_leaves_no_write_without_them(self):
        base = ["execute", "--case", "off", "--backup", str(self.tmp / "b.json")]
        with self.assertRaises(SystemExit):
            self.cli.run(base, self.factory)
        with self.assertRaises(SystemExit):
            self.cli.run(["execute", "--case", "off", "--drained-trial-signoff"], self.factory)
        self.assertEqual([c for c in self.calls if c[0] == "set"], [])

    def test_backup_is_written_first_never_overwritten_and_restores(self):
        b = self.tmp / "b.json"
        # known prior state: the combined profile, installed through the adapter
        pf.activate(self.dev, pf.Profile("combined", 10.0, 1.0), CONSTS, mock=True)
        prior = {t: self.dev.read(t) for t in ("tbl_params", "tbl_bor_params", "tbl_read_release_params")}
        self.assertEqual(self.cli.run(["execute", "--case", "off", "--backup", str(b), "--drained-trial-signoff"], self.factory), 0)
        self.assertEqual(__import__("json").loads(b.read_text()), prior)
        self.assertEqual(self.dev.read("tbl_params")["mode"], CONSTS["MODE_OFF"])
        with self.assertRaises(FileExistsError):
            self.cli.run(["execute", "--case", "off", "--backup", str(b), "--drained-trial-signoff"], self.factory)
        self.assertEqual(self.cli.run(["restore", "--backup", str(b)], self.factory), 0)
        self.assertEqual({t: self.dev.read(t) for t in prior}, prior)
        self.assertEqual(self.cli.run(["verify", "--case", "combined", "--d-a-ms", "10"], self.factory), 0)
        self.assertEqual(self.cli.run(["verify", "--case", "off"], self.factory), 1)
