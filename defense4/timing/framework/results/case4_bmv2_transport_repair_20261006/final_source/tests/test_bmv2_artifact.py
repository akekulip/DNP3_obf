"""The BMv2 artifact against the independent model, on real packets through a real simple_switch.

Each case builds a private user+network namespace (no root, no host interfaces), runs the lab, and compares wire
times from two kernel-timestamped captures with what the model predicts from the same observed request, ACK and
response instants. BMv2 timing is SOFTWARE timing: the tolerances below are measured emulation accuracy, not Tofino
line-rate evidence. Skips when unshare, simple_switch or p4c-bm2-ss are unavailable.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB = HERE.parent / "bmv2" / "lab" / "run_lab.py"
sys.path.insert(0, str(HERE.parent / "model"))
from response_ready_model import Ev, ResponseReadyModel  # noqa: E402

MS = 1_000_000
TOL_ACK_NS = 2.0 * MS          # measured +0.6..+1.5 ms; two loopers + scheduler jitter in software
TOL_GAP_NS = 0.4 * MS


def available():
    return all(shutil.which(x) for x in ("unshare", "simple_switch", "p4c-bm2-ss", "simple_switch_CLI", "ip"))


def lab(step, **kw):
    d = tempfile.mkdtemp(prefix="bmv2lab_")
    r = subprocess.run([sys.executable, "-B", str(LAB), step, d, json.dumps(kw)], capture_output=True, text=True, timeout=240)
    if r.returncode:
        raise RuntimeError("lab failed:\n" + r.stderr[-1500:])
    return json.loads(r.stdout.strip().splitlines()[-1])


def predict(txn, p, policy, horizon_ns=30 * MS):
    """Model prediction from the instants the wire actually showed for this transaction."""
    t0 = txn["t_req"]
    ev = [Ev(0, "REQ", epoch=1, seq=1000, length=22, app=5)]
    if txn["t_A"]:
        ev.append(Ev(txn["t_A"] - t0, "ACK", epoch=1, ack=1022, app=5))
    if txn["t_R"]:
        ev.append(Ev(txn["t_R"] - t0, "RESP", epoch=1, ack=1022, app=5))
    m = ResponseReadyModel(p["da_us"] * 1000, p["gap_us"] * 1000, policy=policy, horizon_ns=horizon_ns).run(ev)
    return {o.kind: o.t for o in m.outs if o.kind in ("ACK", "RESP")}, m


@unittest.skipUnless(available(), "BMv2 toolchain or user namespaces unavailable")
class BMv2VsModel(unittest.TestCase):
    def check(self, run, policy):
        self.assertTrue(all(o == "OK" for o in run["outcomes"]), run["outcomes"])
        p = run["params"]
        for txn in run["txns"]:
            pred, _ = predict(txn, p, policy)
            obs = {"ACK": txn["e_A"] - txn["t_req"], "RESP": txn["e_R"] - txn["t_req"]}
            self.assertGreaterEqual(obs["ACK"], pred["ACK"] - 0.3 * MS, ("ACK left early", obs, pred))
            self.assertLessEqual(obs["ACK"], pred["ACK"] + TOL_ACK_NS, ("ACK late", obs, pred))
            self.assertGreaterEqual(obs["RESP"] - obs["ACK"] if policy == "dual" else obs["RESP"] - pred["RESP"], -0.3 * MS if policy != "dual" else (p["gap_us"] * 1000 - TOL_GAP_NS))
            if policy == "dual":
                self.assertLessEqual(abs((obs["RESP"] - obs["ACK"]) - p["gap_us"] * 1000), TOL_GAP_NS, (obs, pred))
            else:
                self.assertLessEqual(abs(obs["RESP"] - pred["RESP"]), TOL_ACK_NS, (obs, pred))
            self.assertLess(obs["ACK"], obs["RESP"] + 0.3 * MS if policy != "dual" else obs["RESP"], "response must not precede its ACK in dual mode")
        return run

    def test_early_response_waits_for_the_deadline(self):
        self.check(lab("step5", mode=4, da_us=10000, gap_us=1000, budget=1000, loop_pps=20000, latency_ms=2.0, count=3), "dual")

    def test_late_response_is_not_delayed_further_than_the_gap(self):
        self.check(lab("step5", mode=4, da_us=10000, gap_us=1000, budget=1000, loop_pps=20000, latency_ms=20.0, count=3), "dual")

    def test_ack_focused_is_d_a_zero_with_a_small_guard(self):
        run = self.check(lab("step5", mode=4, da_us=0, gap_us=200, budget=1000, loop_pps=20000, latency_ms=8.0, count=3), "dual")
        for t in run["txns"]:
            self.assertGreaterEqual(t["e_A"], t["t_R"] - 0.1 * MS, "the ACK must wait for the response")

    def test_response_focused_forwards_the_ack_and_schedules_the_response(self):
        run = self.check(lab("step5", mode=2, da_us=0, gap_us=5000, budget=1000, loop_pps=20000, latency_ms=2.0, count=3), "response_focused")
        for t in run["txns"]:
            self.assertLess(t["e_A"] - t["t_A"], 1.0 * MS, "the ACK must pass at once")      # never held
            self.assertGreaterEqual(t["e_R"] - t["t_A"], 5.0 * MS - 0.3 * MS)

    def test_watchdog_fallback_then_native_late_response_and_the_next_transaction(self):
        run = lab("step5", mode=4, da_us=10000, gap_us=1000, budget=250, loop_pps=20000, latency_ms=90.0, count=3,
                  wait_fallback=True)
        self.assertTrue(all(o == "OK" for o in run["outcomes"]), run["outcomes"])
        for t in run["txns"]:
            self.assertEqual(t["release_outcome"], "fallback")
            h_obs = (t["switch_ev_us"]["5"] - t["switch_ev_us"]["0"]) * 1000
            self.assertGreater(h_obs, 0)
            self.assertLess(h_obs + 1 * MS, t["t_R"] - t["t_req"], "the scenario needs the response after the horizon")
            self.assertAlmostEqual(t["e_A"] - t["t_req"], h_obs, delta=max(0.2 * h_obs, 3 * MS), msg="the ACK leaves at the horizon")
            self.assertLess(t["e_R"] - t["t_R"], 2 * MS, "a response after fallback is forwarded at native timing")
            pred, m = predict(t, run["params"], "dual", horizon_ns=h_obs)
            self.assertEqual(m.counters.get("late_response"), 1)


@unittest.skipUnless(available(), "BMv2 toolchain or user namespaces unavailable")
class BMv2Size(unittest.TestCase):
    def split_ok(self, run):
        self.assertTrue(all(o == "OK" for o in run["outcomes"]), run["outcomes"])
        self.assertTrue(run["split"])
        for r in run["split"]:
            self.assertEqual(r["orig_len"], 49)
            self.assertEqual(r["seq_order"], [28, 21])
            self.assertTrue(all(r[k] for k in ("reassembled_equal", "contiguous", "checksums_ok", "prefix_flags_clear", "dnp3_ok",
                                              "equals_software_carve")), r)

    def test_size_only_splits_and_does_not_hold(self):
        run = lab("step5", mode=0, shape=1, da_us=0, gap_us=0, budget=1000, loop_pps=20000, latency_ms=2.0, count=3)
        self.split_ok(run)
        for t in run["txns"]:                                     # size-only: nothing is held, the ACK passes at once
            self.assertLess(t["e_A"] - t["t_A"], 1.0 * MS)

    def test_joint_timing_and_size(self):
        run = lab("step5", mode=4, shape=1, da_us=10000, gap_us=1000, budget=1000, loop_pps=20000, latency_ms=2.0, count=3)
        self.split_ok(run)
        for t in run["txns"]:                                     # timing is still enforced when the response is carved
            self.assertGreaterEqual(t["e_A"] - t["t_req"], 9.7 * MS)
            self.assertLessEqual(abs((t["e_R"] - t["e_A"]) - 1.0 * MS), TOL_GAP_NS)

    def test_timing_only_leaves_the_response_unsplit(self):
        run = lab("step5", mode=4, shape=0, da_us=10000, gap_us=1000, budget=1000, loop_pps=20000, latency_ms=2.0, count=2)
        self.assertTrue(all(o == "OK" for o in run["outcomes"]))
        for r in run["split"]:
            self.assertEqual(r["seq_order"], [49])

    def test_an_unsupported_payload_size_stays_unsplit_with_shaping_on(self):
        run = lab("step5", mode=4, shape=1, da_us=10000, gap_us=1000, budget=1000, loop_pps=20000, latency_ms=2.0, count=2, force_points=31)
        self.assertTrue(all(o == "OK" for o in run["outcomes"]))
        for r in run["split"]:
            self.assertNotEqual(r["orig_len"], 49)
            self.assertEqual(r["seq_order"], [r["orig_len"]])


if __name__ == "__main__":
    unittest.main()
