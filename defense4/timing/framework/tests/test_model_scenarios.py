"""Scenario expectations for the response-ready model, hand-derived from POLICY_CONTRACT.md."""
import random
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "model"))
from response_ready_model import (DEFAULT_H_NS, MASK, HALF, Ev, ResponseReadyModel, due,  # noqa: E402
                                  quantize_ns, to_tick)

MS = 1_000_000
DA, GAP = 10 * MS, 999_936          # 1 ms floors to 3906 quanta of 256 ns
DAQ = quantize_ns(DA)               # realized D_A: 9,999,872 ns (control.py quantizes it too)
REQ = dict(epoch=1, seq=1000, length=22, app=5)
GOOD = dict(epoch=1, ack=1022, app=5)


def run(events, **kw):
    return ResponseReadyModel(DA, 1 * MS, **kw).run(events)


def req(t=0, **kw):
    return Ev(t, "REQ", **{**REQ, **kw})


def ack(t, **kw):
    return Ev(t, "ACK", **{**GOOD, **kw})


def resp(t, **kw):
    return Ev(t, "RESP", **{**GOOD, **kw})


class Release(unittest.TestCase):
    def check(self, r, e_a, outcome="normal"):
        self.assertEqual([(o.kind, o.t, o.reason) for o in r.outs if o.kind != "REQ"],
                         [("ACK", e_a, "normal"), ("RESP", e_a + GAP, "normal")])
        self.assertEqual(r.counters, {outcome: 1})
        self.assertEqual(r.state, "IDLE")

    def test_quantization(self):
        self.assertEqual(quantize_ns(1 * MS), GAP)
        self.assertEqual(DAQ, 9_999_872)

    def test_early_response_waits_for_deadline(self):
        self.check(run([req(), ack(500_000), resp(2 * MS)]), DAQ)

    def test_response_exactly_at_deadline(self):
        self.check(run([req(), ack(500_000), resp(DAQ)]), DAQ)

    def test_response_just_after_deadline(self):
        self.check(run([req(), ack(500_000), resp(DAQ + 1000)]), DAQ + 1000)

    def test_late_within_watchdog_drains_only_when_response_seen(self):
        self.check(run([req(), ack(500_000), resp(20 * MS)]), 20 * MS)

    def test_deadline_passing_without_response_does_not_release_ack(self):
        r = run([req(), ack(500_000), resp(20 * MS)])
        self.assertTrue(all(o.t >= 20 * MS for o in r.outs if o.kind == "ACK"))

    def test_response_before_ack_and_ack_after_deadline(self):
        self.check(run([req(), resp(3 * MS), ack(12 * MS)]), 12 * MS)

    def test_response_never_precedes_ack(self):
        r = run([req(), ack(MS), resp(2 * MS)])
        self.assertLess(r.find("ACK")[0].t, r.find("RESP")[0].t)

    def test_native_ack_anchor(self):
        r = ResponseReadyModel(DA, 1 * MS, anchor="native_ack").run([req(), ack(3 * MS), resp(2 * MS)])
        self.check(r, 3 * MS + DAQ)

    def test_tie_at_watchdog_instant_goes_to_normal(self):
        self.check(run([req(), ack(MS), resp(DEFAULT_H_NS)]), DEFAULT_H_NS)


class ResponseFocused(unittest.TestCase):
    """Case 2: the ACK is forwarded on arrival; e_R = max(t_R, t_A + gap)."""

    def go(self, events, **kw):
        return ResponseReadyModel(DA, 1 * MS, policy="response_focused", **kw).run(events)

    def outs(self, r):
        return [(o.kind, o.t, o.reason) for o in r.outs if o.kind != "REQ"]

    def test_ack_is_never_held(self):
        r = self.go([req(), ack(500_000), resp(40 * MS // 4)])
        self.assertEqual(self.outs(r)[0], ("ACK", 500_000, "forwarded"))

    def test_response_before_the_ack_relative_deadline_waits_for_it(self):
        r = self.go([req(), ack(2 * MS), resp(2 * MS + 100_000)])
        self.assertEqual(self.outs(r), [("ACK", 2 * MS, "forwarded"), ("RESP", 2 * MS + GAP, "normal")])

    def test_response_after_the_deadline_is_not_delayed(self):
        r = self.go([req(), ack(2 * MS), resp(8 * MS)])
        self.assertEqual(self.outs(r)[1], ("RESP", 8 * MS, "normal"))

    def test_response_first_then_ack(self):
        r = self.go([req(), resp(MS), ack(3 * MS)])
        self.assertEqual(self.outs(r), [("ACK", 3 * MS, "forwarded"), ("RESP", 3 * MS + GAP, "normal")])

    def test_gap_is_constant_for_responses_inside_the_window(self):
        gaps = []
        for t_r in (2 * MS + 1, 2 * MS + 300_000, 2 * MS + 900_000):
            o = self.outs(self.go([req(), ack(2 * MS), resp(t_r)]))
            gaps.append(o[1][1] - o[0][1])
        self.assertEqual(set(gaps), {GAP})

    def test_response_never_arrives_leaves_ack_out_and_state_free(self):
        r = self.go([req(), ack(MS)])
        self.assertEqual(self.outs(r), [("ACK", MS, "forwarded")])
        self.assertEqual(r.counters, {"fallback_no_response": 1})

    def test_ack_never_arrives_response_released_by_watchdog(self):
        r = self.go([req(), resp(MS)])
        self.assertEqual(self.outs(r), [("RESP", DEFAULT_H_NS, "watchdog")])
        self.assertEqual(r.counters, {"fallback_no_ack": 1})


class Fallback(unittest.TestCase):
    def test_never_arrives(self):
        r = run([req(), ack(MS)])
        self.assertEqual([(o.kind, o.t, o.reason) for o in r.outs if o.kind == "ACK"],
                         [("ACK", DEFAULT_H_NS, "watchdog")])
        self.assertEqual(r.counters, {"fallback_no_response": 1})
        self.assertEqual(r.find("RESP"), [])

    def test_beyond_watchdog_is_late_native_and_counted_separately(self):
        r = run([req(), ack(MS), resp(40 * MS)])
        self.assertEqual(r.counters, {"fallback_no_response": 1, "late_response": 1})
        self.assertEqual([(o.t, o.reason) for o in r.find("RESP")], [(40 * MS, "late_native")])
        self.assertEqual(r.state, "IDLE")

    def test_state_reusable_after_fallback(self):
        r = run([req(), ack(MS), req(50 * MS, seq=2000), ack(51 * MS, ack=2022), resp(52 * MS, ack=2022)])
        self.assertEqual(r.counters["normal"], 1)
        self.assertEqual(r.state, "IDLE")

    def test_response_seen_but_ack_never_arrives(self):
        r = run([req(), resp(2 * MS)])
        self.assertEqual(r.counters, {"fallback_no_ack": 1})
        self.assertEqual(r.find("ACK"), [])
        self.assertEqual([o.reason for o in r.find("RESP")], ["watchdog"])


class Association(unittest.TestCase):
    def test_wrong_app_sequence_is_stale_then_good_response_proceeds(self):
        r = run([req(), ack(MS), resp(2 * MS, app=9), resp(3 * MS)])
        self.assertEqual(r.counters["stale_response"], 1)
        self.assertEqual(r.counters["normal"], 1)
        self.assertEqual(r.find("RESP")[0].reason, "stale_forwarded")

    def test_wrong_tcp_ack_number_is_stale(self):
        r = run([req(), ack(MS), resp(2 * MS, ack=999)])
        self.assertEqual(r.counters["stale_response"], 1)

    def test_other_epoch_is_stale_after_reconnect(self):
        r = run([req(), ack(MS), resp(2 * MS, epoch=2), resp(3 * MS)])
        self.assertEqual(r.counters["stale_response"], 1)

    def test_duplicate_ack_released_once(self):
        r = run([req(), ack(MS), ack(2 * MS), resp(3 * MS)])
        self.assertEqual(r.counters["dup_ack_dropped"], 1)
        self.assertEqual(len(r.find("ACK")), 1)

    def test_duplicate_response_dropped(self):
        r = run([req(), ack(MS), resp(2 * MS), resp(3 * MS)])
        self.assertEqual(r.counters["dup_response_dropped"], 1)
        self.assertEqual(len(r.find("RESP")), 1)

    def test_unmatched_ack_forwarded_unchanged(self):
        r = run([req(), ack(MS, ack=5)])
        self.assertEqual(r.counters["ack_unmatched"], 1)


class Bypass(unittest.TestCase):
    def test_busy_request_bypassed_and_first_transaction_unharmed(self):
        r = run([req(), ack(MS), req(2 * MS, seq=3000), resp(4 * MS)])
        self.assertEqual(r.counters, {"bypass_busy": 1, "normal": 1})

    def test_unsupported_request_leaves_state_idle(self):
        r = run([req(supported=False)])
        self.assertEqual(r.counters, {"bypass_unsupported": 1})
        self.assertEqual(r.state, "IDLE")

    def test_back_to_back_without_restart(self):
        evs = [req(), ack(MS), resp(2 * MS),
               req(100 * MS, seq=2000, app=6), ack(101 * MS, ack=2022), resp(102 * MS, ack=2022, app=6)]
        r = run(evs)
        self.assertEqual(r.counters, {"normal": 2})
        self.assertEqual(r.state, "IDLE")

    def test_fin_flushes_held_packets_and_frees_state(self):
        r = run([req(), ack(MS), resp(2 * MS), Ev(3 * MS, "FIN", epoch=1)])
        self.assertEqual([o.reason for o in r.outs if o.kind != "REQ"], ["reset_flush", "reset_flush"])
        self.assertEqual(r.state, "IDLE")
        self.assertEqual(r.counters, {"reset_flush": 1})


class Clock(unittest.TestCase):
    def test_modular_compare_matches_integer_compare_across_wrap(self):
        rng = random.Random(7)
        for _ in range(5000):
            base = rng.choice([0, MASK - 1000, MASK - 50, HALF - 10, HALF + 10, rng.getrandbits(32)])
            delta = rng.randrange(-(HALF - 1), HALF)
            now, dl = (base + delta) & MASK, base
            self.assertEqual(due(now, dl), delta >= 0, (base, delta))

    def test_timestamp_conversion_wraps_at_32_bit_nanoseconds(self):
        self.assertEqual(to_tick(1 << 32), 0)
        self.assertEqual(to_tick((1 << 32) - 256), MASK - 255)


if __name__ == "__main__":
    unittest.main()
