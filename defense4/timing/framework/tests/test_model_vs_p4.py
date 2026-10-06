"""Run identical READ scenarios through the independent model and through the P4's own tables.

The simulator (p4_pass_sim.py) executes the source's register actions and const tables; the model
(model/response_ready_model.py) is written from the contract. Agreement is required on outcome class,
and on release instants within the stated token-loop tolerance. These legacy scenarios use expiry_enabled=0 and a boolean match abstraction;
stale/wrong-ack cases test table decisions only. Real-byte tracker, full-cookie and
independent expiry regressions live in test_case4_packet_parity.py. Neither suite
proves parser/CRC behavior, BOR OPERATE, physical queues or wire departure.
"""
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "model"))
from p4_pass_sim import P4Sim  # noqa: E402
from response_ready_model import Ev, ResponseReadyModel  # noqa: E402

MS = 1_000_000
DA, GAP = 10 * MS, 1 * MS
TAU, ADM = 1711, 5000
GRID = 256
FWD = {"forwarded", "late_native", "stale_forwarded", "forwarded_unchanged", "unmatched_forwarded", "forwarded_ungated"}


def klass(reason):
    return "fwd" if reason in FWD else reason


def both(events, da=DA, budget=18000, offset=0, mode="MODE_D4_DUAL", policy="dual", gap=GAP):
    """events: (t, 'REQ'|'ACK'|'RESP', match). Returns (model outs, sim outs)."""
    mev = []
    for t, kind, match in events:
        if kind == "REQ":
            mev.append(Ev(t, "REQ", epoch=1, seq=1000, length=22, app=5))
        else:
            mev.append(Ev(t, kind, epoch=1, ack=1022 if match else 5, app=5))
    horizon = ADM + (budget + 1) * TAU
    m = ResponseReadyModel(da, gap, horizon_ns=horizon, policy=policy).run(mev)
    s = P4Sim(da, gap, tau_ns=TAU, budget=budget, adm_delay_ns=ADM, t_offset_ns=offset, mode=mode, expiry_enabled=0).run(events)
    mo = [(o.kind, o.t, klass(o.reason)) for o in m.outs if o.kind in ("ACK", "RESP")]
    so = [(k, t, klass(r)) for k, t, r in s.outs]
    return m, s, sorted(mo, key=lambda x: (x[1], x[0])), sorted(so, key=lambda x: (x[1], x[0]))


class Agree(unittest.TestCase):
    def check(self, events, **kw):
        m, s, mo, so = both(events, **kw)
        self.assertEqual([(k, c) for k, _, c in mo], [(k, c) for k, _, c in so], (mo, so, s.trace[:6]))
        for (k, tm, c), (_, ts, _) in zip(mo, so):
            if c == "fwd":
                self.assertEqual(tm, ts, (mo, so))
            else:
                tol = TAU + GRID + (TAU if k == "RESP" else 0) + (TAU if kw.get("budget", 18000) != 18000 else 0)
                self.assertTrue(-GRID <= ts - tm <= tol + TAU, (k, tm, ts, ts - tm, tol))
        return m, s

    def test_early_response(self):
        self.check([(0, "REQ", True), (500_000, "ACK", True), (2 * MS, "RESP", True)])

    def test_response_just_after_deadline(self):
        self.check([(0, "REQ", True), (500_000, "ACK", True), (DA + 1000, "RESP", True)])

    def test_late_response_within_watchdog(self):
        self.check([(0, "REQ", True), (500_000, "ACK", True), (20 * MS, "RESP", True)])

    def test_response_before_ack(self):
        self.check([(0, "REQ", True), (3 * MS, "RESP", True), (4 * MS, "ACK", True)])

    def test_ack_after_deadline_and_response_pending(self):
        self.check([(0, "REQ", True), (3 * MS, "RESP", True), (12 * MS, "ACK", True)])

    def test_deadline_alone_never_releases_ack(self):
        m, s = self.check([(0, "REQ", True), (500_000, "ACK", True), (25 * MS, "RESP", True)])
        self.assertGreaterEqual(s.outs[0][1], 25 * MS)

    def test_clock_wrap_inside_transaction(self):
        # 32-bit nanosecond clock wraps 4.5 ms into the 10 ms hold
        self.check([(0, "REQ", True), (500_000, "ACK", True), (2 * MS, "RESP", True)], offset=(1 << 32) - 4_500_000)

    def test_clock_wrap_exactly_at_arming(self):
        self.check([(0, "REQ", True), (500_000, "ACK", True), (12 * MS, "RESP", True)], offset=(1 << 32) - 1_000)


class FallbackAgree(unittest.TestCase):
    """Small budget so the watchdog is a few ms: 3,000 passes x 1.711 us = 5.1 ms."""
    B, DA2 = 3000, 2 * MS

    def test_response_never_arrives(self):
        m, s, mo, so = both([(0, "REQ", True), (500_000, "ACK", True)], da=self.DA2, budget=self.B)
        self.assertEqual([(k, c) for k, _, c in mo], [("ACK", "watchdog")])
        self.assertEqual([(k, c) for k, _, c in so], [("ACK", "watchdog")])
        self.assertLessEqual(abs(so[0][1] - mo[0][1]), 2 * TAU)
        self.assertEqual(s.regs["reg_owner"] & 0x80000000, 0, "owner must be retired after the timeout")

    def test_response_after_watchdog_is_native(self):
        m, s, mo, so = both([(0, "REQ", True), (500_000, "ACK", True), (9 * MS, "RESP", True)],
                            da=self.DA2, budget=self.B)
        self.assertEqual([(k, c) for k, _, c in mo], [(k, c) for k, _, c in so], (mo, so))
        self.assertEqual(mo[-1][1], so[-1][1], "late response must leave at its own arrival time")

    def test_next_transaction_succeeds_after_fallback(self):
        ev = [(0, "REQ", True), (500_000, "ACK", True),
              (20 * MS, "REQ", True), (20 * MS + 500_000, "ACK", True), (21 * MS, "RESP", True)]
        m, s, mo, so = both(ev, da=self.DA2, budget=self.B)
        self.assertEqual([(k, c) for k, _, c in mo], [(k, c) for k, _, c in so], (mo, so, s.trace[-6:]))
        self.assertEqual(s.counters.get("completed"), 1)


class AckFocusedAgree(unittest.TestCase):
    """Case 1 needs no P4 change: MODE_D4_DUAL with D_A = 0 holds the ACK exactly until the response is
    seen, then spaces the response by the minimal guard. Needs a control-plane profile that allows D_A = 0."""

    def test_gap_is_constant_whatever_the_response_latency(self):
        gaps = []
        for t_r in (1 * MS, 4 * MS, 12 * MS, 25 * MS):
            ev = [(0, "REQ", True), (500_000, "ACK", True), (t_r, "RESP", True)]
            m, s, mo, so = both(ev, da=0, gap=256)
            self.assertEqual([(k, c) for k, _, c in mo], [(k, c) for k, _, c in so], (mo, so))
            ack, rsp = (next(t for k, t, _ in so if k == kind) for kind in ("ACK", "RESP"))
            self.assertGreaterEqual(ack, t_r, "the ACK must wait for the response")
            self.assertLessEqual(ack - t_r, 2 * TAU, "...and leave as soon as it is seen")
            gaps.append(rsp - ack)
        self.assertLessEqual(max(gaps) - min(gaps), 2 * TAU, gaps)
        self.assertLessEqual(max(gaps), 2 * TAU + GRID, "the guard is one token loop, not a native spread")

    def test_request_to_ack_now_carries_the_response_latency(self):
        """What the observer still sees: with D_A = 0 the ACK moves to the response, so request-to-ACK
        becomes the device's response latency. Compression of CLRT is not removal of the information."""
        s = P4Sim(0, 256, tau_ns=TAU, adm_delay_ns=ADM, expiry_enabled=0).run([(0, "REQ", True), (500_000, "ACK", True), (7 * MS, "RESP", True)])
        self.assertGreaterEqual(s.outs[0][1], 7 * MS)


class ResponseFocusedAgree(unittest.TestCase):
    """Case 2 in MODE_D2_RESP: ACK forwarded on arrival, response at max(t_R, t_A + gap)."""
    KW = dict(mode="MODE_D2_RESP", policy="response_focused")

    def check(self, events, **kw):
        m, s, mo, so = both(events, **self.KW, **kw)
        self.assertEqual([(k, c) for k, _, c in mo], [(k, c) for k, _, c in so], (mo, so, s.trace[:5]))
        for (k, tm, c), (_, ts, _) in zip(mo, so):
            if k == "ACK":
                self.assertEqual(tm, ts, "the ACK must leave on arrival")
            else:
                self.assertTrue(-GRID <= ts - tm <= 2 * TAU + GRID, (k, tm, ts, ts - tm))
        return s

    def test_response_inside_the_window_waits_for_the_ack_relative_deadline(self):
        s = self.check([(0, "REQ", True), (2 * MS, "ACK", True), (2 * MS + 300_000, "RESP", True)])
        self.assertEqual(s.counters.get("completed"), 1)

    def test_response_after_the_window_is_not_delayed(self):
        self.check([(0, "REQ", True), (2 * MS, "ACK", True), (8 * MS, "RESP", True)])

    def test_response_before_the_ack(self):
        self.check([(0, "REQ", True), (MS, "RESP", True), (3 * MS, "ACK", True)])

    def test_gap_is_constant_inside_the_window(self):
        gaps = []
        for t_r in (2 * MS + 1000, 2 * MS + 400_000, 2 * MS + 900_000):
            s = P4Sim(DA, GAP, tau_ns=TAU, adm_delay_ns=ADM, mode="MODE_D2_RESP", expiry_enabled=0).run(
                [(0, "REQ", True), (2 * MS, "ACK", True), (t_r, "RESP", True)])
            a, r = s.outs
            gaps.append(r[1] - a[1])
        self.assertLessEqual(max(gaps) - min(gaps), 2 * TAU, gaps)

    def test_the_profile_value_d_a_zero_behaves_the_same(self):
        """control profiles write d_ticks = 0 for this case; the request deadline must be irrelevant."""
        self.check([(0, "REQ", True), (2 * MS, "ACK", True), (2 * MS + 300_000, "RESP", True)], da=0)

    def test_back_to_back(self):
        self.check([(0, "REQ", True), (MS, "ACK", True), (1_500_000, "RESP", True),
                    (100 * MS, "REQ", True), (101 * MS, "ACK", True), (101_500_000, "RESP", True)])


class FaultsAndLimits(unittest.TestCase):
    """Behaviour of the P4 when its own machinery fails, characterised from the source's tables."""
    B, DA2 = 3000, 2 * MS

    def sim(self, events, lose=()):
        import heapq
        s = P4Sim(self.DA2, GAP, tau_ns=TAU, budget=self.B, adm_delay_ns=ADM, expiry_enabled=0)
        for t, slot in lose:
            s._n += 1
            heapq.heappush(s.queue, (t, 0, s._n, "LOSE", slot))
        return s.run(events)

    def test_ack_after_watchdog_leaves_at_arrival(self):
        ev = [(0, "REQ", True), (9 * MS, "ACK", True)]
        m, s, mo, so = both(ev, da=self.DA2, budget=self.B)
        self.assertEqual([(k, c, t) for k, t, c in mo if k == "ACK"], [(k, c, t) for k, t, c in so if k == "ACK"])

    def test_stale_generation_survives_a_timeout(self):
        s = self.sim([(0, "REQ", True)])
        self.assertEqual(s.regs["reg_owner"] & 0x80000000, 0)     # owner retired by the timeout
        self.assertEqual(s.regs["reg_tag"], 0xC1)                  # generation is NOT cleared by it

    def test_losing_one_token_releases_that_hold_early_and_the_rest_recovers(self):
        s = self.sim([(0, "REQ", True), (500_000, "ACK", True), (5 * MS, "RESP", True)], lose=[(3 * MS, "ACK")])
        self.assertEqual([(k, r) for k, _, r in s.outs], [("ACK", "tokens_lost"), ("RESP", "normal")])
        self.assertEqual(s.counters.get("completed"), 1)

    def test_losing_both_tokens_leaves_the_owner_armed_KNOWN_LIMITATION(self):
        """With expiry_enabled=0, no timeout pass runs without a token, so nothing retires the owner and every later READ is
        bypassed as busy until the control plane resets state. The contract wants reusable state after
        every outcome; the legacy path retains this limit. Enabled independent expiry is
        separately tested with real packet fixtures."""
        s = self.sim([(0, "REQ", True), (500_000, "ACK", True), (3 * MS, "REQ", True), (50 * MS, "REQ", True)],
                     lose=[(MS, "ACK"), (MS, "RESP")])
        self.assertEqual(s.counters.get("out_arm_busy"), 2)
        self.assertNotEqual(s.regs["reg_owner"] & 0x80000000, 0)


class Sequences(unittest.TestCase):
    def test_back_to_back_without_restart(self):
        ev = [(0, "REQ", True), (500_000, "ACK", True), (2 * MS, "RESP", True),
              (100 * MS, "REQ", True), (100 * MS + 500_000, "ACK", True), (102 * MS, "RESP", True)]
        m, s, mo, so = both(ev)
        self.assertEqual([(k, c) for k, _, c in mo], [(k, c) for k, _, c in so], (mo, so))
        self.assertEqual(s.counters.get("completed"), 2)
        self.assertEqual(s.regs["reg_owner"] & 0x80000000, 0)

    def test_busy_request_is_bypassed(self):
        s = P4Sim(DA, GAP, expiry_enabled=0).run([(0, "REQ", True), (1 * MS, "REQ", True)])
        self.assertEqual(s.counters.get("out_arm_busy"), 1)

    def test_nonmatching_response_forwarded_unchanged(self):
        m, s, mo, so = both([(0, "REQ", True), (500_000, "ACK", True), (2 * MS, "RESP", False), (3 * MS, "RESP", True)])
        self.assertEqual([(k, c) for k, _, c in mo], [(k, c) for k, _, c in so], (mo, so))


if __name__ == "__main__":
    unittest.main()
