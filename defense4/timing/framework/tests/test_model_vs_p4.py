"""Run identical READ scenarios through the independent model and through the P4's own tables.

The simulator (p4_pass_sim.py) executes the source's register actions and const tables; the model
(model/response_ready_model.py) is written from the contract. Agreement is required on outcome class,
and on release instants within the stated token-loop tolerance. Association registers are not
simulated (a match flag stands in), so stale/wrong-ack scenarios here test the table decisions only.
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
FWD = {"late_native", "stale_forwarded", "forwarded_unchanged", "unmatched_forwarded"}


def klass(reason):
    return "fwd" if reason in FWD else reason


def both(events, da=DA, budget=18000, offset=0):
    """events: (t, 'REQ'|'ACK'|'RESP', match). Returns (model outs, sim outs)."""
    mev = []
    for t, kind, match in events:
        if kind == "REQ":
            mev.append(Ev(t, "REQ", epoch=1, seq=1000, length=22, app=5))
        else:
            mev.append(Ev(t, kind, epoch=1, ack=1022 if match else 5, app=5))
    horizon = ADM + (budget + 1) * TAU
    m = ResponseReadyModel(da, GAP, horizon_ns=horizon).run(mev)
    s = P4Sim(da, GAP, tau_ns=TAU, budget=budget, adm_delay_ns=ADM, t_offset_ns=offset).run(events)
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


class Sequences(unittest.TestCase):
    def test_back_to_back_without_restart(self):
        ev = [(0, "REQ", True), (500_000, "ACK", True), (2 * MS, "RESP", True),
              (100 * MS, "REQ", True), (100 * MS + 500_000, "ACK", True), (102 * MS, "RESP", True)]
        m, s, mo, so = both(ev)
        self.assertEqual([(k, c) for k, _, c in mo], [(k, c) for k, _, c in so], (mo, so))
        self.assertEqual(s.counters.get("completed"), 2)
        self.assertEqual(s.regs["reg_owner"] & 0x80000000, 0)

    def test_busy_request_is_bypassed(self):
        s = P4Sim(DA, GAP).run([(0, "REQ", True), (1 * MS, "REQ", True)])
        self.assertEqual(s.counters.get("out_arm_busy"), 1)

    def test_nonmatching_response_forwarded_unchanged(self):
        m, s, mo, so = both([(0, "REQ", True), (500_000, "ACK", True), (2 * MS, "RESP", False), (3 * MS, "RESP", True)])
        self.assertEqual([(k, c) for k, _, c in mo], [(k, c) for k, _, c in so], (mo, so))


if __name__ == "__main__":
    unittest.main()
