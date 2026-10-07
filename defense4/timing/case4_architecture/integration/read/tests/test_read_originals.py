"""T9: ACK/response original admission, hold and release against join_reference.

Whole-program SOURCE-LEVEL runs. Every expectation is derived from join_reference (the oracle with
heartbeat phase P0+L and arrivals shifted by L) or from the design rows named in each test; none from
reading the P4. Window helpers: a release is emitted in (visible, visible + L].
"""
import unittest

import whole_program as w
from read_scenario import (ACK_FRAME, ACK_OFF, CELLS, L, MS, PERIOD, PHASE, REQ_FRAME, RSP_FRAME, RSP_OFF, T, ack,
                           admissions, assert_window, emitted, jr, new_sim, oracle, read, request, response, ticks)

FORWARD = w.PORTS['FORWARD_PORT']
HB_RETURN = w.PORTS['HB_RETURN']


def run_read(d_ms, ack_off, rsp_off, horizon, setup=None):
    sim = new_sim(d_ms)
    ticks(sim, T, T + horizon)
    read(sim, T, ack_off, rsp_off)
    if setup:
        setup(sim)
    sim.run(T + horizon)
    return sim


def expect_all(test, sim, d_ms, label):
    """Check ACK and response emissions of one READ against the oracle; returns (em_a, em_r)."""
    adm_a, adm_r = admissions(sim)
    expect = oracle(sim, d_ms, adm_a, adm_r)
    em_a = emitted(sim, ACK_FRAME)
    em_r = emitted(sim, RSP_FRAME)
    test.assertEqual(sim.drops, [], label)
    if adm_a is None:
        test.assertEqual(em_a, [], label)
    else:
        test.assertEqual(len(em_a), 1, label)
        if expect.e_ack >= adm_a + 5 * L:
            assert_window(test, em_a[0], expect.e_ack, label + ' ACK')
        else:                                       # release bit already set at admission: first held pass
            test.assertTrue(adm_a < em_a[0] <= adm_a + 6 * L, (label, em_a, adm_a))
    if adm_r is None:
        test.assertEqual(em_r, [], label)
    else:
        test.assertEqual(len(em_r), 1, label)
        if expect.rsp_reason == 'fallback_no_ack':
            visible = expect.e_rsp
        else:
            visible = jr.tick_ge(jr.quantize(em_a[0]) + jr.GAP_NS, PHASE + L)
        if visible >= adm_r + 5 * L:
            assert_window(test, em_r[0], visible, label + ' response')
        else:
            test.assertTrue(adm_r < em_r[0] <= adm_r + 6 * L, (label, em_r, adm_r))
    return (em_a or [None])[0], (em_r or [None])[0]


class Hold(unittest.TestCase):
    def test_originals_are_not_forwarded_before_the_oracle_release(self):
        sim = run_read(5, ACK_OFF, RSP_OFF, 3_000_000)          # horizon ends before D_A
        self.assertEqual(emitted(sim, ACK_FRAME), [])
        self.assertEqual(emitted(sim, RSP_FRAME), [])
        self.assertEqual(sim.src.cells[('', 'debt_cell')][0], 2)             # both receipts owned
        self.assertEqual(sim.src.cells[('credits', 'cell')][0]['credit'], (1 << 16) | 0x101)
        self.assertEqual(sim.src.cells[('credits', 'cell')][1]['credit'], (1 << 16) | 0x101)


class Matrix(unittest.TestCase):
    """T2-EARLY, T2-LATE, T2-ABSENT and the D_A matrix, each against the oracle."""
    SCENARIOS = {
        'early': (ACK_OFF, RSP_OFF),
        'ack_early_rsp_late': (ACK_OFF, 7_013_000),
        'ack_late_rsp_early': (12_017_000, RSP_OFF),
        'both_after_deadline': (21_017_000, 22_013_000),
        'ack_absent': (None, RSP_OFF),
        'rsp_absent': (ACK_OFF, None),
        'ack_after_readiness': (33_017_000, 1_013_000),
        'rsp_after_readiness': (1_017_000, 35_013_000),
    }

    def test_matrix(self):
        for d_ms in (5, 10, 15, 20):
            for name, (a, r) in self.SCENARIOS.items():
                horizon = 37_000_000 if name.endswith('after_readiness') else 33_000_000
                sim = run_read(d_ms, a, r, horizon)
                expect_all(self, sim, d_ms, '%s D_A=%d' % (name, d_ms))


class DelayedCommit(unittest.TestCase):
    def test_response_deadline_follows_the_actual_ack_commit_not_the_ideal_release(self):
        lost = (T + 4_900_000, T + 8_000_000)
        sim = new_sim(5)
        sim.lose = lambda time, egress, raw: egress == HB_RETURN and lost[0] <= time < lost[1]
        ticks(sim, T, T + 12_000_000)
        read(sim, T)
        sim.run(T + 12_000_000)
        adm_a, adm_r = admissions(sim)
        ideal = jr.ideal(T, 5, adm_a, adm_r)
        (em_a,), (em_r,) = emitted(sim, ACK_FRAME), emitted(sim, RSP_FRAME)
        self.assertGreater(em_a, lost[1])                       # ACK waited for a surviving service pass
        self.assertGreater(em_a - ideal.e_ack, 2_000_000)
        self.assertGreaterEqual(em_r - em_a, jr.GAP_NS)         # gap counted from the actual commit
        self.assertGreater(em_r, ideal.e_rsp + 2_000_000)       # not at the ideal e_A + CLRT_new
        deadline = sim.cell('committed_response_deadline')['word'] - 1
        self.assertEqual(deadline, jr.quantize(em_a) + jr.GAP_NS)


class Duplicates(unittest.TestCase):
    def test_duplicated_held_ack_is_forwarded_exactly_once(self):
        sim = new_sim(5)
        hits = []

        def duplicate(time, egress, raw):
            hit = egress == w.PORTS['HELD_RETURN'] and raw[16:18] == bytes([1, 4]) and time == T + ACK_OFF + 5 * L
            hits.append(hit)
            return hit
        sim.duplicate = duplicate
        ticks(sim, T, T + 8_000_000)
        read(sim, T)
        sim.run(T + 8_000_000)
        self.assertEqual(sum(hits), 1)
        self.assertEqual(len(emitted(sim, ACK_FRAME)), 1)
        self.assertEqual(len(emitted(sim, RSP_FRAME)), 1)
        self.assertEqual([q for q in sim.queue if q[2] == w.PORTS['HELD_RETURN']], [])   # no copy circulates on
        self.assertEqual(sim.src.cells[('', 'debt_cell')][0], 0)
        self.assertTrue(any(d[2] == 'drop_ctl' for d in sim.drops))

    def test_duplicate_created_after_release_is_suppressed(self):
        sim = new_sim(5)
        # duplicate a copy of the held ACK on every pass after D_A, so one copy survives the release
        hits = []

        def duplicate(time, egress, raw):
            hit = (egress == w.PORTS['HELD_RETURN'] and raw[16:18] == bytes([1, 4])
                   and T + 4_900_000 <= time < T + 5_020_000)
            hits.append(hit)
            return hit
        sim.duplicate = duplicate
        ticks(sim, T, T + 9_000_000)
        read(sim, T)
        sim.run(T + 9_000_000)
        self.assertGreaterEqual(sum(hits), 3)
        self.assertEqual(len(emitted(sim, ACK_FRAME)), 1)
        self.assertEqual([q for q in sim.queue if q[2] == w.PORTS['HELD_RETURN']], [])
        self.assertEqual(sim.src.cells[('', 'debt_cell')][0], 0)

    def test_second_ack_of_the_same_read_is_not_held_again(self):
        sim = new_sim(5)
        ticks(sim, T, T + 8_000_000)
        read(sim, T)
        ack(sim, T + 600_000)                                    # a second ACK original, same association
        sim.run(T + 8_000_000)
        self.assertEqual(len(emitted(sim, ACK_FRAME)), 2)
        first, second = sorted(emitted(sim, ACK_FRAME))
        self.assertLess(first, T + 1_000_000)                   # the extra copy is forwarded unheld
        self.assertGreater(second, T + 5_000_000)               # the held original keeps its schedule


if __name__ == '__main__':
    unittest.main()
