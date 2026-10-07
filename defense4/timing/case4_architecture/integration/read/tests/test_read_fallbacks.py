"""T10: FALLBACK_NO_ACK, the 40 ms cap, lost originals and a finite heartbeat, against join_reference.

Whole-program SOURCE-LEVEL runs. The oracle is join_reference (ideal and ticked schedules); an original
that is lost after admission is "absent" from the oracle's point of view because it never commits.
"""
import unittest

import whole_program as w
from read_scenario import (ACK_FRAME, ACK_OFF, L, PERIOD, PHASE, REQ_FRAME, RSP_FRAME, RSP_OFF, T, admissions,
                           assert_window, emitted, jr, new_sim, oracle, read, request, ticks)

HELD = w.PORTS['HELD_RETURN']
RELAY = w.PORTS['RELAY_PORT']
MS = 1_000_000


def reports(sim):
    return [t for t, port, raw in sim.emitted if len(raw) == 48]


def lose_kinds(sim, kinds, after):
    sim.lose = lambda time, egress, raw: egress == HELD and time >= after and raw[16] in kinds


class Cap(unittest.TestCase):
    def test_late_originals_before_the_cap_clamp_the_response_to_the_cap(self):
        sim = new_sim(5)
        horizon = 44 * MS
        ticks(sim, T, T + horizon)
        read(sim, T, ack_off=39_517_000, rsp_off=39_713_000)
        sim.run(T + horizon)
        self.assertEqual(sim.drops, [])
        adm_a, adm_r = admissions(sim)
        expect = oracle(sim, 5, adm_a, adm_r)
        self.assertEqual(expect.rsp_reason, 'cap')
        (em_a,), (em_r,) = emitted(sim, ACK_FRAME), emitted(sim, RSP_FRAME)
        self.assertTrue(adm_a < em_a <= adm_a + 6 * L)
        assert_window(self, em_r, expect.e_rsp, 'response clamped at the cap')
        self.assertLessEqual(em_r - T, jr.CAP_NS + PERIOD + L)
        self.assertLess(em_r - em_a, jr.GAP_NS)                      # the 1 ms gap was cut short by the cap

    def test_originals_after_the_cap_are_released_at_once(self):
        sim = new_sim(5)
        horizon = 46 * MS
        ticks(sim, T, T + horizon)
        read(sim, T, ack_off=41_017_000, rsp_off=42_013_000)
        sim.run(T + horizon)
        adm_a, adm_r = admissions(sim)
        expect = oracle(sim, 5, adm_a, adm_r)
        self.assertEqual((expect.ack_reason, expect.rsp_reason), ('bypass', 'bypass'))
        (em_a,), (em_r,) = emitted(sim, ACK_FRAME), emitted(sim, RSP_FRAME)
        self.assertTrue(adm_a < em_a <= adm_a + 6 * L)
        self.assertTrue(adm_r < em_r <= adm_r + 6 * L)

    def test_no_hold_exceeds_the_cap_for_any_d_a(self):
        for d_ms in (5, 20):
            for ack_off, rsp_off in ((ACK_OFF, None), (None, RSP_OFF), (ACK_OFF, RSP_OFF)):
                sim = new_sim(d_ms)
                ticks(sim, T, T + 34 * MS)
                read(sim, T, ack_off, rsp_off)
                sim.run(T + 34 * MS)
                for frame in (ACK_FRAME, RSP_FRAME):
                    for time in emitted(sim, frame):
                        self.assertLessEqual(time - T, jr.READINESS_NS + 2 * PERIOD, (d_ms, ack_off, rsp_off))


class OneLost(unittest.TestCase):
    """T2-ONE-LOST: the circulating ACK is lost mid-hold."""

    def setUp(self):
        self.sim = sim = new_sim(5)
        self.horizon = 34 * MS
        ticks(sim, T, T + self.horizon)
        read(sim, T)
        lose_kinds(sim, (1,), T + 2 * MS)
        sim.run(T + self.horizon)

    def test_heartbeat_keeps_advancing(self):
        times = reports(self.sim)
        self.assertGreaterEqual(len(times), self.horizon // PERIOD - 2)
        self.assertEqual([b - a for a, b in zip(times, times[1:])], [PERIOD] * (len(times) - 1))

    def test_the_other_original_is_released_by_readiness_per_the_oracle(self):
        adm_a, adm_r = admissions(self.sim)
        expect = oracle(self.sim, 5, None, adm_r)                  # a lost ACK never commits: absent
        self.assertEqual(expect.rsp_reason, 'fallback_no_ack')
        (em_r,) = emitted(self.sim, RSP_FRAME)
        assert_window(self, em_r, expect.e_rsp, 'response released by readiness')
        self.assertLessEqual(em_r - T, jr.CAP_NS)

    def test_no_terminal_is_fabricated_and_the_debt_stays(self):
        self.assertEqual(emitted(self.sim, ACK_FRAME), [])
        self.assertEqual(self.sim.src.cells[('credits', 'cell')][0]['credit'], (1 << 16) | 0x101)   # still owned
        self.assertEqual(self.sim.src.cells[('credits', 'cell')][1]['credit'], (1 << 16) | 0x100)   # debited
        self.assertEqual(self.sim.src.cells[('', 'debt_cell')][0], 1)

    def test_reuse_is_refused_until_the_controller_drains(self):
        sim = self.sim
        request(sim, T + 35 * MS)
        sim.run(T + 36 * MS)
        self.assertEqual(list(sim.src.cells[('', 'bypass_counters')]), [1, 0, 0, 0])
        self.assertEqual(sim.cell('cookie_counter')['cookie'], 1)
        self.assertEqual(emitted(sim, REQ_FRAME, port=RELAY)[-1], T + 35 * MS + 3 * L)
        # TEST-ONLY quiescent fixture: retain the installed tag, clear debt/owned bit: clear the owned receipt and the debt, then a new READ is admitted
        sim.src.cells[('', 'debt_cell')][0] = 0
        sim.src.cells[('credits', 'cell')][0] = {'epoch': 1, 'credit': 1 << 16}
        request(sim, T + 37 * MS)
        sim.run(T + 38 * MS)
        self.assertEqual(sim.cell('cookie_counter')['cookie'], 2)
        self.assertEqual(sim.cell('timing_binding')['cookie'], 2)


class BothLost(unittest.TestCase):
    """T2-BOTH-LOST: both circulating originals are lost."""

    def setUp(self):
        self.sim = sim = new_sim(5)
        self.horizon = 45 * MS
        ticks(sim, T, T + self.horizon)
        read(sim, T)
        lose_kinds(sim, (1, 2), T + 2 * MS)
        sim.run(T + self.horizon)

    def test_nothing_is_fabricated_and_the_heartbeat_continues(self):
        sim = self.sim
        self.assertEqual(emitted(sim, ACK_FRAME), [])
        self.assertEqual(emitted(sim, RSP_FRAME), [])
        self.assertEqual(sim.src.cells[('', 'debt_cell')][0], 2)
        self.assertEqual([sim.src.cells[('credits', 'cell')][i]['credit'] for i in (0, 1)],
                         [(1 << 16) | 0x101] * 2)
        times = reports(sim)
        self.assertGreaterEqual(len(times), self.horizon // PERIOD - 2)
        self.assertEqual([b - a for a, b in zip(times, times[1:])], [PERIOD] * (len(times) - 1))

    def test_readiness_and_cap_state_is_finite_and_the_pin_is_free(self):
        sim = self.sim
        self.assertEqual(sim.cell('releases')['word'] & 2, 2)           # readiness released the ACK slot
        self.assertEqual(sim.cell('ready_response')['word'], 1)         # cap/fallback marked the response ready
        self.assertEqual(sim.src.cells[('work', 'work')][0]['phase'], 4)
        self.assertEqual([q for q in sim.queue if q[2] == HELD], [])

    def test_next_read_is_busy_until_drain_then_admitted_and_scheduled(self):
        sim = self.sim
        request(sim, T + 46 * MS)
        sim.run(T + 47 * MS)
        self.assertEqual(sim.src.cells[('', 'bypass_counters')][0], 1)
        self.assertEqual(sim.cell('cookie_counter')['cookie'], 1)
        sim.src.cells[('', 'debt_cell')][0] = 0
        for i in (0, 1):
            sim.src.cells[('credits', 'cell')][i] = {'epoch': 1, 'credit': 1 << 16}
        sim.lose = lambda time, egress, raw: False                # the lost originals were a one-off
        ticks(sim, T + 47 * MS, T + 60 * MS)
        read(sim, T + 48 * MS)
        sim.run(T + 58 * MS)
        self.assertEqual(sim.cell('timing_binding')['cookie'], 2)
        (em_a,) = emitted(sim, ACK_FRAME)
        (em_r,) = emitted(sim, RSP_FRAME)
        self.assertGreater(em_a - (T + 48 * MS), 4_900_000)
        self.assertGreater(em_r - em_a, jr.GAP_NS)


class FiniteHeartbeat(unittest.TestCase):
    def test_ticks_without_an_association_change_nothing(self):
        sim = new_sim(5)
        ticks(sim, T, T + 50 * MS)
        sim.run(T + 50 * MS)
        self.assertEqual(sim.drops, [])
        self.assertTrue(all(len(raw) == 48 for _, _, raw in sim.emitted))
        for name in ('admission_anchor', 'observations', 'releases', 'committed_response_deadline', 'ready_response'):
            self.assertEqual(sim.cell(name), {'cookie': 0, 'word': 0}, name)
        self.assertGreaterEqual(len(reports(sim)), 48)


if __name__ == '__main__':
    unittest.main()
