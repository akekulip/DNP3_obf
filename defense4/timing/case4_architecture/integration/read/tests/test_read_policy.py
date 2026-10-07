"""T11: policy-off while held, reset quarantine and reuse (T2-POLICY-OFF, T2-RESET, T2-REUSE).

Whole-program SOURCE-LEVEL runs. Expected schedules come from join_reference; the behaviours named by
the design (STEP2_DESIGN 4.5): held originals are forwarded, an unsent OPERATE is aborted, terminal
credits are debited independent of the holding flag, quarantine admits no new request of its epoch,
and reuse needs zero debt.
"""
import unittest

import whole_program as w
from read_scenario import (ACK_FRAME, ACK_OFF, L, PERIOD, REQ_FRAME, RSP_FRAME, RSP_OFF, T, ack, admissions,
                           assert_window, emitted, jr, new_sim, oracle, operate, read, request, reset, ticks)

HELD = w.PORTS['HELD_RETURN']
RELAY = w.PORTS['RELAY_PORT']
MS = 1_000_000
OWNED, ISSUED = 0x001, 0x100


def credit(sim, index):
    return sim.src.cells[('credits', 'cell')][index]['credit']


def debt(sim):
    return sim.src.cells[('', 'debt_cell')][0]


def counters(sim):
    return list(sim.src.cells[('', 'bypass_counters')])


def held_read(d_ms=5, until=2 * MS):
    sim = new_sim(d_ms)
    ticks(sim, T, T + 60 * MS)
    read(sim, T)
    sim.run(T + until)
    assert debt(sim) == 2 and not sim.emitted[:0] and not emitted(sim, ACK_FRAME)
    return sim


class PolicyOff(unittest.TestCase):
    def test_held_originals_are_forwarded_and_debited_when_policy_goes_off(self):
        sim = held_read()
        flip = T + 2 * MS
        sim.src.cells[('', 'holding_policy')][0] = 0
        sim.run(T + 3 * MS)
        (em_a,), (em_r,) = emitted(sim, ACK_FRAME), emitted(sim, RSP_FRAME)
        for em in (em_a, em_r):
            self.assertTrue(flip <= em <= flip + 2 * L, (em - flip))
        ideal = jr.ideal(T, 5, *admissions(sim))
        self.assertLess(em_a, T + ideal.e_ack - 2 * MS)          # far ahead of the held schedule
        self.assertEqual(debt(sim), 0)
        self.assertEqual([credit(sim, 0), credit(sim, 1)], [(1 << 16) | ISSUED] * 2)   # owned bit cleared
        self.assertEqual(len(emitted(sim, ACK_FRAME)) + len(emitted(sim, RSP_FRAME)), 2)
        self.assertEqual([q for q in sim.queue if q[2] == HELD], [])

    def test_unsent_operate_is_aborted_and_its_credit_debited(self):
        sim = new_sim(5)
        ticks(sim, T, T + 8 * MS)
        request(sim, T)
        sim.run(T + MS)
        sim.src.cells[('credits', 'cell')][2] = {'epoch': 1, 'credit': 1 << 16}     # OPERATE slot of this READ
        operate(sim, T + MS + 17_000)
        sim.run(T + 2 * MS)
        self.assertEqual(debt(sim), 1)
        self.assertEqual(credit(sim, 2), (1 << 16) | ISSUED | OWNED)
        sim.src.cells[('', 'holding_policy')][0] = 0
        sim.run(T + 3 * MS)
        self.assertEqual(emitted(sim, ACK_FRAME), [])                # the OPERATE original was never sent
        self.assertEqual(credit(sim, 2), (1 << 16) | ISSUED)
        self.assertEqual(debt(sim), 0)
        self.assertTrue(any(d[2] == 'drop_ctl' for d in sim.drops))

    def test_policy_back_on_holds_the_next_read_per_the_oracle(self):
        sim = held_read()
        sim.src.cells[('', 'holding_policy')][0] = 0
        sim.run(T + 3 * MS)
        sim.src.cells[('', 'holding_policy')][0] = 1
        second = T + 10 * MS
        sim.src.cells[('credits', 'cell')][0] = {'epoch': 1, 'credit': 1 << 16}
        read(sim, second)
        sim.run(second + 8 * MS)
        adm_a, adm_r = admissions(sim, after=second)
        expect = oracle(sim, 5, adm_a, adm_r)
        em_a = emitted(sim, ACK_FRAME, after=second)
        self.assertEqual(len(em_a), 1)
        assert_window(self, em_a[0], expect.e_ack, 'second READ held after policy back on')

    def test_policy_off_read_is_forwarded_unheld_end_to_end(self):
        sim = new_sim(5)
        sim.src.cells[('', 'holding_policy')][0] = 0
        read(sim, T)
        sim.run(T + MS)
        self.assertEqual(emitted(sim, REQ_FRAME, port=RELAY), [T])
        self.assertEqual(len(emitted(sim, ACK_FRAME)), 1)
        self.assertEqual(len(emitted(sim, RSP_FRAME)), 1)
        self.assertLess(emitted(sim, ACK_FRAME)[0], T + ACK_OFF + 4 * L)
        self.assertEqual(debt(sim), 0)


class Reset(unittest.TestCase):
    def test_reset_flushes_held_originals_and_is_consumed(self):
        sim = held_read()
        flip = T + 2 * MS
        reset(sim, flip + 7_000)
        sim.run(T + 3 * MS)
        (em_a,), (em_r,) = emitted(sim, ACK_FRAME), emitted(sim, RSP_FRAME)
        for em in (em_a, em_r):
            self.assertTrue(flip <= em <= flip + 3 * L, em - flip)
        self.assertEqual(debt(sim), 0)
        self.assertEqual([c for c in sim.emitted if c[2].startswith(w.ETH + bytes(6)) and len(c[2]) < 40], [])
        self.assertTrue(any(d[1] == w.PORTS['T_IN'] and d[2] == 'drop_ctl' for d in sim.drops))
        self.assertEqual(sim.cell('cookie_counter')['cookie'], 1)

    def test_reset_of_another_epoch_does_not_flush(self):
        sim = held_read()
        reset(sim, T + 2 * MS + 7_000, epoch=2)
        sim.run(T + 4 * MS)
        self.assertEqual(emitted(sim, ACK_FRAME), [])
        self.assertEqual(debt(sim), 2)

    def test_quarantined_epoch_admits_no_request_and_holds_no_original(self):
        sim = held_read()
        reset(sim, T + 2 * MS + 7_000)
        sim.run(T + 3 * MS)
        request(sim, T + 4 * MS)
        ack(sim, T + 4 * MS + 400_000)
        sim.run(T + 5 * MS)
        self.assertEqual(counters(sim), [0, 0, 1, 1])                  # request: policy/quarantine; ACK: unheld
        self.assertEqual(sim.cell('cookie_counter')['cookie'], 1)
        self.assertEqual(emitted(sim, REQ_FRAME, port=RELAY)[-1], T + 4 * MS)
        self.assertEqual(emitted(sim, ACK_FRAME)[-1], T + 4 * MS + 400_000)    # forwarded in its first pass

    def test_reuse_after_reset_needs_zero_debt_then_a_new_epoch_is_scheduled(self):
        sim = held_read()
        reset(sim, T + 2 * MS + 7_000)
        sim.run(T + 3 * MS)
        self.assertEqual(debt(sim), 0)
        second = T + 4 * MS
        sim.src.cells[('credits', 'cell')][0] = {'epoch': 1, 'credit': 1 << 16}
        read(sim, second, epoch=2)
        sim.run(second + 8 * MS)
        self.assertEqual(sim.cell('timing_binding'), {'epoch': 2, 'cookie': 2})
        adm_a, adm_r = admissions(sim, after=second)
        expect = oracle(sim, 5, adm_a, adm_r)
        em_a = emitted(sim, ACK_FRAME, after=second)
        self.assertEqual(len(em_a), 1)
        assert_window(self, em_a[0], expect.e_ack, 'reuse after reset (epoch 2)')

    def test_reuse_is_refused_while_a_lost_original_still_owns_credit(self):
        sim = new_sim(5)
        ticks(sim, T, T + 60 * MS)
        read(sim, T)
        sim.lose = lambda time, egress, raw: egress == HELD and time >= T + MS and raw[16] == 1
        sim.run(T + 2 * MS)
        reset(sim, T + 2 * MS + 7_000)
        sim.run(T + 4 * MS)
        self.assertEqual(len(emitted(sim, RSP_FRAME)), 1)              # the survivor was flushed
        self.assertEqual(emitted(sim, ACK_FRAME), [])
        self.assertEqual(debt(sim), 1)
        request(sim, T + 5 * MS, epoch=2)
        sim.run(T + 6 * MS)
        self.assertEqual(counters(sim)[0], 1)                           # busy: reuse refused
        self.assertEqual(sim.cell('cookie_counter')['cookie'], 1)
        sim.src.cells[('', 'debt_cell')][0] = 0                         # controller drain
        sim.src.cells[('credits', 'cell')][0] = {'epoch': 0, 'credit': 0}
        request(sim, T + 7 * MS, epoch=2)
        sim.run(T + 8 * MS)
        self.assertEqual(sim.cell('timing_binding'), {'epoch': 2, 'cookie': 2})


if __name__ == '__main__':
    unittest.main()
