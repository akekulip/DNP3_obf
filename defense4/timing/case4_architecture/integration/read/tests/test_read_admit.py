"""T8: READ request ADMIT passes (cookie mint, receipts, association commit, request forward, bypass).

Whole-program SOURCE-LEVEL runs (see whole_program.py); recirculation latency L is a parameter.
Expected values come from join_reference (anchor = t0q) and from the design (STEP2_DESIGN 1.5, 4.5),
not from reading the P4.
"""
import unittest

import whole_program as w
from read_scenario import (ACK_OFF, L, REQ_FRAME, T, ack, ACK_FRAME, emitted, jr, new_sim, read, request,
                           response, ticks)

BUSY, EXHAUSTED, POLICY, UNHELD = 0, 1, 2, 3
RELAY, FORWARD = w.PORTS['RELAY_PORT'], w.PORTS['FORWARD_PORT']


def counters(sim):
    return list(sim.src.cells[('', 'bypass_counters')])


def pin_phase(sim):
    return sim.src.cells[('work', 'work')][0]['phase']


class Admit(unittest.TestCase):
    def test_request_runs_four_passes_commits_the_association_and_forwards_unchanged(self):
        sim = new_sim()
        request(sim, T, epoch=7)
        sim.run(T + 10 * L)
        self.assertEqual(sim.drops, [])
        passes = [(t - T, p) for t, p, _ in sim.log]
        held, t_in = w.PORTS['HELD_RETURN'], w.PORTS['T_IN']
        self.assertEqual(passes, [(0, t_in), (L, held), (2 * L, held), (3 * L, held)])
        self.assertEqual([(t - T, p, raw) for t, p, raw in sim.emitted], [(3 * L, RELAY, REQ_FRAME)])
        self.assertEqual(pin_phase(sim), 4)
        self.assertEqual(sim.cell('timing_binding'), {'epoch': 7, 'cookie': 1})
        self.assertEqual(sim.cell('admission_anchor'), {'cookie': 1, 'word': T | 1})      # request-anchored t0q
        self.assertEqual(sim.src.cells[('credits', 'cell')][0], {'epoch': 7, 'credit': 1 << 16})
        self.assertEqual(sim.src.cells[('credits', 'cell')][1], {'epoch': 7, 'credit': 1 << 16})
        self.assertEqual(counters(sim), [0, 0, 0, 0])

    def test_cookie_is_minted_once_per_read_and_never_reused(self):
        sim = new_sim()
        for k in range(3):
            request(sim, T + k * 1_000_000, epoch=3)
        sim.run(T + 4_000_000)
        self.assertEqual(sim.cell('cookie_counter'), {'cookie': 3, 'word': 3 << 16})
        self.assertEqual(sim.cell('timing_binding'), {'epoch': 3, 'cookie': 3})
        self.assertEqual(len(emitted(sim, REQ_FRAME, port=RELAY)), 3)

    def test_anchor_is_the_request_arrival_not_a_later_original(self):
        sim = new_sim()
        ticks(sim, T, T + 2_000_000)
        read(sim, T)
        sim.run(T + 2_000_000)
        self.assertEqual(sim.cell('admission_anchor')['word'] - 1, T)

    def test_exhaustion_boundary_65535_is_the_last_cookie(self):
        sim = new_sim()
        sim.src.cells[('', 'cookie_counter')][0] = {'cookie': 65534, 'word': 0xfffe0000}
        request(sim, T)
        request(sim, T + 1_000_000)
        sim.run(T + 2_000_000)
        self.assertEqual(sim.cell('timing_binding'), {'epoch': 1, 'cookie': 65535})
        self.assertEqual(emitted(sim, REQ_FRAME, port=RELAY), [T + 3 * L, T + 1_000_000 + 3 * L])
        self.assertEqual(counters(sim), [0, 1, 0, 0])             # second request refused: exhausted
        self.assertEqual(sim.cell('cookie_counter')['word'], 0)
        self.assertEqual(sim.cell('timing_binding')['cookie'], 65535)     # association unchanged
        request(sim, T + 2_000_000)
        sim.run(T + 3_000_000)
        self.assertEqual(counters(sim), [0, 2, 0, 0])
        self.assertEqual(sim.cell('cookie_counter')['cookie'], 65536)
        self.assertEqual(pin_phase(sim), 4)

    def test_busy_debt_forwards_the_request_unchanged_and_mints_nothing(self):
        sim = new_sim()
        ticks(sim, T, T + 6_000_000)
        read(sim, T, rsp_off=None)
        # lose the circulating ACK original after its admission: its receipt stays owned (debt 1)
        sim.lose = lambda time, egress, raw: egress == w.PORTS['HELD_RETURN'] and time > T + ACK_OFF + 4 * L \
            and raw[16:18] == bytes([1, 4])
        sim.run(T + 2_000_000)
        self.assertEqual(sim.src.cells[('', 'debt_cell')][0], 1)
        before = (sim.cell('cookie_counter'), sim.cell('timing_binding'), sim.cell('admission_anchor'))
        request(sim, T + 3_000_000)
        sim.run(T + 4_000_000)
        self.assertEqual(emitted(sim, REQ_FRAME, port=RELAY)[-1], T + 3_000_000 + 3 * L)
        self.assertEqual(counters(sim)[BUSY], 1)
        self.assertEqual((sim.cell('cookie_counter'), sim.cell('timing_binding'), sim.cell('admission_anchor')), before)
        self.assertEqual(pin_phase(sim), 4)

    def test_request_while_pinned_is_forwarded_unchanged_and_counted_busy(self):
        sim = new_sim()
        request(sim, T)
        request(sim, T + L + 7_000)            # claim while the first request's pin is held
        sim.run(T + 1_000_000)
        self.assertEqual(counters(sim), [1, 0, 0, 0])
        self.assertEqual(sim.cell('cookie_counter')['cookie'], 1)
        self.assertEqual(len(emitted(sim, REQ_FRAME, port=RELAY)), 2)
        self.assertEqual(pin_phase(sim), 4)

    def test_policy_off_forwards_the_request_unchanged(self):
        sim = new_sim()
        sim.src.cells[('', 'holding_policy')][0] = 0
        request(sim, T)
        sim.run(T + 1_000_000)
        self.assertEqual([(t - T, p, raw) for t, p, raw in sim.emitted], [(0, RELAY, REQ_FRAME)])
        self.assertEqual(counters(sim), [0, 0, 1, 0])
        self.assertEqual(sim.cell('cookie_counter'), {'cookie': 0, 'word': 0})

    def test_original_without_an_association_is_forwarded_unheld(self):
        sim = new_sim()
        ack(sim, T)
        sim.run(T + 1_000_000)
        self.assertEqual([(t - T, p) for t, p, _ in sim.emitted], [(3 * L, FORWARD)])
        self.assertEqual(counters(sim), [0, 0, 0, 1])
        self.assertEqual(sim.src.cells[('', 'debt_cell')][0], 0)
        self.assertEqual(pin_phase(sim), 4)

    def test_original_of_another_epoch_is_not_held(self):
        sim = new_sim()
        ticks(sim, T, T + 2_000_000)
        request(sim, T, epoch=7)
        ack(sim, T + ACK_OFF, epoch=8)
        sim.run(T + 2_000_000)
        self.assertEqual(len(emitted(sim, ACK_FRAME, port=FORWARD)), 1)
        self.assertEqual(sim.src.cells[('', 'debt_cell')][0], 0)


if __name__ == '__main__':
    unittest.main()
