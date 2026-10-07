"""Actual pinned request returns racing reset and current policy rereads."""
import copy
import unittest
import whole_program as w
from read_scenario import L, T, REQ_FRAME, new_sim, request, reset, emitted, CELLS


class CancelledRequest(unittest.TestCase):
    def test_reset_and_policy_before_each_request_side_effect_boundary(self):
        for boundary in (1, 2, 3):
            for cause in ('reset', 'policy'):
                with self.subTest(boundary=boundary, cause=cause):
                    sim = new_sim()
                    request(sim, T)
                    before = T + boundary * L - 7000
                    sim.run(before)
                    cookie = sim.cell('cookie_counter')['cookie']
                    credits = copy.deepcopy(sim.src.cells[('credits', 'cell')])
                    cells = {name: copy.deepcopy(sim.cell(name)) for name in CELLS}
                    if cause == 'reset':
                        reset(sim, before)
                        reset(sim, before + 1000)  # duplicate, never another producer
                    else:
                        sim.src.cells[('', 'holding_policy')][0] = 0
                    sim.run(T + 8 * L)
                    self.assertEqual(sim.cell('timing_binding'), {'epoch': 0, 'cookie': 0})
                    self.assertEqual({name: sim.cell(name) for name in CELLS}, cells)
                    self.assertEqual(sim.cell('cookie_counter')['cookie'], cookie)
                    self.assertEqual(sim.src.cells[('credits', 'cell')], credits)
                    self.assertEqual(sim.cell('debt_cell'), 0)
                    self.assertEqual(sim.src.cells[('work', 'work')][0], {'generation': 1, 'phase': 4})
                    self.assertEqual(len(emitted(sim, REQ_FRAME, port=w.PORTS['RELAY_PORT'])), 1)
                    # A cancelled minted cookie is consumed, never rolled back.
                    self.assertEqual(cookie, 1 if boundary == 3 else 0)
                    self.assertEqual(sim.src.cells[('', 'bypass_counters')][2], 1)

    def test_cancelled_return_remains_cancelled_if_policy_is_reenabled(self):
        for boundary in (1, 2):
            with self.subTest(boundary=boundary):
                sim = new_sim();request(sim, T)
                sim.run(T + boundary * L - 7000)
                sim.src.cells[('', 'holding_policy')][0] = 0
                sim.run(T + boundary * L)
                sim.src.cells[('', 'holding_policy')][0] = 1
                sim.run(T + 8 * L)
                self.assertEqual(sim.cell('timing_binding'), {'epoch': 0, 'cookie': 0})
                self.assertEqual(sim.cell('cookie_counter')['cookie'], 0)
                self.assertEqual(sim.src.cells[('work', 'work')][0]['phase'], 4)
                self.assertEqual(len(emitted(sim, REQ_FRAME, port=w.PORTS['RELAY_PORT'])), 1)

    def test_duplicate_request_return_cannot_mint_a_second_cookie(self):
        sim = new_sim()
        sim.duplicate = lambda time, port, raw: time == T + L
        request(sim, T);sim.run(T + 8 * L)
        self.assertEqual(sim.cell('cookie_counter')['cookie'], 1)
        self.assertEqual(sim.cell('timing_binding'), {'epoch': 1, 'cookie': 1})
        self.assertEqual(sim.cell('debt_cell'), 0)
        self.assertEqual(sim.src.cells[('work', 'work')][0]['phase'], 4)
        self.assertEqual(len(emitted(sim, REQ_FRAME, port=w.PORTS['RELAY_PORT'])), 1)

    def test_cancelled_installed_ack_consumes_cookie_and_next_request_advances(self):
        sim = new_sim();request(sim, T)
        sim.run(T + 3 * L - 7000)
        sim.src.cells[('', 'holding_policy')][0] = 0
        sim.run(T + 5 * L)
        self.assertEqual(sim.src.cells[('credits', 'cell')][0], {'epoch': 1, 'credit': 1 << 16})
        self.assertEqual(sim.src.cells[('credits', 'cell')][1], {'epoch': 0, 'credit': 0})
        self.assertEqual(sim.cell('cookie_counter')['cookie'], 1)
        sim.src.cells[('', 'holding_policy')][0] = 1
        request(sim, T + 6 * L);sim.run(T + 12 * L)
        self.assertEqual(sim.cell('cookie_counter')['cookie'], 2)
        self.assertEqual(sim.cell('timing_binding'), {'epoch': 1, 'cookie': 2})
        self.assertEqual(sim.cell('debt_cell'), 0)

    def test_foreign_reset_does_not_cancel_the_current_request(self):
        for boundary in (1, 2, 3):
            with self.subTest(boundary=boundary):
                sim = new_sim();request(sim, T)
                reset(sim, T + boundary * L - 7000, epoch=2)
                sim.run(T + 8 * L)
                self.assertEqual(sim.cell('timing_binding'), {'epoch': 1, 'cookie': 1})
                self.assertEqual(sim.src.cells[('work', 'work')][0]['phase'], 4)
                self.assertEqual(sim.cell('debt_cell'), 0)
                self.assertEqual(len(emitted(sim, REQ_FRAME, port=w.PORTS['RELAY_PORT'])), 1)
