"""Whole-program SOURCE-LEVEL tests of read_timing.p4 (tickets T6, T7; design T2-* rows).

Runs the repository P4 text, parser to deparser, through the harness interpreter with an event
scheduler (see whole_program.py). Source-level only: no compiler, ASIC, traffic manager or
packet generator. Recirculation latency L is a model parameter, not a measurement; results
bound the program's logic, not target timing.

Decision instants. A heartbeat tick injects a pktgen packet at tick time P0 that snapshots
anchor/seen/deadline; the first return pass P1 = P0 + L evaluates eligibility with the clock
of P1 and writes the release/ready bit. Original loops see that bit on their next pass, so a
release is emitted in (P1, P1 + L]. The oracle (join_reference) therefore runs with heartbeat
phase P0 + L and arrivals shifted by L (an observation must precede the snapshot).
"""
import unittest
from pathlib import Path

import importlib.util
import sys

import whole_program as w

ARCH = w.ARCH
READ = ARCH / 'integration/read'
spec = importlib.util.spec_from_file_location('join_reference', READ / 'join_reference.py')
jr = importlib.util.module_from_spec(spec)
sys.modules['join_reference'] = jr
spec.loader.exec_module(jr)
TEXT = (READ / 'read_timing.p4').read_text()
PROBE_DIR = ARCH / 'ownership/p4'
PROBE = (PROBE_DIR / 'held_timing_expected_probe.p4').read_text()

T = 1 << 24
PERIOD, L = jr.HEARTBEAT_NS, 50_000
PHASE = T % PERIOD
ACK_FRAME = w.pure_ack()
RSP_FRAME = w.typed_frame(2)[20:]
ACK_OFF, RSP_OFF = 117_000, 313_000          # offsets keep original passes off the tick passes
CELLS = ('admission_anchor', 'observations', 'releases', 'committed_response_deadline', 'ready_response')


def params(d_ms):
    return (jr.DA_NS[d_ms], jr.READINESS_NS, jr.GAP_NS, jr.CAP_NS)


def new_sim(d_ms=5, text=TEXT, include=READ, **kw):
    sim = w.Sim(text, include, loop_ns=L, params=params(d_ms) if text is TEXT else None, **kw)
    return sim


def ticks(sim, start, stop):
    k = 0
    while T + k * PERIOD < stop:
        if T + k * PERIOD >= start:
            sim.at(T + k * PERIOD, w.PORTS['HB_PKTGEN'], w.pktgen_frame())
        k += 1


def inject(sim, base, ack_off=ACK_OFF, rsp_off=RSP_OFF):
    if ack_off is not None:
        sim.at(base + ack_off, w.PORTS['ACK_INPUT'], ACK_FRAME)
    if rsp_off is not None:
        sim.at(base + rsp_off, w.PORTS['TYPED_INPUT'], w.typed_frame(2))


def admissions(sim, after=0):
    found = {}
    for time, _, events in sim.log:
        if time < after:
            continue
        for event in events:
            if event in ('action relay_ack', 'action relay_response'):
                found.setdefault(event, time)
    return found.get('action relay_ack'), found.get('action relay_response')


def emitted(sim, frame, after=0):
    return [time for time, _, raw in sim.emitted if raw == frame and time >= after]


def oracle(sim, anchor_word, d_ms, adm_a, adm_r):
    t0 = anchor_word - 1
    shift = lambda t: None if t is None else t + L
    return jr.ticked(t0, d_ms, shift(adm_a), shift(adm_r), phase=PHASE + L)


def assert_window(test, observed, release_visible, label):
    test.assertTrue(release_visible < observed <= release_visible + L,
                    '%s: emitted %d, release visible %d (window +%d)' % (label, observed, release_visible, L))


class NormalPath(unittest.TestCase):
    def check(self, d_ms, ack_off=ACK_OFF, rsp_off=RSP_OFF, horizon=None):
        horizon = horizon or jr.DA_NS[d_ms] + 4_000_000
        sim = new_sim(d_ms)
        ticks(sim, T, T + horizon)
        inject(sim, T, ack_off, rsp_off)
        sim.run(T + horizon)
        self.assertEqual(sim.drops, [])
        adm_a, adm_r = admissions(sim)
        anchor = sim.cell('admission_anchor')['word']
        expect = oracle(sim, anchor, d_ms, adm_a, adm_r)
        (em_a,), (em_r,) = emitted(sim, ACK_FRAME), emitted(sim, RSP_FRAME)
        assert_window(self, em_a, expect.e_ack, 'ACK D_A=%d' % d_ms)
        ready = jr.tick_ge(jr.quantize(em_a) + jr.GAP_NS, PHASE + L)
        assert_window(self, em_r, ready, 'response D_A=%d' % d_ms)
        # idealized schedule from the oracle bounds the observed one (loop latency only adds)
        ideal = jr.ideal(anchor - 1, d_ms, adm_a, adm_r)
        self.assertLessEqual(ideal.e_ack, em_a)
        self.assertLess(em_a - ideal.e_ack, PERIOD + 2 * L)
        self.assertLessEqual(ideal.e_rsp, em_r)
        self.assertLess(em_r - ideal.e_rsp, 2 * PERIOD + 4 * L)
        return sim, em_a, em_r

    def test_every_d_a_releases_ack_then_response_per_oracle(self):
        for d_ms in (5, 10, 15, 20):
            sim, em_a, em_r = self.check(d_ms)
            gap = em_r - em_a
            self.assertGreater(gap, jr.GAP_NS)                   # never early
            self.assertLess(gap, jr.GAP_NS + 2 * PERIOD + 2 * L)  # bounded by tick + loop granularity

    def test_late_response_moves_the_ack_release_to_the_response(self):
        sim, em_a, _ = self.check(5, rsp_off=7_013_000, horizon=10_000_000)
        self.assertGreater(em_a, T + 7_013_000)

    def test_heartbeat_reports_are_independent_of_originals(self):
        sim, _, _ = self.check(5)
        reports = [t for t, port, raw in sim.emitted if len(raw) == 48]
        self.assertGreaterEqual(len(reports), (jr.DA_NS[5] + 4_000_000) // PERIOD - 2)
        self.assertEqual([b - a for a, b in zip(reports, reports[1:])], [PERIOD] * (len(reports) - 1))

    def test_original_bytes_are_forwarded_unchanged_once(self):
        sim, _, _ = self.check(5)
        self.assertEqual(len(emitted(sim, ACK_FRAME)), 1)
        self.assertEqual(len(emitted(sim, RSP_FRAME)), 1)
        self.assertTrue(all(port == w.PORTS['FORWARD_PORT'] for _, port, _ in sim.emitted))


class Fallbacks(unittest.TestCase):
    def test_response_alone_is_released_at_readiness(self):
        sim = new_sim(5)
        horizon = jr.READINESS_NS + 3_000_000
        ticks(sim, T, T + horizon)
        inject(sim, T, ack_off=None)
        sim.run(T + horizon)
        _, adm_r = admissions(sim)
        anchor = sim.cell('admission_anchor')['word']
        expect = oracle(sim, anchor, 5, None, adm_r)
        self.assertEqual(expect.rsp_reason, 'fallback_no_ack')
        (em_r,) = emitted(sim, RSP_FRAME)
        assert_window(self, em_r, expect.e_rsp, 'response-only fallback')
        self.assertLess(em_r - (anchor - 1), 30_500_000)         # finite, about 30 ms
        self.assertEqual(emitted(sim, ACK_FRAME), [])

    def test_ack_alone_is_released_at_readiness(self):
        sim = new_sim(5)
        horizon = jr.READINESS_NS + 3_000_000
        ticks(sim, T, T + horizon)
        inject(sim, T, rsp_off=None)
        sim.run(T + horizon)
        adm_a, _ = admissions(sim)
        anchor = sim.cell('admission_anchor')['word']
        expect = oracle(sim, anchor, 5, adm_a, None)
        self.assertEqual(expect.ack_reason, 'fallback')
        (em_a,) = emitted(sim, ACK_FRAME)
        assert_window(self, em_a, expect.e_ack, 'ACK-alone fallback')
        self.assertLess(em_a - (anchor - 1), 30_500_000)


class Rearm(unittest.TestCase):
    """T2-REARM whole program: a second association must not inherit the first one's state."""

    def test_second_read_is_held_for_its_own_d_a(self):
        sim = new_sim(5)
        second = T + 12_000_000
        ticks(sim, T, second + 7_000_000)
        inject(sim, T)
        inject(sim, second)
        sim.run(second - 1)
        self.assertEqual(len(emitted(sim, ACK_FRAME)), 1)
        self.assertEqual(len(emitted(sim, RSP_FRAME)), 1)
        # control-plane re-arm: new association cookie 2 everywhere the fixture keeps it
        sim.src.cells[('', 'association_cookie')][0] = 2
        sim.src.cells[('', 'timing_binding')][0] = {'epoch': 1, 'cookie': 2}
        for cell in sim.src.cells[('credits', 'cell')]:
            cell.update(epoch=1, credit=2 << 16)
        sim.run(second + 7_000_000)
        self.assertEqual(sim.drops, [])
        adm_a, adm_r = admissions(sim, after=second)
        self.assertEqual(sim.cell('admission_anchor')['cookie'], 2)
        anchor = sim.cell('admission_anchor')['word']
        self.assertGreater(anchor - 1, second)                    # armed by the second READ
        expect = oracle(sim, anchor, 5, adm_a, adm_r)
        (em_a,) = emitted(sim, ACK_FRAME, after=second)
        (em_r,) = emitted(sim, RSP_FRAME, after=second)
        assert_window(self, em_a, expect.e_ack, 'second ACK')
        self.assertGreater(em_a - adm_a, 4_900_000)               # stale release would be immediate
        assert_window(self, em_r, jr.tick_ge(jr.quantize(em_a) + jr.GAP_NS, PHASE + L), 'second response')
        for name in CELLS:
            self.assertEqual(sim.cell(name)['cookie'], 2, name)


class HeartbeatLoss(unittest.TestCase):
    """T2-HB-LOSS whole program: one lost service pass must not stop later timing progress."""

    @staticmethod
    def lose_first_service_pass(sim, after, port):
        state = {'lost': 0}

        def lose(time, egress, raw):
            if egress == port and time >= after and state['lost'] == 0:
                state['lost'] = 1
                return True
            return False
        sim.lose = lose
        return state

    def test_new_program_recovers_on_the_next_tick(self):
        sim = new_sim(5)
        state = self.lose_first_service_pass(sim, T + 1_000_000, w.PORTS['HB_RETURN'])
        horizon = jr.DA_NS[5] + 4_000_000
        ticks(sim, T, T + horizon)
        inject(sim, T)
        sim.run(T + horizon)
        self.assertEqual(state['lost'], 1)
        self.assertEqual([d for d in sim.drops if 'lost' not in d[2]], [])
        adm_a, adm_r = admissions(sim)
        expect = oracle(sim, sim.cell('admission_anchor')['word'], 5, adm_a, adm_r)
        (em_a,) = emitted(sim, ACK_FRAME)
        assert_window(self, em_a, expect.e_ack, 'ACK after lost pass (loss was before the due tick)')
        self.assertEqual(len(emitted(sim, RSP_FRAME)), 1)

    def test_loss_of_the_deciding_pass_delays_by_at_most_one_tick(self):
        sim = new_sim(5)
        due = T + 200_000 + jr.DA_NS[5]
        state = self.lose_first_service_pass(sim, due - 2 * PERIOD, w.PORTS['HB_RETURN'])
        horizon = jr.DA_NS[5] + 4_000_000
        ticks(sim, T, T + horizon)
        inject(sim, T)
        sim.run(T + horizon)
        self.assertEqual(state['lost'], 1)
        adm_a, adm_r = admissions(sim)
        expect = oracle(sim, sim.cell('admission_anchor')['word'], 5, adm_a, adm_r)
        (em_a,) = emitted(sim, ACK_FRAME)
        self.assertTrue(expect.e_ack < em_a <= expect.e_ack + L + 2 * PERIOD, (em_a - T, expect.e_ack - T))

    def test_frozen_probe_wedges_after_one_lost_service_pass(self):
        """Baseline for the defect T7 removes: same loss on the untouched probe, heartbeat_work pins."""
        ports = (71, 73)
        horizon = 12_000_000

        def run(lose):
            sim = w.Sim(PROBE, PROBE_DIR, loop_ns=L, loopbacks=ports)
            if lose:
                self.lose_first_service_pass(sim, T + 1_000_000, 73)
            ticks(sim, T, T + horizon)
            inject(sim, T)
            sim.run(T + horizon)
            return sim
        control = run(False)
        self.assertEqual(len(emitted(control, ACK_FRAME)), 1, 'probe releases without loss')
        wedged = run(True)
        self.assertEqual(emitted(wedged, ACK_FRAME), [], 'probe never releases after one lost pass')


if __name__ == '__main__':
    unittest.main()
