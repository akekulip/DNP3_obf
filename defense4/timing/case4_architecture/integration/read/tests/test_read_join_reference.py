"""READ join schedule oracle (ticket T1), checked against ownership/reference.Schedule.

join_reference.py is an independent re-statement of the READ schedule:
  e_A = max(t0 + D_A, t_A, t_R)            (both originals held, before readiness)
  e_R = e_A + CLRT_new                     (CLRT_new = 999,936 ns on a 256 ns grid)
with fallback at readiness (30 ms) and a hard cap (40 ms). Software only: no P4, no target.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

ARCH = Path(__file__).resolve().parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ref = load('ownership_reference', ARCH / 'ownership/reference.py')
jr = load('join_reference', ARCH / 'integration/read/join_reference.py')

MS = 1_000_000
q = jr.quantize
MASK = 0xFFFFFFFF
STEP = 256


def first_time(predicate, lo, hi):
    """Smallest 256 ns-grid time in [lo, hi] with predicate true (monotone), else None."""
    if not predicate(hi):
        return None
    lo //= STEP
    hi //= STEP
    while lo < hi:
        mid = (lo + hi) // 2
        if predicate(mid * STEP):
            hi = mid
        else:
            lo = mid + 1
    return lo * STEP


def schedule_driver(t0, d_a_ns, t_a, t_r, horizon=45 * MS):
    """Drive ownership.reference.Schedule with the same events; returns (e_A, e_R).

    Times are unwrapped ns; Schedule only ever sees `& MASK`. A commit at the same
    instant as the readiness snapshot does not arm the response deadline (snapshot first).
    """
    end = t0 + horizon

    def fresh(now, commit):
        s = ref.Schedule(t0 & MASK, d_a_ns)
        s.ack_seen = t_a is not None and now >= t_a
        s.response_seen = t_r is not None and now >= t_r
        if commit is not None and commit < now:
            s.commit_ack(commit & MASK)
        return s

    e_a = None
    if t_a is not None:
        e_a = first_time(
            lambda now: now >= t_a and (fresh(now, None).ack_due(now & MASK) or
                                        fresh(now, None).readiness_expired(now & MASK)),
            t0, end)
    e_r = None
    if t_r is not None:
        def pred(now):
            s = fresh(now, e_a)
            return now >= t_r and (s.response_due(now & MASK) or s.fallback_due(now & MASK))
        # The predicate is monotone only inside each of the unarmed (<= commit) and armed
        # (> commit) regions, so search them separately.
        if e_a is None:
            e_r = first_time(pred, t0, end)
        else:
            e_r = first_time(pred, t0, e_a) or first_time(pred, e_a + STEP, end)
    return e_a, e_r


class Constants(unittest.TestCase):
    def test_quantized_constants_match_the_probe_literals(self):
        self.assertEqual(jr.DA_NS, {5: 4_999_936, 10: 9_999_872, 15: 14_999_808, 20: 20_000_000})
        self.assertEqual(jr.READINESS_NS, 29_999_872)
        self.assertEqual(jr.GAP_NS, 999_936)
        self.assertEqual(jr.CAP_NS, 40_000_000)
        self.assertEqual(jr.HEARTBEAT_NS, 100_000)
        for value in (*jr.DA_NS.values(), jr.READINESS_NS, jr.GAP_NS, jr.CAP_NS):
            self.assertEqual(value % 256, 0)

    def test_quantize_masks_low_byte(self):
        self.assertEqual(jr.quantize(0x12345678), 0x12345600)


class IdealEquations(unittest.TestCase):
    T0 = 0x01000000

    def test_normal_path_equations_for_every_d_a(self):
        for d_ms in (5, 10, 15, 20):
            r = jr.ideal(self.T0, d_ms, t_ack=self.T0 + 100_000, t_rsp=self.T0 + 300_000)
            self.assertEqual(r.e_ack, self.T0 + jr.DA_NS[d_ms], d_ms)
            self.assertEqual(r.e_rsp, r.e_ack + 999_936)
            self.assertEqual((r.ack_reason, r.rsp_reason), ('normal', 'gap'))

    def test_late_original_moves_e_ack_to_the_later_arrival(self):
        t_r = q(self.T0 + 12 * MS)
        r = jr.ideal(self.T0, 5, t_ack=self.T0 + 1 * MS, t_rsp=t_r)
        self.assertEqual(r.e_ack, t_r)
        self.assertEqual(r.e_rsp, t_r + 999_936)
        t_a = q(self.T0 + 13 * MS)
        r = jr.ideal(self.T0, 5, t_ack=t_a, t_rsp=self.T0 + 1 * MS)
        self.assertEqual(r.e_ack, t_a)

    def test_ack_without_response_falls_back_at_readiness(self):
        r = jr.ideal(self.T0, 5, t_ack=self.T0 + MS, t_rsp=None)
        self.assertEqual(r.e_ack, self.T0 + 29_999_872)
        self.assertEqual(r.ack_reason, 'fallback')
        self.assertIsNone(r.e_rsp)

    def test_response_without_ack_is_released_at_readiness(self):
        r = jr.ideal(self.T0, 5, t_ack=None, t_rsp=self.T0 + MS)
        self.assertIsNone(r.e_ack)
        self.assertEqual(r.e_rsp, self.T0 + 29_999_872)
        self.assertEqual(r.rsp_reason, 'fallback_no_ack')

    def test_both_absent_releases_nothing(self):
        r = jr.ideal(self.T0, 5, None, None)
        self.assertEqual((r.e_ack, r.e_rsp), (None, None))

    def test_response_after_readiness_with_ack_committed_uses_the_gap(self):
        t_r = q(self.T0 + 35 * MS)
        r = jr.ideal(self.T0, 5, t_ack=self.T0 + MS, t_rsp=t_r)
        self.assertEqual(r.e_ack, self.T0 + 29_999_872)
        self.assertEqual(r.e_rsp, t_r)          # deadline armed at 30 ms + gap is long past
        self.assertEqual(r.rsp_reason, 'gap')

    def test_fallback_is_finite_at_30ms_for_all_d_a(self):
        for d_ms in (5, 10, 15, 20):
            r = jr.ideal(self.T0, d_ms, t_ack=self.T0, t_rsp=None)
            self.assertLessEqual(r.e_ack - self.T0, 30 * MS)


class Cap(unittest.TestCase):
    T0 = 0x01000000

    def test_cap_clamps_response_commit_after_readiness(self):
        r = jr.ideal(self.T0, 5, t_ack=self.T0 + 39_500_000, t_rsp=self.T0 + 39_900_000)
        self.assertEqual(r.e_ack, q(self.T0 + 39_500_000))
        self.assertEqual(r.e_rsp, self.T0 + 40_000_000)   # 39.5 + 1.0 ms would exceed the cap
        self.assertEqual(r.rsp_reason, 'cap')

    def test_original_arriving_after_cap_is_not_held(self):
        r = jr.ideal(self.T0, 5, t_ack=self.T0 + 41 * MS, t_rsp=self.T0 + 42 * MS)
        self.assertEqual((r.e_ack, r.e_rsp), (q(self.T0 + 41 * MS), q(self.T0 + 42 * MS)))
        self.assertEqual((r.ack_reason, r.rsp_reason), ('bypass', 'bypass'))

    def test_no_release_exceeds_cap_for_held_originals(self):
        for t_a in range(0, 40 * MS, 3_700_000):
            for t_r in (None, 0, 7 * MS, 29 * MS, 39_999_000):
                r = jr.ideal(self.T0, 20, t_a, t_r)
                for e in (r.e_ack, r.e_rsp):
                    self.assertTrue(e is None or e - self.T0 <= jr.CAP_NS)


class AgainstSchedule(unittest.TestCase):
    """Matrix: D_A x early/late/absent x clock wrap, equal to ownership.reference.Schedule."""
    SCENARIOS = {
        'both_early': (100_000, 300_000),
        'ack_early_rsp_late': (100_000, 7 * MS),
        'ack_late_rsp_early': (12 * MS, 200_000),
        'both_after_deadline': (21 * MS, 22 * MS),
        'ack_absent': (None, 500_000),
        'rsp_absent': (500_000, None),
        'ack_after_readiness': (33 * MS, 1 * MS),
        'rsp_after_readiness': (1 * MS, 35 * MS),
        'both_absent': (None, None),
    }
    BASES = {'plain': 0x01000000, 'wrap': 0xFFFFFFFF - 3 * MS + 1 - 0xFF & ~0xFF}

    def test_matrix(self):
        count = 0
        for base_name, base in self.BASES.items():
            self.assertEqual(base & 0xFF, 0)
            for d_ms in (5, 10, 15, 20):
                for name, (a, r_) in self.SCENARIOS.items():
                    t_a = None if a is None else q(base + a)
                    t_r = None if r_ is None else q(base + r_)
                    mine = jr.ideal(base, d_ms, t_a, t_r)
                    theirs = schedule_driver(base, d_ms * MS, t_a, t_r)
                    label = (base_name, d_ms, name)
                    self.assertEqual((mine.e_ack, mine.e_rsp), theirs, label)
                    count += 1
        self.assertEqual(count, 2 * 4 * 9)

    def test_wrap_case_really_crosses_2_pow_32(self):
        base = self.BASES['wrap']
        r = jr.ideal(base, 5, base + 100_000, base + 300_000)
        self.assertGreater(r.e_ack, MASK)
        self.assertEqual(jr.wrap(r.e_ack), (base + jr.DA_NS[5]) & MASK)
        self.assertLess(jr.wrap(r.e_ack), base)


class Heartbeat(unittest.TestCase):
    T0 = 0x01000000

    def test_ticked_releases_at_first_tick_not_before(self):
        ideal = jr.ideal(self.T0, 5, self.T0 + 100_000, self.T0 + 300_000)
        for phase in (0, 33_000, 99_999):
            t = jr.ticked(self.T0, 5, self.T0 + 100_000, self.T0 + 300_000, phase=phase)
            self.assertGreaterEqual(t.e_ack, ideal.e_ack)
            self.assertLess(t.e_ack - ideal.e_ack, jr.HEARTBEAT_NS)
            self.assertEqual((t.e_ack - phase) % jr.HEARTBEAT_NS, 0)
            self.assertGreaterEqual(t.e_rsp, t.e_ack + jr.GAP_NS)
            self.assertLess(t.e_rsp - (t.e_ack + jr.GAP_NS), jr.HEARTBEAT_NS)

    def test_ticked_is_independent_of_original_arrival_phase(self):
        a = jr.ticked(self.T0, 10, self.T0 + 1 * MS, self.T0 + 2 * MS, phase=0)
        b = jr.ticked(self.T0, 10, self.T0 + 1 * MS + 777, self.T0 + 2 * MS + 5, phase=0)
        self.assertEqual((a.e_ack, a.e_rsp), (b.e_ack, b.e_rsp))


if __name__ == '__main__':
    unittest.main()
