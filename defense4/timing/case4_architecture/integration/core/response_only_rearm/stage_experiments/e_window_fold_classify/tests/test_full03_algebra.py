#!/usr/bin/env python3
"""Algebraic coverage for full_03 reverse-window exact/clamp split."""
from __future__ import annotations

import random
import unittest


def baseline_from_b(distance: int, original_window: int, b_value: int):
    if original_window < distance:
        return ("zero", 0)
    endpoint = (b_value - distance) & 0xffffffff
    if endpoint <= 0xffff:
        return ("exact", endpoint & 0xffff)
    return ("clamp", 0xffff)


def full03_from_b(distance: int, original_window: int, b_value: int):
    if original_window < distance:
        return ("zero", 0)
    hi = (b_value >> 16) & 0xffff
    lo = b_value & 0xffff
    if hi == 0 and lo >= distance:
        return ("exact", (lo - distance) & 0xffff)
    if hi == 1 and lo < distance:
        return ("exact", (lo - distance) & 0xffff)
    return ("clamp", 0xffff)


class Full03Algebra(unittest.TestCase):
    def test_exhaustive_original_window_thresholds(self):
        for distance in range(1, 59):
            for original_window in range(0, 65536):
                # One exact and one clamp representative prove the only window-dependent split: < d is zero.
                self.assertEqual(full03_from_b(distance, original_window, distance),
                                 baseline_from_b(distance, original_window, distance))
                self.assertEqual(full03_from_b(distance, original_window, 0x20000),
                                 baseline_from_b(distance, original_window, 0x20000))

    def test_exhaustive_b_boundaries_for_threshold_windows(self):
        for distance in range(1, 59):
            b_values = set(range(0, distance + 2))
            b_values.update(range(max(0, 0xffff - distance - 2), 0xffff + distance + 3))
            b_values.update(range(0x10000 - 2, 0x10000 + distance + 3))
            b_values.update(range(0x1ffff - distance - 2, 0x1ffff + distance + 3))
            b_values.update([0xffffffff, 0xfffffffe, 0x80000000, 0x7fffffff, 0x20000])
            for original_window in (0, max(0, distance - 1), distance, min(65535, distance + 1), 65535):
                for b_value in {v & 0xffffffff for v in b_values}:
                    self.assertEqual(full03_from_b(distance, original_window, b_value),
                                     baseline_from_b(distance, original_window, b_value),
                                     (distance, original_window, b_value))

    def test_random_modular_gap_window_space(self):
        rng = random.Random(3)
        for _ in range(200000):
            distance = rng.randint(1, 58)
            original_window = rng.getrandbits(16)
            gap = rng.getrandbits(32)
            b_value = (gap + original_window) & 0xffffffff
            self.assertEqual(full03_from_b(distance, original_window, b_value),
                             baseline_from_b(distance, original_window, b_value))


if __name__ == '__main__':
    unittest.main(verbosity=2)
