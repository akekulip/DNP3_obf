#!/usr/bin/env python3
"""Algebraic parity for the E window-fold classify_rev row split."""
from __future__ import annotations

import random
import unittest


def baseline(end: int, start: int, offset: int, window: int):
    offset &= 0xffffffff
    if offset < 0x80000000:
        return ("translate", (end + offset) & 0xffffffff, window, 9)
    distance = (-offset) & 0xffffffff
    if distance > 58:
        return ("drop", None, None, 11)
    if window < distance:
        return ("zero", start, 0, 10)
    endpoint = (end - start + window - distance) & 0xffffffff
    return ("exact" if endpoint <= 0xffff else "clamp", start, min(endpoint, 0xffff), 10)


def folded(end: int, start: int, offset: int, window: int):
    offset &= 0xffffffff
    final_endpoint = (end - start + window + offset) & 0xffffffff
    if offset < 0x80000000:
        return ("translate", (end + offset) & 0xffffffff, window, 9)
    distance = (-offset) & 0xffffffff
    if distance > 58:
        return ("drop", None, None, 11)
    if window < distance:
        return ("zero", start, 0, 10)
    if (final_endpoint & 0xffff0000) == 0:
        return ("exact", start, final_endpoint & 0xffff, 10)
    return ("clamp", start, 0xffff, 10)


class RowEquivalence(unittest.TestCase):
    def test_boundaries_and_random_match_existing_regression_domain(self):
        rng = random.Random(1)
        cases = []
        for distance in range(1, 59):
            for window in sorted({0, distance - 1, distance, distance + 1, 65535}):
                cases.append((950, 901, -distance, window))
                cases.append((0x20, 0xfffffff0, -distance, window))
                # Explicit spillover: endpoint before subtract is just above 65535.
                cases.append((0x10000 + distance, 0, -distance, window))
                cases.append((0x10000 + distance + 1, 0, -distance, window))
        for offset in (0, 1, 58, 0x7fffffff, 0x80000000, 0x80000001, -59, -65535):
            for window in (0, 1, 58, 65535):
                cases.append((950, 901, offset, window))
        cases += [(rng.getrandbits(32), rng.getrandbits(32), rng.getrandbits(32), rng.getrandbits(16)) for _ in range(5000)]
        for end, start, offset, window in cases:
            with self.subTest(end=end, start=start, offset=offset, window=window):
                self.assertEqual(folded(end, start, offset, window), baseline(end, start, offset, window))


if __name__ == '__main__':
    unittest.main(verbosity=2)
