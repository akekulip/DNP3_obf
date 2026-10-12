#!/usr/bin/env python3
"""Proof that the proposed early wireACK-p fold is not equivalent generally."""
from __future__ import annotations

import random
import unittest


def current_endpoint(img_end: int, img_start: int, img_wend: int, wire_ack: int, window: int) -> int:
    # Current source: m.r = wire_ack - img_wend; endpoint = img_end - img_start + window + m.r.
    return (img_end - img_start + window + ((wire_ack - img_wend) & 0xffffffff)) & 0xffffffff


def proposed_endpoint(img_start: int, wire_ack: int, window: int) -> int:
    # Requested shortcut: q-p+r == original_wireACK-p, then add window.
    return (wire_ack - img_start + window) & 0xffffffff


class Full02Algebra(unittest.TestCase):
    def test_existing_regression_counterexample_wend_not_equal_end(self):
        img_end, img_start, img_wend = 950, 901, 959
        wire_ack = img_wend - 1
        window = 1
        self.assertEqual(current_endpoint(img_end, img_start, img_wend, wire_ack, window), 49)
        self.assertEqual(proposed_endpoint(img_start, wire_ack, window), 58)
        self.assertNotEqual(current_endpoint(img_end, img_start, img_wend, wire_ack, window),
                            proposed_endpoint(img_start, wire_ack, window))

    def test_equivalent_only_when_img_wend_matches_img_end(self):
        rng = random.Random(2)
        for _ in range(1000):
            img_start = rng.getrandbits(32)
            img_end = rng.getrandbits(32)
            wire_ack = rng.getrandbits(32)
            window = rng.getrandbits(16)
            self.assertEqual(current_endpoint(img_end, img_start, img_end, wire_ack, window),
                             proposed_endpoint(img_start, wire_ack, window))


if __name__ == '__main__':
    unittest.main(verbosity=2)
