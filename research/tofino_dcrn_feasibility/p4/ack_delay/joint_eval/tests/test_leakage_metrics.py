#!/usr/bin/env python3
"""
Verify the joint-eval leakage metrics on SYNTHETIC fixtures — a leaky channel and a normalized one — so
the analysis is trusted before it is ever pointed at real per-run feature tables. No hardware data.

  leaky      : feature is device-dependent (each of k devices has a well-separated feature mean)
               -> MI near log2(k) bits, balanced accuracy near 1.0, chance NOT within CI.
  normalized : feature is device-INDEPENDENT (identical distribution for all devices)
               -> MI near 0, balanced accuracy near chance, chance WITHIN CI.
"""
import os
import sys
import unittest

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from leakage_metrics import (mutual_information, balanced_accuracy_grouped, bootstrap_ci,  # noqa: E402
                             within_chance)

K = 3          # devices/classes
GROUPS = 12    # independent sessions/runs (grouping unit)
PER = 40       # samples per group


def make_dataset(leaky, seed=1):
    rng = np.random.default_rng(seed)
    X, y, g = [], [], []
    for gi in range(GROUPS):
        dev = gi % K                                   # each group belongs to one device
        for _ in range(PER):
            if leaky:
                val = dev * 10.0 + rng.normal(0, 1.0)  # device-separated feature (leak)
            else:
                val = rng.normal(5.0, 1.0)             # identical for all devices (normalized)
            X.append(val); y.append(dev); g.append(gi)
    return np.array(X), np.array(y), np.array(g)


class TestLeakageMetrics(unittest.TestCase):
    def test_leaky_channel_detected(self):
        X, y, g = make_dataset(leaky=True)
        mi = mutual_information(X, y)
        bal, chance = balanced_accuracy_grouped(X, y, g)
        self.assertGreater(mi, 1.0)                    # near log2(3)=1.58 bits
        self.assertGreater(bal, 0.9)                   # feature separates devices
        # per-group accuracy CI should sit above chance
        accs = []
        for gi in np.unique(g):
            te = g == gi; tr = ~te
            if np.unique(y[tr]).size < 2:
                continue
            from leakage_metrics import _nearest_centroid_fit_predict
            Xa = X[:, None]
            pred = _nearest_centroid_fit_predict(Xa[tr], y[tr], Xa[te])
            accs.append((pred == y[te]).mean())
        _, lo, hi = bootstrap_ci(accs, seed=0)
        self.assertFalse(within_chance(bal, lo, hi, chance))   # leak: chance NOT in CI

    def test_normalized_channel_is_at_chance(self):
        X, y, g = make_dataset(leaky=False)
        mi = mutual_information(X, y)
        bal, chance = balanced_accuracy_grouped(X, y, g)
        self.assertLess(mi, 0.05)                      # ~0 bits: no channel
        self.assertLess(abs(bal - chance), 0.15)       # near 1/3
        accs = []
        for gi in np.unique(g):
            te = g == gi; tr = ~te
            if np.unique(y[tr]).size < 2:
                continue
            from leakage_metrics import _nearest_centroid_fit_predict
            Xa = X[:, None]
            pred = _nearest_centroid_fit_predict(Xa[tr], y[tr], Xa[te])
            accs.append((pred == y[te]).mean())
        _, lo, hi = bootstrap_ci(accs, seed=0)
        self.assertTrue(within_chance(bal, lo, hi, chance))    # normalized: chance IN CI

    def test_grouping_prevents_session_leak(self):
        # sanity: grouped split never trains and tests on the same group
        X, y, g = make_dataset(leaky=True)
        self.assertEqual(len(np.unique(g)), GROUPS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
