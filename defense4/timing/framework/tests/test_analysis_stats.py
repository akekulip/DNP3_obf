import random
import sys
import unittest
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "analysis"))
import stats  # noqa: E402


class Stats(unittest.TestCase):
    def test_matches_numpy_on_random_data(self):
        rng = random.Random(3)
        for n in (2, 3, 10, 101, 1000):
            v = [rng.lognormvariate(0, 1) for _ in range(n)]
            s = stats.summarize(v)
            self.assertAlmostEqual(s["mean"], float(np.mean(v)))
            self.assertAlmostEqual(s["variance_sample"], float(np.var(v, ddof=1)))
            self.assertAlmostEqual(s["sd_sample"], float(np.std(v, ddof=1)))
            for key, p in (("median", 50), ("q1", 25), ("q3", 75), ("p95", 95), ("p99", 99), ("p999", 99.9)):
                self.assertAlmostEqual(s[key], float(np.percentile(v, p)), places=9, msg=(n, key))
            self.assertAlmostEqual(s["iqr"], float(np.percentile(v, 75) - np.percentile(v, 25)))

    def test_variance_is_sample_not_population(self):
        self.assertAlmostEqual(stats.summarize([1, 2, 3, 4])["variance_sample"], 5 / 3)

    def test_no_completion_rate_without_a_denominator(self):
        self.assertNotIn("completion_rate", stats.summarize([1, 2, 3]))
        self.assertEqual(stats.summarize([1, 2, 3], attempted=4)["completion_rate"], 0.75)
        with self.assertRaises(ValueError):
            stats.summarize([1, 2, 3], attempted=2)

    def test_window_is_over_the_stated_denominator_not_the_subset(self):
        w = stats.window_fraction([1.0, 1.0, 5.0], 0.9, 1.1, denominator=10)
        self.assertEqual((w["inside"], w["denominator"], w["fraction"]), (2, 10, 0.2))
        with self.assertRaises(ValueError):
            stats.window_fraction([1.0] * 5, 0, 2, denominator=3)

    def test_histogram_percent_is_of_the_whole_condition_and_reports_what_fell_outside(self):
        h = stats.histogram([0.5, 1.5, 1.5, 9.0, -1.0], [0, 1, 2, 3], denominator=5)
        self.assertEqual(h["counts"], [1, 2, 0])
        self.assertEqual((h["below"], h["above"]), (1, 1))
        self.assertAlmostEqual(sum(h["percent"]), 60.0)               # 40 % is outside the plotted range, and says so
        self.assertEqual(stats.histogram([3.0], [0, 1, 2, 3], 1)["counts"], [0, 0, 1])   # the last bin is closed

    def test_empty_and_bad_inputs_raise(self):
        with self.assertRaises(ValueError):
            stats.summarize([])
        with self.assertRaises(ValueError):
            stats.quantile([1.0], 1.5)

    def test_formby_signature_follows_equation_1(self):
        sig = stats.formby_signature([0.0, 0.049, 0.05, 14.99, 15.0, 15.01, 99.0], H=15.0, B=4)    # width 5, bins [0,5) [5,10) [10,15), overflow
        self.assertEqual(sig["signature"], [3, 0, 1, 2])
        self.assertEqual(sig["bin_width"], 5.0)
        self.assertEqual(sig["exactly_H_uncounted"], 1)
        self.assertEqual(sum(sig["signature"]) + sig["exactly_H_uncounted"], 7)
        big = stats.formby_signature([i * 0.01 for i in range(1501)], H=15.0, B=200)
        self.assertEqual(len(big["signature"]), 200)
        self.assertAlmostEqual(big["bin_width"], 15.0 / 199)

    def test_formby_signature_rejects_bad_parameters(self):
        for B, H in ((2, 1.0), (200, 0.0)):
            with self.assertRaises(ValueError):
                stats.formby_signature([1.0], H, B)


if __name__ == "__main__":
    unittest.main()
