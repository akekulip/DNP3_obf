"""Distribution statistics: percentiles, ECDF, fixed-width entropy, bootstrap CIs.

Percentile convention (documented, load-bearing): ``method='nearest'`` — the
reported percentile is an actual empirical order statistic, never an interpolated
value. This reproduces the accepted paper anchors (native OFF Campaign A
p99 = 13.67 ms, max = 15.65 ms) exactly, whereas linear interpolation would not.

Entropy binning rule (documented): Shannon entropy in bits over fixed-width bins
of ``BIN_WIDTH_MS`` = 0.5 ms spanning [0, ceil(max)] ms. ``effective_states`` is
2**H. The same rule is applied to every distribution so entropies are comparable.
"""

from __future__ import annotations

import math
from typing import Callable

import numpy as np

PCT_METHOD = "nearest"
BIN_WIDTH_MS = 0.5


def pct(x: np.ndarray, q: float, method: str = PCT_METHOD) -> float:
    """Percentile ``q`` (0-100) with the documented nearest-order-statistic rule."""
    return float(np.percentile(np.asarray(x, dtype=float), q, method=method))


def ecdf(x: np.ndarray) -> tuple[list[float], list[float]]:
    """Return (sorted_values, cdf) where cdf[i] = (i+1)/n."""
    s = np.sort(np.asarray(x, dtype=float))
    n = s.size
    return s.tolist(), [(i + 1) / n for i in range(n)]


def entropy_bits(x: np.ndarray, bin_width: float = BIN_WIDTH_MS) -> tuple[float, float]:
    """Shannon entropy (bits) and effective states 2**H over fixed-width bins."""
    a = np.asarray(x, dtype=float)
    if a.size == 0:
        return 0.0, 1.0
    hi = math.ceil(max(a.max(), bin_width))
    edges = np.arange(0.0, hi + bin_width, bin_width)
    counts, _ = np.histogram(a, bins=edges)
    p = counts[counts > 0] / counts.sum()
    h = float(-(p * np.log2(p)).sum())
    return h, float(2.0 ** h)


def summary(x: np.ndarray) -> dict:
    """Count/min/median/p95/p99/max, p5-p95 spread, IQR, entropy, effective states."""
    a = np.asarray(x, dtype=float)
    n = a.size
    if n == 0:
        return {"n": 0}
    h, eff = entropy_bits(a)
    return {
        "n": int(n),
        "min": float(a.min()),
        "p5": pct(a, 5),
        "median": pct(a, 50),
        "p95": pct(a, 95),
        "p99": pct(a, 99) if n >= 100 else None,
        "max": float(a.max()),
        "mean": float(a.mean()),
        "p5_p95_spread_ms": pct(a, 95) - pct(a, 5),
        "iqr_ms": pct(a, 75) - pct(a, 25),
        "entropy_bits": h,
        "effective_states": eff,
        "pct_method": PCT_METHOD,
        "entropy_bin_width_ms": BIN_WIDTH_MS,
    }


def wilson_ci(k: int, n: int, alpha: float = 0.05) -> dict | None:
    """Wilson score interval for a binomial proportion k/n (e.g. coverage).

    Wilson is preferred over the normal-approximation Wald interval near p=1, which
    is exactly the coverage regime here. Returns None if n == 0.
    """
    if n <= 0:
        return None
    from scipy.stats import norm

    z = float(norm.ppf(1 - alpha / 2))
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return {
        "point": float(p),
        "k": int(k),
        "n": int(n),
        "ci_lo": float(max(0.0, centre - half)),
        "ci_hi": float(min(1.0, centre + half)),
        "alpha": alpha,
        "method": "wilson_score",
    }


def bootstrap_ci(
    x: np.ndarray,
    stat: Callable[[np.ndarray], float],
    B: int = 2000,
    seed: int = 20260807,
    alpha: float = 0.05,
    n_min: int = 20,
) -> dict | None:
    """Percentile-bootstrap CI for ``stat`` on ``x``.

    Returns None if n < ``n_min`` (CI not reported rather than fabricated).
    Transaction-level resampling; the session-clustering caveat is stated in the
    report. Seed is fixed for reproducibility.
    """
    a = np.asarray(x, dtype=float)
    if a.size < n_min:
        return None
    rng = np.random.default_rng(seed)
    n = a.size
    reps = np.empty(B, dtype=float)
    for b in range(B):
        reps[b] = stat(a[rng.integers(0, n, n)])
    lo = float(np.percentile(reps, 100 * alpha / 2))
    hi = float(np.percentile(reps, 100 * (1 - alpha / 2)))
    return {
        "point": float(stat(a)),
        "ci_lo": lo,
        "ci_hi": hi,
        "alpha": alpha,
        "B": B,
        "seed": seed,
        "method": "percentile_bootstrap_transaction_level",
    }
