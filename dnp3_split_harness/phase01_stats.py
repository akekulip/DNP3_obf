"""phase01_stats.py -- distribution statistics for Phase 01 (numpy only, no scipy).

Descriptive statistics, seeded bootstrap confidence intervals, and two-sample
distributional comparisons (Kolmogorov-Smirnov statistic, 1-D Wasserstein distance,
Cliff's delta, Cohen's d) implemented directly on numpy so Phase 01 adds no dependency
and stays Python 3.8 compatible. All randomized routines take an explicit seed.
"""

from __future__ import annotations

import math
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np


def _clean(values: Sequence[Optional[float]]) -> np.ndarray:
    arr = np.array([v for v in values if v is not None], dtype=float)
    return arr[np.isfinite(arr)]


def describe(values: Sequence[Optional[float]]) -> Dict[str, Optional[float]]:
    """Full descriptive summary. Percentiles use linear interpolation."""
    arr = _clean(values)
    if arr.size == 0:
        keys = ["n", "mean", "median", "std", "cv", "min", "p5", "p25",
                "p75", "p95", "p99", "max"]
        out: Dict[str, Optional[float]] = {k: None for k in keys}
        out["n"] = 0
        return out
    mean = float(arr.mean())
    std = float(arr.std(ddof=0))
    p = np.percentile(arr, [5, 25, 50, 75, 95, 99])
    return {
        "n": int(arr.size),
        "mean": round(mean, 6),
        "median": round(float(p[2]), 6),
        "std": round(std, 6),
        "cv": round(std / mean, 6) if mean != 0 else None,
        "min": round(float(arr.min()), 6),
        "p5": round(float(p[0]), 6),
        "p25": round(float(p[1]), 6),
        "p75": round(float(p[3]), 6),
        "p95": round(float(p[4]), 6),
        "p99": round(float(p[5]), 6),
        "max": round(float(arr.max()), 6),
    }


def bootstrap_ci(
    values: Sequence[Optional[float]],
    statistic: str = "mean",
    n_boot: int = 2000,
    alpha: float = 0.05,
    seed: int = 12345,
) -> Dict[str, Optional[float]]:
    """Percentile bootstrap CI for 'mean' or 'median'. Returns {stat, lo, hi, n, n_boot}."""
    arr = _clean(values)
    if arr.size == 0:
        return {"statistic": statistic, "point": None, "lo": None, "hi": None,
                "n": 0, "n_boot": n_boot}
    func = np.mean if statistic == "mean" else np.median
    point = float(func(arr))
    if arr.size == 1:
        return {"statistic": statistic, "point": round(point, 6),
                "lo": round(point, 6), "hi": round(point, 6),
                "n": 1, "n_boot": n_boot}
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, arr.size, size=(n_boot, arr.size))
    boot = func(arr[idx], axis=1)
    lo = float(np.percentile(boot, 100 * (alpha / 2)))
    hi = float(np.percentile(boot, 100 * (1 - alpha / 2)))
    return {"statistic": statistic, "point": round(point, 6),
            "lo": round(lo, 6), "hi": round(hi, 6),
            "n": int(arr.size), "n_boot": n_boot}


def ks_2samp_stat(a: Sequence[Optional[float]], b: Sequence[Optional[float]]) -> Optional[float]:
    """Two-sample Kolmogorov-Smirnov statistic D = max|F_a - F_b| (numpy)."""
    x = np.sort(_clean(a))
    y = np.sort(_clean(b))
    if x.size == 0 or y.size == 0:
        return None
    grid = np.concatenate([x, y])
    cdf_x = np.searchsorted(x, grid, side="right") / x.size
    cdf_y = np.searchsorted(y, grid, side="right") / y.size
    return round(float(np.max(np.abs(cdf_x - cdf_y))), 6)


def wasserstein1(a: Sequence[Optional[float]], b: Sequence[Optional[float]]) -> Optional[float]:
    """1-D Wasserstein-1 distance W1 = integral of |F_a - F_b| (numpy)."""
    x = np.sort(_clean(a))
    y = np.sort(_clean(b))
    if x.size == 0 or y.size == 0:
        return None
    grid = np.sort(np.concatenate([x, y]))
    deltas = np.diff(grid)
    cdf_x = np.searchsorted(x, grid[:-1], side="right") / x.size
    cdf_y = np.searchsorted(y, grid[:-1], side="right") / y.size
    return round(float(np.sum(np.abs(cdf_x - cdf_y) * deltas)), 6)


def cliffs_delta(a: Sequence[Optional[float]], b: Sequence[Optional[float]]) -> Optional[float]:
    """Cliff's delta effect size in [-1, 1] via a rank-based O(n log n) computation."""
    x = _clean(a)
    y = _clean(b)
    if x.size == 0 or y.size == 0:
        return None
    ys = np.sort(y)
    greater = np.sum(np.searchsorted(ys, x, side="left"))          # count y < xi
    less_or_eq = np.sum(np.searchsorted(ys, x, side="right"))      # count y <= xi
    less = x.size * ys.size - less_or_eq                           # count y > xi
    return round(float((greater - less) / (x.size * ys.size)), 6)


def cohens_d(a: Sequence[Optional[float]], b: Sequence[Optional[float]]) -> Optional[float]:
    """Cohen's d with pooled standard deviation."""
    x = _clean(a)
    y = _clean(b)
    if x.size < 2 or y.size < 2:
        return None
    nx, ny = x.size, y.size
    sp2 = ((nx - 1) * x.var(ddof=1) + (ny - 1) * y.var(ddof=1)) / (nx + ny - 2)
    if sp2 == 0:
        return 0.0
    return round(float((x.mean() - y.mean()) / math.sqrt(sp2)), 6)


def wilson_ci(k: int, n: int, z: float = 1.96) -> Dict[str, Optional[float]]:
    """Wilson score 95% CI for a binomial proportion k/n (better than normal for small n)."""
    if n == 0:
        return {"p": None, "lo": None, "hi": None, "k": k, "n": n}
    p = k / n
    denom = 1.0 + z * z / n
    center = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return {"p": round(p, 4), "lo": round(max(0.0, center - half), 4),
            "hi": round(min(1.0, center + half), 4), "k": k, "n": n}


def compare_distributions(
    a: Sequence[Optional[float]], b: Sequence[Optional[float]]
) -> Dict[str, Optional[float]]:
    """Bundle KS, Wasserstein-1, Cliff's delta, Cohen's d, and the two medians."""
    x = _clean(a)
    y = _clean(b)
    return {
        "n_a": int(x.size), "n_b": int(y.size),
        "median_a": round(float(np.median(x)), 6) if x.size else None,
        "median_b": round(float(np.median(y)), 6) if y.size else None,
        "ks": ks_2samp_stat(a, b),
        "wasserstein1": wasserstein1(a, b),
        "cliffs_delta": cliffs_delta(a, b),
        "cohens_d": cohens_d(a, b),
    }
