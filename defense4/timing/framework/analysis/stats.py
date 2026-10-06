"""Summary statistics for latency populations, with every denominator stated.

Standard library only. Quantiles use linear interpolation between order statistics (numpy's default, type 7).
Sample variance divides by n - 1. Nothing is renormalised silently: window percentages take the denominator they are given.
"""
import math


def quantile(sorted_vals, p):
    if not sorted_vals:
        raise ValueError("no data")
    if not 0.0 <= p <= 1.0:
        raise ValueError("p must be in [0, 1]")
    h = (len(sorted_vals) - 1) * p
    lo = int(math.floor(h))
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (h - lo) * (sorted_vals[hi] - sorted_vals[lo])


def summarize(values, *, attempted=None):
    """n, mean, median, IQR, sample variance and sd, selected quantiles and the full range.

    `attempted` is the denominator for the completion rate; without it none is reported, because a value
    that is not stated is not a value."""
    v = sorted(float(x) for x in values)
    n = len(v)
    if n == 0:
        raise ValueError("no data")
    mean = sum(v) / n
    var = sum((x - mean) ** 2 for x in v) / (n - 1) if n > 1 else float("nan")
    q1, med, q3 = (quantile(v, p) for p in (0.25, 0.5, 0.75))
    out = {"n": n, "mean": mean, "median": med, "q1": q1, "q3": q3, "iqr": q3 - q1,
           "variance_sample": var, "sd_sample": math.sqrt(var) if n > 1 else float("nan"),
           "min": v[0], "max": v[-1], "p05": quantile(v, 0.05), "p95": quantile(v, 0.95),
           "p99": quantile(v, 0.99), "p999": quantile(v, 0.999)}
    if attempted is not None:
        if attempted < n:
            raise ValueError("attempted (%d) is smaller than the number of values (%d)" % (attempted, n))
        out["attempted"] = attempted
        out["completion_rate"] = n / attempted
    return out


def window_fraction(values, lo, hi, denominator):
    """Share of the stated denominator whose value lies in [lo, hi]. Values outside, and exchanges with no value,
    stay in the denominator; a zoomed subset is never renormalised."""
    if denominator <= 0:
        raise ValueError("denominator must be positive")
    inside = sum(1 for x in values if lo <= x <= hi)
    if inside > denominator:
        raise ValueError("more values than the denominator")
    return {"inside": inside, "denominator": denominator, "fraction": inside / denominator}


def histogram(values, edges, denominator):
    """Counts per [edge_i, edge_{i+1}) bin (last bin closed), as a percentage of the whole condition, plus what fell outside."""
    counts = [0] * (len(edges) - 1)
    below = above = 0
    for x in values:
        if x < edges[0]:
            below += 1
        elif x > edges[-1]:
            above += 1
        else:
            i = min(max(i for i in range(len(edges) - 1) if edges[i] <= x), len(edges) - 2)
            counts[i] += 1
    return {"edges": list(edges), "counts": counts, "percent": [100.0 * c / denominator for c in counts],
            "below": below, "above": above, "denominator": denominator}


def formby_signature(values, H, B=200):
    """Formby et al., NDSS 2016, Eq. (1): B elements. For 0 < j < B, s_j counts t_{j-1} <= m < t_j with t_i = i*H/(B-1);
    s_B counts m > H. So there are B-1 regular bins of width H/(B-1) and one overflow element; a value exactly equal to H
    belongs to neither (as printed), and is returned separately so the total is accounted for."""
    if B < 3 or H <= 0:
        raise ValueError("need B >= 3 and H > 0")
    width = H / (B - 1)
    s = [0] * B
    on_edge = negative = nonfinite = total = 0
    for m in values:
        total += 1
        if not math.isfinite(m):
            nonfinite += 1
        elif m < 0:
            negative += 1
        elif m > H:
            s[B - 1] += 1
        elif m == H:
            on_edge += 1
        elif m >= 0:
            s[min(int(m / width), B - 2)] += 1
    return {"signature": s, "bin_width": width, "H": H, "B": B,
            "exactly_H_uncounted": on_edge, "negative_uncounted": negative,
            "nonfinite_uncounted": nonfinite, "input_count": total,
            "overflow_count": s[-1]}
