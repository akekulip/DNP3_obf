"""Exact timestamp ties must agree with the bin boundaries reported to readers."""
from decimal import Decimal
from pathlib import Path
import sys

import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "audit_current/tools"))
import clrt_distribution_and_variance as clrt


def test_clrt_zoom_bins_and_combined_plot_use_the_declared_decimal_boundaries(monkeypatch):
    captures = []
    monkeypatch.setattr(clrt, "emit", lambda fig, *a, **kw: captures.append(fig))
    values = np.array([7.925, 7.930, 7.935, 7.965, 7.970, 8.030, 8.035, 8.075, 8.100])
    arms = {arm: values for arm in ("native", "obfuscated")}
    rows = []
    clrt.figure_zoom(arms, 8.0, None, [], rows)
    for row in rows:
        lo, hi = row["bin_lo_ms"], row["bin_hi_ms"]
        last = hi == 8.1
        expected = sum(lo <= v <= hi if last else lo <= v < hi for v in values)
        assert row["transactions"] == expected
        assert row["edge_convention"].startswith("[lo, hi]" if last else "[lo, hi)")

    accounting = {"read_rows": 2 * len(values), "non_read_rows": 0, "excluded_from_plot": 0}
    clrt.figure_clrt_grid(arms, 8.0, None, [], accounting, [])
    edges = [float(Decimal("7.9") + Decimal("0.005") * i) for i in range(41)]
    expected = [100 * sum(lo <= v <= hi if i == 39 else lo <= v < hi for v in values) / len(values)
                for i, (lo, hi) in enumerate(zip(edges, edges[1:]))]
    for arm_patches in (captures[-1].axes[1].patches[:40], captures[-1].axes[1].patches[40:]):
        np.testing.assert_allclose([p.get_height() for p in arm_patches], expected)
    plt.close("all")
