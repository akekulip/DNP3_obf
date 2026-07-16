#!/usr/bin/env python3
"""Phase 01 trace-characterization figures.

Reusable, deterministic figure generator for the DNP3 ACK/timing
trace-characterization study. Reads a single run's
``tables/ack_trace_characterization.csv`` (one row per transaction) and
writes 15 publication-style figures into ``<run-dir>/figures/``. Each figure is
exported as PNG (150 dpi), vector PDF, and SVG, with a JSON metadata sidecar
recording provenance and the statistical transformation applied.

Only device-specific rows (``is_reference == False``) are analysed. Pure-ACK
metrics are populated only for ``SEPARATE_ACK_RESPONSE`` rows; blank cells are
dropped for the pure-ACK figures.

Python 3.8 compatible. No pandas: standard ``csv`` + numpy + matplotlib (Agg).
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

DEFAULT_RUN_DIR = "runs/20260716T024101Z_phase_01_real_trace_characterization"
SCRIPT_NAME = "phase01_figures.py"
IMAGE_FORMATS: Tuple[str, ...] = ("png", "pdf", "svg")
PNG_DPI = 200

DEVICE_ORDER: Tuple[str, ...] = ("SEL751", "AB1400", "ION7550")

# Per-device styling: distinct colour AND linestyle AND marker so the figures
# remain distinguishable when printed in grayscale.
DEVICE_STYLE: Dict[str, Dict[str, str]] = {
    "SEL751": {"color": "#1f3a93", "linestyle": "-", "marker": "o"},
    "AB1400": {"color": "#d1691e", "linestyle": "--", "marker": "s"},
    "ION7550": {"color": "#2e7d32", "linestyle": "-.", "marker": "^"},
}

# Classification categories used by the ACK-mode fraction figure.
ACK_MODES: Tuple[str, ...] = (
    "COMBINED_ACK_RESPONSE",
    "SEPARATE_ACK_RESPONSE",
    "OTHER_OR_AMBIGUOUS",
)
ACK_MODE_LABELS: Dict[str, str] = {
    "COMBINED_ACK_RESPONSE": "Combined",
    "SEPARATE_ACK_RESPONSE": "Separate",
    "OTHER_OR_AMBIGUOUS": "Other/ambiguous",
}
ACK_MODE_HATCH: Dict[str, str] = {
    "COMBINED_ACK_RESPONSE": "",
    "SEPARATE_ACK_RESPONSE": "///",
    "OTHER_OR_AMBIGUOUS": "xx",
}
ACK_MODE_COLOR: Dict[str, str] = {
    "COMBINED_ACK_RESPONSE": "#4d4d4d",
    "SEPARATE_ACK_RESPONSE": "#bdbdbd",
    "OTHER_OR_AMBIGUOUS": "#f0f0f0",
}


# --------------------------------------------------------------------------- #
# Data loading
# --------------------------------------------------------------------------- #


def git_commit() -> str:
    """Return the current git HEAD commit, or ``"unknown"`` if unavailable."""
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
        )
        return out.decode().strip()
    except Exception:  # pragma: no cover - defensive
        return "unknown"


def load_rows(csv_path: Path) -> List[Dict[str, str]]:
    """Load all CSV rows as dicts."""
    with csv_path.open(newline="") as fh:
        return list(csv.DictReader(fh))


def device_rows(rows: Sequence[Dict[str, str]]) -> List[Dict[str, str]]:
    """Return only device-specific rows (is_reference == False)."""
    return [r for r in rows if r.get("is_reference", "").strip() == "False"]


def is_l_capture(row: Dict[str, str]) -> bool:
    """A capture ending in 'L.pcap' is the L capture; else base."""
    return row.get("capture", "").endswith("L.pcap")


def floats(
    rows: Sequence[Dict[str, str]], col: str
) -> np.ndarray:
    """Extract a numeric column, dropping blank cells."""
    out: List[float] = []
    for r in rows:
        v = r.get(col, "")
        if v is None or str(v).strip() == "":
            continue
        try:
            out.append(float(v))
        except ValueError:
            continue
    return np.asarray(out, dtype=float)


def by_device(
    rows: Sequence[Dict[str, str]],
) -> Dict[str, List[Dict[str, str]]]:
    """Group rows by device_label, preserving DEVICE_ORDER."""
    groups: Dict[str, List[Dict[str, str]]] = {d: [] for d in DEVICE_ORDER}
    for r in rows:
        dev = r.get("device_label", "")
        if dev in groups:
            groups[dev].append(r)
    return groups


# --------------------------------------------------------------------------- #
# Plot / IO helpers
# --------------------------------------------------------------------------- #


def apply_style() -> None:
    """Restrained publication defaults."""
    plt.rcParams.update(
        {
            "figure.dpi": 110,
            "font.size": 10,
            "axes.titlesize": 11,
            "axes.labelsize": 10,
            "legend.fontsize": 8.5,
            "axes.grid": True,
            "grid.alpha": 0.3,
            "grid.linewidth": 0.6,
            "axes.axisbelow": True,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "savefig.bbox": "tight",
        }
    )


def ecdf(values: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Empirical CDF: return sorted x and y = (1..n)/n."""
    x = np.sort(values)
    y = np.arange(1, x.size + 1, dtype=float) / x.size
    return x, y


def save_figure(
    fig: plt.Figure,
    figures_dir: Path,
    figname: str,
    *,
    source_table: str,
    source_run_id: str,
    commit: str,
    run_dir_arg: str,
    filters: str,
    sample_size: int,
    statistical_transformation: str,
) -> List[Path]:
    """Save a figure in all image formats and write its metadata sidecar."""
    written: List[Path] = []
    for ext in IMAGE_FORMATS:
        path = figures_dir / "{}.{}".format(figname, ext)
        if ext == "png":
            fig.savefig(path, dpi=PNG_DPI)
        else:
            fig.savefig(path)
        written.append(path)
    plt.close(fig)

    meta = {
        "producing_script": SCRIPT_NAME,
        "source_table": source_table,
        "source_run_id": source_run_id,
        "git_commit": commit,
        "filters": filters,
        "sample_size": sample_size,
        "statistical_transformation": statistical_transformation,
        "generation_command": "python3 {} --run-dir {}".format(
            SCRIPT_NAME, run_dir_arg
        ),
    }
    sidecar = figures_dir / "{}.metadata.json".format(figname)
    sidecar.write_text(json.dumps(meta, indent=2) + "\n")
    written.append(sidecar)
    logger.info("wrote %s (n=%d)", figname, sample_size)
    return written


# --------------------------------------------------------------------------- #
# Figure builders. Each returns (figname, sample_size, filters, transform).
# --------------------------------------------------------------------------- #


def fig_cdf_per_device(
    groups: Dict[str, List[Dict[str, str]]],
    col: str,
    xlabel: str,
    title: str,
    figname: str,
    *,
    only_devices: Optional[Sequence[str]] = None,
) -> Tuple[str, int, str, str]:
    devices = list(only_devices) if only_devices else list(DEVICE_ORDER)
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    total = 0
    per_dev_n = []
    for dev in devices:
        vals = floats(groups.get(dev, []), col)
        if vals.size == 0:
            continue
        x, y = ecdf(vals)
        st = DEVICE_STYLE[dev]
        ax.plot(
            x,
            y,
            drawstyle="steps-post",
            color=st["color"],
            linestyle=st["linestyle"],
            linewidth=1.6,
            label="{} (n={})".format(dev, vals.size),
        )
        # sparse markers to aid grayscale reading without clutter
        if vals.size > 1:
            idx = np.linspace(0, x.size - 1, min(8, x.size)).astype(int)
            ax.plot(
                x[idx],
                y[idx],
                linestyle="none",
                marker=st["marker"],
                markersize=5,
                markerfacecolor="white",
                markeredgecolor=st["color"],
            )
        total += vals.size
        per_dev_n.append("{}={}".format(dev, vals.size))
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Empirical CDF (fraction ≤ x)")
    ax.set_ylim(0, 1.02)
    ax.set_title("{}\n(n={}; {})".format(title, total, ", ".join(per_dev_n)))
    ax.legend(loc="lower right", frameon=False)
    fig.tight_layout()
    filters = "is_reference==False"
    if only_devices:
        filters += "; SEPARATE_ACK_RESPONSE only (non-blank {})".format(col)
    return figname, total, filters, "empirical CDF"


def _violin_with_fallback(
    ax: plt.Axes,
    datasets: Sequence[np.ndarray],
    labels: Sequence[str],
) -> List[str]:
    """Draw violins for datasets with >=2 points and variance; scatter n<2.

    Returns a list of human-readable notes about any device that could not be
    rendered as a violin (degenerate).
    """
    notes: List[str] = []
    positions = np.arange(1, len(datasets) + 1)
    violin_data = []
    violin_pos = []
    violin_idx = []
    for i, data in enumerate(datasets):
        if data.size >= 2 and np.ptp(data) > 0:
            violin_data.append(data)
            violin_pos.append(positions[i])
            violin_idx.append(i)
        else:
            # degenerate: draw the raw point(s)
            xs = np.full(data.size, positions[i])
            ax.plot(
                xs,
                data,
                linestyle="none",
                marker="D",
                markersize=7,
                color="#b00020",
                zorder=5,
            )
            notes.append(
                "{}: n={} (no variance) -> shown as point, not violin".format(
                    labels[i], data.size
                )
            )
    if violin_data:
        parts = ax.violinplot(
            violin_data,
            positions=violin_pos,
            showmedians=True,
            showextrema=True,
            widths=0.7,
        )
        for pc in parts["bodies"]:
            pc.set_facecolor("#9ecae1")
            pc.set_edgecolor("#08519c")
            pc.set_alpha(0.75)
        for key in ("cmedians", "cbars", "cmins", "cmaxes"):
            if key in parts:
                parts[key].set_color("#08306b")
                parts[key].set_linewidth(1.1)
    ax.set_xticks(list(positions))
    ax.set_xticklabels(list(labels))
    return notes


def fig_violin(
    groups: Dict[str, List[Dict[str, str]]],
    col: str,
    ylabel: str,
    title: str,
    figname: str,
    *,
    only_devices: Optional[Sequence[str]] = None,
) -> Tuple[str, int, str, str]:
    devices = list(only_devices) if only_devices else list(DEVICE_ORDER)
    datasets = []
    labels = []
    total = 0
    for dev in devices:
        vals = floats(groups.get(dev, []), col)
        datasets.append(vals)
        labels.append("{}\n(n={})".format(dev, vals.size))
        total += vals.size
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    notes = _violin_with_fallback(ax, datasets, labels)
    ax.set_ylabel(ylabel)
    ax.set_xlabel("Device")
    sub = "(n={})".format(total)
    if notes:
        sub += " — " + "; ".join(notes)
    ax.set_title("{}\n{}".format(title, sub))
    fig.tight_layout()
    filters = "is_reference==False"
    if only_devices:
        filters += "; SEPARATE_ACK_RESPONSE only (non-blank {})".format(col)
    return figname, total, filters, "kernel density (violin), median marked"


def fig_hist_per_device(
    groups: Dict[str, List[Dict[str, str]]],
    col: str,
    xlabel: str,
    title: str,
    figname: str,
) -> Tuple[str, int, str, str]:
    fig, axes = plt.subplots(
        len(DEVICE_ORDER), 1, figsize=(6.4, 6.6), sharex=True
    )
    total = 0
    all_vals = []
    for dev in DEVICE_ORDER:
        all_vals.append(floats(groups.get(dev, []), col))
    # common bins across devices for comparability
    pooled = np.concatenate([v for v in all_vals if v.size]) if any(
        v.size for v in all_vals
    ) else np.array([0.0, 1.0])
    bins = np.histogram_bin_edges(pooled, bins=40)
    for ax, dev, vals in zip(axes, DEVICE_ORDER, all_vals):
        st = DEVICE_STYLE[dev]
        if vals.size:
            ax.hist(
                vals,
                bins=bins,
                color=st["color"],
                alpha=0.75,
                edgecolor="black",
                linewidth=0.3,
            )
            median = float(np.median(vals))
            ax.axvline(
                median,
                color="black",
                linestyle=":",
                linewidth=1.2,
                label="median={:.2f} ms".format(median),
            )
            ax.legend(loc="upper right", frameon=False)
        ax.set_ylabel("count")
        ax.set_title("{} (n={})".format(dev, vals.size), fontsize=9, loc="left")
        total += vals.size
    axes[-1].set_xlabel(xlabel)
    fig.suptitle("{}\n(n={})".format(title, total), fontsize=11)
    fig.tight_layout(rect=(0, 0, 1, 0.97))
    return figname, total, "is_reference==False", "histogram (shared bins)"


def fig_size_dist(
    groups: Dict[str, List[Dict[str, str]]],
    col: str,
    xlabel: str,
    title: str,
    figname: str,
) -> Tuple[str, int, str, str]:
    """Grouped bar chart of discrete packet-size values per device."""
    fig, ax = plt.subplots(figsize=(6.8, 4.2))
    # collect the union of integer sizes observed
    per_dev_counts: Dict[str, Dict[int, int]] = {}
    all_sizes = set()
    total = 0
    for dev in DEVICE_ORDER:
        vals = floats(groups.get(dev, []), col)
        counts: Dict[int, int] = {}
        for v in vals:
            iv = int(round(v))
            counts[iv] = counts.get(iv, 0) + 1
            all_sizes.add(iv)
        per_dev_counts[dev] = counts
        total += vals.size
    sizes = sorted(all_sizes)
    x = np.arange(len(sizes))
    width = 0.26
    for i, dev in enumerate(DEVICE_ORDER):
        st = DEVICE_STYLE[dev]
        n_dev = sum(per_dev_counts[dev].values())
        fracs = [
            (per_dev_counts[dev].get(s, 0) / n_dev if n_dev else 0.0)
            for s in sizes
        ]
        ax.bar(
            x + (i - 1) * width,
            fracs,
            width,
            color=st["color"],
            edgecolor="black",
            linewidth=0.3,
            hatch=ACK_MODE_HATCH.get("", ""),
            label="{} (n={})".format(dev, n_dev),
        )
    ax.set_xticks(x)
    ax.set_xticklabels([str(s) for s in sizes])
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Fraction of transactions")
    ax.set_title("{}\n(n={})".format(title, total))
    ax.legend(frameon=False)
    fig.tight_layout()
    return figname, total, "is_reference==False", "normalized value distribution"


def fig_ack_mode_fraction(
    groups: Dict[str, List[Dict[str, str]]],
    figname: str,
) -> Tuple[str, int, str, str]:
    fig, ax = plt.subplots(figsize=(6.6, 4.2))
    x = np.arange(len(DEVICE_ORDER))
    bottom = np.zeros(len(DEVICE_ORDER))
    total = 0
    dev_totals = []
    for dev in DEVICE_ORDER:
        dev_totals.append(len(groups.get(dev, [])))
        total += len(groups.get(dev, []))
    for mode in ACK_MODES:
        fracs = []
        for dev in DEVICE_ORDER:
            rows = groups.get(dev, [])
            n = len(rows)
            c = sum(1 for r in rows if r.get("classification", "") == mode)
            fracs.append(c / n if n else 0.0)
        fracs_arr = np.asarray(fracs)
        ax.bar(
            x,
            fracs_arr,
            bottom=bottom,
            color=ACK_MODE_COLOR[mode],
            edgecolor="black",
            linewidth=0.5,
            hatch=ACK_MODE_HATCH[mode],
            label=ACK_MODE_LABELS[mode],
        )
        # annotate non-trivial segments
        for xi, f in zip(x, fracs_arr):
            if f > 0.03:
                ax.text(
                    xi,
                    bottom[int(xi)] + f / 2,
                    "{:.0%}".format(f),
                    ha="center",
                    va="center",
                    fontsize=8,
                    color="black",
                )
        bottom = bottom + fracs_arr
    ax.set_xticks(x)
    ax.set_xticklabels(
        ["{}\n(n={})".format(d, t) for d, t in zip(DEVICE_ORDER, dev_totals)]
    )
    ax.set_ylabel("Fraction of transactions")
    ax.set_ylim(0, 1.08)
    ax.set_title("ACK-mode composition by device\n(n={})".format(total))
    ax.legend(frameon=False, ncol=3, loc="upper center")
    fig.tight_layout()
    return figname, total, "is_reference==False", "per-device class fractions"


def fig_base_vs_l(
    ds_rows: Sequence[Dict[str, str]],
    figname: str,
) -> Tuple[str, int, str, str]:
    col = "req_to_resp_ms"
    fig, axes = plt.subplots(
        1, len(DEVICE_ORDER), figsize=(10.5, 3.8), sharey=True
    )
    total = 0
    for ax, dev in zip(axes, DEVICE_ORDER):
        base = floats(
            [r for r in ds_rows if r["device_label"] == dev and not is_l_capture(r)],
            col,
        )
        lcap = floats(
            [r for r in ds_rows if r["device_label"] == dev and is_l_capture(r)],
            col,
        )
        if base.size:
            x, y = ecdf(base)
            ax.plot(
                x, y, drawstyle="steps-post", color="#333333",
                linestyle="-", linewidth=1.6,
                label="base (n={})".format(base.size),
            )
        if lcap.size:
            x, y = ecdf(lcap)
            ax.plot(
                x, y, drawstyle="steps-post", color="#c1440e",
                linestyle="--", linewidth=1.6,
                label="L (n={})".format(lcap.size),
            )
        ax.set_title(dev, fontsize=10)
        ax.set_xlabel("Request-to-response latency (ms)")
        ax.set_ylim(0, 1.02)
        ax.legend(loc="lower right", frameon=False, fontsize=8)
        total += base.size + lcap.size
    axes[0].set_ylabel("Empirical CDF (fraction ≤ x)")
    fig.suptitle(
        "Base vs L capture: request-to-response latency\n(n={})".format(total),
        fontsize=11,
    )
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    return (
        figname,
        total,
        "is_reference==False; split by base vs L capture",
        "empirical CDF (base vs L)",
    )


def fig_correlation_heatmap(
    ds_rows: Sequence[Dict[str, str]],
    figname: str,
) -> Tuple[str, int, str, str]:
    features = [
        "req_to_resp_ms",
        "req_tcp_len",
        "resp_tcp_len",
        "packet_count",
        "transaction_ip_bytes",
        "pure_ack_to_resp_ms",
    ]
    # Build a column-wise value/NaN matrix; pure_ack_to_resp_ms is NaN on the
    # non-SEPARATE rows, so correlations use pairwise-complete observations.
    n_rows = len(ds_rows)
    mat = np.full((n_rows, len(features)), np.nan)
    for i, r in enumerate(ds_rows):
        for j, f in enumerate(features):
            v = r.get(f, "")
            if v is not None and str(v).strip() != "":
                try:
                    mat[i, j] = float(v)
                except ValueError:
                    pass
    k = len(features)
    corr = np.full((k, k), np.nan)
    min_pair_n = n_rows
    for a in range(k):
        for b in range(k):
            mask = ~np.isnan(mat[:, a]) & ~np.isnan(mat[:, b])
            npair = int(mask.sum())
            if npair >= 2:
                va = mat[mask, a]
                vb = mat[mask, b]
                if np.ptp(va) > 0 and np.ptp(vb) > 0:
                    corr[a, b] = np.corrcoef(va, vb)[0, 1]
                elif a == b:
                    corr[a, b] = 1.0
                if a != b:
                    min_pair_n = min(min_pair_n, npair)
    np.fill_diagonal(corr, 1.0)

    fig, ax = plt.subplots(figsize=(6.6, 5.6))
    im = ax.imshow(corr, cmap="RdBu_r", vmin=-1, vmax=1)
    ax.set_xticks(range(k))
    ax.set_yticks(range(k))
    ax.set_xticklabels(features, rotation=45, ha="right", fontsize=8)
    ax.set_yticklabels(features, fontsize=8)
    for a in range(k):
        for b in range(k):
            if not np.isnan(corr[a, b]):
                ax.text(
                    b, a, "{:.2f}".format(corr[a, b]),
                    ha="center", va="center",
                    color="white" if abs(corr[a, b]) > 0.55 else "black",
                    fontsize=8,
                )
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("Pearson r")
    ax.set_title(
        "Feature correlation (Pearson, pairwise-complete)\n"
        "(n={} rows; pure_ack_to_resp_ms pairs n≥{})".format(
            n_rows, min_pair_n
        )
    )
    fig.tight_layout()
    return (
        figname,
        n_rows,
        "is_reference==False; pairwise-complete (pure_ack_to_resp_ms only on "
        "SEPARATE rows)",
        "Pearson correlation (pairwise deletion)",
    )


def _pick_representative(
    rows: Sequence[Dict[str, str]], col: str
) -> Optional[Dict[str, str]]:
    """Pick the row whose ``col`` is closest to the median of ``col``."""
    valid = [r for r in rows if r.get(col, "").strip() != ""]
    if not valid:
        return None
    vals = np.array([float(r[col]) for r in valid])
    med = float(np.median(vals))
    idx = int(np.argmin(np.abs(vals - med)))
    return valid[idx]


def fig_combined_timeline(
    ds_rows: Sequence[Dict[str, str]],
    figname: str,
) -> Tuple[str, int, str, str]:
    combined = [
        r
        for r in ds_rows
        if r.get("classification", "") == "COMBINED_ACK_RESPONSE"
    ]
    rep = _pick_representative(combined, "req_to_resp_ms")
    fig, ax = plt.subplots(figsize=(7.6, 3.2))
    if rep is None:
        ax.text(0.5, 0.5, "no COMBINED transaction available",
                ha="center", va="center")
        ax.axis("off")
        return figname, 0, "COMBINED_ACK_RESPONSE", "none (no data)"
    t_resp = float(rep["req_to_resp_ms"])
    req_len = rep.get("req_tcp_len", "?")
    resp_len = rep.get("resp_tcp_len", "?")
    dev = rep.get("device_label", "?")
    cap = rep.get("capture", "?")

    ax.hlines(1.0, -0.05 * t_resp, t_resp * 1.15, color="#888888", linewidth=1.2)
    # request event
    ax.plot([0], [1.0], marker="v", markersize=13, color="#1f3a93")
    ax.annotate(
        "Request\n(master → outstation)\nreq_tcp_len={} B".format(req_len),
        xy=(0, 1.0), xytext=(0, 1.28), ha="center", fontsize=8.5,
        arrowprops=dict(arrowstyle="-", color="#1f3a93", lw=0.8),
    )
    # combined response (ACK piggybacked)
    ax.plot([t_resp], [1.0], marker="^", markersize=13, color="#2e7d32")
    ax.annotate(
        "Response with piggybacked ACK\n(outstation → master)\n"
        "resp_tcp_len={} B".format(resp_len),
        xy=(t_resp, 1.0), xytext=(t_resp, 0.62), ha="center", fontsize=8.5,
        arrowprops=dict(arrowstyle="-", color="#2e7d32", lw=0.8),
    )
    ax.annotate(
        "",
        xy=(t_resp, 1.08), xytext=(0, 1.08),
        arrowprops=dict(arrowstyle="<->", color="black", lw=1.0),
    )
    ax.text(
        t_resp / 2, 1.12,
        "req→resp = {:.2f} ms".format(t_resp),
        ha="center", fontsize=9,
    )
    ax.set_ylim(0.4, 1.5)
    ax.set_yticks([])
    ax.set_xlabel("Time since request (ms)")
    ax.set_title(
        "Combined-ACK transaction timeline — {} [{}]\n"
        "single ACK+response packet (packet_count={})".format(
            dev, cap, rep.get("packet_count", "?")
        )
    )
    fig.tight_layout()
    return (
        figname,
        1,
        "COMBINED_ACK_RESPONSE; representative (median req_to_resp_ms)",
        "single-transaction event timeline",
    )


def fig_separate_timeline(
    ds_rows: Sequence[Dict[str, str]],
    figname: str,
) -> Tuple[str, int, str, str]:
    separate = [
        r
        for r in ds_rows
        if r.get("classification", "") == "SEPARATE_ACK_RESPONSE"
        and r.get("req_to_pure_ack_ms", "").strip() != ""
        and r.get("pure_ack_to_resp_ms", "").strip() != ""
    ]
    rep = _pick_representative(separate, "req_to_resp_ms")
    fig, ax = plt.subplots(figsize=(7.6, 3.2))
    if rep is None:
        ax.text(0.5, 0.5, "no SEPARATE transaction available",
                ha="center", va="center")
        ax.axis("off")
        return figname, 0, "SEPARATE_ACK_RESPONSE", "none (no data)"
    t_ack = float(rep["req_to_pure_ack_ms"])
    t_resp = float(rep["req_to_resp_ms"])
    req_len = rep.get("req_tcp_len", "?")
    resp_len = rep.get("resp_tcp_len", "?")
    dev = rep.get("device_label", "?")
    cap = rep.get("capture", "?")

    ax.hlines(1.0, -0.05 * t_resp, t_resp * 1.15, color="#888888", linewidth=1.2)
    # request
    ax.plot([0], [1.0], marker="v", markersize=13, color="#1f3a93")
    ax.annotate(
        "Request\nreq_tcp_len={} B".format(req_len),
        xy=(0, 1.0), xytext=(0, 1.30), ha="center", fontsize=8.5,
        arrowprops=dict(arrowstyle="-", color="#1f3a93", lw=0.8),
    )
    # pure ACK
    ax.plot([t_ack], [1.0], marker="o", markersize=11, color="#d1691e",
            markerfacecolor="white")
    ax.annotate(
        "Pure TCP ACK\n(no payload)",
        xy=(t_ack, 1.0), xytext=(t_ack, 0.60), ha="center", fontsize=8.5,
        arrowprops=dict(arrowstyle="-", color="#d1691e", lw=0.8),
    )
    # response
    ax.plot([t_resp], [1.0], marker="^", markersize=13, color="#2e7d32")
    ax.annotate(
        "Response\nresp_tcp_len={} B".format(resp_len),
        xy=(t_resp, 1.0), xytext=(t_resp, 1.30), ha="center", fontsize=8.5,
        arrowprops=dict(arrowstyle="-", color="#2e7d32", lw=0.8),
    )
    # gap annotations
    ax.annotate(
        "", xy=(t_ack, 1.10), xytext=(0, 1.10),
        arrowprops=dict(arrowstyle="<->", color="black", lw=0.9),
    )
    ax.text(t_ack / 2, 1.13, "req→ACK\n{:.2f} ms".format(t_ack),
            ha="center", fontsize=8)
    ax.annotate(
        "", xy=(t_resp, 1.10), xytext=(t_ack, 1.10),
        arrowprops=dict(arrowstyle="<->", color="black", lw=0.9),
    )
    ax.text((t_ack + t_resp) / 2, 1.13,
            "ACK→resp\n{:.2f} ms".format(t_resp - t_ack),
            ha="center", fontsize=8)
    ax.set_ylim(0.4, 1.55)
    ax.set_yticks([])
    ax.set_xlabel("Time since request (ms)")
    ax.set_title(
        "Separate-ACK transaction timeline — {} [{}]\n"
        "request → pure ACK → response (packet_count={})".format(
            dev, cap, rep.get("packet_count", "?")
        )
    )
    fig.tight_layout()
    return (
        figname,
        1,
        "SEPARATE_ACK_RESPONSE; representative (median req_to_resp_ms)",
        "single-transaction event timeline",
    )


def fig_anomaly_summary(
    ds_rows: Sequence[Dict[str, str]],
    figname: str,
) -> Tuple[str, int, str, str]:
    def count_int_gt0(col: str) -> int:
        c = 0
        for r in ds_rows:
            v = r.get(col, "").strip()
            if v == "":
                continue
            try:
                if float(v) > 0:
                    c += 1
            except ValueError:
                pass
        return c

    def count_true(col: str) -> int:
        return sum(1 for r in ds_rows if r.get(col, "").strip() == "True")

    categories = [
        ("Retransmission", count_int_gt0("retransmission_count")),
        ("Duplicate ACK", count_int_gt0("duplicate_ack_count")),
        ("Out-of-order", count_true("out_of_order")),
        ("Reset", count_true("reset")),
        ("Missing response", count_true("missing_response")),
    ]
    labels = [c[0] for c in categories]
    counts = [c[1] for c in categories]
    total = len(ds_rows)

    fig, ax = plt.subplots(figsize=(7.0, 4.2))
    x = np.arange(len(labels))
    bars = ax.bar(
        x, counts, color="#8c2d04", edgecolor="black", linewidth=0.4, width=0.6
    )
    for xi, cnt in zip(x, counts):
        ax.text(
            xi, cnt + max(counts) * 0.01 if max(counts) else 0.02,
            "{}\n({:.2%})".format(cnt, cnt / total if total else 0),
            ha="center", va="bottom", fontsize=8,
        )
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=15, ha="right")
    ax.set_ylabel("Transactions with anomaly (count)")
    ax.set_ylim(0, (max(counts) * 1.18) if max(counts) else 1)
    ax.set_title(
        "TCP anomaly summary across transactions\n"
        "(n={} transactions)".format(total)
    )
    fig.tight_layout()
    return (
        figname,
        total,
        "is_reference==False; retransmission/dup-ack count>0, "
        "out_of_order/reset/missing_response==True",
        "per-anomaly transaction counts",
    )


def fig_timing_vs_size_scatter(
    groups: Dict[str, List[Dict[str, str]]],
    figname: str,
) -> Tuple[str, int, str, str]:
    fig, ax = plt.subplots(figsize=(6.8, 4.6))
    total = 0
    rng = np.random.RandomState(0)  # deterministic jitter for discrete sizes
    for dev in DEVICE_ORDER:
        rows = groups.get(dev, [])
        x = floats(rows, "resp_tcp_len")
        y = floats(rows, "req_to_resp_ms")
        m = min(x.size, y.size)
        if m == 0:
            continue
        x = x[:m]
        y = y[:m]
        st = DEVICE_STYLE[dev]
        jitter = rng.uniform(-0.35, 0.35, size=x.size)
        ax.scatter(
            x + jitter,
            y,
            s=14,
            marker=st["marker"],
            facecolor="none",
            edgecolor=st["color"],
            linewidths=0.7,
            alpha=0.55,
            label="{} (n={})".format(dev, x.size),
        )
        total += x.size
    ax.set_xlabel("Response TCP payload length (bytes)")
    ax.set_ylabel("Request-to-response latency (ms)")
    ax.set_title(
        "Response size vs request-to-response latency\n"
        "(n={}; x jittered ±0.35 B for visibility)".format(total)
    )
    ax.legend(frameon=False)
    fig.tight_layout()
    return (
        figname,
        total,
        "is_reference==False",
        "scatter (deterministic x-jitter for discrete sizes)",
    )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


def generate_all(run_dir: Path, run_dir_arg: str) -> int:
    csv_path = run_dir / "tables" / "ack_trace_characterization.csv"
    if not csv_path.exists():
        logger.error("source table not found: %s", csv_path)
        return 1
    figures_dir = run_dir / "figures"
    figures_dir.mkdir(parents=True, exist_ok=True)

    source_table = "tables/ack_trace_characterization.csv"
    source_run_id = run_dir.name
    commit = git_commit()

    rows = load_rows(csv_path)
    ds = device_rows(rows)
    groups = by_device(ds)
    logger.info(
        "loaded %d rows; %d device-specific; per-device %s",
        len(rows),
        len(ds),
        {d: len(groups[d]) for d in DEVICE_ORDER},
    )

    sep_devices = [d for d in DEVICE_ORDER if any(
        r.get("classification") == "SEPARATE_ACK_RESPONSE" for r in groups[d]
    )]

    apply_style()

    # Each entry: builder callable returning (figname, n, filters, transform).
    specs = [
        lambda: fig_cdf_per_device(
            groups, "req_to_resp_ms",
            "Request-to-response latency (ms)",
            "Request-to-response latency CDF by device",
            "fig01_req_to_resp_cdf",
        ),
        lambda: fig_cdf_per_device(
            groups, "req_to_pure_ack_ms",
            "Request-to-pure-ACK latency (ms)",
            "Request-to-pure-ACK latency CDF (separate-ACK devices)",
            "fig02_req_to_pure_ack_cdf",
            only_devices=sep_devices,
        ),
        lambda: fig_cdf_per_device(
            groups, "pure_ack_to_resp_ms",
            "Pure-ACK-to-response latency (ms)",
            "Pure-ACK-to-response latency CDF (separate-ACK devices)",
            "fig03_pure_ack_to_resp_cdf",
            only_devices=sep_devices,
        ),
        lambda: fig_violin(
            groups, "req_to_resp_ms",
            "Request-to-response latency (ms)",
            "Request-to-response latency distribution by device",
            "fig04_req_to_resp_violin",
        ),
        lambda: fig_violin(
            groups, "pure_ack_to_resp_ms",
            "Pure-ACK-to-response latency (ms)",
            "Pure-ACK-to-response latency (separate-ACK devices)",
            "fig05_ack_to_resp_violin",
            only_devices=sep_devices,
        ),
        lambda: fig_hist_per_device(
            groups, "req_to_resp_ms",
            "Request-to-response latency (ms)",
            "Per-device request-to-response latency histograms",
            "fig06_req_to_resp_hist",
        ),
        lambda: fig_size_dist(
            groups, "req_tcp_len",
            "Request TCP payload length (bytes)",
            "Request-size distribution by device",
            "fig07_request_size_dist",
        ),
        lambda: fig_size_dist(
            groups, "resp_tcp_len",
            "Response TCP payload length (bytes)",
            "Response-size distribution by device",
            "fig08_response_size_dist",
        ),
        lambda: fig_ack_mode_fraction(groups, "fig09_ack_mode_fraction"),
        lambda: fig_base_vs_l(ds, "fig10_base_vs_L_cdf"),
        lambda: fig_correlation_heatmap(ds, "fig11_correlation_heatmap"),
        lambda: fig_combined_timeline(ds, "fig12_combined_ack_timeline"),
        lambda: fig_separate_timeline(ds, "fig13_separate_ack_timeline"),
        lambda: fig_anomaly_summary(ds, "fig14_tcp_anomaly_summary"),
        lambda: fig_timing_vs_size_scatter(
            groups, "fig15_timing_vs_respsize_scatter"
        ),
    ]

    written: List[Path] = []
    for build in specs:
        figname, n, filters, transform = build()
        # Each builder leaves exactly one open figure; it is the current one.
        written += save_figure(
            plt.gcf(),
            figures_dir,
            figname,
            source_table=source_table,
            source_run_id=source_run_id,
            commit=commit,
            run_dir_arg=run_dir_arg,
            filters=filters,
            sample_size=n,
            statistical_transformation=transform,
        )

    n_png = len(list(figures_dir.glob("*.png")))
    n_pdf = len(list(figures_dir.glob("*.pdf")))
    n_svg = len(list(figures_dir.glob("*.svg")))
    n_meta = len(list(figures_dir.glob("*.metadata.json")))
    logger.info(
        "figures dir: %d png, %d pdf, %d svg, %d sidecars",
        n_png, n_pdf, n_svg, n_meta,
    )
    ok = (n_png == 15 and n_pdf == 15 and n_svg == 15 and n_meta == 15)
    if not ok:
        logger.error("expected 15/15/15/15, got %d/%d/%d/%d",
                     n_png, n_pdf, n_svg, n_meta)
        return 2
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-dir",
        default=DEFAULT_RUN_DIR,
        help="Run directory containing tables/ack_trace_characterization.csv",
    )
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
    )
    run_dir = Path(args.run_dir)
    return generate_all(run_dir, args.run_dir)


if __name__ == "__main__":
    sys.exit(main())
