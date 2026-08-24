"""IEEE figure style for the timing figures — self-contained, no path outside this repository.

Follows the `ieee-paper-figures` conventions: figures are rendered at their FINAL printed
size (never rescaled in LaTeX), 9 pt Times New Roman, boxed legend, major+minor grid, vector
PDF for the manuscript. `utils_mpl.py` and `paper_palettes.py` are vendored beside this file,
which is what that skill prescribes for a paper repository — importing them from a user's
home directory would make the reproduction depend on a machine, not on the repository.

Two deliberate departures from the skill's default snippet:

  * `transparent=False`. The skill's example saves transparent; a transparent PDF placed on a
    dark viewer background renders as black boxes. Every figure here is opaque white.
  * `pdf.fonttype = 42`. Text stays text, so the manuscript is searchable and the type stays
    crisp instead of being flattened to paths.

Series colours come from `alessandretti-nature` (Alessandretti, Nature 2020), the four-series
default with published provenance, in the same role mapping the project has used since the
first CLRT figures. One meaning per colour across every figure:

    Timing OFF, READ   vermillion      Timing ON, READ   blue
    Timing OFF, SBO    orange          Timing ON, SBO    green

Colour is never the only channel: the Timing OFF arm is solid, Timing ON is dashed, and the
two transaction classes carry different markers, so the figures survive greyscale printing.
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
import paper_palettes as pp  # noqa: E402
import utils_mpl  # noqa: E402

# IEEE column measures. Decide the width first; never rescale in LaTeX.
COL_WIDTH_IN = 3.5       # single column (88.9 mm)
PAGE_WIDTH_IN = 7.16     # double column (181.8 mm)

# Times New Roman with metric-compatible fallbacks, so the figures still build on a machine
# that lacks the Microsoft core fonts.
SERIF_STACK = ["Times New Roman", "Nimbus Roman", "Liberation Serif", "FreeSerif",
               "DejaVu Serif"]

_BLUE, _ORANGE, _GREEN, _RED = pp.get("alessandretti-nature")

TIMING_OFF = _RED        # timing mode OFF (the size-shaping datapath was active in both arms)
TIMING_ON = _BLUE        # timing mode ON
TIMING_OFF_ALT = _ORANGE  # timing OFF, second transaction class
TIMING_ON_ALT = _GREEN    # timing ON, second transaction class

SERIES_1, SERIES_2, SERIES_3 = _RED, _BLUE, _GREEN  # panels where both series share one arm

NEUTRAL = "#000000"
GREY = "#666666"

# The wording used on the figures, defined once. Legends and axis labels are the only text
# the figures carry; everything explanatory belongs in the LaTeX caption.
LABEL_OFF = "Timing OFF"
LABEL_ON = "Timing ON"
LABEL_READ = "READ"
LABEL_SBO = "SBO"


def use_ieee():
    """Apply the IEEE conventions from utils_mpl, then this project's additions."""
    utils_mpl.set_global()                       # 9 pt Times, bold labels, boxed legend
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": SERIF_STACK,
        # math in the same serif as the body text
        "mathtext.fontset": "custom",
        "mathtext.rm": SERIF_STACK[0],
        "mathtext.it": "%s:italic" % SERIF_STACK[0],
        "mathtext.bf": "%s:bold" % SERIF_STACK[0],
        "axes.labelpad": 4.0,                    # 8 pt pushes labels off a 2.2 in figure
        "axes.labelweight": "normal",
        "axes.titleweight": "normal",
        "axes.titlesize": 9.0,
        "axes.linewidth": 0.6,
        "xtick.labelsize": 8.0,
        "ytick.labelsize": 8.0,
        "legend.fontsize": 8.0,
        "lines.linewidth": 1.0,
        "lines.markersize": 3.0,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "savefig.facecolor": "white",
        "savefig.edgecolor": "white",
        "pdf.fonttype": 42,
        "ps.fonttype": 42,
        "svg.fonttype": "none",
    })


def grid(fig, ax, major=True, minor=True):
    """Grid, then tight_layout. Call LAST, after every label and legend.

    minor=False on a logarithmic axis: a decade's worth of minor lines reads as hatching.
    """
    for a in (ax if isinstance(ax, (list, tuple)) else [ax]):
        utils_mpl.set_grid(fig, a, major=major, minor=minor)


def _sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def _repo_relative(p):
    """Path relative to the repository root, so a sidecar never records a machine path."""
    p = Path(p).resolve()
    for parent in [p] + list(p.parents):
        if (parent / "defense4").is_dir() and (parent / ".gitignore").exists():
            try:
                return str(p.relative_to(parent))
            except ValueError:
                break
    return str(p)


def save(fig, outdir, stem, inputs, caption, stats_note, data_rows=None, data_header=None):
    """Export the figure at its natural size, plus its provenance sidecar.

    inputs      the exact files the figure was built from
    caption     caption draft for the manuscript
    stats_note  what statistic is shown and how it was computed
    data_rows   the numbers behind the figure, written beside it as CSV
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    pdf = outdir / ("%s.pdf" % stem)
    png = outdir / ("%s.png" % stem)
    # No bbox_inches="tight": the figure is exported at exactly the size it was created at,
    # so a column-width figure stays column-width and 9 pt type really is 9 pt on the page.
    fig.savefig(pdf, transparent=False, facecolor="white")
    fig.savefig(png, transparent=False, facecolor="white", dpi=600)
    plt.close(fig)

    artifacts = {pdf.name: _sha256(pdf), png.name: _sha256(png)}
    if data_rows is not None:
        dcsv = outdir / ("%s_data.csv" % stem)
        with open(dcsv, "w", newline="") as f:
            w = csv.writer(f)
            if data_header:
                w.writerow(data_header)
            w.writerows(data_rows)
        artifacts[dcsv.name] = _sha256(dcsv)

    side = {
        "figure": stem,
        "inputs": [{"path": _repo_relative(p), "sha256": _sha256(p)} for p in inputs],
        "caption_draft": caption,
        "statistical_method": stats_note,
        "artifacts": artifacts,
        "style": {"width_in": round(fig.get_size_inches()[0], 3),
                  "background": "opaque white (transparent=False)",
                  "png_dpi": 600, "pdf_fonttype": 42,
                  "font_stack": SERIF_STACK,
                  "base_size_pt": 9.0,
                  "palette": "alessandretti-nature (Nature 2020); line style and marker "
                             "also differ, so the figures read in greyscale",
                  "conventions": "ieee-paper-figures skill; utils_mpl vendored in analysis/"},
    }
    with open(outdir / ("%s.provenance.json" % stem), "w") as f:
        json.dump(side, f, indent=2)
        f.write("\n")
    with open(outdir / ("%s.caption.md" % stem), "w") as f:
        f.write("### %s\n\n%s\n\n**Statistics.** %s\n" % (stem, caption, stats_note))
    print("  %-42s pdf+png(600dpi)+data+caption+provenance" % stem)
    return pdf, png
