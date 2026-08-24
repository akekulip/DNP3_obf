"""IEEE figure style for the timing figures — self-contained, no external skill or tool path.

Everything the figures need to look like IEEE figures lives here: column widths, 8-9 pt
serif type at final printed size, a colourblind-safe palette whose members also separate in
greyscale, and an export step that writes a vector PDF for the manuscript alongside a
600 dpi PNG preview.

Two rules the export enforces, because both have bitten this project before:
  * the canvas is opaque white (transparent=False). A transparent PDF placed on a dark
    viewer background renders as black boxes.
  * text is text, never paths (pdf.fonttype = 42 embeds TrueType), so the manuscript can
    be searched and the type stays crisp.

Each figure also writes its own provenance sidecar: the exact input files, the data behind
the figure as CSV, a caption draft, a note on the statistics, and the SHA-256 of every
artifact. A figure that cannot say where its numbers came from should not be in a paper.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# IEEE two-column layout
COL_WIDTH_IN = 3.5      # single column
PAGE_WIDTH_IN = 7.16    # double column

# Serif stack: Times New Roman when the system has it, then metric-compatible fallbacks.
SERIF_STACK = ["Times New Roman", "Nimbus Roman", "Liberation Serif", "FreeSerif",
               "DejaVu Serif"]

# Okabe-Ito, a colourblind-safe qualitative palette. One meaning per colour everywhere.
#
# The two arms are named for what actually differed between them: the timing mode. They are
# NOT "native" and "defended" in the sense of an unmodified device against a protected one.
# Both arms ran the same unified binary with the size-shaping datapath active; only the
# timing mode was toggled. Naming the constants TIMING_OFF / TIMING_ON keeps that straight
# in the code as well as on the page.
TIMING_OFF = "#D55E00"      # vermillion   — timing mode OFF (shaping still active)
TIMING_ON = "#0072B2"       # blue         — timing mode ON
TIMING_OFF_ALT = "#E69F00"  # orange       — timing OFF, second transaction class
TIMING_ON_ALT = "#009E73"   # bluish green — timing ON, second transaction class

# Neutral series colours for panels where both series come from the same arm.
SERIES_1 = "#D55E00"
SERIES_2 = "#0072B2"
SERIES_3 = "#009E73"

NEUTRAL = "#000000"
GREY = "#666666"

# Greyscale separation: colour is never the only channel.
STYLE_TIMING_OFF = dict(color=TIMING_OFF, linestyle="-", marker="o")
STYLE_TIMING_ON = dict(color=TIMING_ON, linestyle="--", marker="s")

# Wording used on the figures and in the captions, defined once.
LABEL_OFF = "Timing OFF"
LABEL_ON = "Timing ON"
NOTE_BOTH_ARMS = "size shaping active in both arms"


def use_ieee(base_pt=8.5):
    plt.rcParams.update({
        "font.family": "serif",
        "font.serif": SERIF_STACK,
        # math set in the same serif as the body text, so "$A$" does not arrive in a
        # different typeface from "A" in the caption
        "mathtext.fontset": "custom",
        "mathtext.rm": SERIF_STACK[0],
        "mathtext.it": "%s:italic" % SERIF_STACK[0],
        "mathtext.bf": "%s:bold" % SERIF_STACK[0],
        "font.size": base_pt,
        "axes.labelsize": base_pt,
        "axes.titlesize": base_pt,
        "xtick.labelsize": base_pt - 0.5,
        "ytick.labelsize": base_pt - 0.5,
        "legend.fontsize": base_pt - 0.5,
        "axes.linewidth": 0.6,
        "grid.linewidth": 0.4,
        "lines.linewidth": 1.0,
        "lines.markersize": 3.0,
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "axes.grid": True,
        "grid.alpha": 0.30,
        "grid.color": "#B0B0B0",
        "axes.axisbelow": True,
        "legend.frameon": True,
        "legend.framealpha": 1.0,
        "legend.edgecolor": "0.3",
        "legend.fancybox": False,
        "legend.borderpad": 0.35,
        "legend.handlelength": 1.8,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "savefig.facecolor": "white",
        "savefig.edgecolor": "white",
        "pdf.fonttype": 42,      # embed TrueType — text stays text
        "ps.fonttype": 42,
        "svg.fonttype": "none",
    })


def _sha256(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def save(fig, outdir, stem, inputs, caption, stats_note, data_rows=None,
         data_header=None):
    """Export the figure plus its provenance sidecar.

    inputs      list of the exact files the figure was built from
    caption     caption draft for the manuscript
    stats_note  what statistic is shown and how it was computed
    data_rows   the numbers behind the figure, written next to it as CSV
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    pdf = outdir / ("%s.pdf" % stem)
    png = outdir / ("%s.png" % stem)
    # No bbox_inches="tight": the figure is exported at exactly the size it was created
    # at, so a column-width figure stays column-width and the 8.5 pt type really is 8.5 pt
    # on the printed page instead of being rescaled by however much whitespace was cropped.
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
        "inputs": [{"path": str(p), "sha256": _sha256(p)} for p in inputs],
        "caption_draft": caption,
        "statistical_method": stats_note,
        "artifacts": artifacts,
        "style": {"width_in": round(fig.get_size_inches()[0], 3),
                  "background": "opaque white (transparent=False)",
                  "png_dpi": 600, "pdf_fonttype": 42,
                  "font_stack": SERIF_STACK,
                  "palette": "Okabe-Ito colourblind-safe; line style and marker also differ"},
    }
    with open(outdir / ("%s.provenance.json" % stem), "w") as f:
        json.dump(side, f, indent=2)
        f.write("\n")
    with open(outdir / ("%s.caption.md" % stem), "w") as f:
        f.write("### %s\n\n%s\n\n**Statistics.** %s\n" % (stem, caption, stats_note))
    print("  %-34s pdf+png(600dpi)+data+caption+provenance" % stem)
    return pdf, png
