"""Self-contained figure style for the NDSS manuscript. No dependency outside this venv."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

COL_W, PAGE_W = 3.5, 7.16          # NDSS column is 3.5 in; text block 7.16 in
SERIF = ["Nimbus Roman", "Times New Roman", "Liberation Serif", "DejaVu Serif"]
# Colourblind-safe (Okabe-Ito). One meaning per colour across every figure.
OFF, ON = "#D55E00", "#0072B2"      # Timing OFF (vermillion), Obfuscated (blue)
C_READ, C_SELECT, C_OPERATE = "#0072B2", "#E69F00", "#009E73"
GREY = "#555555"
LS = {"native": "-", "obfuscated": "--"}
MK = {"READ": "o", "SELECT": "s", "OPERATE": "^"}
HATCH = {"native": "///", "obfuscated": "\\\\\\"}
LBL = {"native": "Timing OFF", "obfuscated": "Obfuscated"}


def use():
    plt.rcParams.update({
        "font.family": "serif", "font.serif": SERIF, "font.size": 9,
        "axes.labelsize": 9, "axes.titlesize": 9, "xtick.labelsize": 8,
        "ytick.labelsize": 8, "legend.fontsize": 7.5, "figure.dpi": 600,
        "savefig.dpi": 600, "pdf.fonttype": 42, "ps.fonttype": 42, "svg.fonttype": "none",
        "axes.linewidth": 0.6, "grid.linewidth": 0.4, "lines.linewidth": 1.1,
        "figure.facecolor": "white", "axes.facecolor": "white",
        "savefig.facecolor": "white", "mathtext.fontset": "custom",
        "mathtext.rm": SERIF[0], "mathtext.it": SERIF[0] + ":italic",
    })


def grid(axes):
    for a in (axes if isinstance(axes, (list, tuple)) else [axes]):
        a.grid(True, which="major", color="#CCCCCC", lw=0.4, zorder=0)
        a.set_axisbelow(True)


def save(fig, outdir, stem, caption, inputs, notes):
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    pdf = outdir / f"{stem}.pdf"
    fig.savefig(pdf, facecolor="white", transparent=False)
    plt.close(fig)
    h = hashlib.sha256(pdf.read_bytes()).hexdigest()
    (outdir / f"{stem}.provenance.json").write_text(json.dumps(
        {"figure": stem, "caption": caption, "inputs": inputs, "notes": notes,
         "width_in": round(fig.get_size_inches()[0], 3), "sha256": h,
         "style": "NDSS 3.5 in column / 7.16 in text block, Times 9 pt, Okabe-Ito palette, "
                  "pdf.fonttype 42, opaque white"}, indent=1) + "\n")
    print(f"  {stem:38s} {round(fig.get_size_inches()[0],2)} in  {h[:12]}")
    return pdf
