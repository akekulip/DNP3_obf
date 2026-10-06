"""Self-contained figure style and publication contract for the NDSS manuscript.

Every figure emitted through :func:`save` carries the same artefact set:

* a vector PDF at final printed size,
* a 600-dpi PNG preview,
* the exact figure data as CSV, so a reader can rebuild the plot without the pipeline,
* a caption draft, a statistical-method note and a limitations note,
* a provenance JSON naming every input by repository-relative path *and* SHA-256, the analysis
  script and configuration by path and SHA-256, the source commit, the deterministic seed, the
  output hashes, the figure dimensions and the exact command that produced it.

No result value is ever written into a figure script; everything is read from the canonical
tables and the analysis JSON.
"""
from __future__ import annotations
import csv, hashlib, json, os, subprocess, sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import scienceplots  # noqa: F401  registers the "science" / "ieee" / "no-latex" styles

# IEEEtran's \columnwidth is 251.06 pt, not 252, so a 3.5 in figure overran every column by
# 0.94 pt and logged an overfull box for each. 3.48 in is 250.56 pt and fits.
COL_W, PAGE_W = 3.48, 7.16         # NDSS column is 3.48 in usable; text block 7.16 in
SERIF = ["Nimbus Roman", "Times New Roman", "Liberation Serif", "DejaVu Serif"]
# Colourblind-safe (Okabe-Ito). One meaning per colour across every figure.
OFF, ON = "#D55E00", "#0072B2"      # Timing OFF (vermillion), Obfuscated (blue)
C_READ, C_SELECT, C_OPERATE = "#0072B2", "#E69F00", "#009E73"
GREY = "#555555"
LS = {"native": "-", "obfuscated": "--"}
MK = {"READ": "o", "SELECT": "s", "OPERATE": "^"}
# Per-class line style, so a class is identifiable without colour.
LS_CLASS = {"READ": "-", "SELECT": "--", "OPERATE": ":"}
HATCH = {"native": "///", "obfuscated": "\\\\\\"}   # retired: hatch at column width reads as noise
# The second, non-colour channel that keeps the two arms apart in greyscale: Timing OFF is
# drawn open (white fill, coloured outline) and Obfuscated solid. A reader printing the
# paper in black and white sees an empty box against a filled one, which survives
# photocopying better than a hatch does at 3.5 in.
FILL = {"native": "white", "obfuscated": None}   # None: use the arm colour
FILL_ALPHA = {"native": 1.0, "obfuscated": 0.55}


def arm_face(arm, colour):
    """Face colour for an arm: open for Timing OFF, solid for Obfuscated."""
    return FILL[arm] or colour
LBL = {"native": "Timing OFF", "obfuscated": "Obfuscated"}

# Smallest type allowed anywhere in a figure, at final printed size.
MIN_PT = 8.0
# Repository root, so provenance paths are repository-relative and portable.
# This file is <root>/defense4/timing/evidence/campaign_v1/repro/figstyle_ndss.py, so the root
# is five levels up from the containing directory.
REPO_ROOT = Path(__file__).resolve().parents[5]


def use():
    """SciencePlots' tick and legend discipline, this manuscript's palette and column size.

    The base is SciencePlots ``science`` + ``ieee`` (garrettj403/SciencePlots): ticks inward on
    all four sides, minor ticks visible, thin spines, no legend frame, 600 dpi. That is what
    makes a plot read as a journal figure rather than a matplotlib default.

    ``no-latex`` is appended, for two reasons that are not preference:

    * ``science`` sets ``text.usetex``, which needs ``cm-super`` (for ``type1ec.sty``) and
      ``dvipng``; neither is installed and both need root. Without them nothing renders at all.
    * even with them, the ``science`` preamble loads only ``amsmath`` and ``amssymb``, no font
      package, so every figure would come out in Computer Modern while the manuscript body is
      Times. ``mathtext`` with the Times-compatible serif below keeps the two in the same face,
      which is also what the venue preflight's font check requires.

    Three further defaults are deliberately overridden and must stay overridden:

    * its ``axes.prop_cycle`` (and the ``ieee`` style's black/red/blue/green) is not
      colourblind-safe, and this manuscript holds one meaning per colour across every figure,
      so the Okabe-Ito palette above wins;
    * its ``figure.figsize`` of 3.3 in is the generic two-column width, while the NDSS column
      is 3.5 in;
    * its ``savefig.bbox = "tight"`` crops the canvas after layout, so the emitted PDF is not
      the size that was requested and no longer lands at a known width in the column. Layout is
      done by ``constrained_layout`` instead and the box is left standard.
    """
    plt.style.use(["science", "ieee", "no-latex"])
    plt.rcParams.update({
        "font.family": "serif", "font.serif": SERIF, "font.size": 9,
        "axes.labelsize": 9, "axes.titlesize": 9, "xtick.labelsize": 8,
        "ytick.labelsize": 8, "legend.fontsize": 8, "figure.dpi": 600,
        "savefig.dpi": 600, "pdf.fonttype": 42, "ps.fonttype": 42, "svg.fonttype": "none",
        "axes.linewidth": 0.6, "grid.linewidth": 0.3, "lines.linewidth": 1.1,
        "figure.facecolor": "white", "axes.facecolor": "white",
        "savefig.facecolor": "white", "mathtext.fontset": "custom",
        "mathtext.rm": SERIF[0], "mathtext.it": SERIF[0] + ":italic",
        # One meaning per colour, colourblind-safe. Overrides the SciencePlots cycle.
        "axes.prop_cycle": matplotlib.cycler(color=[C_READ, C_SELECT, C_OPERATE, OFF, GREY]),
        # The emitted PDF must be exactly the size the figure asked for.
        "savefig.bbox": "standard", "savefig.pad_inches": 0.0,
        "figure.constrained_layout.use": True,
        "figure.constrained_layout.h_pad": 0.02, "figure.constrained_layout.w_pad": 0.02,
        "figure.constrained_layout.hspace": 0.03, "figure.constrained_layout.wspace": 0.03,
        # A frame around a key is a box of white drawn over the data. Direct labels and
        # frameless keys read better at column width.
        "legend.frameon": False, "legend.borderpad": 0.2, "legend.handletextpad": 0.5,
        "legend.labelspacing": 0.25, "legend.borderaxespad": 0.3,
        "xtick.major.size": 2.6, "ytick.major.size": 2.6,
        "xtick.minor.size": 1.4, "ytick.minor.size": 1.4,
        "xtick.major.width": 0.5, "ytick.major.width": 0.5,
        "xtick.minor.width": 0.4, "ytick.minor.width": 0.4,
        "xtick.major.pad": 2.0, "ytick.major.pad": 2.0,
        "axes.labelpad": 2.0,
    })


def grid(axes):
    """No interior rules.

    SciencePlots draws no grid and relies on minor ticks, which is the convention in IEEE and
    NDSS figures, and it is what the Ditto figures these plots are matched to do. The hairline
    grid this function used to add is gone: across a column-width panel it competed with the
    data it was meant to help read. The name is kept because the call sites use it.
    """
    for a in (axes if isinstance(axes, (list, tuple)) else [axes]):
        a.grid(False)
        a.set_axisbelow(True)


def key(ax, **kw):
    """The legend as Ditto draws it: a white box with a thin grey border, inside the panel."""
    opts = dict(frameon=True, framealpha=1.0, facecolor="white", edgecolor="#666666",
                fancybox=False, borderpad=0.35, handlelength=1.6, handletextpad=0.5,
                labelspacing=0.28, fontsize=8)
    opts.update(kw)
    leg = ax.legend(**opts)
    if leg is not None:
        leg.get_frame().set_linewidth(0.5)
    return leg


def nogrid(axes):
    for a in (axes if isinstance(axes, (list, tuple)) else [axes]):
        a.grid(False)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 16), b""):
            h.update(c)
    return h.hexdigest()


def _rel(path):
    """A location-independent path for provenance.

    A file that lives in the repository is recorded repository-relative. A file the pipeline
    produced into its output directory is recorded under a ``pipeline-output/`` prefix, because
    that directory is chosen at run time: recording its absolute path would leak the operator's
    working directory and would make otherwise identical runs disagree. The SHA-256 recorded
    beside the path is what actually identifies the content.
    """
    p = Path(path).resolve()
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return "pipeline-output/" + p.name


def _git_commit():
    try:
        r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(REPO_ROOT),
                           capture_output=True, text=True, timeout=20)
        return r.stdout.strip() or None
    except Exception:
        return None


def check_min_font(fig, stem, problems):
    """No text anywhere in the figure may fall below MIN_PT at final printed size."""
    for t in fig.findobj(match=matplotlib.text.Text):
        s = t.get_text()
        if not s or not s.strip():
            continue
        if t.get_fontsize() < MIN_PT - 1e-9:
            problems.append(f"{stem}: text {s[:28]!r} is {t.get_fontsize()} pt, below {MIN_PT} pt")


def save(fig, outdir, stem, caption, inputs, notes, data_rows=None, data_fields=None,
         method_note="", limitation_note="", seed=None):
    """Emit the full artefact set for one figure and return the PDF path.

    ``inputs`` are paths to every file the figure consumed; each is recorded with its SHA-256.
    ``data_rows``/``data_fields`` are the exact plotted values, written as the figure-data CSV.
    """
    outdir = Path(outdir); outdir.mkdir(parents=True, exist_ok=True)
    problems = []
    check_min_font(fig, stem, problems)
    if problems:
        raise SystemExit("figure style violation:\n  " + "\n  ".join(problems))

    pdf = outdir / f"{stem}.pdf"
    png = outdir / f"{stem}.png"
    # Omit the creation timestamp so the same inputs always give the same bytes.
    meta = {"CreationDate": None, "Producer": None, "Creator": None}
    fig.savefig(pdf, facecolor="white", transparent=False, metadata=meta)
    fig.savefig(png, facecolor="white", transparent=False, dpi=600)
    w_in, h_in = (round(float(v), 3) for v in fig.get_size_inches())
    plt.close(fig)

    # ---- figure-data CSV: the exact numbers behind the marks
    data_path = None
    if data_rows:
        data_path = outdir / f"{stem}_data.csv"
        fields = data_fields or list(data_rows[0].keys())
        # newline="" stops the csv module adding its own line ending; lineterminator pins it to
        # LF so the file does not land in git with CRLF and trip whitespace checks.
        with open(data_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, lineterminator="\n")
            w.writeheader(); w.writerows(data_rows)

    # ---- caption, method and limitation notes
    (outdir / f"{stem}.caption.md").write_text(caption.strip() + "\n")
    (outdir / f"{stem}.method.md").write_text(
        (method_note or "Not stated.").strip() + "\n")
    (outdir / f"{stem}.limitations.md").write_text(
        (limitation_note or "Not stated.").strip() + "\n")

    # ---- provenance: every input by path and hash, plus script, config, commit, seed, outputs
    script = Path(sys.argv[0]).resolve() if sys.argv and sys.argv[0] else None
    prov = {
        "figure": stem,
        "caption": caption,
        # Recorded with the same location-independent paths, so two runs that differ only in
        # where the output directory sits produce the same provenance.
        "generation_command": (" ".join(["python"] + [_rel(a) if os.path.sep in a else a
                                                      for a in sys.argv])
                               if script else None),
        "source_commit": _git_commit(),
        "deterministic_seed": seed,
        "analysis_script": ({"path": _rel(script), "sha256": sha256_file(script)}
                            if script and script.exists() else None),
        "style_module": {"path": _rel(__file__), "sha256": sha256_file(__file__)},
        "inputs": [{"path": _rel(p), "sha256": sha256_file(p)} for p in inputs
                   if os.path.exists(p)],
        "missing_inputs": [str(p) for p in inputs if not os.path.exists(p)],
        # The figure data CSV is the authoritative carrier of the numbers and is byte-
        # reproducible wherever the pinned environment installs. The vector PDF is the
        # authoritative published rendering, and is byte-reproducible WITHIN a machine: across
        # machines the plotted values agree while the last bits of a coordinate may not, because
        # the transform stack runs in floating point. See audit_current/REPRODUCIBILITY_SCOPE.md. The PNG is a
        # raster preview produced by the Agg backend, whose output depends on the bundled
        # FreeType and libpng of the interpreter build; two environments that satisfy the same
        # lock file can differ in a few hundred pixels. It is therefore recorded but not
        # hash-gated, and the reproducibility gate ignores it.
        "outputs": {
            "pdf": {"path": _rel(pdf), "sha256": sha256_file(pdf), "authoritative": True},
            "png": {"path": _rel(png), "sha256": sha256_file(png), "dpi": 600,
                    "authoritative": False,
                    "note": ("raster preview; byte-identity is not guaranteed across "
                             "interpreter builds and is not gated")},
            "data_csv": ({"path": _rel(data_path), "sha256": sha256_file(data_path),
                          "rows": len(data_rows), "authoritative": True} if data_path else None),
        },
        "figure_dimensions_in": {"width": w_in, "height": h_in},
        "method_note": method_note,
        "limitation_note": limitation_note,
        "notes": notes,
        "style": ("SciencePlots science+no-latex base (ticks in on four sides, minor ticks, "
                  "frameless keys), NDSS 3.5 in column / 7.16 in text block, "
                  "Times-compatible serif, minimum "
                  f"{MIN_PT} pt at printed size, Okabe-Ito palette, line style and marker vary "
                  "with colour so the figure reads in greyscale, pdf.fonttype 42 (no Type 3), "
                  "opaque white background"),
    }
    (outdir / f"{stem}.provenance.json").write_text(json.dumps(prov, indent=1) + "\n")
    print(f"  {stem:24s} {w_in:5.2f} x {h_in:4.2f} in  pdf {prov['outputs']['pdf']['sha256'][:12]}"
          f"  png {prov['outputs']['png']['sha256'][:12]}"
          f"{'  data ' + str(len(data_rows)) + ' rows' if data_rows else ''}")
    return pdf
