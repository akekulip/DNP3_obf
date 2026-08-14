"""Shared style/data helpers for the E_FINAL IEEE figures.

All figures load from the saved CSV/JSON in ../ (csv/ and *.json). No hardcoded
measurement values: numbers are read from disk at plot time.

Palette provenance: Okabe & Ito colorblind-safe qualitative set
(Wong, Nature Methods 8:441, 2011). One meaning per color across all figures:
  native  -> vermillion  #D55E00
  defended-> blue        #0072B2
READ/SELECT distinguished by shade/marker, not new hues.
"""
import csv
import json
import sys
from pathlib import Path

# IEEE-conventions matplotlib helper (9 pt Times New Roman, boxed legend, grid)
sys.path.insert(0, str(Path.home() / "Projects/Tooling/inkscape_python_figures"))
import utils_mpl  # noqa: E402

HERE = Path(__file__).resolve().parent
DATA = HERE.parent                       # E_FINAL/
CSV = DATA / "csv"
FIGS = DATA / "figs"
FIGS.mkdir(exist_ok=True)

# Okabe-Ito
C_NATIVE = "#D55E00"      # vermillion
C_DEFENDED = "#0072B2"    # blue
C_READ = "#D55E00"
C_SELECT = "#E69F00"      # orange (READ/SELECT within native, warm family)
C_DEF_READ = "#0072B2"    # blue
C_DEF_SELECT = "#56B4E9"  # sky blue (defended family, cool)
C_CHANCE = "#000000"
C_BASELINE = "#009E73"    # bluish green


def _read_csv(name):
    with open(CSV / name) as f:
        return list(csv.DictReader(f))


def clrt(name, req_func=None, drop_cold=True):
    """Return list of clrt_ms floats from a txn CSV.

    Uses clrt_ms where non-empty and (drop_cold) cold==0, optionally filtered
    by req_func (1=READ, 3=SELECT, 4=OPERATE).
    """
    out = []
    for r in _read_csv(name):
        if req_func is not None and int(r["req_func"]) != req_func:
            continue
        if drop_cold and r.get("cold", "0").strip() not in ("0", ""):
            continue
        v = r.get("clrt_ms", "").strip()
        if v == "":
            continue
        out.append(float(v))
    return out


def load_json(name):
    with open(DATA / name) as f:
        return json.load(f)


def sbo(name):
    """Return dict of lists {A_ms, R_ms, echo_ack_ms} from an sbo_j*.csv."""
    rows = _read_csv(name)
    return {
        "A": [float(r["A_ms"]) for r in rows],
        "R": [float(r["R_ms"]) for r in rows],
        "echo": [float(r["echo_ack_ms"]) for r in rows],
    }


def save(fig, stem):
    """Export PDF (vector, manuscript) + PNG (300 dpi) at final printed size."""
    pdf = FIGS / f"{stem}.pdf"
    png = FIGS / f"{stem}.png"
    fig.savefig(pdf, transparent=True)
    fig.savefig(png, dpi=300)
    print(f"  wrote {pdf.name}, {png.name}")
    return pdf, png
