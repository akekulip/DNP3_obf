"""One visual language for every Defense 3 figure (the reviewer's global formatting rules).

Import this in every figure script so a colour means the same thing everywhere:

    import d3_style as ds
    ds.setup()                       # utils_mpl.set_global() + the D3 palette
    ax.plot(x, y, color=ds.ACK, ...) # blue = ACK, everywhere

Meaning            -> treatment
  native traffic   -> near-black
  ACK              -> blue   (fixed)
  RESPONSE         -> orange (fixed, contrasts ACK)
  blocker/internal -> neutral gray
  safe / pass      -> green  (restrained)
  defect/reject    -> red    (restrained)
  historical/unrepaired -> dashed / hollow
  final/repaired        -> solid
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.expanduser("~"),
                                "Projects/Tooling/inkscape_python_figures"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import utils_mpl  # noqa: E402

# --- the fixed semantic colours (alessandretti-nature, one meaning each) ---
NATIVE = "#222222"    # near-black
ACK = "#2177B5"       # blue
RESPONSE = "#FF800E"  # orange
BLOCKER = "#9199A1"   # neutral gray (internal tokens/clones)
PASS = "#2BA02B"      # green
FAIL = "#D72927"      # red
STATE = "#7A5DC7"     # muted purple, for state-register accesses only

# per-D arm colours, consistent across figs 1/3/7 (native -> D=16 ramp)
ARM = {"native": NATIVE, "d1": "#8CB8D8", "d2": "#5B9BC9",
       "d4": "#2177B5", "d8": "#155A8A", "d16": "#0B3A5C"}

# line styles
SOLID = dict(linestyle="-")
HIST = dict(linestyle="--")   # historical / unrepaired result


def setup(size=(3.5, 2.4), dpi=100):
    """utils_mpl global defaults + return (fig, ax). Honours D3_FIG_W (single-col width)."""
    utils_mpl.set_global()
    w = os.environ.get("D3_FIG_W")
    if w:
        size = (float(w), size[1])
    return utils_mpl.get_fig(size=size, dpi=dpi)


def setup_only():
    utils_mpl.set_global()


def grid(fig, ax):
    utils_mpl.set_grid(fig, ax)
