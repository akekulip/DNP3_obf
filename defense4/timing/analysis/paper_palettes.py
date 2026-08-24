"""Venue-proven color palettes extracted from published scientific figures.

Palettes lifted from figures in Nature, Science, PNAS, Nat Commun, and other
venues, curated by nehSgnaiL/awesome-scientific-figure (local clone:
~/Projects/Tooling/awesome-scientific-figure — see its README for the source
figure of every palette). Slugs below match the catalog in
references/paper-palettes.md.

Usage in a figure script:

    import paper_palettes as pp
    pp.apply("alessandretti-nature")        # set the matplotlib color cycle
    colors = pp.get("xu-rsif")              # raw hex list for manual use
    cm = pp.cmap("peng-nat-geosci")         # colormap from sequential/diverging sets

CLI:

    python paper_palettes.py --list
    python paper_palettes.py --preview swatches.pdf
"""

import argparse
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class Palette:
    """One published palette: colors in usage order plus provenance."""

    colors: Tuple[str, ...]
    kind: str  # categorical | sequential | diverging | fill
    source: str  # first-author venue-year of the source figure
    note: str = ""


PALETTES: Dict[str, Palette] = {
    # --- categorical: 2 series -------------------------------------------
    "ibrahim-fr-pair": Palette(
        ("#00CBD2", "#FFAA01"),
        "categorical",
        "Ibrahim, Fundamental Research 2025",
        "teal/amber scatter+fit pair; strong CVD-safe contrast",
    ),
    "xu-ceus-pair": Palette(
        ("#E95C49", "#5AC0D7"),
        "categorical",
        "Xu, Comput Environ Urban Syst 2022",
        "warm/cool boxplot comparison pair",
    ),
    "liang-tbs-pair": Palette(
        ("#1DBDE6", "#F1515E"),
        "categorical",
        "Liang, Travel Behav Soc 2026",
        "cyan/red trend-vs-trend pair",
    ),
    # --- categorical: 3-4 series -----------------------------------------
    "wang-science": Palette(
        ("#375294", "#D93431", "#1F7E46"),
        "categorical",
        "Wang, Science 2009",
        "deep navy/red/green triad for scatter with fits",
    ),
    "xu-rsif": Palette(
        ("#359C7D", "#D15F2E", "#6E72A6"),
        "categorical",
        "Xu, J R Soc Interface 2017",
        "muted teal/orange/slate triad; understated, prints well",
    ),
    "yin-nature": Palette(
        ("#3081AF", "#F18125", "#EA9493", "#95CF95"),
        "categorical",
        "Yin, Nature 2019",
        "two strong + two soft; use soft tones for bands/fills",
    ),
    "alessandretti-nature": Palette(
        ("#2177B5", "#FF800E", "#2BA02B", "#D72927"),
        "categorical",
        "Alessandretti, Nature 2020",
        "refined tab10-like blue/orange/green/red; safe default",
    ),
    "gibbs-nat-commun": Palette(
        ("#1E78B5", "#A6CEE3", "#32A02D", "#B4DF8A"),
        "categorical",
        "Gibbs, Nat Commun 2020",
        "dark/light paired blues+greens for grouped or nested series",
    ),
    "jiang-pnas": Palette(
        ("#296AB2", "#E40519", "#75B728", "#EFE541"),
        "categorical",
        "Jiang, PNAS 2016",
        "vivid; yellow needs a dark background or edge to stay visible",
    ),
    # --- categorical: many series ----------------------------------------
    "xu-tour-manag": Palette(
        ("#2A4291", "#F8CA13", "#C00005", "#64C9EA", "#58AF63", "#E98A02", "#DE24CE"),
        "categorical",
        "Xu, Tourism Management 2021",
        "7-class map/flow palette",
    ),
    "tegally-science": Palette(
        (
            "#2E84BC", "#DA5F00", "#189E78", "#E7288A", "#7570B3", "#E5AA05",
            "#66A51E", "#A6751D", "#EE6AA6", "#FDAE61", "#ACDDA5", "#FFFFBF",
            "#BEBEBE", "#666666",
        ),
        "categorical",
        "Tegally, Science 2022",
        "14-class (ColorBrewer-derived); last resort — prefer <=8 series",
    ),
    # --- sequential / diverging ------------------------------------------
    "xu-ann-aag-heat": Palette(
        ("#F7F7EF", "#FDEDBD", "#FCDA9B", "#FDBD39", "#E83D39"),
        "sequential",
        "Xu, Ann Am Assoc Geogr 2021",
        "cream-to-red heat ramp for density/intensity maps",
    ),
    "xu-ceus-spectral": Palette(
        ("#0098BD", "#4BE3CE", "#FEEDB0", "#FEAC54", "#D1374F"),
        "diverging",
        "Xu, Comput Environ Urban Syst 2019",
        "teal-cream-red spectral ramp (3D surface / signed values)",
    ),
    "peng-nat-geosci": Palette(
        (
            "#4BA6E0", "#7FBFE9", "#B0D4F1", "#DAEAF7",
            "#E2BDE7", "#BA68C8", "#9D27B0", "#683AB7",
        ),
        "diverging",
        "Peng, Nature Geoscience 2026",
        "blue-to-purple diverging colorbar",
    ),
    # --- fills -------------------------------------------------------------
    "jin-emi-fills": Palette(
        ("#FEE0BE", "#A8DCA5", "#FFE1E0"),
        "fill",
        "Jin, Emerg Microbes Infect 2022",
        "pastel box/violin fills; pair with dark edge colors",
    ),
}


def get(name: str) -> List[str]:
    """Return the palette's hex colors in usage order."""
    return list(PALETTES[name].colors)


def names(kind: Optional[str] = None) -> List[str]:
    """List palette slugs, optionally filtered by kind."""
    return [k for k, p in PALETTES.items() if kind is None or p.kind == kind]


def apply(name: str) -> List[str]:
    """Set the matplotlib color cycle to a categorical/fill palette."""
    import matplotlib.pyplot as plt
    from cycler import cycler

    palette = PALETTES[name]
    if palette.kind not in ("categorical", "fill"):
        raise ValueError(f"{name} is {palette.kind}; use cmap() instead")
    plt.rcParams["axes.prop_cycle"] = cycler(color=list(palette.colors))
    return list(palette.colors)


def cmap(name: str, n: int = 256):
    """Build a LinearSegmentedColormap from a sequential/diverging palette."""
    from matplotlib.colors import LinearSegmentedColormap

    palette = PALETTES[name]
    if palette.kind not in ("sequential", "diverging"):
        raise ValueError(f"{name} is {palette.kind}; use apply()/get() instead")
    return LinearSegmentedColormap.from_list(name, list(palette.colors), N=n)


def preview(path: str) -> None:
    """Render a one-page swatch sheet of every palette to path (pdf/png)."""
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(7.16, 0.32 * len(PALETTES) + 0.5))
    ax.set_axis_off()
    for row, (name, palette) in enumerate(PALETTES.items()):
        y = len(PALETTES) - 1 - row
        for col, color in enumerate(palette.colors):
            ax.add_patch(plt.Rectangle((col * 0.32, y), 0.30, 0.8, color=color))
        ax.text(-0.15, y + 0.4, f"{name}  [{palette.kind}]", ha="right",
                va="center", fontsize=8)
        ax.text(0.32 * len(palette.colors) + 0.1, y + 0.4, palette.source,
                ha="left", va="center", fontsize=7, color="#555555")
    ax.set_xlim(-3.2, 8.5)
    ax.set_ylim(-0.2, len(PALETTES))
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="list palettes")
    parser.add_argument("--preview", metavar="PATH", help="write swatch sheet")
    args = parser.parse_args()
    if args.list:
        for name, palette in PALETTES.items():
            print(f"{name:22s} {palette.kind:12s} {len(palette.colors):2d} colors"
                  f"  {palette.source}")
    if args.preview:
        preview(args.preview)
        print(f"wrote {args.preview}")


if __name__ == "__main__":
    main()
