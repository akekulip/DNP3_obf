#!/usr/bin/env python3
"""Render the two paper figures as tight vector PDFs for LaTeX inclusion.

Run with the research venv:  ~/.venvs/research/bin/python make_figures.py
Every number here matches the harness reports; nothing is invented.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["DejaVu Sans"],
    "svg.fonttype": "none",
})

INK = "#1a1a1a"
GREY = "#6b7280"


def box(ax, x, y, w, h, title, lines=None, face="#eef2ff", edge="#4b5563",
        lw=1.2, tsize=10, lsize=8.4, tcolor=INK, italic_last=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                 boxstyle="round,pad=0.002,rounding_size=0.01",
                 fc=face, ec=edge, lw=lw))
    cx = x + w / 2.0
    if not lines:
        ax.text(cx, y + h / 2.0, title, ha="center", va="center",
                fontsize=tsize, fontweight="bold", color=tcolor)
        return
    # Height-aware stack: title + description lines centered as one block,
    # always inside the box regardless of box height.
    n = len(lines)
    line_gap = 0.046
    block_h = 0.052 + n * line_gap          # title band + lines
    top = y + h / 2.0 + block_h / 2.0        # top of the text block
    ax.text(cx, top, title, ha="center", va="top",
            fontsize=tsize, fontweight="bold", color=tcolor)
    for i, ln in enumerate(lines):
        last = italic_last and i == n - 1
        it = "italic" if last else "normal"
        col = "#166534" if last else "#374151"
        ax.text(cx, top - 0.052 - i * line_gap, ln, ha="center", va="top",
                fontsize=lsize, style=it, color=col)


# ------------------------------------------------------------- Figure 1
def figure1(path):
    fig, ax = plt.subplots(figsize=(7.2, 4.3))
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")

    # Master (left)
    box(ax, 0.015, 0.44, 0.185, 0.20, "Master",
        ["(OpenDNP3)", "link addr 1"], face="#f3f4f6", edge=INK, lw=1.5,
        tsize=11, lsize=8.4)
    ax.text(0.1075, 0.36, "reassembles the identical\napplication message",
            ha="center", va="top", fontsize=7.8, color=GREY)

    # Server container (right), header sits above the first inner box
    ax.add_patch(FancyBboxPatch((0.47, 0.05), 0.515, 0.90,
                 boxstyle="round,pad=0.002,rounding_size=0.01",
                 fc="white", ec=INK, lw=1.7))
    ax.text(0.7275, 0.915, "Split-replay server", ha="center", va="top",
            fontsize=11, fontweight="bold")
    ax.text(0.7275, 0.876, "stands in for the outstation (TCP/20000, link addr 10)",
            ha="center", va="top", fontsize=7.8, color=GREY)

    box(ax, 0.49, 0.685, 0.475, 0.115, "Frame reassembler",
        ["whole DNP3 frames from the TCP stream (LEN field)"], lsize=7.9)
    box(ax, 0.49, 0.545, 0.475, 0.115, "Request parser + exchange map",
        ["match function code + app seq; refuse unmatched"], lsize=7.9)
    box(ax, 0.49, 0.375, 0.475, 0.145, "CRC-boundary splitter",
        ["cut only on existing CRC block boundaries",
         'invariant: b"".join(chunks) == response'],
        face="#e7f0e9", italic_last=True, lsize=7.9)
    box(ax, 0.49, 0.08, 0.225, 0.235, "Captured responses",
        ["from baseline PCAP"], face="#f9fafb", edge="#9ca3af", lsize=7.9)
    box(ax, 0.74, 0.08, 0.225, 0.235, "Delivery mode",
        ["full = verbatim replay", "crc-boundary = split",
         "both fragments split"], face="#f9fafb", edge="#9ca3af", lsize=7.9)

    # three arrows in the gutter between master (right edge 0.20) and
    # container (left edge 0.47); short labels, well separated
    def gutter_arrow(y_master, y_srv, text, col=INK, dashed=False, to_srv=True):
        a, b = ((0.20, y_master), (0.47, y_srv)) if to_srv else \
               ((0.47, y_srv), (0.20, y_master))
        ax.add_patch(FancyArrowPatch(a, b, arrowstyle="-|>", mutation_scale=12,
                     lw=1.4, color=col, shrinkA=0, shrinkB=0,
                     linestyle=(":" if dashed else "-")))
        ax.text(0.335, max(a[1], b[1]) + 0.022, text, ha="center",
                va="bottom", fontsize=8.2, color=col)

    gutter_arrow(0.60, 0.74, "READ request", to_srv=True)
    gutter_arrow(0.50, 0.47, "split chunks", to_srv=False)
    ax.add_patch(FancyArrowPatch((0.20, 0.44), (0.47, 0.62),
                 arrowstyle="-|>", mutation_scale=12, lw=1.3, color=GREY,
                 linestyle=":", shrinkA=0, shrinkB=0))
    ax.text(0.335, 0.40, "DNP3 CONFIRM", ha="center", va="top",
            fontsize=8.2, color=GREY)

    ax.text(0.015, 0.02, "Master command is unchanged: the server occupies the "
            "outstation's address and port.", ha="left", va="bottom",
            fontsize=8, color="#374151")

    fig.savefig(path, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)


# ------------------------------------------------------------- Figure 2
def figure2(path):
    fig, ax = plt.subplots(figsize=(7.0, 3.9))
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    x0, bw = 0.05, 0.90

    ax.text(x0, 0.97, "One captured 2,407-byte DNP3 READ response",
            fontsize=11, fontweight="bold", va="top")
    ax.text(x0, 0.925, "Both rows carry the identical bytes; only the TCP "
            "segmentation differs. Bar width is proportional to bytes.",
            fontsize=8, color=GREY, va="top")

    def bar(y, n, label, sub, face):
        ax.text(x0, y + 0.055, label, fontsize=9.4, fontweight="bold", va="bottom")
        ax.text(x0 + bw, y + 0.055, sub, fontsize=8.2, color="#374151",
                ha="right", va="bottom")
        ax.add_patch(plt.Rectangle((x0, y), bw, 0.05, fc=face, ec=INK, lw=1.3))
        if n <= 20:
            for i in range(1, n):
                xx = x0 + bw * i / n
                ax.plot([xx, xx], [y, y + 0.05], color=INK, lw=0.9)
        else:
            for i in range(1, n):
                xx = x0 + bw * i / n
                ax.plot([xx, xx], [y, y + 0.05], color="#9ca3af", lw=0.28)

    bar(0.79, 9, "Native OpenDNP3 segmentation",
        "9 link frames (up to 292 B each)", "#eef2ff")
    bar(0.66, 141, "CRC-boundary split, 1 block/chunk",
        "141 chunks (at most 18 B each)", "#e7f0e9")

    # sweep panel
    ax.text(x0, 0.545, "Granularity sweep (blocks per chunk)",
            fontsize=9.4, fontweight="bold", va="bottom")
    sweep = [(1, 141), (2, 71), (4, 36), (8, 18)]
    pw, gap = 0.205, 0.023
    cx = x0
    for bpc, chunks in sweep:
        ax.add_patch(plt.Rectangle((cx, 0.42), pw, 0.045, fc="white",
                     ec=INK, lw=1.1))
        col, lw = ("#1a1a1a", 0.8) if chunks <= 20 else ("#9ca3af", 0.25)
        for i in range(1, chunks):
            xx = cx + pw * i / chunks
            ax.plot([xx, xx], [0.42, 0.465], color=col, lw=lw)
        ax.text(cx + pw / 2, 0.40, "bpc=%d -> %d chunks" % (bpc, chunks),
                ha="center", va="top", fontsize=8)
        cx += pw + gap

    ax.add_patch(FancyBboxPatch((x0, 0.14), bw, 0.16,
                 boxstyle="round,pad=0.003,rounding_size=0.01",
                 fc="#f9fafb", ec="#9ca3af", lw=1.1))
    ax.text(x0 + bw / 2, 0.255, "Every granularity accepted by the master",
            ha="center", va="center", fontsize=9.4, fontweight="bold")
    ax.text(x0 + bw / 2, 0.19, "800 measurements delivered, DNP3 CONFIRM "
            "returned, 0 TCP retransmissions, 0 resets, byte-preservation PASS",
            ha="center", va="center", fontsize=8.2, color="#374151")

    fig.savefig(path, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)


if __name__ == "__main__":
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    figure1(os.path.join(here, "fig1_architecture.pdf"))
    figure2(os.path.join(here, "fig2_baseline_vs_split.pdf"))
    print("wrote fig1_architecture.pdf and fig2_baseline_vs_split.pdf")
