"""FIG-5: Response segmentation -- native single segment vs defended CRC split.

AUDIT CORRECTION: regenerated directly from csv/size_verdict.csv (the corrected,
sequence-reconstructed size source), NOT from VERDICT.json strings. Each row
carries the on-wire segment_vector ("49" or "28|21"), the transaction class, and
source_copy_escape. The native response leaves as one 49-byte segment; the
defended path splits it at a DNP3 CRC boundary into [28, 21] (28+21 == 49).

Groups plotted (counts read from the CSV):
  native READ         segment [49]     n=100
  defended READ       segment [28,21]  n=600
  defended SELECT     segment [28,21]  n=500
  defended 49-byte escapes (a defended txn that came out as a single 49-byte
  segment): n=0.

The title says "sequence-reconstructed, CRC-valid" -- it does NOT claim
byte-preserving/byte-exact.
"""
import csv
from collections import Counter
import numpy as np
import _figstyle as S

S.utils_mpl.set_global()

NATIVE_PCAP = "e1_native_size_shapeoff.pcap"
DEF_READ_PCAP = "e2_def_read.pcap"
DEF_SELECT_PCAP = "e2_def.pcap"


def load_rows():
    with open(S.CSV / "size_verdict.csv") as f:
        return list(csv.DictReader(f))


def parse_vec(s):
    return [int(x) for x in s.split("|") if x.strip()]


rows = load_rows()

# groups defined by (pcap, class); segment vector must be uniform within a group
groups = [
    ("native\nREAD", NATIVE_PCAP, "READ", [S.C_NATIVE]),
    ("defended\nREAD", DEF_READ_PCAP, "READ", [S.C_DEFENDED, S.C_DEF_SELECT]),
    ("defended\nSELECT", DEF_SELECT_PCAP, "SELECT", [S.C_DEFENDED, S.C_DEF_SELECT]),
]

plotted = []
for label, pcap, cls, seg_colors in groups:
    sub = [r for r in rows if r["pcap"] == pcap and r["class"] == cls]
    vecs = Counter(r["segment_vector"] for r in sub)
    assert len(vecs) == 1, f"{label}: non-uniform segment vectors {vecs}"
    vec = parse_vec(next(iter(vecs)))
    n = len(sub)
    plotted.append((f"{label}\nn={n}", vec, seg_colors))

# escapes: any DEFENDED transaction that reported source_copy_escape != 0,
# OR a defended row that collapsed to a single 49-byte segment.
def_rows = [r for r in rows if r["pcap"] in (DEF_READ_PCAP, DEF_SELECT_PCAP)]
n_escape = sum(1 for r in def_rows
               if r["source_copy_escape"].strip() not in ("0", "")
               or r["segment_vector"] == "49")

fig, ax = S.utils_mpl.get_fig(size=(3.6, 2.5))


def stacked(x, segs, seg_colors):
    bottom = 0
    for i, seg in enumerate(segs):
        ax.bar(x, seg, bottom=bottom, width=0.55,
               color=seg_colors[i % len(seg_colors)], edgecolor="k", lw=0.8)
        ax.text(x, bottom + seg / 2, str(seg), ha="center", va="center",
                fontsize=8.5, color="white", fontweight="bold")
        bottom += seg
    return bottom


xs = np.arange(len(plotted))
tops = [stacked(x, vec, cols) for x, (_, vec, cols) in zip(xs, plotted)]
ax.set_xticks(xs)
ax.set_xticklabels([lbl for lbl, _, _ in plotted], fontsize=7.5)
ax.set_ylabel("Response bytes (by TCP segment)")
ax.set_title(f"sequence-reconstructed, CRC-valid "
             f"(49-byte escapes: {n_escape})", fontsize=8.0)
S.utils_mpl.set_y_axis(ax, bnd=[0, max(tops) * 1.18])
ax.set_xlim(-0.6, len(plotted) - 0.4)
S.utils_mpl.set_grid(fig, ax)
S.save(fig, "FIG-5_segment_size")
