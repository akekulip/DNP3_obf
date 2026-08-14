"""FIG-5: Response segmentation -- native single segment vs defended CRC split.

Data: VERDICT.json ("size": native_segment, defended_segment, source_copy_escapes).
The native response leaves as one 49-byte segment; the defended path splits it,
byte-preserving, at a DNP3 CRC boundary into [28, 21] (28+21 == 49). Parsed
directly from the JSON strings so no size value is hardcoded.

Note: the per-transaction CSVs record resp_seg_vector uniformly as 28 (the DNP3
application-layer response length), NOT the on-wire TCP segmentation; the
segmentation vectors live only in VERDICT.json, which is the plotted source.
"""
import re
import numpy as np
import matplotlib.pyplot as plt
import _figstyle as S

S.utils_mpl.set_global()

v = S.load_json("VERDICT.json")["size"]


def parse_vec(s):
    return [int(x) for x in re.findall(r"\d+", s.split("]")[0])]


native = parse_vec(v["native_segment"])            # [49]
defended = parse_vec(v["defended_segment"])         # [28, 21]
escapes = v["source_copy_escapes"]

fig, ax = S.utils_mpl.get_fig(size=(3.5, 2.4))

# native: single stacked bar at x=0; defended: stacked segments at x=1
def stacked(x, segs, base_color, seg_colors):
    bottom = 0
    for i, seg in enumerate(segs):
        ax.bar(x, seg, bottom=bottom, width=0.55, color=seg_colors[i],
               edgecolor="k", lw=0.8)
        ax.text(x, bottom + seg / 2, str(seg), ha="center", va="center",
                fontsize=8.5, color="white", fontweight="bold")
        bottom += seg
    return bottom


tot_n = stacked(0, native, None, [S.C_NATIVE])
tot_d = stacked(1, defended, None, [S.C_DEFENDED, S.C_DEF_SELECT])
ax.set_xticks([0, 1])
ax.set_xticklabels([f"native\n[{','.join(map(str, native))}]",
                    f"defended\n[{','.join(map(str, defended))}]"])
ax.set_ylabel("Response bytes (by TCP segment)")
ax.set_title(f"CRC-boundary split, byte-preserving ({escapes} escapes)")
S.utils_mpl.set_y_axis(ax, bnd=[0, max(tot_n, tot_d) * 1.18])
ax.set_xlim(-0.6, 1.6)
S.utils_mpl.set_grid(fig, ax)
S.save(fig, "FIG-5_segment_size")
