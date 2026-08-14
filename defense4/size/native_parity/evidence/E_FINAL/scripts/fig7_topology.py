"""FIG-7: Testbed and observation-point schematic.

Labels (IPs, ports, sha, tcp_timestamps, the T0+J limitation) are parsed from
VERDICT.json "testbed" / "limitations" so the schematic text tracks the data.
Drawn with matplotlib at IEEE double-column width.

Topology: master (Vision, dp9) -> one physical Tofino running
defense4_rrc_bor_unified12 (dp8 RRC loopback / dp10 BOR loopback / dp64 relay,
dp68 internal pktgen) -> physical SEL-751. The passive observer's capture point
is the master-facing link. dp68 is an internal pktgen/recirc/clone port with no
host-capturable relay-facing tap.
"""
import re
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import _figstyle as S

S.utils_mpl.set_global()

vd = S.load_json("VERDICT.json")
testbed = vd["testbed"]
sha = re.search(r"sha (\w+)", testbed)
sha = sha.group(1) if sha else ""
master_ip = re.search(r"Vision (\d+\.\d+\.\d+\.\d+)", testbed)
master_ip = master_ip.group(1) if master_ip else ""
relay_ip = re.search(r"SEL-751 (\d+\.\d+\.\d+\.\d+)", testbed)
relay_ip = relay_ip.group(1) if relay_ip else ""
ts = "tcp_timestamps=0" if "tcp_timestamps=0" in testbed else ""

fig, ax = S.utils_mpl.get_fig(size=(7.16, 2.6))
ax.set_xlim(0, 100)
ax.set_ylim(0, 46)
ax.axis("off")


def box(cx, cy, w, h, text, fc, tc="k"):
    ax.add_patch(FancyBboxPatch((cx - w / 2, cy - h / 2), w, h,
                 boxstyle="round,pad=0.4,rounding_size=1.2",
                 fc=fc, ec="k", lw=1.2, alpha=0.9))
    ax.text(cx, cy, text, ha="center", va="center", fontsize=8.5, color=tc)


def arrow(x0, x1, y, color="k", style="-|>"):
    ax.add_patch(FancyArrowPatch((x0, y), (x1, y), arrowstyle=style,
                 mutation_scale=12, lw=1.4, color=color))


# nodes
box(13, 30, 22, 12, f"Master\n(Vision, dp9)\n{master_ip}", "#DDE6F0")
box(50, 30, 30, 20,
    f"Tofino-1\ndefense4_rrc_bor_unified12\nsha {sha[:8]}", "#E8E8E8")
box(87, 30, 20, 12, f"SEL-751\n(outstation)\n{relay_ip}", "#F0E0DD")

# internal loopback ports inside the Tofino box
ax.text(50, 24.5,
        "dp8 RRC loop  |  dp10 BOR loop  |  dp64 relay  |  dp68 pktgen",
        ha="center", va="center", fontsize=6.6, style="italic")

# links
arrow(24, 35, 30, color=S.C_DEFENDED)   # master <-> tofino (bidir drawn one way)
arrow(35, 24, 27, color=S.C_DEFENDED)
arrow(65, 77, 30, color="#666666")      # tofino -> relay
arrow(77, 65, 27, color="#666666")

# master-facing capture point (the passive observer)
ax.plot(29.5, 28.5, marker="v", ms=11, color=S.C_NATIVE, mec="k", zorder=5)
ax.annotate("passive observer\n(master-facing capture)", xy=(29.5, 30.5),
            xytext=(29.5, 43), ha="center", fontsize=7.0, color=S.C_NATIVE,
            arrowprops=dict(arrowstyle="->", color=S.C_NATIVE, lw=1.0))

# relay-facing: NO tap
ax.plot(71, 28.5, marker="x", ms=10, color="#888888", mew=2, zorder=5)
ax.annotate("no relay-facing tap\n(dp68 internal; T0+J inferred)",
            xy=(71, 27), xytext=(71, 9), ha="center", fontsize=7.0,
            color="#555555",
            arrowprops=dict(arrowstyle="->", color="#888888", lw=1.0))

if ts:
    ax.text(50, 2.5, ts, ha="center", fontsize=7.0, family="monospace",
            color="#333333")

fig.tight_layout()
S.save(fig, "FIG-7_testbed_topology")
