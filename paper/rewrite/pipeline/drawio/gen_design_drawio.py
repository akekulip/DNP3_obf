"""Figure 4 in the idiom of Ditto (NDSS 2022) Fig. 4: draw the queues, not sentences about them.

Queues are segmented FIFO glyphs, packets are the only saturated colour, every label is small and
grey beside the thing it names, the container is named quietly at its own bottom edge, and there
is no legend. The release rules stay in the Design section's equations, where they belong.
1 unit = 1 pt at the final 3.5 in width.
"""
import html

W, H = 252, 136
SLATE, RULE, SOFT = "#2F3E4E", "#C5CCD3", "#6B6B6B"
VERM, GREY, GREEN, BLUE, AMBER = "#D55E00", "#555555", "#009E73", "#0072B2", "#E69F00"
cells, n = [], [1]

def nid():
    n[0] += 1
    return f"c{n[0]}"

def vertex(x, y, w, h, style, value=""):
    i = nid()
    val = html.escape(value).replace("&lt;br&gt;", "&#xa;")
    cells.append(f'<mxCell id="{i}" value="{val}" style="{style}" vertex="1" parent="1">'
                 f'<mxGeometry x="{x:.2f}" y="{y:.2f}" width="{w:.2f}" height="{h:.2f}" as="geometry"/></mxCell>')
    return i

def text(x, y, w, h, value, size=7, align="left", colour=SOFT, italic=False):
    return vertex(x, y, w, h, f"text;html=0;strokeColor=none;fillColor=none;align={align};"
                              f"verticalAlign=middle;fontFamily=Times New Roman;fontSize={size};"
                              f"fontColor={colour};spacing=0;{'fontStyle=2;' if italic else ''}", value)

def edge(p0, p1, style, pts=()):
    i = nid()
    g = ('<mxGeometry relative="1" as="geometry">'
         f'<mxPoint x="{p0[0]:.2f}" y="{p0[1]:.2f}" as="sourcePoint"/>'
         f'<mxPoint x="{p1[0]:.2f}" y="{p1[1]:.2f}" as="targetPoint"/>')
    if pts:
        g += '<Array as="points">' + "".join(f'<mxPoint x="{x}" y="{y}"/>' for x, y in pts) + '</Array>'
    cells.append(f'<mxCell id="{i}" style="{style}" edge="1" parent="1">{g}</mxGeometry></mxCell>')

def arrow(p0, p1, colour, width=1.0, dashed=False, pts=()):
    d = "dashed=1;dashPattern=3 2;" if dashed else ""
    edge(p0, p1, f"endArrow=block;endFill=1;endSize=4;strokeColor={colour};strokeWidth={width};"
                 f"rounded=1;{d}", pts)

QX, QW, CELLS = 72, 52, 7
CW = QW / CELLS

def queue(y, packets, colour, label):
    """A FIFO glyph: seven cells, the head ones holding packets. The head is at the right."""
    for k in range(CELLS):
        filled = k >= CELLS - packets
        vertex(QX + k * CW, y, CW, 8,
               f"fillColor={colour if filled else '#FFFFFF'};strokeColor={RULE};strokeWidth=0.5;")
    text(QX + QW + 4, y - 0.5, 48, 9, label)

# ---------------- the switch, named quietly at its own bottom edge ----------------
vertex(26, 4, 204, 124, f"rounded=1;arcSize=2;fillColor=#F7F8FA;strokeColor={RULE};strokeWidth=0.7;")
text(26, 116, 204, 9, "programmable switch (one P4 pipeline)", 7, align="center")

# ---------------- ingress: every arrival is classified here, from either side ----------------
vertex(34, 44, 24, 42, f"shape=trapezoid;direction=north;perimeter=trapezoidPerimeter;"
                       f"fillColor=#E7EBEF;strokeColor={SLATE};strokeWidth=0.7;")
text(30, 88, 32, 9, "classify,", 7, align="center")
text(30, 96, 32, 9, "arm", 7, align="center")
# The request comes from the master; the acknowledgment and the response come back from the
# relay. Both reach ingress, which is why the lanes can hold either.
arrow((2, 56), (33, 56), VERM, 1.2)
text(0, 47, 32, 9, "from master", 7, align="center", colour=VERM)
arrow((2, 74), (33, 74), GREY, 0.9, dashed=True)
text(0, 76, 32, 9, "from relay", 7, align="center")

# ---------------- read lane: blockers above each held packet, strict priority ----------------
text(QX, 8, 120, 9, "read lane (READ, SELECT)", 7.5, colour=SLATE)
queue(16, 4, AMBER, "blockers")
queue(28, 1, GREY,  "held ACK")
queue(40, 4, AMBER, "blockers")
queue(52, 1, GREEN, "held response")
# ---------------- control lane ----------------
text(QX, 66, 120, 9, "control lane (OPERATE)", 7.5, colour=SLATE)
queue(74, 4, AMBER, "blockers")
queue(86, 1, BLUE,  "held OPERATE")

# ingress feeds the held queue of each lane
arrow((58, 58), (QX - 1, 32), SLATE, 0.8, pts=((66, 58), (66, 32)))
arrow((58, 72), (QX - 1, 90), SLATE, 0.8, pts=((66, 72), (66, 90)))

# ---------------- strict-priority schedulers drain each lane ----------------
for y0, y1 in ((16, 60), (74, 94)):
    vertex(180, y0, 12, y1 - y0, f"shape=triangle;direction=east;fillColor=#E7EBEF;"
                                 f"strokeColor={SLATE};strokeWidth=0.7;")
text(172, 62, 40, 9, "strict priority", 7, align="center")

# ---------------- what leaves ----------------
arrow((192, 38), (228, 38), VERM, 1.2)
text(194, 28, 36, 9, "to master", 7, colour=VERM)
arrow((192, 80), (228, 80), VERM, 1.2)
text(194, 70, 36, 9, "to master", 7, colour=VERM)
arrow((192, 90), (228, 90), GREY, 0.9, dashed=True)
text(194, 96, 36, 9, "to relay", 7)

# ---------------- the generator that keeps the blocker queues non-empty ----------------
# One dashed trunk with a branch into each blocker queue, rather than three separate runs.
vertex(QX, 100, QW, 10, f"rounded=1;arcSize=20;fillColor=#FFFFFF;strokeColor={RULE};strokeWidth=0.6;")
text(QX, 100, QW, 10, "packet generator", 6.5, align="center")
edge((QX - 4, 105), (QX - 4, 18), f"endArrow=none;strokeColor={AMBER};strokeWidth=0.6;"
                                  "dashed=1;dashPattern=2 1.5;")
for y in (20, 44, 78):
    arrow((QX - 4, y), (QX - 0.5, y), AMBER, 0.6, dashed=True)

xml = (f'<mxfile host="drawio"><diagram name="fig_design" id="des">'
       f'<mxGraphModel dx="0" dy="0" grid="0" gridSize="4" guides="0" tooltips="0" connect="0" '
       f'arrows="0" fold="0" page="1" pageScale="1" pageWidth="{W}" pageHeight="{H}" '
       f'background="#ffffff" math="0" shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
       + "".join(cells) + '</root></mxGraphModel></diagram></mxfile>')
out = "/home/philip/Projects/DNP3/paper/rewrite/figures/fig_design.drawio"
open(out, "w").write(xml)
print("wrote", out, len(cells), "cells")
