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
text(26, 120, 204, 9, "programmable switch", 8, align="center")

# ---------------- ingress: every arrival is classified here, from either side ----------------
vertex(34, 34, 24, 44, f"shape=trapezoid;direction=north;perimeter=trapezoidPerimeter;"
                       f"fillColor=#E7EBEF;strokeColor={SLATE};strokeWidth=0.7;")
text(28, 82, 36, 9, "classify", 8, align="center")
arrow((2, 46), (33, 46), VERM, 1.2)
text(0, 36, 32, 9, "from master", 8, align="center", colour=VERM)
arrow((2, 66), (33, 66), GREY, 0.9, dashed=True)
text(0, 68, 32, 9, "from relay", 8, align="center")

# ---------------- the two lanes ----------------
# Only the held queues are named, and by what they hold. The blocker queues are the amber ones
# and the loopback names them once for all three. Ditto's Fig. 4 carries seven labels and no
# parameter symbols; the release rules live in the Design section's equations, and repeating
# them here would only crowd the drawing.
text(QX, 2, 120, 9, "read lane", 8, colour=SLATE)
queue(12, 4, AMBER, "")
queue(24, 1, GREY,  "ACK")
queue(36, 4, AMBER, "")
queue(48, 1, GREEN, "response")
text(QX, 64, 120, 9, "control lane", 8, colour=SLATE)
queue(74, 4, AMBER, "")
queue(86, 1, BLUE,  "OPERATE")

arrow((58, 48), (QX - 1, 28), SLATE, 0.8, pts=((66, 48), (66, 28)))
arrow((58, 64), (QX - 1, 90), SLATE, 0.8, pts=((66, 64), (66, 90)))

# ---------------- strict-priority schedulers drain each lane ----------------
for y0, y1 in ((12, 56), (74, 94)):
    vertex(180, y0, 12, y1 - y0, f"shape=triangle;direction=east;fillColor=#E7EBEF;"
                                 f"strokeColor={SLATE};strokeWidth=0.7;")

# ---------------- what leaves ----------------
arrow((192, 34), (228, 34), VERM, 1.2)
text(194, 24, 36, 9, "to master", 8, colour=VERM)
arrow((192, 84), (228, 84), GREY, 0.9, dashed=True)
text(194, 74, 36, 9, "to relay", 8)

# ---------------- the blocker loopbacks, drawn rather than boxed ----------------
# Two of them, not one. The read ladder and the control pair sit on separate loopback ports in
# separate scheduling domains, which is what keeps the higher-priority read reservoirs from
# starving the OPERATE reservoir; a single "packet generator" box said none of that. Each loop
# stays inside its own lane's band so the two never cross, and neither crosses an egress arrow.
DASH = f"endArrow=none;strokeColor={AMBER};strokeWidth=0.6;dashed=1;dashPattern=2 1.5;rounded=1;"
#           return path y   blocker queue inlets
for ret, inlets in ((60, (16, 40)), (102, (78,))):
    edge((174, ret - 2), (QX - 6, ret), DASH, pts=((174, ret), (QX - 6, ret)))
    edge((QX - 6, ret), (QX - 6, min(inlets)), DASH)
    for y in inlets:
        arrow((QX - 6, y), (QX - 0.5, y), AMBER, 0.6, dashed=True)
# Below the lower return path, not on it: at y=98 the label sat in the line.
text(114, 105, 66, 9, "blocker loopback", 8, colour=AMBER)

xml = (f'<mxfile host="drawio"><diagram name="fig_design" id="des">'
       f'<mxGraphModel dx="0" dy="0" grid="0" gridSize="4" guides="0" tooltips="0" connect="0" '
       f'arrows="0" fold="0" page="1" pageScale="1" pageWidth="{W}" pageHeight="{H}" '
       f'background="#ffffff" math="0" shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
       + "".join(cells) + '</root></mxGraphModel></diagram></mxfile>')
out = "/home/philip/Projects/DNP3/paper/rewrite/figures/fig_design.drawio"
open(out, "w").write(xml)
print("wrote", out, len(cells), "cells")
