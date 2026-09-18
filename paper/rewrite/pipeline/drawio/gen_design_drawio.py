"""Figure 3 in the idiom of Ditto (NDSS 2022) Fig. 4: draw the queues, not sentences about them.

The drawing reads left to right, the way Ditto's does. Packets enter on the left, wait in a queue
behind the blocker packets that hold them, and leave on the right at their deadline. The two
endpoints sit outside the switch, because neither of them is part of the mechanism. Each lane is a
box holding its own queues, and the blocker loopback returns into the blocker queues it feeds
rather than trailing off the drawing.

Every lane is drawn in the direction its held packets travel, so every arrow points right: the read
lane carries what the outstation returns to the master, and the control lane carries the OPERATE the
master sends to the outstation.

1 unit = 1 pt at the final 3.5 in width.
"""
import html

W, H = 252, 116
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


QX, QW, CELLS = 96, 46, 6
CW = QW / CELLS


def queue(y, packets, colour, label):
    """A FIFO glyph: six cells, the head ones holding packets. The head is at the right."""
    for k in range(CELLS):
        filled = k >= CELLS - packets
        vertex(QX + k * CW, y, CW, 7.5,
               f"fillColor={colour if filled else '#FFFFFF'};strokeColor={RULE};strokeWidth=0.5;")
    if label:
        text(QX + QW + 3, y - 0.75, 40, 9, label)


def endpoint(x, y, name):
    """An endpoint drawn outside the switch, because it is not part of the mechanism."""
    vertex(x, y, 30, 15, f"rounded=1;arcSize=18;fillColor=#FFFFFF;strokeColor={SLATE};"
                         f"strokeWidth=0.7;fontFamily=Times New Roman;fontSize=7;"
                         f"fontColor={SLATE};verticalAlign=middle;align=center;", name)


# ---------------- the switch, named quietly at its own bottom edge ----------------
BX0, BX1 = 40, 212
vertex(BX0, 2, BX1 - BX0, 110, f"rounded=1;arcSize=2;fillColor=#F7F8FA;strokeColor={RULE};"
                               f"strokeWidth=0.7;")
text(BX0, 104, BX1 - BX0, 9, "programmable switch", 8, align="center")

# ---------------- the endpoints, outside the box on either side ----------------
endpoint(0, 26, "Outstation")
endpoint(216, 26, "Master")
text(0, 42, 32, 9, "ACK, response", 7, align="center")
text(0, 70, 34, 9, "OPERATE", 7, align="center", colour=SLATE)
text(0, 77, 34, 9, "from Master", 7, align="center")

# ---------------- ingress classifies every arrival ----------------
vertex(48, 20, 18, 66, f"shape=trapezoid;direction=north;perimeter=trapezoidPerimeter;"
                       f"fillColor=#E7EBEF;strokeColor={SLATE};strokeWidth=0.7;")
text(42, 88, 30, 9, "classify", 8, align="center")
arrow((30, 34), (47, 34), GREEN, 1.0)
arrow((30, 78), (47, 78), BLUE, 1.0)

# ---------------- the read lane, a box of its own ----------------
vertex(88, 11, 104, 43, f"rounded=0;fillColor=none;strokeColor={RULE};strokeWidth=0.6;"
                        f"dashed=1;dashPattern=3 2;")
queue(22, 4, AMBER, "")
queue(31, 1, GREY, "ACK")
queue(40, 1, GREEN, "response")
text(QX, 47, 60, 9, "read lane", 7, colour=SLATE)

# ---------------- the control lane, a box of its own ----------------
vertex(88, 60, 104, 38, f"rounded=0;fillColor=none;strokeColor={RULE};strokeWidth=0.6;"
                        f"dashed=1;dashPattern=3 2;")
queue(70, 4, AMBER, "")
queue(79, 1, BLUE, "OPERATE")
text(QX, 88, 60, 9, "control lane", 7, colour=SLATE)

arrow((66, 34), (QX - 1, 34), SLATE, 0.7)
arrow((66, 78), (QX - 1, 82), SLATE, 0.7, pts=((80, 78), (80, 82)))

# ---------------- a strict-priority scheduler drains each lane ----------------
for y0, y1 in ((22, 48), (70, 87)):
    vertex(196, y0, 10, y1 - y0, f"shape=triangle;direction=east;fillColor=#E7EBEF;"
                                 f"strokeColor={SLATE};strokeWidth=0.7;")

# ---------------- what leaves, on the right ----------------
arrow((206, 34), (215, 34), GREEN, 1.0)
arrow((206, 78), (215, 78), BLUE, 1.0)
text(202, 88, 46, 9, "to Outstation", 7, align="center")

# ---------------- the blocker loopback, closed back into the queues it feeds ----------------
# It leaves the scheduler, turns inside the switch and re-enters the blocker queue, which is what
# keeps that queue non-empty until the deadline. Drawn closed because it never reaches a cable: an
# open end would suggest blocker packets leave the switch.
LOOP = (f"endArrow=none;strokeColor={AMBER};strokeWidth=0.7;dashed=1;dashPattern=3 2;rounded=1;")
# Each loop starts on the scheduler that drains the lane, so both of its ends are attached.
for sched_top, ret, inlet in ((22, 15, 25.75), (70, 65, 73.75)):
    edge((201, sched_top), (QX - 5, ret), LOOP, pts=((201, ret), (QX - 5, ret)))
    edge((QX - 5, ret), (QX - 5, inlet), LOOP)
    arrow((QX - 5, inlet), (QX - 0.5, inlet), AMBER, 0.7, dashed=True)
text(112, 1, 80, 8, "blocker loopback", 7, colour=AMBER)

xml = (f'<mxfile host="drawio"><diagram name="fig_design" id="des">'
       f'<mxGraphModel dx="0" dy="0" grid="0" gridSize="4" guides="0" tooltips="0" connect="0" '
       f'arrows="0" fold="0" page="1" pageScale="1" pageWidth="{W}" pageHeight="{H}" '
       f'background="#ffffff" math="0" shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
       + "".join(cells) + '</root></mxGraphModel></diagram></mxfile>')
out = "/home/philip/Projects/DNP3/paper/rewrite/figures/fig_design.drawio"
open(out, "w").write(xml)
print("wrote", out, len(cells), "cells")
