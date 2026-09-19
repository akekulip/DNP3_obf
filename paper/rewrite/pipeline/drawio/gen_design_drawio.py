"""Figure 3 in the idiom of Ditto (NDSS 2022) Fig. 3: draw the queues, not sentences about them.

The drawing reads left to right and is a pipeline view of one transaction rather than a map of the
wire: everything on the left arrives at the switch, everything on the right leaves it, and each
arrival and departure names the endpoint it came from or goes to. That framing is what lets every
arrow point right while the two lanes carry traffic in opposite directions, which they do.

Four things this drawing has to get right, because the earlier version got each of them wrong.

1. **The request arms the deadlines.** Both release instants are computed from the request's own
   arrival, so the request has to be in the figure. The earlier version showed only what the
   outstation sends, which left the reader unable to see where a deadline comes from.
2. **The read lane has four queues, not three.** Each held packet has its own blocker queue above
   it. That is what lets the acknowledgment and the response be released independently, and the
   dual-deadline construction depends on it.
3. **One endpoint appears once.** The earlier version put "Outstation" on the left and
   "to Outstation" on the right, which reads as a contradiction.
4. **Labels are small.** Ditto's in-figure text is markedly smaller than its caption; ours was
   close to caption size and swamped the drawing.

Colour carries two meanings and nothing else: amber is a blocker packet, and a held packet keeps
the colour its lane uses elsewhere in the paper. Everything structural is grey. There is no legend
box -- each queue is named inline, which is how Ditto does it.

1 unit = 1 pt at the final 7.16 in (double-column) width.
"""
import html

W, H = 512, 166
SLATE, RULE, SOFT = "#2F3E4E", "#C5CCD3", "#6B6B6B"
VERM, GREY, GREEN, BLUE, AMBER = "#D55E00", "#555555", "#009E73", "#0072B2", "#E69F00"
FONT = "Times New Roman"
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


def text(x, y, w, h, value, size=6, align="left", colour=SOFT, italic=False):
    st = f"text;html=0;strokeColor=none;fillColor=none;align={align};verticalAlign=middle;" \
         f"fontFamily={FONT};fontSize={size};fontColor={colour};spacing=0;"
    if italic:
        st += "fontStyle=2;"
    return vertex(x, y, w, h, st, value)


def edge(p0, p1, style, pts=()):
    i = nid()
    g = ('<mxGeometry relative="1" as="geometry">'
         f'<mxPoint x="{p0[0]:.2f}" y="{p0[1]:.2f}" as="sourcePoint"/>'
         f'<mxPoint x="{p1[0]:.2f}" y="{p1[1]:.2f}" as="targetPoint"/>')
    if pts:
        g += '<Array as="points">' + "".join(f'<mxPoint x="{x}" y="{y}"/>' for x, y in pts) + '</Array>'
    cells.append(f'<mxCell id="{i}" style="{style}" edge="1" parent="1">{g}</mxGeometry></mxCell>')


def arrow(p0, p1, colour, width=0.8, dashed=False, pts=()):
    d = "dashed=1;dashPattern=3 2;" if dashed else ""
    edge(p0, p1, f"endArrow=block;endFill=1;endSize=4;strokeColor={colour};strokeWidth={width};"
                 f"rounded=1;{d}", pts)


# ---------------- the queue glyph: a FIFO whose head is at the right ----------------
QX, CELLS, CW, QH = 176, 6, 11.5, 8.0
QW = CELLS * CW                                  # 176 .. 245


def queue(y, packets, colour, name, released=""):
    for k in range(CELLS):
        filled = k >= CELLS - packets
        vertex(QX + k * CW, y, CW, QH,
               f"fillColor={colour if filled else '#FFFFFF'};strokeColor={RULE};strokeWidth=0.5;")
    text(QX + QW + 5, y - 0.5, 68, 9, name, 6.5, colour=SLATE)
    if released:
        text(QX + QW + 74, y - 0.5, 92, 9, released, 6, italic=True)


# ---------------- the switch ----------------
BX0, BX1, BY0, BY1 = 60, 434, 6, 160
vertex(BX0, BY0, BX1 - BX0, BY1 - BY0,
       f"rounded=1;arcSize=2;fillColor=#F7F8FA;strokeColor={RULE};strokeWidth=0.7;")
text(BX0 + 5, BY0 + 4, 120, 9, "programmable switch", 6.5)

# ---------------- what arrives, on the left, each named with where it came from ----------------
for y, what, whence, col in ((28, "request", "from master", BLUE),
                             (76, "acknowledgment", "from outstation", GREY),
                             (102, "response", "from outstation", GREEN)):
    text(0, y - 8, 54, 9, what, 6.5, align="right", colour=SLATE)
    text(0, y - 0.5, 54, 9, whence, 6, align="right")
    arrow((56, y), (66, y), col, 0.9)

# ---------------- ingress classifies every arrival ----------------
vertex(66, 16, 14, 96, f"shape=trapezoid;direction=north;perimeter=trapezoidPerimeter;"
                       f"fillColor=#E7EBEF;strokeColor={SLATE};strokeWidth=0.7;")
text(58, 116, 30, 9, "classify", 6.5, align="center")

# ---------------- the request arms both deadlines, then leaves ----------------
# This is the whole of the security argument in one box: both release instants are computed from
# the request's own arrival, so neither of them carries anything the outstation did. The instants
# themselves are printed beside the queues they govern, not here, so the reader meets each one
# where it acts.
vertex(98, 19, 58, 18, f"rounded=1;arcSize=16;fillColor=#FFFFFF;strokeColor={BLUE};"
                       f"strokeWidth=0.8;fontFamily={FONT};fontSize=6.5;fontColor={SLATE};"
                       f"verticalAlign=middle;align=center;", "arm deadlines")
arrow((80, 28), (97, 28), BLUE, 0.9)
arrow((156, 28), (410, 28), BLUE, 0.9)

# two annotations that sit above the lanes, clear of every rule and arrow
text(146, 38, 200, 9, "blocker packets recirculate, and reach no cable", 6, colour=AMBER)

# ---------------- the read lane: two held packets, each behind its own blocker queue ----------
vertex(140, 46, 264, 66, f"rounded=0;fillColor=none;strokeColor={RULE};strokeWidth=0.6;"
                         f"dashed=1;dashPattern=3 2;")
text(144, 47, 80, 9, "read lane", 6.5, colour=SLATE)
queue(60, 4, AMBER, "blocker")
queue(72, 1, GREY, "acknowledgment", "released at T0 + DA")
queue(86, 4, AMBER, "blocker")
queue(98, 1, GREEN, "response", "released at T0 + DA + DR")
arrow((80, 76), (174, 76), GREY, 0.8)
arrow((80, 102), (174, 102), GREEN, 0.8)

# ---------------- the control lane, the same alphabet at a smaller scope ------------------------
vertex(140, 116, 264, 38, f"rounded=0;fillColor=none;strokeColor={RULE};strokeWidth=0.6;"
                          f"dashed=1;dashPattern=3 2;")
text(144, 117, 80, 9, "control lane", 6.5, colour=SLATE)
queue(130, 4, AMBER, "blocker")
queue(142, 1, BLUE, "command", "released at T0 + J")
arrow((127, 37), (174, 146), BLUE, 0.8, pts=((127, 146),))
text(84, 120, 40, 9, "command only", 6, align="right", colour=BLUE)

# ---------------- a strict-priority scheduler drains each held queue --------------------------
# The blocker queue outranks the queue it guards, so nothing below it is served while a blocker
# packet is present. Vertical position alone used to carry that; the annotation above says it.
for y0, y1 in ((60, 84), (86, 110), (130, 154)):
    vertex(410, y0, 9, y1 - y0, f"shape=triangle;direction=east;fillColor=#E7EBEF;"
                                f"strokeColor={SLATE};strokeWidth=0.7;")
# Named once, beside the scheduler it describes, rather than floating at the top of the drawing.
text(344, 60, 60, 9, "strict priority", 6, align="right")

# ---------------- what leaves, on the right, each named with where it goes ---------------------
arrow((419, 76), (436, 76), GREY, 0.9)
arrow((419, 102), (436, 102), GREEN, 0.9)
arrow((419, 146), (436, 146), BLUE, 0.9)
text(440, 24, 72, 9, "to outstation", 6)
text(440, 72, 72, 9, "to master", 6)
text(440, 98, 72, 9, "to master", 6)
text(440, 142, 72, 9, "to outstation", 6)

# ---------------- the blocker loopback, closed back into the queues it feeds -------------------
# It leaves the scheduler, turns inside the switch and re-enters the blocker queue, which is what
# keeps that queue non-empty until the deadline. Drawn closed because it never reaches a cable: an
# open end would suggest blocker packets leave the switch. Each return runs in the gap above its
# own blocker row, so it crosses no label.
LOOP = f"endArrow=none;strokeColor={AMBER};strokeWidth=0.7;dashed=1;dashPattern=3 2;rounded=1;"
for sched_y, ret in ((60, 56), (86, 82), (130, 126)):
    edge((414, sched_y), (170, ret), LOOP, pts=((414, ret), (170, ret)))
    edge((170, ret), (170, sched_y + 4), LOOP)
    arrow((170, sched_y + 4), (175, sched_y + 4), AMBER, 0.7, dashed=True)

xml = (f'<mxfile host="drawio"><diagram name="fig_design" id="des">'
       f'<mxGraphModel dx="0" dy="0" grid="0" gridSize="4" guides="0" tooltips="0" connect="0" '
       f'arrows="0" fold="0" page="1" pageScale="1" pageWidth="{W}" pageHeight="{H}" '
       f'background="#ffffff" math="0" shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
       + "".join(cells) + '</root></mxGraphModel></diagram></mxfile>')
out = "/home/philip/Projects/DNP3/paper/rewrite/figures/fig_design.drawio"
open(out, "w").write(xml)
print("wrote", out, len(cells), "cells")
