"""Figure 1 as a draw.io document, with the same device icons as Figure 2.
1 unit = 1 pt at the final 3.5 in width. Geometry is computed, not placed by eye."""
import html
W = 252
XM, XO = 52.0, 214.0
XC = (XM + XO) / 2
SLANT = 5.0
BLUE, GREY, GREEN, VERM = "#0072B2", "#555555", "#009E73", "#D55E00"
INK, SOFT, RULE, SLATE = "#1F2A36", "#6B6B6B", "#C5CCD3", "#2F3E4E"
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

def text(x, y, w, h, value, size=8, align="center", colour=INK, italic=False, rot=0):
    st = (f"text;html=0;strokeColor=none;fillColor=none;align={align};verticalAlign=middle;"
          f"fontFamily=Times New Roman;fontSize={size};fontColor={colour};spacing=0;"
          f"{'fontStyle=2;' if italic else ''}{f'rotation={rot};' if rot else ''}")
    return vertex(x, y, w, h, st, value)

def line(p0, p1, style):
    i = nid()
    cells.append(f'<mxCell id="{i}" style="{style}" edge="1" parent="1"><mxGeometry relative="1" as="geometry">'
                 f'<mxPoint x="{p0[0]:.2f}" y="{p0[1]:.2f}" as="sourcePoint"/>'
                 f'<mxPoint x="{p1[0]:.2f}" y="{p1[1]:.2f}" as="targetPoint"/></mxGeometry></mxCell>')

def arrow(p0, p1, colour, width=0.95):
    line(p0, p1, f"endArrow=block;endFill=1;endSize=4;startArrow=none;strokeColor={colour};strokeWidth={width};")

def rule(p0, p1, colour, width=0.6, dash=None):
    d = f"dashed=1;dashPattern={dash};" if dash else ""
    line(p0, p1, f"endArrow=none;startArrow=none;strokeColor={colour};strokeWidth={width};{d}")

def relay(x, y, s=1.0):
    """The SEL-751A faceplate, identical to Figure 2's, scaled by s."""
    P = lambda dx, dy, w, h, st: vertex(x + dx * s, y + dy * s, w * s, h * s, st)
    P(0, 0, 26, 34, f"rounded=1;arcSize=6;fillColor=#EEF2F6;strokeColor={SLATE};strokeWidth=0.9;")
    P(3, 3.5, 20, 8, f"rounded=1;arcSize=10;fillColor=#CFE3D6;strokeColor={SLATE};strokeWidth=0.4;")
    P(5, 6.1, 13, 0.55, f"fillColor={SLATE};strokeColor=none;")
    P(5, 8.6, 8, 0.55, f"fillColor={SLATE};strokeColor=none;")
    for k, yy in enumerate((16, 20, 24, 28)):
        P(3.9, yy - 1.3, 2.6, 2.6, f"ellipse;fillColor={GREEN if k == 0 else '#C4CCD4'};strokeColor=none;")
        P(8, yy - 0.25, 6 - (k % 2), 0.5, "fillColor=#9AA4AE;strokeColor=none;")
    for dx, dy in ((17, 19), (21, 19), (17, 24), (21, 24)):
        P(dx, dy, 3, 3, f"rounded=1;arcSize=15;fillColor=#C4CCD4;strokeColor={SLATE};strokeWidth=0.3;")

def msg(y, l2r, colour, name, fc=None):
    x1, x2 = (XM + 1.5, XO - 1.5) if l2r else (XO - 1.5, XM + 1.5)
    arrow((x1, y), (x2, y + SLANT), colour)
    ym = y + SLANT / 2
    text(XC - 60, ym - 12, 120, 9, name)
    if fc:   # function codes in their own column by the outstation, grey
        text(XO - 36, ym - 12, 32, 9, f"FC {fc}", 7, align="right", colour=SOFT)

def activation(y0, y1):
    vertex(XO - 3, y0, 6, y1 - y0, f"fillColor=#BFE6D9;strokeColor={GREEN};strokeWidth=0.6;")

def bracket(y0, y1, sym, w=10, ital=True):
    x = XM - 14
    rule((x, y0), (x, y1), VERM, 1.0)
    for yy in (y0, y1):
        rule((x - 2, yy), (x + 2, yy), VERM, 1.0)
        rule((x + 2, yy), (XM - 1, yy), VERM, 0.45, "1.2 1.2")
    text(x - 3 - w, (y0 + y1) / 2 - 5, w, 10, sym, 9, align="right", colour=VERM, italic=ital)

def frame(y0, y1, label, tabw):
    vertex(30, y0, 206, y1 - y0, f"rounded=1;arcSize=2;fillColor=none;strokeColor={RULE};strokeWidth=0.6;")
    vertex(30, y0, tabw, 10, f"rounded=0;fillColor=#F2F4F7;strokeColor={RULE};strokeWidth=0.6;")
    text(33, y0 + 0.5, tabw - 4, 9, label, 7.5, align="left", italic=True)

# ---- header: the icons and the two names, nothing else
vertex(XM - 17, 3, 34, 26, "html=1;pointerEvents=1;dashed=0;strokeColor=#ffffff;strokeWidth=1.2;outlineConnect=0;"
                          f"shape=mxgraph.cisco.computers_and_peripherals.workstation;fillColor={SLATE};")
relay(XO - 10.4, 2, 0.8)
text(XM - 30, 31, 60, 9, "Master")
text(XO - 30, 31, 60, 9, "SEL-751A")
for x in (XM, XO):
    rule((x, 44), (x, 240), "#9AA4AE", 0.6, "2 2")

def panel(y, label):
    text(XC - 70, y, 140, 9, label, 7.5, colour=SOFT, italic=True)

# ---- (a) READ
panel(47, "(a) READ poll")
msg(72, True, BLUE, "READ")
msg(88, False, GREY, "ACK")
msg(104, False, GREEN, "Response")
activation(88, 104)
bracket(88 + SLANT, 104 + SLANT, "CLRT", w=24, ital=False)

# ---- (b) select-before-operate
panel(123, "(b) Select-before-operate control")
msg(148, True, BLUE, "SELECT")
msg(164, False, GREY, "ACK")
msg(180, False, GREEN, "Response")
msg(196, True, BLUE, "OPERATE")
msg(212, False, GREY, "ACK")
msg(228, False, GREEN, "Response")
activation(164, 180)
activation(212, 228)
bracket(212 + SLANT, 228 + SLANT, "O")

H = 244
xml = (f'<mxfile host="drawio"><diagram name="fig_ladder" id="lad">'
       f'<mxGraphModel dx="0" dy="0" grid="0" gridSize="4" guides="0" tooltips="0" connect="0" arrows="0" '
       f'fold="0" page="1" pageScale="1" pageWidth="{W}" pageHeight="{H}" background="#ffffff" math="0" '
       f'shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>' + "".join(cells) +
       '</root></mxGraphModel></diagram></mxfile>')
out = "/home/philip/Projects/DNP3/paper/rewrite/figures/fig_ladder.drawio"
open(out, "w").write(xml)
print("wrote", out, len(cells), "cells")
