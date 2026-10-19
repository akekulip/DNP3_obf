"""Figure 1 as a draw.io document: the two DNP3 transactions, CLRT and PRT.
1 unit = 1 pt at the final 3.5 in width. Geometry is computed, not placed by eye."""
import html
W, H = 252, 176
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

# ---- the two transactions side by side, not stacked.
# Stacked, this figure stood 3.43 in tall in a 3.5 in column, a third of the page it sat on, and
# its two panels repeated one pair of lifelines nine rows deep. Side by side the height is the
# longer transaction alone. The device icons are gone with the stacking: Figure 2 establishes
# both devices, and repeating them twice here would spend the width the panels need.
# Geometry is chosen so nothing overruns the 252 unit page: the bracket gutter on the left of
# each panel is 34 units, which is what its label needs, and the head labels are narrow enough
# that panel (a) right and panel (b) left do not meet.
PANELS = ((32.0, 98.0, "(a) READ poll"), (140.0, 232.0, "(b) Select-before-operate"))
TOP, BOT = 26.0, 164.0

def msg(xm, xo, y, l2r, colour, name, w=66):
    x1, x2 = (xm + 1.5, xo - 1.5) if l2r else (xo - 1.5, xm + 1.5)
    arrow((x1, y), (x2, y + SLANT), colour)
    # Centred between the master lifeline and the outstation's activation bar, so a label never
    # touches the bar; a two-line label is raised by one line.
    lines = name.count("\n") + 1
    cx = (xm + xo - 6) / 2
    text(cx - w / 2, y + SLANT / 2 - 3 - 9 * lines, w, 9 * lines, name.replace("\n", "<br>"), 8, align="center")

def activation(xo, y0, y1):
    vertex(xo - 3, y0, 6, y1 - y0, f"fillColor=#BFE6D9;strokeColor={GREEN};strokeWidth=0.6;")

def bracket(xm, y0, y1, sym, w=22, ital=False):
    """An interval on the master's lifeline: a double-headed arrow whose two heads sit exactly at the
    instants of the two packets that define it, with dotted leaders to those packets."""
    x = xm - 10
    line((x, y0), (x, y1), f"startArrow=block;startFill=1;startSize=3;endArrow=block;endFill=1;endSize=3;"
                           f"strokeColor={VERM};strokeWidth=0.9;")
    for yy in (y0, y1):
        rule((x, yy), (xm - 1, yy), VERM, 0.45, "1.2 1.2")
    text(x - 2 - w, (y0 + y1) / 2 - 5, w, 10, sym, 9, align="right", colour=VERM, italic=ital)

for xm, xo, title in PANELS:
    text((xm + xo) / 2 - 50, 2, 100, 9, title, 8, align="center", colour=SOFT, italic=True)
    text(xm - 23, 13, 46, 9, "Master", 8, align="center")
    text(xo - 23, 13, 46, 9, "Outstation", 8, align="center")
    for x in (xm, xo):
        rule((x, TOP), (x, BOT), "#9AA4AE", 0.6, "2 2")

# Packet names and function codes as IEEE 1815 names them (READ 0x01, SELECT 0x03, OPERATE 0x04,
# solicited RESPONSE 0x81, UNSOLICITED_RESPONSE 0x82; verified 2026-10-19 against the standard and
# protocol/hw_vepa/clrt_check.py). CLRT and PRT follow Formby et al. (NDSS 2016, Sec. IV-A and IV-B):
# CLRT runs from the outstation's TCP ACK to its DNP3 response; PRT ("operation time" there) runs from
# the OPERATE command seen at the master-side tap to the unsolicited response reporting the change.
XA, OA, _ = PANELS[0]
msg(XA, OA, 38, True, BLUE, "READ (0x01)")
msg(XA, OA, 58, False, GREY, "TCP ACK")
msg(XA, OA, 78, False, GREEN, "RESPONSE (0x81)")
activation(OA, 58, 78)
bracket(XA, 58 + SLANT, 78 + SLANT, "CLRT")

XB, OB, _ = PANELS[1]
ROWS = ((True, BLUE, "SELECT (0x03)"), (False, GREY, "TCP ACK"), (False, GREEN, "RESPONSE (0x81)"),
        (True, BLUE, "OPERATE (0x04)"), (False, GREY, "TCP ACK"), (False, GREEN, "RESPONSE (0x81)"),
        (False, GREEN, "UNSOLICITED\nRESPONSE (0x82)"))
ROW_Y = (38, 55, 72, 89, 106, 123, 146)
for (l2r, colour, name), y in zip(ROWS, ROW_Y):
    msg(XB, OB, y, l2r, colour, name)
# Rows in panel (b): SELECT 38, ACK 54, RESPONSE 70, OPERATE 86, ACK 102, RESPONSE 118,
# UNSOLICITED RESPONSE 140 (two-line label). PRT starts where the OPERATE leaves the master (its tap instant) and
# ends where the unsolicited response, sent after the output has changed state, reaches the master.
activation(OB, 55, 72)
activation(OB, 106, 123)
bracket(XB, 89, 146 + SLANT, "PRT")

xml = (f'<mxfile host="drawio"><diagram name="fig_ladder" id="lad">'
       f'<mxGraphModel dx="0" dy="0" grid="0" gridSize="4" guides="0" tooltips="0" connect="0" arrows="0" '
       f'fold="0" page="1" pageScale="1" pageWidth="{W}" pageHeight="{H}" background="#ffffff" math="0" '
       f'shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>' + "".join(cells) +
       '</root></mxGraphModel></diagram></mxfile>')
out = "/home/philip/Projects/DNP3/paper/rewrite/figures/fig_ladder.drawio"
open(out, "w").write(xml)
print("wrote", out, len(cells), "cells")
