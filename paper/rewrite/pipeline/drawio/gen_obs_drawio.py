"""Figure 2 as a draw.io document: Cisco stencils for the network devices, a native-shape
faceplate for the protective relay. 1 unit = 1 pt at the final 3.5 in width."""
import html, sys
sys.path.insert(0, __file__.rsplit("/", 1)[0])
from adversary_stencil import stencil_style
W, H = 252, 90
SLATE, VERM, GREY = "#2F3E4E", "#D55E00", "#8A8A8A"
ZONE_FILL, ZONE_EDGE = "#FDF5F0", "#EAAE7F"          # vermillion at 6% / 50% over white
FONT = "fontFamily=Times New Roman;fontColor=#1F2A36;"
cells, n = [], [1]

def nid():
    n[0] += 1
    return f"c{n[0]}"

def vertex(x, y, w, h, style, value=""):
    i = nid()
    val = html.escape(value).replace("&lt;br&gt;", "&#xa;")
    cells.append(f'<mxCell id="{i}" value="{val}" style="{style}" vertex="1" parent="1">'
                 f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
    return i

def text(x, y, w, h, value, size=8, align="center", colour="#1F2A36", italic=False):
    st = (f"text;html=0;strokeColor=none;fillColor=none;align={align};verticalAlign=middle;"
          f"fontFamily=Times New Roman;fontSize={size};fontColor={colour};"
          f"{'fontStyle=2;' if italic else ''}spacing=0;")
    return vertex(x, y, w, h, st, value)

def edge(style, src=None, tgt=None, sp=None, tp=None, pts=()):
    i = nid()
    a = f' source="{src}"' if src else ""
    b = f' target="{tgt}"' if tgt else ""
    g = '<mxGeometry relative="1" as="geometry">'
    if sp: g += f'<mxPoint x="{sp[0]}" y="{sp[1]}" as="sourcePoint"/>'
    if tp: g += f'<mxPoint x="{tp[0]}" y="{tp[1]}" as="targetPoint"/>'
    if pts:
        g += '<Array as="points">' + "".join(f'<mxPoint x="{x}" y="{y}"/>' for x, y in pts) + '</Array>'
    g += '</mxGeometry>'
    cells.append(f'<mxCell id="{i}" style="{style}" edge="1" parent="1"{a}{b}>{g}</mxCell>')

CISCO = ("html=1;pointerEvents=1;dashed=0;strokeColor=#ffffff;strokeWidth=1.2;"
         "outlineConnect=0;shape=mxgraph.cisco.{name};fillColor={fill};")

# ---- the adversary's view, shaded: first, so everything else paints over it
vertex(2, 2, 100, 84, f"rounded=1;arcSize=3;fillColor={ZONE_FILL};strokeColor={ZONE_EDGE};"
                      "dashed=1;dashPattern=3 2;strokeWidth=0.6;")

# ---- devices
master = vertex(8, 40, 34, 26, CISCO.format(name="computers_and_peripherals.workstation", fill=SLATE))
switch = vertex(120, 41, 52, 24, CISCO.format(name="switches.workgroup_switch", fill=SLATE))
# A hooded figure, not draw.io's person-at-a-desk: the desk figure reads as an ordinary user.
adv    = vertex(62, 6, 18, 21, stencil_style(VERM))

# SEL-751A protective relay faceplate, native shapes so it stays vector
rx, ry = 214, 36
vertex(rx, ry, 26, 34, f"rounded=1;arcSize=6;fillColor=#EEF2F6;strokeColor={SLATE};strokeWidth=0.9;")
vertex(rx + 3, ry + 3.5, 20, 8, f"rounded=1;arcSize=10;fillColor=#CFE3D6;strokeColor={SLATE};strokeWidth=0.4;")
for k, yy in enumerate((16, 20, 24, 28)):
    vertex(rx + 3.9, ry + yy - 1.3, 2.6, 2.6,
           f"ellipse;fillColor={'#009E73' if k == 0 else '#C4CCD4'};strokeColor=none;")
    vertex(rx + 8, ry + yy - 0.25, 6 - (k % 2), 0.5, "fillColor=#9AA4AE;strokeColor=none;")
for dx, dy in ((17, 19), (21, 19), (17, 24), (21, 24)):
    vertex(rx + dx, ry + dy, 3, 3, f"rounded=1;arcSize=15;fillColor=#C4CCD4;strokeColor={SLATE};strokeWidth=0.3;")
vertex(rx + 5, ry + 6.1, 13, 0.55, f"fillColor={SLATE};strokeColor=none;")
vertex(rx + 5, ry + 8.6, 8, 0.55, f"fillColor={SLATE};strokeColor=none;")

# ---- links. Only the observed one carries colour; solid against dashed says the rest.
edge(f"endArrow=block;startArrow=block;endFill=1;startFill=1;endSize=4;startSize=4;"
     f"strokeColor={VERM};strokeWidth=1.4;", sp=(43, 53), tp=(119, 53))
edge(f"endArrow=block;startArrow=block;endFill=1;startFill=1;endSize=4;startSize=4;"
     f"strokeColor={GREY};strokeWidth=1.0;dashed=1;dashPattern=3 2;", sp=(173, 53), tp=(213, 53))
edge(f"endArrow=oval;endFill=1;endSize=4;startArrow=none;strokeColor={VERM};strokeWidth=0.8;"
     "dashed=1;dashPattern=2 1.5;", sp=(70, 33), tp=(70, 53))
# the two switch-internal lanes, dashed like everything else nobody observes
for x0, x1 in ((130, 142), (150, 162)):
    edge(f"endArrow=none;startArrow=none;strokeColor={GREY};strokeWidth=0.8;dashed=1;"
         "dashPattern=2.4 1.8;rounded=1;", sp=(x0, 65), tp=(x1, 65), pts=((x0, 72), (x1, 72)))

# ---- labels: the four actors, nothing else
text(2, 10, 54, 18, "passive<br>adversary", 7.5, align="right", colour=VERM)
text(5, 75, 40, 10, "Master")
text(111, 75, 70, 10, "Programmable switch")
text(209, 75, 36, 10, "SEL-751A")

xml = (f'<mxfile host="drawio"><diagram name="fig_observation" id="obs">'
       f'<mxGraphModel dx="0" dy="0" grid="0" gridSize="4" guides="0" tooltips="0" connect="0" '
       f'arrows="0" fold="0" page="1" pageScale="1" pageWidth="{W}" pageHeight="{H}" '
       f'background="#ffffff" math="0" shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>'
       + "".join(cells) + '</root></mxGraphModel></diagram></mxfile>')
out = "/home/philip/Projects/DNP3/paper/rewrite/figures/fig_observation.drawio"
open(out, "w").write(xml)
print("wrote", out, len(cells), "cells")
