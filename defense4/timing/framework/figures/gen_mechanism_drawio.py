"""Generate the framework mechanism diagram as an editable draw.io file. Geometry is computed here; labels are plain text
(html=0, no wrap) so the SVG export carries no foreignObject. Only mechanisms that exist in the working framework are drawn.
Blockers and held packets are different packet kinds on different arrows; every arrow into a queue comes from the decision step, and the
only way back to ingress is the loopback port."""
from pathlib import Path
from xml.sax.saxutils import quoteattr

cells, nid = [], [1]


def new_id():
    nid[0] += 1
    return "c%d" % nid[0]


def box(x, y, w, h, text, fill="#ffffff", stroke="#222222", dashed=False, bold=False, size=11, align="center", valign="middle"):
    i = new_id()
    style = ("rounded=0;whiteSpace=nowrap;html=0;fillColor=%s;strokeColor=%s;strokeWidth=1;fontSize=%d;fontFamily=Times New Roman;"
             "align=%s;verticalAlign=%s;%s%s" % (fill, stroke, size, align, valign, "dashed=1;" if dashed else "", "fontStyle=1;" if bold else ""))
    cells.append('<mxCell id="%s" value=%s style=%s vertex="1" parent="1"><mxGeometry x="%d" y="%d" width="%d" height="%d" as="geometry"/></mxCell>'
                 % (i, quoteattr(text), quoteattr(style), x, y, w, h))
    return i


def label(x, y, w, h, text, size=10, align="center", color="#222222"):
    i = new_id()
    style = "text;html=0;whiteSpace=nowrap;fontSize=%d;fontFamily=Times New Roman;align=%s;verticalAlign=middle;strokeColor=none;fillColor=none;fontColor=%s;" % (size, align, color)
    cells.append('<mxCell id="%s" value=%s style=%s vertex="1" parent="1"><mxGeometry x="%d" y="%d" width="%d" height="%d" as="geometry"/></mxCell>'
                 % (i, quoteattr(text), quoteattr(style), x, y, w, h))


def arrow(points, color="#1f4e9e", dashed=False, both=False, width=1.6):
    """Polyline through absolute points; the first is the source, the last the target."""
    i = new_id()
    style = ("edgeStyle=none;html=0;strokeColor=%s;strokeWidth=%s;endArrow=block;endFill=1;%s%s"
             % (color, width, "dashed=1;" if dashed else "", "startArrow=block;startFill=1;" if both else ""))
    pts = "".join('<mxPoint x="%d" y="%d"/>' % p for p in points[1:-1])
    cells.append('<mxCell id="%s" style=%s edge="1" parent="1"><mxGeometry relative="1" as="geometry"><mxPoint x="%d" y="%d" as="sourcePoint"/>'
                 '<mxPoint x="%d" y="%d" as="targetPoint"/>%s</mxGeometry></mxCell>'
                 % (i, quoteattr(style), points[0][0], points[0][1], points[-1][0], points[-1][1],
                    ("<Array as=\"points\">%s</Array>" % pts) if pts else ""))


BLUE, ORANGE, GREY = "#1f4e9e", "#c25b00", "#555555"
# endpoints and the switch frame
box(10, 215, 100, 70, "Master", fill="#eef3fb")
box(1150, 215, 110, 70, "Outstation\n(relay)", fill="#eef3fb")
box(135, 70, 990, 500, "", fill="#fafafa", dashed=True)
label(145, 74, 160, 18, "Programmable switch", 11, "left")
# ingress: state on top so the control arrow reaches it without crossing another step
box(165, 110, 250, 360, "", fill="#ffffff")
label(170, 114, 240, 18, "Ingress", 11, "center", "#000000")
box(180, 145, 220, 66, "Transaction state\n(owner, generation, deadlines)", size=10, fill="#f3f3f3")
box(180, 225, 220, 66, "Parse and classify role\n(request, pure ACK, Read response)", size=10)
box(180, 305, 220, 62, "Decide: hold, release,\nor forward unchanged", size=10)
box(180, 385, 220, 66, "Clone of the request\nbecomes the blocker tokens", size=10, dashed=True)
# traffic manager
box(495, 110, 270, 300, "", fill="#ffffff")
label(500, 114, 260, 18, "Traffic manager", 11, "center", "#000000")
box(515, 150, 230, 52, "ACK hold queue", size=10, fill="#eaf0fb", stroke=BLUE)
box(515, 218, 230, 52, "Response hold queue", size=10, fill="#eaf0fb", stroke=BLUE)
box(585, 286, 160, 52, "Blocker queue", size=10, fill="#fdf0e3", stroke=ORANGE, dashed=True)
label(515, 350, 230, 44, "queues drain through the\nloopback port only", 9, "center", GREY)
# loopback port, below both frames' interiors
box(495, 500, 270, 40, "Loopback port: egress back to ingress", size=10, fill="#f3f3f3")
# egress
box(805, 110, 300, 300, "", fill="#ffffff")
label(810, 114, 290, 18, "Egress", 11, "center", "#000000")
box(840, 165, 240, 80, "Forward unchanged\n(tail of every released packet)", size=10)
box(840, 280, 240, 100, "Optional size carve\nprefix and suffix replicas of one\n49-byte response (28 + 21 bytes)", size=10, dashed=True)
# control plane: straight down into the state block
box(165, 12, 250, 40, "Control plane: mode, D_A, gap, watchdog budget", size=10, fill="#eef3fb")
arrow([(290, 52), (290, 145)], color=GREY)
# traffic in and out
arrow([(110, 258), (165, 258)], color=GREY, both=True)         # master <-> ingress (parse step)
arrow([(1105, 250), (1150, 250)], color=GREY, both=True)       # egress <-> outstation
# gap lanes between ingress (right edge 415) and traffic manager (left edge 495): 428 release, 442 held, 456 blocker
arrow([(400, 330), (428, 330), (428, 96), (890, 96), (890, 165)], color=BLUE)     # release / unheld: decide -> forward
arrow([(822, 96), (822, 330), (840, 330)], color=BLUE)                            # ...and into the carve
arrow([(400, 352), (442, 352), (442, 176), (515, 176)], color=BLUE)               # decide -> ACK hold queue
arrow([(442, 244), (515, 244)], color=BLUE)                                        # decide -> response hold queue
arrow([(400, 430), (456, 430), (456, 312), (585, 312)], color=ORANGE, dashed=True) # clone -> blocker queue
label(540, 74, 280, 14, "released packets, and packets that are never held", 9, "center", GREY)
# queues drain to the loopback port, one line per packet kind
arrow([(540, 270), (540, 500)], color=BLUE)
arrow([(650, 338), (650, 500)], color=ORANGE, dashed=True)
# the only way back to ingress: loopback port -> bottom edge of ingress, one line per kind
arrow([(495, 512), (330, 512), (330, 470)], color=BLUE)
arrow([(495, 530), (250, 530), (250, 470)], color=ORANGE, dashed=True)
# legend and scope
arrow([(805, 450), (840, 450)], color=BLUE)
label(845, 442, 200, 16, "held packet or released packet", 9, "left", GREY)
arrow([(805, 470), (840, 470)], color=ORANGE, dashed=True)
label(845, 462, 200, 16, "blocker token", 9, "left", GREY)
label(805, 490, 310, 28, "Read lane only: control (SELECT, OPERATE) is not implemented", 9, "left", GREY)

xml = ('<mxfile host="framework"><diagram name="mechanism" id="m1"><mxGraphModel dx="1280" dy="640" grid="0" guides="1" tooltips="1" connect="1" arrows="1" '
       'fold="1" page="1" pageScale="1" pageWidth="1280" pageHeight="590" math="0" shadow="0"><root><mxCell id="0"/><mxCell id="1" parent="0"/>%s</root></mxGraphModel></diagram></mxfile>'
       % "".join(cells))
Path(__file__).with_name("fig_framework_mechanism.drawio").write_text(xml)
print("cells:", len(cells))
