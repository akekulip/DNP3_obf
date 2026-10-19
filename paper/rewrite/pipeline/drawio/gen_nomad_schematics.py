"""NOMAD schematics as editable draw.io documents: the release timeline and the components.

fig_nomad_timeline: one READ and one OPERATE transaction under Timing+Size at D = 10 ms,
J = 10 ms, on three lanes (master, switch, outstation). Every instant is read from
eval_m11_09_20261018_02_paper/tables/table_timeline.csv (campaign medians); no time is placed by
eye. fig_nomad_components: NOMAD's three components (objectives and constraints in the control
plane; the obfuscation infrastructure N/T/E in the data plane; the three strategies), with the
facts of ctl_timing_01/evidence/m11_09/DESIGN_FACTS.md as labels.

    python3 gen_nomad_schematics.py      # writes both .drawio files into figures/nomad/
"""
import csv
import html
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
PAPER_DIR = (REPO / 'defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/'
             'seg61_02/evidence/evaluation_campaigns/eval_m11_09_20261018_02_paper')
OUT = REPO / 'paper/rewrite/figures/nomad'
BLUE, GREY, GREEN, VERM, PURPLE = '#0072B2', '#555555', '#009E73', '#D55E00', '#CC79A7'
INK, SOFT, RULE, BOX = '#222222', '#6B6B6B', '#999999', '#AEB8C1'


class Page:
    def __init__(self, name, width, height):
        self.name, self.width, self.height, self.cells, self.n = name, width, height, [], 1

    def _id(self):
        self.n += 1
        return 'c%d' % self.n

    def vertex(self, x, y, w, h, style, value=''):
        value = html.escape(value, quote=True).replace('\n', '&#xa;')
        self.cells.append('<mxCell id="%s" value="%s" style="%s" vertex="1" parent="1"><mxGeometry x="%.2f" '
                          'y="%.2f" width="%.2f" height="%.2f" as="geometry"/></mxCell>'
                          % (self._id(), value, style, x, y, w, h))

    def text(self, x, y, w, h, value, size=8, align='center', colour=INK, italic=False, bold=False):
        if size < 8:
            raise ValueError('text below 8 pt: ' + value)
        style = ('text;html=0;whiteSpace=nowrap;strokeColor=none;fillColor=none;align=%s;verticalAlign=middle;'
                 'fontFamily=Times New Roman;fontSize=%.1f;fontColor=%s;spacing=0;fontStyle=%d;'
                 % (align, size, colour, (2 if italic else 0) | (1 if bold else 0)))
        self.vertex(x, y, w, h, style, value)

    def box(self, x, y, w, h, value='', fill='#FFFFFF', stroke=BOX, size=8, dashed=False, align='center', bold=False):
        style = ('rounded=0;html=0;whiteSpace=nowrap;align=%s;verticalAlign=middle;fontFamily=Times New Roman;'
                 'fontSize=%.1f;fontColor=%s;fillColor=%s;strokeColor=%s;strokeWidth=0.75;spacing=3;fontStyle=%d;%s'
                 % (align, size, INK, fill, stroke, 1 if bold else 0, 'dashed=1;dashPattern=3 2;' if dashed else ''))
        self.vertex(x, y, w, h, style, value)

    def line(self, p0, p1, colour, arrow=True, width=0.9, dash=None, points=(), both=False):
        style = ('endArrow=%s;endFill=1;endSize=3.5;startArrow=%s;startFill=1;startSize=3.5;strokeColor=%s;'
                 'strokeWidth=%.2f;html=0;%s' % ('block' if arrow else 'none', 'block' if both else 'none', colour, width,
                                                'dashed=1;dashPattern=%s;' % dash if dash else ''))
        mid = ('<Array as="points">%s</Array>' % ''.join('<mxPoint x="%.2f" y="%.2f"/>' % p for p in points)
               if points else '')
        self.cells.append('<mxCell id="%s" style="%s" edge="1" parent="1"><mxGeometry relative="1" as="geometry">'
                          '<mxPoint x="%.2f" y="%.2f" as="sourcePoint"/><mxPoint x="%.2f" y="%.2f" as="targetPoint"/>'
                          '%s</mxGeometry></mxCell>' % (self._id(), style, p0[0], p0[1], p1[0], p1[1], mid))

    def write(self, path):
        xml = ('<mxfile host="drawio"><diagram name="%s" id="%s"><mxGraphModel dx="0" dy="0" grid="0" gridSize="4" '
               'guides="0" tooltips="0" connect="0" arrows="0" fold="0" page="1" pageScale="1" pageWidth="%d" '
               'pageHeight="%d" background="#ffffff" math="0" shadow="0"><root><mxCell id="0"/>'
               '<mxCell id="1" parent="0"/>%s</root></mxGraphModel></diagram></mxfile>'
               % (self.name, self.name, self.width, self.height, ''.join(self.cells)))
        path.write_text(xml)
        print('wrote', path, len(self.cells), 'cells')


def timeline():
    rows = list(csv.DictReader((PAPER_DIR / 'tables/table_timeline.csv').read_text().splitlines()))
    v = {(r['operation'], r['quantity']): float(r['value_ms']) for r in rows}
    p = Page('fig_nomad_timeline', 252, 222)
    x0, x1, tmax = 52.0, 246.0, 44.0
    tx = lambda ms: x0 + ms * (x1 - x0) / tmax
    for top, op, title in ((4.0, 'READ', '(a) READ: ACK and response held'),
                           (112.0, 'OPERATE', '(b) OPERATE: held for J, then ACK and response held')):
        m, s, o = top + 22.0, top + 46.0, top + 70.0
        p.text(2.0, top, 240.0, 10.0, title, 8, align='left', colour=SOFT, italic=True)
        for name, y in (('Master', m), ('Switch', s), ('Outstation', o)):
            p.line((x0, y), (x1, y), RULE, arrow=False, width=0.5)
            p.text(0.0, y - 5.0, x0 - 5.0, 10.0, name, 8, align='right')
        j = v[op, 'J_hold']
        da, d = v['envelope', 'da'], v['envelope', 'D']
        ack, resp = v[op, 'released_ack'], v[op, 'released_response']
        n_ack, n_resp = j + v[op, 'native_ack_after_delivery'], j + v[op, 'native_response_after_delivery']
        p.line((tx(0), m), (tx(0), s), BLUE)
        if j:
            p.vertex(tx(0), s - 2.0, tx(j) - tx(0), 4.0, 'fillColor=%s;strokeColor=none;' % PURPLE)
            p.text(tx(0), s - 14.0, tx(j) - tx(0), 9.0, 'hold J', 8, colour=PURPLE)
        p.line((tx(j), s), (tx(j), o), BLUE)
        p.line((tx(n_ack), o), (tx(n_ack) + 2.5, s), GREY, dash='3 2')
        p.line((tx(n_resp), o), (tx(n_resp) + 2.5, s), GREEN, dash='3 2')
        p.line((tx(ack), s), (tx(ack), m), GREY)
        p.line((tx(resp), s), (tx(resp), m), GREEN)
        for t in (da,):
            p.line((tx(t), m - 4.0), (tx(t), o + 4.0), VERM, arrow=False, width=0.6, dash='1 1.6')
        y = o + 12.0
        p.line((tx(0), y), (tx(da), y), VERM, arrow=False, width=0.7)
        p.text(tx(0), y + 1.0, tx(da) - tx(0), 9.0, 'da: ACK not before t0 + da', 8, colour=VERM)
        y = m + 8.0
        p.line((tx(ack) + 1.0, y), (tx(resp) - 1.0, y), VERM, arrow=False, width=0.7)
        p.text(tx(ack) + 4.0, y + 1.0, tx(resp) - tx(ack) - 4.0, 9.0, 'D = CLRT seen', 8, colour=VERM)
        p.text(tx(0) + 2.0, m - 11.0, 30.0, 9.0, 'request t0', 8, align='left', colour=BLUE)
        p.text(tx(n_resp) + 3.0, o + 1.0, 60.0, 9.0, 'native response', 8, align='left', colour=GREEN)
    p.write(OUT / 'fig_nomad_timeline.drawio')


def components():
    p = Page('fig_nomad_components', 516, 214)
    p.box(4, 92, 66, 40, 'SCADA\nmaster')
    p.box(446, 92, 66, 40, 'Outstation\n(IED)')
    p.box(84, 4, 348, 46, 'Obfuscation objectives and constraints (control plane)\n'
          'targets: CLRT D, OPERATE hold J, 61-byte responses;  envelope da, pb, readiness, cap from L, G\n'
          'constraints: packet availability, DNP3/TCP timers, IEEE 1815 conformance', fill='#F4F6F8', size=8)
    p.box(84, 62, 348, 148, '', fill='#FFFFFF', stroke=RULE, dashed=True)
    p.text(90, 64, 200, 10, 'Obfuscation infrastructure (one Tofino-1)', 8, align='left', colour=SOFT, italic=True)
    p.box(94, 78, 150, 52, 'N (pipe 0 ingress)\nparse DNP3: function code,\nobject, qualifier, index ranges;\n'
          'bind transaction', size=8, align='left')
    p.box(272, 78, 150, 52, 'T (pipe 1 ingress)\nhold ACK, response, OPERATE\nin queues; blocker tokens\n'
          'recirculate until release', size=8, align='left')
    p.box(272, 142, 150, 52, 'E (pipe 0 egress)\nre-encode responses by index\nranges / transport frames;\n'
          'map TCP sequence numbers', size=8, align='left')
    p.box(94, 142, 150, 52, 'Obfuscation strategies\nS1 timing replacement (T)\nS2 OPERATE hold (T)\n'
          'S3 response splitting (E)', size=8, align='left', fill='#FBF3F8', stroke=PURPLE)
    p.line((70, 112), (84, 112), INK, both=True)
    p.line((432, 112), (446, 112), INK, both=True)
    p.line((244, 104), (272, 104), BLUE)
    p.line((347, 130), (347, 142), BLUE)
    p.text(250, 92, 22, 10, 'timed', 8, colour=SOFT)
    p.line((258, 50), (258, 62), VERM)
    p.text(262, 51, 80, 10, 'installs policy', 8, align='left', colour=VERM)
    p.write(OUT / 'fig_nomad_components.drawio')


if __name__ == '__main__':
    OUT.mkdir(parents=True, exist_ok=True)
    timeline()
    components()
