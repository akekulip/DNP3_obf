"""Render the design page from the JSON-compatible YAML specification.

Only this page is replaced in the user's multi-page draw.io document. The other
pages are retained byte-for-byte. Geometry and labels live in fig_design.spec.yaml;
the renderer uses only the Python standard library.
"""
import html
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIGURES = HERE.parent.parent / 'figures'
SPEC = HERE / 'fig_design.spec.yaml'
OUT = FIGURES / 'fig_design.drawio'


def escape(value):
    return html.escape(str(value), quote=True).replace('\n', '&#xa;')


def render(spec):
    page = spec['page']
    cells = ['<mxCell id="0"/>', '<mxCell id="1" parent="0"/>']
    for n in spec['nodes']:
        x, y, w, h = n['bounds']
        size = n.get('size', 8)
        if size < 8:
            raise ValueError(f"Text below 8 pt: {n['id']}")
        kind = n['kind']
        shape = {'text': 'text', 'box': 'rounded=0',
                 'trapezoid': 'shape=trapezoid;direction=east;perimeter=trapezoidPerimeter'}[kind]
        style = (f'{shape};html=0;whiteSpace=nowrap;align={n.get("align", "center")};'
                 f'verticalAlign=middle;fontFamily=Times New Roman;fontSize={size};'
                 f'fontColor={n.get("color", "#2F3E4E")};'
                 f'fontStyle={1 if n.get("bold") else 0};spacing=0;'
                 f'fillColor={n.get("fill", "none" if kind == "text" else "#FFFFFF")};'
                 f'strokeColor={n.get("stroke", "none" if kind == "text" else "#AEB8C1")};'
                 f'strokeWidth={n.get("line_width", .75)};')
        if n.get('dashed'):
            style += 'dashed=1;dashPattern=3 2;'
        cells.append(f'<mxCell id="{escape(n["id"])}" value="{escape(n.get("label", ""))}" '
                     f'style="{escape(style)}" vertex="1" parent="1">'
                     f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
    for e in spec['edges']:
        points = e['points']
        style = (f'endArrow={"block" if e.get("arrow", True) else "none"};endFill=1;endSize=4;'
                 f'strokeColor={e["color"]};strokeWidth=0.85;rounded=0;html=0;')
        if e.get('dashed'):
            style += 'dashed=1;dashPattern=4 3;'
        coords = lambda p: f'x="{p[0]}" y="{p[1]}"'
        geometry = (f'<mxPoint {coords(points[0])} as="sourcePoint"/>'
                    f'<mxPoint {coords(points[-1])} as="targetPoint"/>')
        if len(points) > 2:
            geometry += '<Array as="points">' + ''.join(f'<mxPoint {coords(p)}/>' for p in points[1:-1]) + '</Array>'
        cells.append(f'<mxCell id="{escape(e["id"])}" value="" style="{escape(style)}" edge="1" parent="1">'
                     f'<mxGeometry relative="1" as="geometry">{geometry}</mxGeometry></mxCell>')
    return (f'<diagram name="{escape(page["name"])}" id="{escape(page["id"])}">'
            f'<mxGraphModel grid="0" guides="1" page="1" pageScale="1" '
            f'pageWidth="{page["width"]}" pageHeight="{page["height"]}" math="0" shadow="0">'
            '<root>' + ''.join(cells) + '</root></mxGraphModel></diagram>')


def main():
    spec = json.loads(SPEC.read_text())  # JSON is a strict subset of YAML 1.2.
    page = spec['page']
    original = OUT.read_text()
    pattern = re.compile(rf'<diagram name="{re.escape(page["name"])}" id="{re.escape(page["id"])}">.*?</diagram>', re.S)
    if len(pattern.findall(original)) != 1:
        raise ValueError('Expected exactly one design page; refusing to replace another page')
    updated = pattern.sub(lambda _: render(spec), original)
    if updated != original:
        OUT.write_text(updated)
    print(f'Regenerated only {page["name"]}: {OUT}')


if __name__ == '__main__':
    main()
