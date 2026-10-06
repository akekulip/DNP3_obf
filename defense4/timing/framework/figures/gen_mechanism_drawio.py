"""Render the canonical YAML offline, then export at 7.16 inches and 300 DPI.

Requires the installed Draw.io skill (Node >=20), draw.io Desktop and Inkscape.
The YAML contains the mechanism and geometry; this script only invokes renderers
and sets physical SVG dimensions. No manuscript or frozen paper files are touched.
"""
import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASENAME = "fig_framework_mechanism"


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True, timeout=60)


def desktop_attempt(*args):
    """Retain a failed export attempt without attributing an old file to it."""
    output=Path(args[3])
    output.unlink(missing_ok=True)
    try:
        run(*args)
        return {'status':'passed','output':str(output)}
    except (subprocess.CalledProcessError,subprocess.TimeoutExpired) as exc:
        output.unlink(missing_ok=True)
        return {'status':'unavailable','output':str(output),'reason':str(exc)}


def provenance(node,cli,spec,svg,drawio,work,files,export_status):
    command=[str(value) for value in (node,cli,spec,work/'strict-check.drawio',
                                    '--validate','--strict-warnings')]
    strict=subprocess.run(command,capture_output=True,text=True,timeout=60)
    log=strict.stdout+strict.stderr
    (work/'strict-validation.log').write_text(log)
    (work/'strict-validation.json').write_text(json.dumps(dict(command=command,exit_code=strict.returncode),indent=2)+'\n')
    root=ET.parse(svg).getroot()
    viewbox=[float(v) for v in root.attrib['viewBox'].split()]
    fonts=[float(v) for v in re.findall(r'font-size="([\d.]+)"',svg.read_text())]
    png=(HERE/(BASENAME+'.png')).read_bytes()
    width,height=struct.unpack('!II',png[16:24])
    cells=list(ET.parse(drawio).getroot().iter('mxCell'))
    evidence=HERE.parent/'results/case4_bmv2_transport_repair_20261006/verification.json'
    software=json.loads(evidence.read_text())
    current=HERE.parents[1]/'response_ready/src/defense4_response_ready.p4'
    value=dict(source=spec.name,generator=Path(__file__).name,profile='academic-paper',
        figure_type='architecture',width_in=7.16,svg_viewbox=viewbox,png_pixels=[width,height],
        minimum_svg_font_px=min(fonts),minimum_final_font_pt=min(fonts)*515.52/viewbox[2],
        palette=dict(name='preserved-source-blue-orange-gray',colors=['#1f4e9e','#c25b00','#555555'],
            colorblind_safe=None,grayscale_safe=None,meaning_redundant_in_labels_and_line_styles=True),
        exports=export_status,
        validation=dict(xml='passed',strict_exit_code=strict.returncode,
            warning_count=log.count('[warning]'),label_fit_warnings=log.count('label needs'),
            strict_routing='passed' if strict.returncode==0 else 'not passed; retained routing/label policy warnings',
            node_count=sum(cell.get('vertex')=='1' for cell in cells),
            edge_count=sum(cell.get('edge')=='1' for cell in cells),
            warning_log=str((work/'strict-validation.log').relative_to(ROOT)),
            visual='Requires separate exported PNG and manuscript-scale review'),
        evidence_class='Proposed full target graph and separately executed software size graph; no complete target compilation or hardware claim',
        source_bindings=dict(proposal_source_sha256=hashlib.sha256(current.read_bytes()).hexdigest(),
            proposal_status='Source identity only; historical compiler passes do not qualify this edited source',
            software_source_sha256=software['source_sha256'],software_evidence=str(evidence.relative_to(HERE.parent))),
        pdfinfo=subprocess.check_output(['pdfinfo',str(HERE/(BASENAME+'.pdf'))],text=True),
        pdffonts=subprocess.check_output(['pdffonts',str(HERE/(BASENAME+'.pdf'))],text=True),
        files={path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in files})
    (HERE/'figure_provenance.json').write_text(json.dumps(value,indent=2)+'\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=Path)
    parser.add_argument("--cli", type=Path,
                        default=Path.home() / ".agents/skills/drawio/scripts/cli.js")
    args = parser.parse_args()
    candidates = [args.node] if args.node else sorted(
        (Path.home() / ".nvm/versions/node").glob("v*/bin/node"), reverse=True)
    candidates += [Path(shutil.which("node") or "/missing-node")]
    node = next((candidate for candidate in candidates if candidate and candidate.exists()
                 and int(subprocess.check_output([str(candidate), "-p", "process.versions.node.split('.')[0]"], text=True)) >= 20), None)
    if node is None or not args.cli.exists():
        raise SystemExit("Installed Draw.io skill and Node >=20 are required")
    work = ROOT / ".drawio-tmp/case4-mechanism"
    work.mkdir(parents=True, exist_ok=True)
    spec = HERE / (BASENAME + ".spec.yaml")
    drawio = HERE / (BASENAME + ".drawio")
    svg = HERE / (BASENAME + ".svg")
    run(node, args.cli, spec, drawio, "--validate", "--write-sidecars", "--sidecar-dir", work)
    preview=desktop_attempt(node, args.cli, spec, work / "mechanism.preview.png", "--validate", "--visual-preview")
    run(node, args.cli, spec, svg, "--validate")
    ET.register_namespace("", "http://www.w3.org/2000/svg")
    tree = ET.parse(svg)
    root = tree.getroot()
    viewbox = [float(part) for part in root.attrib["viewBox"].split()]
    root.set("width", "7.16in")
    root.set("height", "%.8fin" % (7.16 * viewbox[3] / viewbox[2]))
    tree.write(svg, encoding="utf-8", xml_declaration=True)
    # Desktop outputs are retained as independent export evidence. Inkscape's
    # final exports follow the physical SVG page size exactly.
    desktop=[desktop_attempt(node, args.cli, spec, work / ("desktop-final."+suffix),
                             "--validate", "--use-desktop") for suffix in ('png','pdf')]
    export_status={'preview':preview,'desktop':desktop}
    (work/'export-status.json').write_text(json.dumps(export_status,indent=2)+'\n')
    run("inkscape", svg, "--export-type=pdf", "--export-filename=" + str(HERE / (BASENAME + ".pdf")))
    run("inkscape", svg, "--export-type=png", "--export-dpi=300", "--export-filename=" + str(HERE / (BASENAME + ".png")))
    files = [HERE / (BASENAME + suffix) for suffix in (".spec.yaml", ".drawio", ".svg", ".pdf", ".png")]
    (HERE / "FIGURES.sha256").write_text("".join(
        hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n" for path in files))
    provenance(node,args.cli,spec,svg,drawio,work,files,export_status)


if __name__ == "__main__":
    main()
