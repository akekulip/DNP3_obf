"""Render the canonical YAML offline, then export at 7.16 inches and 300 DPI.

Requires the installed Draw.io skill (Node >=20), draw.io Desktop and Inkscape.
The YAML contains the mechanism and geometry; this script only invokes renderers
and sets physical SVG dimensions. No manuscript or frozen paper files are touched.
"""
import argparse
import hashlib
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
BASENAME = "fig_framework_mechanism"


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True)


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
    run(node, args.cli, spec, work / "mechanism.preview.png", "--validate", "--visual-preview")
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
    run(node, args.cli, spec, work / "desktop-final.png", "--validate", "--use-desktop")
    run(node, args.cli, spec, work / "desktop-final.pdf", "--validate", "--use-desktop")
    run("inkscape", svg, "--export-type=pdf", "--export-filename=" + str(HERE / (BASENAME + ".pdf")))
    run("inkscape", svg, "--export-type=png", "--export-dpi=300", "--export-filename=" + str(HERE / (BASENAME + ".png")))
    files = [HERE / (BASENAME + suffix) for suffix in (".spec.yaml", ".drawio", ".svg", ".pdf", ".png")]
    (HERE / "FIGURES.sha256").write_text("".join(
        hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name + "\n" for path in files))


if __name__ == "__main__":
    main()
