#!/usr/bin/env bash
# build_nomad.sh - NOMAD schematics: gen_nomad_schematics.py -> draw.io Desktop SVG -> finalize -> PDF/PNG.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FIGS="$(cd "$HERE/../../figures" && pwd)/nomad"
PY="${RESEARCH_PYTHON:-python3}"
DRAWIO="${DRAWIO_CMD:-$HOME/.local/bin/drawio-headless}"
INKSCAPE="${INKSCAPE:-$HOME/.local/bin/inkscape}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
"$PY" "$HERE/gen_nomad_schematics.py"
for f in fig_nomad_timeline fig_nomad_components fig_psa_pipeline; do
    "$DRAWIO" -x -f svg --border 2 -o "$TMP/$f.svg" "$FIGS/$f.drawio" >/dev/null 2>&1
    if grep -q '<foreignObject' "$TMP/$f.svg"; then echo "error: $f has foreignObject text" >&2; exit 2; fi
done
"$PY" "$HERE/finalize_svg.py" "$TMP/fig_nomad_timeline.svg" "$FIGS/fig_nomad_timeline.svg" ntl "NOMAD release timeline" \
  "One READ and one OPERATE under Timing+Size at D = 10 ms, J = 10 ms, on master, switch and outstation lanes, placed at campaign medians. The switch holds the acknowledgment until the deadline da after the request and releases the response D after the acknowledgment; an OPERATE is first held for J before delivery."
"$PY" "$HERE/finalize_svg.py" "$TMP/fig_nomad_components.svg" "$FIGS/fig_nomad_components.svg" ncp "NOMAD components" \
  "The control plane installs obfuscation objectives and constraints on one Tofino-1. In the data plane N parses and binds DNP3 transactions, T holds acknowledgments, responses and OPERATE commands in queues while blocker tokens recirculate, and E re-encodes responses and maps TCP sequence numbers. The three strategies are timing replacement, OPERATE hold and response splitting."
"$PY" "$HERE/finalize_svg.py" "$TMP/fig_psa_pipeline.svg" "$FIGS/fig_psa_pipeline.svg" psa "Programmable data plane" \
  "An ingress pipeline of parser, match/action units and deparser, the traffic manager's queues and buffers, and an egress pipeline of parser, match/action units and deparser."
for f in fig_nomad_timeline fig_nomad_components fig_psa_pipeline; do
    "$INKSCAPE" "$FIGS/$f.svg" --export-type=pdf --export-filename="$FIGS/$f.pdf" >/dev/null 2>&1
    "$INKSCAPE" "$FIGS/$f.svg" --export-type=png --export-dpi=600 --export-filename="$FIGS/$f.png" >/dev/null 2>&1
done
( cd "$FIGS" && sha256sum *.drawio *.svg *.png > SCHEMATICS.sha256 )
echo "built: $(ls "$FIGS")"
