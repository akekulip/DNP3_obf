#!/usr/bin/env bash
# build.sh - regenerate Figures 1 and 2 from their draw.io sources.
#
#   gen_*_drawio.py  ->  figures/<fig>.drawio   (editable in draw.io; geometry computed)
#   draw.io Desktop  ->  SVG, labels as plain SVG text (html=0, no wrap: no foreignObject)
#   finalize_svg.py  ->  figures/<fig>.svg      (exact width, title/desc, no dark-mode CSS)
#
# pipeline/export_schematics.sh then turns the SVG into the PDF and PNG and hashes them,
# exactly as for the other schematic. Requires draw.io Desktop; DRAWIO_CMD overrides the path.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FIGS="$(cd "$HERE/../../figures" && pwd)"
PY="${RESEARCH_PYTHON:-python3}"
DRAWIO="${DRAWIO_CMD:-$HOME/.local/bin/drawio-headless}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

"$PY" "$HERE/gen_ladder_drawio.py"
"$PY" "$HERE/gen_obs_drawio.py"
"$PY" "$HERE/gen_design_drawio.py"
for f in fig_ladder fig_observation fig_design; do
    "$DRAWIO" -x -f svg --border 2 -o "$TMP/$f.svg" "$FIGS/$f.drawio" >/dev/null 2>&1
    if grep -q '<foreignObject' "$TMP/$f.svg"; then
        echo "error: $f.svg carries foreignObject text, which the PDF step cannot render" >&2; exit 2
    fi
done
"$PY" "$HERE/finalize_svg.py" "$TMP/fig_ladder.svg" "$FIGS/fig_ladder.svg" lad "DNP3 transaction ladder" \
  "Two DNP3 transactions between a SCADA master and an SEL-751A outstation, time running downwards. Requests are blue, transport acknowledgments grey and application responses green, with DNP3 function codes in grey beside the outstation. A bar on the outstation's lifeline marks the interval in which the device produces the answer. On the master side, c is the READ's cross-layer response time and O the master-visible OPERATE response-to-acknowledgment interval, both measured between the acknowledgment and the response arriving at the master."
"$PY" "$HERE/finalize_svg.py" "$TMP/fig_design.svg" "$FIGS/fig_design.svg" des "Design overview" \
  "The drawing reads left to right. The outstation and the master sit outside one programmable switch. Inside it, ingress classifies each arrival and arms its release deadlines; the read lane holds the acknowledgment and the response of a READ or SELECT, and the control lane holds an OPERATE. Each held packet waits behind a queue of blocker packets the switch generates, which a strict-priority scheduler drains first, and the blocker loopback returns into those queues without reaching a cable."
"$PY" "$HERE/finalize_svg.py" "$TMP/fig_observation.svg" "$FIGS/fig_observation.svg" obs "Observation model" \
  "A SCADA master reaches an SEL-751A protective relay through one programmable switch. A passive adversary taps the master-facing link, the only part of the path it observes, which is shaded; the relay-facing link and the switch's two internal loopback lanes, one for reads and one for control, are dashed and are observed by neither the adversary nor the authors."
