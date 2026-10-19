#!/usr/bin/env bash
# build.sh - regenerate the schematics from their draw.io sources.
# Use --design to update only the design page and its SVG.
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

case "${1:-}" in
    "") FIGURE_NAMES=(fig_ladder fig_observation fig_design) ;;
    --design) FIGURE_NAMES=(fig_design) ;;
    *) echo "usage: $0 [--design]" >&2; exit 2 ;;
esac
if [[ "${1:-}" != "--design" ]]; then
    "$PY" "$HERE/gen_ladder_drawio.py"
    "$PY" "$HERE/gen_obs_drawio.py"
fi
"$PY" "$HERE/gen_design_drawio.py"
for f in "${FIGURE_NAMES[@]}"; do
    PAGE_ARGS=()
    [[ "$f" != "fig_design" ]] || PAGE_ARGS=(--page-index 2)
    "$DRAWIO" -x -f svg "${PAGE_ARGS[@]}" --border 2 -o "$TMP/$f.svg" "$FIGS/$f.drawio" >/dev/null 2>&1
    if grep -q '<foreignObject' "$TMP/$f.svg"; then
        echo "error: $f.svg carries foreignObject text, which the PDF step cannot render" >&2; exit 2
    fi
done
if [[ "${1:-}" != "--design" ]]; then
"$PY" "$HERE/finalize_svg.py" "$TMP/fig_ladder.svg" "$FIGS/fig_ladder.svg" lad "DNP3 transaction ladder" \
  "Two DNP3 transactions between a SCADA master and the outstation, time running downwards, with DNP3 function codes in parentheses. Requests are blue, TCP acknowledgments grey and responses green. In (a), a READ is acknowledged by a TCP ACK and answered by a RESPONSE; CLRT runs from the TCP ACK to the RESPONSE at the master. In (b), a SELECT and an OPERATE are each acknowledged and answered, and the outstation later sends an UNSOLICITED RESPONSE reporting the state change; PRT runs from the OPERATE to the UNSOLICITED RESPONSE."
"$PY" "$HERE/finalize_svg.py" "$TMP/fig_observation.svg" "$FIGS/fig_observation.svg" obs "Observation model" \
  "A SCADA master reaches the outstation, a protective relay, through one programmable switch. A passive adversary taps the master-facing link, the only part of the path it observes, which is shaded; the relay-facing link and the switch's two internal loopback lanes, one for reads and one for control, are dashed and are observed by neither the adversary nor the authors."
fi
"$PY" "$HERE/finalize_svg.py" "$TMP/fig_design.svg" "$FIGS/fig_design.svg" des "Packet flow and P4 queue-based holding" \
  "The master and outstation exchange requests, acknowledgments and responses through a P4 switch. Ingress classifies packets, arms request deadlines and selects queues. Internal blocker packets have priority over held packets. ACK and response queues share one scheduler; OPERATE uses another. Both internal loopback paths bypass egress and return to ingress for blocker expiry checks or forwarding released packets through normal egress."
