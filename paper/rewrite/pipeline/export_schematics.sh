#!/usr/bin/env bash
# export_schematics.sh - export the hand-drawn schematics (Figures 1-3) from SVG to PDF and
# 600 dpi PNG, and mirror them into the timing tree.
#
#   paper/rewrite/figures/fig_{ladder,observation,design}.svg   (source of truth)
#     -> paper/rewrite/figures/<name>.pdf, <name>.png
#     -> defense4/timing/figures/schematics/<name>.{svg,pdf,png}   (byte-identical copies)
#
# Uses `inkscape` from PATH and requires Inkscape 1.x (the 0.92 CLI lacks --export-filename
# and cannot render these files). If your PATH resolves to an older Inkscape, prepend the
# directory that holds a 1.x binary, e.g.  PATH="$HOME/.local/bin:$PATH" ./export_schematics.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAPER_FIGS="$(cd "${HERE}/../figures" && pwd)"
REPO="$(cd "${HERE}/../../.." && pwd)"
MIRROR="${REPO}/defense4/timing/figures/schematics"

INKSCAPE="${INKSCAPE:-$(command -v inkscape || true)}"
if [[ -z "${INKSCAPE}" ]]; then
  echo "inkscape not found on PATH" >&2; exit 1
fi
ver="$("${INKSCAPE}" --version 2>/dev/null | grep -oE 'Inkscape [0-9]+' | head -1 | sed -E 's/Inkscape //')"
if [[ "${ver}" != "1" && "${ver}" != "2" ]]; then
  echo "need Inkscape 1.x on PATH; found: $("${INKSCAPE}" --version 2>/dev/null | head -1)" >&2; exit 1
fi

mkdir -p "${MIRROR}"
for name in fig_ladder fig_observation fig_design; do
  svg="${PAPER_FIGS}/${name}.svg"
  [[ -f "${svg}" ]] || { echo "missing ${svg}" >&2; exit 1; }
  "${INKSCAPE}" "${svg}" --export-type=pdf --export-filename="${PAPER_FIGS}/${name}.pdf" >/dev/null 2>&1
  "${INKSCAPE}" "${svg}" --export-type=png --export-dpi=600 --export-filename="${PAPER_FIGS}/${name}.png" >/dev/null 2>&1
  for ext in svg pdf png; do
    cp "${PAPER_FIGS}/${name}.${ext}" "${MIRROR}/${name}.${ext}"
    cmp -s "${PAPER_FIGS}/${name}.${ext}" "${MIRROR}/${name}.${ext}" || { echo "mirror differs: ${name}.${ext}" >&2; exit 1; }
  done
  printf '  %-16s pdf+png(600dpi) exported, mirrored (identical)\n' "${name}"
done

# hashes, for FIGURE_PROVENANCE.md
( cd "${PAPER_FIGS}" && sha256sum fig_ladder.{svg,pdf,png} fig_observation.{svg,pdf,png} fig_design.{svg,pdf,png} ) > "${PAPER_FIGS}/SCHEMATICS.sha256"
echo "  hashes -> figures/SCHEMATICS.sha256"
