#!/usr/bin/env bash
# Export the two current introductory schematics from SVG to PDF and 600 dpi PNG.
# --check verifies the exported files and hashes without changing the source tree.
# Inkscape 1.x or later is required; INKSCAPE overrides PATH resolution.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAPER_FIGS="$(cd "${HERE}/../figures" && pwd)"

case "${1:-}" in
  ""|--check) FIGURE_NAMES=(fig_ladder fig_observation) ;;
  *) echo "usage: $0 [--check]" >&2; exit 2 ;;
esac

INKSCAPE="${INKSCAPE:-$(command -v inkscape || true)}"
if [[ -z "${INKSCAPE}" ]]; then
  echo "inkscape not found on PATH" >&2; exit 1
fi
ver="$("${INKSCAPE}" --version 2>/dev/null | grep -oE 'Inkscape [0-9]+' | head -1 | sed -E 's/Inkscape //')"
if [[ "${ver}" != "1" && "${ver}" != "2" ]]; then
  echo "need Inkscape 1.x on PATH; found: $("${INKSCAPE}" --version 2>/dev/null | head -1)" >&2; exit 1
fi


# --check verifies without writing anything into the tree. It cannot compare PDFs byte for byte,
# because Inkscape stamps each one with a /CreationDate, so it compares them with that line
# removed. The 600 dpi PNG export is deterministic and is compared whole: that is what proves the
# published raster came from the SVG now on disk.
if [[ "${1:-}" == "--check" ]]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "${tmp}"' EXIT
  fail=0
  for name in "${FIGURE_NAMES[@]}"; do
    svg="${PAPER_FIGS}/${name}.svg"
    [[ -f "${svg}" ]] || { echo "missing ${svg}" >&2; fail=1; continue; }
    "${INKSCAPE}" "${svg}" --export-type=pdf --export-filename="${tmp}/${name}.pdf" >/dev/null 2>&1
    "${INKSCAPE}" "${svg}" --export-type=png --export-dpi=600 --export-filename="${tmp}/${name}.png" >/dev/null 2>&1
    note=""
    cmp -s "${tmp}/${name}.png" "${PAPER_FIGS}/${name}.png" || { note="${note} png-stale"; fail=1; }
    a="$(sed '/^   \/CreationDate/d' "${tmp}/${name}.pdf" | sha256sum | cut -d' ' -f1)"
    b="$(sed '/^   \/CreationDate/d' "${PAPER_FIGS}/${name}.pdf" | sha256sum | cut -d' ' -f1)"
    [[ "${a}" == "${b}" ]] || { note="${note} pdf-stale"; fail=1; }
    printf '  %-16s %s\n' "${name}" "${note:- matches the SVG on disk}"
  done
  ( cd "${PAPER_FIGS}" && sha256sum --quiet -c SCHEMATICS.sha256 ) \
    && echo "  SCHEMATICS.sha256 verified" || { echo "  SCHEMATICS.sha256 does NOT match" >&2; fail=1; }
  [[ "${fail}" -eq 0 ]] && echo "schematics: 0 problems" || { echo "schematics: stale artefacts, re-run without --check" >&2; exit 1; }
  exit 0
fi

for name in "${FIGURE_NAMES[@]}"; do
  svg="${PAPER_FIGS}/${name}.svg"
  [[ -f "${svg}" ]] || { echo "missing ${svg}" >&2; exit 1; }
  "${INKSCAPE}" "${svg}" --export-type=pdf --export-filename="${PAPER_FIGS}/${name}.pdf" >/dev/null 2>&1
  "${INKSCAPE}" "${svg}" --export-type=png --export-dpi=600 --export-filename="${PAPER_FIGS}/${name}.png" >/dev/null 2>&1
  printf '  %-16s pdf+png(600dpi) exported\n' "${name}"
done

# hashes, for each figure's .provenance.json
( cd "${PAPER_FIGS}" && sha256sum fig_ladder.{svg,pdf,png} fig_observation.{svg,pdf,png} ) > "${PAPER_FIGS}/SCHEMATICS.sha256"
echo "  hashes -> figures/SCHEMATICS.sha256"
