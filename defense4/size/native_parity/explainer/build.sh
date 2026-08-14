#!/usr/bin/env bash
# Build the Defense-4 explainer into DOCX + PDF from the Markdown master.
# Figures are referenced from ./figs (PNG, readable resolution).
# Usage: ./build.sh
set -euo pipefail
cd "$(dirname "$0")"

SRC="DEFENSE4_EXPLAINER.md"
TECTONIC="$HOME/.local/bin/tectonic"

echo "[build] pandoc $(pandoc --version | head -1)"

# --- DOCX (editable) ---
pandoc "$SRC" \
  --from markdown \
  --toc --toc-depth=2 \
  --number-sections \
  -o DEFENSE4_EXPLAINER.docx
echo "[build] wrote DEFENSE4_EXPLAINER.docx ($(du -h DEFENSE4_EXPLAINER.docx | cut -f1))"

# --- PDF (visually verifiable) via tectonic ---
pandoc "$SRC" \
  --from markdown \
  --toc --toc-depth=2 \
  --number-sections \
  --pdf-engine=tectonic \
  -V mainfont="DejaVu Serif" -V monofont="DejaVu Sans Mono" -V mathfont="DejaVu Math TeX Gyre" \
  -V geometry:margin=1in \
  -V documentclass=article \
  -V fontsize=10pt \
  -V colorlinks=true \
  -o DEFENSE4_EXPLAINER.pdf
echo "[build] wrote DEFENSE4_EXPLAINER.pdf ($(du -h DEFENSE4_EXPLAINER.pdf | cut -f1))"

# --- Meeting reference sheet (2-page quick ref) ---
if [ -f MEETING_REFERENCE.md ]; then
  pandoc MEETING_REFERENCE.md --from markdown --pdf-engine=tectonic -V mainfont="DejaVu Serif" -V monofont="DejaVu Sans Mono" \
    -V geometry:margin=0.7in -V fontsize=9pt -o MEETING_REFERENCE.pdf
  echo "[build] wrote MEETING_REFERENCE.pdf"
fi

echo "[build] done."
