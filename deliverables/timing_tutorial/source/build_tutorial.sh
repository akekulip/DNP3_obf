#!/usr/bin/env bash
# build_tutorial.sh — render the tutorial to a self-contained index.html and a PDF FROM THE SAME
# SOURCE (tutorial_source.md), so the two can never contradict each other (direcr2 §14).
#   HTML : pandoc --standalone --embed-resources (all CSS/JS/images inlined; works offline)
#   PDF  : headless Chrome prints THAT html to PDF (renders the embedded SVG + PNG natively)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SRC="$HERE/tutorial_source.md"
TPL="$HERE/template.html"
HTML="$ROOT/index.html"
PDF="$ROOT/DNP3_TIMING_NORMALIZER_TUTORIAL.pdf"

COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u '+%Y-%m-%d %H:%M UTC')"

echo "[1/4] regenerate diagrams"
python3 "$HERE/make_diagrams.py" --out "$ROOT/assets" >/dev/null

echo "[2/4] stamp commit/date into a working copy"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
sed -e "s/@COMMIT@/$COMMIT/g" -e "s/@DATE@/$DATE/g" "$SRC" > "$WORK/tutorial.md"

echo "[3/4] render self-contained HTML (pandoc)"
# run from the source dir so ../assets/* image paths resolve, then --embed-resources inlines them
( cd "$HERE" && pandoc "$WORK/tutorial.md" \
    --standalone --embed-resources --toc --toc-depth=1 \
    --template "$TPL" --metadata title="DNP3 In-Network Timing Normalizer — Tutorial" \
    -o "$HTML" )
echo "    wrote $HTML ($(du -h "$HTML" | cut -f1))"

echo "[4/4] print the same HTML to PDF (headless Chrome)"
CHROME="$(command -v google-chrome || command -v chromium || command -v chromium-browser || true)"
if [ -n "$CHROME" ]; then
  # keep Chrome's print footer so the PDF carries page numbers (direcr2 §14); the build
  # commit + date are also stamped into the document body's buildinfo block.
  "$CHROME" --headless=new --disable-gpu --no-sandbox \
    --print-to-pdf="$PDF" "file://$HTML" >/dev/null 2>&1 || \
  "$CHROME" --headless --disable-gpu --no-sandbox \
    --print-to-pdf="$PDF" "file://$HTML" >/dev/null 2>&1
  echo "    wrote $PDF ($(du -h "$PDF" | cut -f1))"
else
  echo "    WARNING: no Chrome/Chromium found; PDF not generated. HTML is complete."
fi
echo "done."
