#!/usr/bin/env bash
# build.sh — render the inline-live report to a self-contained HTML and a single-column PDF
# FROM THE SAME SOURCE, so the two can never contradict each other.
#   diagrams : regenerated every build (SVG schematics + matplotlib data figures)
#   HTML     : pandoc --standalone --embed-resources (CSS/JS/images inlined; works offline)
#   PDF      : headless Chrome prints THAT html; the template's @media print drops the
#              sidebar and removes the max-width, giving a single column with all figures.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SRC="$HERE/report_source.md"
TPL="$HERE/template.html"
HTML="$ROOT/index.html"
PDF="$ROOT/DNP3_INLINE_LIVE_REPORT.pdf"
RPY="${RESEARCH_PYTHON:-$HOME/.venvs/research/bin/python}"

COMMIT="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u '+%Y-%m-%d %H:%M UTC')"

echo "[1/4] regenerate diagrams and figures"
python3 "$HERE/make_diagrams.py" --out "$ROOT/assets" >/dev/null
if [ -x "$RPY" ]; then
  "$RPY" "$HERE/make_figures.py" --out "$ROOT/assets" >/dev/null
else
  echo "    WARNING: research python not found at $RPY — data figures NOT regenerated"
fi

echo "[2/4] stamp commit/date"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
sed -e "s/@COMMIT@/$COMMIT/g" -e "s/@DATE@/$DATE/g" "$SRC" > "$WORK/report.md"

echo "[3/4] render self-contained HTML"
( cd "$HERE" && pandoc "$WORK/report.md" \
    --standalone --embed-resources --toc --toc-depth=2 \
    --template "$TPL" \
    --metadata title="DNP3 In-Network Timing Normalizer — Live Inline on a Physical SEL-751" \
    -o "$HTML" )
echo "    wrote $HTML ($(du -h "$HTML" | cut -f1))"

echo "[4/4] print to single-column PDF"
CHROME="$(command -v google-chrome || command -v chromium || command -v chromium-browser || true)"
if [ -n "$CHROME" ]; then
  "$CHROME" --headless=new --disable-gpu --no-sandbox --no-pdf-header-footer \
      --print-to-pdf="$PDF" "file://$HTML" >/dev/null 2>&1 ||
  "$CHROME" --headless=new --disable-gpu --no-sandbox \
      --print-to-pdf="$PDF" "file://$HTML" >/dev/null 2>&1 ||
  "$CHROME" --headless --disable-gpu --no-sandbox \
      --print-to-pdf="$PDF" "file://$HTML" >/dev/null 2>&1
  echo "    wrote $PDF ($(du -h "$PDF" | cut -f1))"
else
  echo "    WARNING: no Chrome/Chromium found; PDF not generated. HTML is complete."
fi
