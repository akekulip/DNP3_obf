#!/usr/bin/env bash
# build_v2.sh — regenerate the corrected package from authoritative_results.json.
# Order matters: manifest -> figures -> documents -> HTML -> PDF. Nothing is hand-edited.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REPO="$(cd "$ROOT/../.." && pwd)"
EV="$REPO/evidence/corrected_v2"
RPY="${RESEARCH_PYTHON:-$HOME/.venvs/research/bin/python}"
COMMIT="$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo unknown)"
DATE="$(date -u '+%Y-%m-%d %H:%M UTC')"

echo "[1/5] rebuild the authoritative manifest from the shipped pcaps"
"$RPY" "$EV/scripts/build_authoritative.py" >/dev/null

echo "[2/5] regenerate figures from the manifest"
"$RPY" "$EV/scripts/make_figures_v2.py" --out "$ROOT/figures" >/dev/null

echo "[3/5] regenerate documents from the manifest"
"$RPY" "$EV/scripts/gen_docs.py" --json "$EV/authoritative_results.json" --out "$ROOT" >/dev/null

echo "[4/5] render HTML"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
sed -e "s/@COMMIT@/$COMMIT/g" -e "s/@DATE@/$DATE/g" \
    "$HERE/corrected_report_source.md" > "$WORK/r.md"
( cd "$HERE" && pandoc "$WORK/r.md" --standalone --embed-resources --toc --toc-depth=2 \
    --template "$HERE/template.html" \
    --metadata title="DNP3 In-Network Timing Normalizer — Defense 2, Live Inline (corrected)" \
    -o "$ROOT/index_v2.html" )
echo "    wrote index_v2.html ($(du -h "$ROOT/index_v2.html" | cut -f1))"

echo "[5/5] print single-column PDF"
CHROME="$(command -v google-chrome || command -v chromium || true)"
if [ -n "$CHROME" ]; then
  "$CHROME" --headless=new --disable-gpu --no-sandbox \
    --print-to-pdf="$ROOT/DNP3_INLINE_LIVE_REPORT_V2.pdf" "file://$ROOT/index_v2.html" >/dev/null 2>&1
  echo "    wrote DNP3_INLINE_LIVE_REPORT_V2.pdf ($(du -h "$ROOT/DNP3_INLINE_LIVE_REPORT_V2.pdf" | cut -f1))"
else
  echo "    WARNING: no Chrome; PDF not generated"
fi
