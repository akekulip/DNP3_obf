#!/usr/bin/env bash
# render_md_pdf.sh - render one of this tree's Markdown notes to a readable PDF.
#
#   ./render_md_pdf.sh ../HOW_MUCH_DELAY_IS_SAFE.md [OUT.pdf]
#
# Default output is the input path with .pdf substituted.
#
# Why a script and not a bare pandoc line: pandoc gives pipe-table columns the LaTeX `l`
# type, which does not wrap, so a table with a prose column runs several inches off the
# page. The Lua filter below assigns each column a share of the text width proportional to
# its longest cell, so prose columns wrap and label columns stay narrow. Writing the widths
# into the Markdown separator rows instead would work, but it makes the source unreadable.
set -euo pipefail

SRC="${1:?usage: render_md_pdf.sh INPUT.md [OUTPUT.pdf]}"
[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 1; }
OUT="${2:-${SRC%.md}.pdf}"

for tool in pandoc; do
  command -v "$tool" >/dev/null || { echo "$tool not found on PATH" >&2; exit 2; }
done
TECTONIC="${TECTONIC:-$(command -v tectonic || echo "$HOME/.local/bin/tectonic")}"
[ -x "$TECTONIC" ] || { echo "tectonic not found; set TECTONIC=/path/to/tectonic" >&2; exit 2; }

FILTER="$(mktemp -t colwidth.XXXXXX.lua)"
trap 'rm -f "$FILTER"' EXIT
cat > "$FILTER" <<'LUA'
-- Give every table column a width proportional to its longest cell, so prose wraps.
local function cell_len(cell)
  return #pandoc.utils.stringify(cell.contents)
end

local function widest(rows, i)
  local w = 0
  for _, row in ipairs(rows) do
    local c = row.cells[i]
    if c then w = math.max(w, cell_len(c)) end
  end
  return w
end

function Table(tbl)
  local n = #tbl.colspecs
  if n == 0 then return nil end
  local rows = {}
  for _, r in ipairs(tbl.head.rows) do rows[#rows + 1] = r end
  for _, body in ipairs(tbl.bodies) do
    for _, r in ipairs(body.body) do rows[#rows + 1] = r end
  end

  local w, total = {}, 0
  for i = 1, n do
    -- sqrt compresses the range: a 200-character prose cell should be wider than a
    -- 10-character label, but not twenty times wider.
    w[i] = math.sqrt(math.max(widest(rows, i), 3))
    total = total + w[i]
  end
  -- 0.96 leaves the inter-column padding LaTeX adds outside the text block.
  for i = 1, n do
    tbl.colspecs[i][2] = 0.96 * w[i] / total
  end
  return tbl
end
LUA

pandoc "$SRC" \
  --from=gfm \
  --pdf-engine="$TECTONIC" \
  --lua-filter="$FILTER" \
  --toc --toc-depth=2 \
  -V geometry:margin=1in \
  -V fontsize=10pt \
  -V linestretch=1.05 \
  -V colorlinks=true -V linkcolor=RoyalBlue -V urlcolor=RoyalBlue \
  -V mainfont="Times New Roman" \
  -V monofont="DejaVu Sans Mono" \
  -V monofontoptions="Scale=0.80" \
  -V header-includes='\usepackage{ragged2e}\AtBeginEnvironment{longtable}{\small\RaggedRight}' \
  -V header-includes='\usepackage{etoolbox}' \
  -o "$OUT"

echo "  $(basename "$OUT")  $(pdfinfo "$OUT" 2>/dev/null | awk '/^Pages/{print $2" pages"}')  $(stat -c%s "$OUT") bytes"
