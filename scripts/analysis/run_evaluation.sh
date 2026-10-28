#!/bin/bash
# Rows -> Formby classifiers -> figures/tables for one evaluation campaign, into a new output directory.
#   bash scripts/analysis/run_evaluation.sh CAMPAIGN_DIR OUT_DIR
set -euo pipefail
HERE=$(dirname "$(readlink -f "$0")")
CAMPAIGN=$1; OUT=$2
PY=${RESEARCH_PYTHON:-$HOME/.venvs/research/bin/python}
export OMP_NUM_THREADS=${OMP_NUM_THREADS:-8} OPENBLAS_NUM_THREADS=${OPENBLAS_NUM_THREADS:-8}
[ -e "$OUT" ] && { echo "refusing to overwrite $OUT"; exit 2; }
mkdir -p "$OUT"
python3 "$HERE/eval_rows.py" "$CAMPAIGN" --output "$OUT/rows" | tee "$OUT/rows.log"
"$PY" "$HERE/formby_eval.py" "$OUT/rows/rows.csv" --output "$OUT/formby" 2> "$OUT/formby.stderr" | tee "$OUT/formby.log"
set +e   # a failed sufficiency gate (exit 3) still writes every output; record hashes, then report the failure
"$PY" "$HERE/eval_figures.py" "$OUT/rows/rows.csv" "$OUT/formby/formby_results.json" --output "$OUT/figures" \
  2> "$OUT/figures.stderr" | tee "$OUT/figures.log"
rc=${PIPESTATUS[0]}
set -e
python3 "$HERE/eval_report.py" "$OUT"
sha256sum "$OUT"/rows/rows.csv "$OUT"/formby/formby_results.json "$OUT"/figures/*.pdf "$OUT"/figures/*.csv \
  "$OUT"/figures/*.json "$OUT/REPORT_NUMBERS.md" > "$OUT/SHA256SUMS"
[ "$rc" -eq 0 ] || echo "SUFFICIENCY GATE FAILED (figures rc $rc): see $OUT/figures/sufficiency.json"
exit "$rc"
