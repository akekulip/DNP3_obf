#!/usr/bin/env bash
# reproduce.sh - rebuild every campaign_v1 result from the raw captures.
#
# Raw captures and frozen driver logs are inputs and are never written. Everything else is
# regenerated into a temporary tree, then compared against what the repository publishes.
#
#   ./reproduce.sh [OUT_DIR]      default OUT_DIR: /tmp/cv1_out
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${1:-/tmp/cv1_out}"
PY="$HERE/.venv/bin/python"
[ -x "$PY" ] || { echo "create the pinned environment first: uv venv --python 3.13 $HERE/.venv"; exit 2; }
mkdir -p "$OUT"

echo "[1/5] validate every capture and build the canonical transaction table"
"$PY" "$HERE/validate_campaign.py" "$OUT"

echo "[2/5] summary statistics"
"$PY" "$HERE/stats_campaign.py" "$OUT/transactions_canonical.csv" \
      "$($PY -c "import json;print(json.load(open('$HERE/policy_config.json'))['release_budget_D_ms'])")" \
      "$OUT/stats.json"

echo "[3/5] leakage: mutual information in bits, permutation null, two attacker models"
"$PY" "$HERE/leakage_campaign.py" "$OUT/transactions_canonical.csv" "$OUT/leakage.json"

echo "[4/5] figures"
"$PY" "$HERE/make_ndss_figures.py" "$OUT/transactions_canonical.csv" "$OUT/stats.json" \
      "$OUT/leakage.json" "$HERE/policy_config.json" "$OUT/figs"

echo "[5/5] tests"
CV1_OUT="$OUT" "$PY" -m pytest "$HERE/tests" -q

echo
echo "hash manifest -> $OUT/REPRODUCED.sha256"
( cd "$OUT" && sha256sum transactions_canonical.csv per_capture.csv validation_report.json \
    stats.json leakage.json figs/*.pdf > REPRODUCED.sha256 )
echo "done. outputs in $OUT"
