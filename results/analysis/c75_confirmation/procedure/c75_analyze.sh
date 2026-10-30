#!/usr/bin/env bash
# Count the c75 confirmation blocks with the tools used for the c72 and c74 results. Run from the repository root.
set -u
D=${D:?set D=YYYYMMDD}
O=results/analysis/c75_confirmation
P=$O/procedure
B=results/hardware/blocks
DIAG_SHA=$(python3 -c "import json;print(json.load(open('results/builds/c75_diag_mirror/diag_mirror.json'))['source_sha256'])")
trials() { ls -d $B/$1_*/physical_relay/*/*_t* 2>/dev/null; }
for c in sc20 sc5; do
  t=$(trials rc01_hw_c75_${c}_${D}_01); [ -n "$t" ] || { echo "strict $c: no trials"; continue; }
  $RESEARCH_PYTHON scripts/analysis/confirmation_summary.py strict $t --out $O/c75_${c}_summary.json > /dev/null \
    && echo "strict $c: $O/c75_${c}_summary.json"
done
for s in e2c:combined e2o:off; do
  t=$(trials rc01_hw_c75diag_${s%%:*}_${D}_01); [ -n "$t" ] || { echo "starts ${s##*:}: no trials"; continue; }
  $RESEARCH_PYTHON scripts/analysis/confirmation_summary.py starts $t --build-label c75_diag_mirror \
    --source-sha256 "$DIAG_SHA" --out $O/c75_e2_${s##*:}_starts.json > /dev/null \
    && echo "starts ${s##*:}: $O/c75_e2_${s##*:}_starts.json"
done
rec=$(ls -d $B/rc01_hw_c75_recovery_r?_${D}_01_* 2>/dev/null)
if [ -n "$rec" ]; then
  python3 scripts/analysis/recovery_e3.py $rec > $O/c75_e3_trials.json && echo "recovery: $O/c75_e3_trials.json"
  $RESEARCH_PYTHON scripts/analysis/recovery_compare.py \
    --build c72 $(ls -d $B/rc01_hw_c72_recovery_r?_20261028_01_*) \
    --build c74 $(ls -d $B/rc01_hw_c74_recovery_r?_20261030_02_*) \
    --build c75 $rec --out results/analysis/recovery_e3/compare_c72_c74_c75.json > /dev/null \
    && echo "recovery compare: results/analysis/recovery_e3/compare_c72_c74_c75.json"
fi
t=$(trials rc01_hw_c75_e4b_${D}_01)
[ -n "$t" ] && $RESEARCH_PYTHON $P/e4b_counts.py $t --out $O/c75_e4b_counts.json > /dev/null && echo "e4b: $O/c75_e4b_counts.json"
t=$(for c in sc20_${D}_01 sc5_${D}_01 recovery_r1_${D}_01 recovery_r2_${D}_01 recovery_r3_${D}_01 e4b_${D}_01; do trials rc01_hw_c75_$c; done)
[ -n "$t" ] && $RESEARCH_PYTHON $P/first_request_retx.py $t --out $O/c75_first_request_retx.json > /dev/null \
  && echo "first-request retransmissions (exact binary): $O/c75_first_request_retx.json"
true
