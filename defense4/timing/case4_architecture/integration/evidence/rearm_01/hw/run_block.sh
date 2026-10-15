#!/usr/bin/env bash
# One guarded hardware block: plan, run --apply, then the independent restoration check, always.
#
#   bash run_block.sh TOOL CONFIG RUN_ID [TOOL ARGS...]      TOOL: candidate_campaign | candidate_series | candidate_isolation
#
# Exit status: 0 block and restore passed; 1 block failed but restoration verified (the night may continue);
# 2 restoration NOT verified (stop all hardware: preserve state, follow the RUNBOOK recovery procedure).
# A record line goes to rearm_01/hw/run_block.log.
set -u
HW="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HW/../../../../../.." && pwd)"
TOOL="$1"; CONFIG="$2"; RUN_ID="$3"; shift 3
cd "$REPO"
CFG="$(realpath "$CONFIG")"
ROOT="$REPO/defense4/timing/case4_architecture/$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['evidence_dir'])" "$CFG")/$RUN_ID"
LOG="$HW/run_block.log"
OUT="/tmp/run_block_$RUN_ID.out"
echo "$(date -Is) START $TOOL $RUN_ID $*" >> "$LOG"
if ! python3 "$HW/$TOOL.py" plan --config "$CFG" --run-id "$RUN_ID" "$@" > "$OUT.plan" 2>&1; then
    echo "$(date -Is) PLAN-REFUSED $RUN_ID (nothing touched): $(tail -3 "$OUT.plan" | tr '\n' ' ')" >> "$LOG"
    exit 1
fi
DEFENSE4_HW_AUTHORIZED=1 python3 -u "$HW/$TOOL.py" run --apply --config "$CFG" --run-id "$RUN_ID" "$@" > "$OUT" 2>&1
RC=$?
mkdir -p "$ROOT"
cp "$OUT.plan" "$ROOT/run_block_plan.out"; cp "$OUT" "$ROOT/run_block_run.out"
python3 "$HW/restore_verify.py" --config "$CFG" --run-root "$ROOT" > "$ROOT/restore_verify.out" 2>&1
RV=$?
echo "$(date -Is) END $RUN_ID block_rc=$RC restore_verify_rc=$RV $(tail -1 "$ROOT/restore_verify.out")" >> "$LOG"
if [ $RV -ne 0 ]; then exit 2; fi
if [ $RC -ne 0 ]; then exit 1; fi
exit 0
