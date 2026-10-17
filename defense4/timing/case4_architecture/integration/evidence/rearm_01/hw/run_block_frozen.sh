#!/usr/bin/env bash
# The single pre-block entry point (review of 7637390c1): check the freeze record, retain the result beside the
# block's evidence, and run the guarded block only if every frozen file is unchanged and present.
# Review of af7bd434: the check also binds CONFIG to the freeze's one candidate (freeze_gate.py candidate_binding):
# its source, loaded compile, artifacts, frozen config set and model verdict, or a recorded diagnostic exception.
#
#   bash run_block_frozen.sh FREEZE.json TOOL CONFIG RUN_ID [TOOL ARGS...]   (stdin from /dev/null)
#
# Exit 3: the freeze check failed (nothing on the switch touched). Otherwise run_block.sh's own exit status:
# 0 block and restore passed; 1 block failed, restore verified; 2 restore NOT verified (stop all hardware).
set -u
HW="$(cd "$(dirname "$0")" && pwd)"
REPO="$(git -C "$HW" rev-parse --show-toplevel)"
FREEZE="$1"; TOOL="$2"; CONFIG="$3"; RUN_ID="$4"; shift 4
CFG="$(realpath -e "$CONFIG")" || exit 3
ROOT="$REPO/defense4/timing/case4_architecture/$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['evidence_dir'])" "$CFG")/$RUN_ID"
REC="$HW/freeze_checks/$RUN_ID.json"           # outside the run directory, which the block tools create
if ! python3 "$HW/freeze_gate.py" check "$FREEZE" --config "$CFG" --record "$REC"; then
    echo "$(date -Is) FREEZE-REFUSED $RUN_ID (nothing touched)" >> "$HW/run_block.log"
    exit 3
fi
bash "$HW/run_block.sh" "$TOOL" "$CFG" "$RUN_ID" "$@" < /dev/null
RC=$?
mkdir -p "$ROOT" && cp "$REC" "$ROOT/freeze_check.json"
exit $RC
