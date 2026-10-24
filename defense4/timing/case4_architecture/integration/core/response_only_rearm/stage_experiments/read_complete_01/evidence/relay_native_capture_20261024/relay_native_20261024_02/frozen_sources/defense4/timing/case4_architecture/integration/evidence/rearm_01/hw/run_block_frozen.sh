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
FREEZE="$1"; shift
exec python3 "$HW/guarded_block.py" --freeze "$FREEZE" "$@"
