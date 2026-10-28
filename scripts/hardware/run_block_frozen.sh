#!/usr/bin/env bash
# Check the current candidate freeze before any hardware entry: exact source,
# loaded compile, stage limits, 17-driver model gate, config and checker closure.
# Retain the check beside the block evidence, then use the guarded block and
# independent restoration verification. A failed or incomplete check refuses entry.
#
#   bash run_block_frozen.sh FREEZE.json TOOL CONFIG RUN_ID [TOOL ARGS...]   (stdin from /dev/null)
#
# Exit 3: the freeze check failed (nothing on the switch touched). Otherwise run_block.sh's own exit status:
# 0 block and restore passed; 1 block failed, restore verified; 2 restore NOT verified (stop all hardware).
set -u
HW="$(cd "$(dirname "$0")" && pwd)"
FREEZE="$1"; shift
exec python3 "$HW/guarded_block.py" --freeze "$FREEZE" "$@"
