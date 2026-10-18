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
exec python3 "$HW/guarded_block.py" "$@"
