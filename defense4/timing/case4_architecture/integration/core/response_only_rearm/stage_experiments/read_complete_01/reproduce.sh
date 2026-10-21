#!/usr/bin/env bash
# read_complete_01: one entry point that re-derives every offline result and re-checks the recorded evidence.
#
#   bash reproduce.sh                                # offline: software tests, policy, constants, P4, gate, freeze
#   bash reproduce.sh --readout BLOCK_DIR CONFIG [ARMS] # also the independent readout of one recorded block
#                                                      (exit nonzero when that readout fails)
#
# Nothing here loads the switch or generates traffic. The hardware campaign is launched separately with the
# commands in COMPLETION_RECORD.md (evaluation_campaign.py init/start), under its own authorization and gates.
# Every step fails loudly; a step that regenerates a committed file then requires `git diff --exit-code` on it.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
STAGE="$(dirname "$HERE")"
HW="$(cd "$STAGE/../../../evidence/rearm_01/hw" && pwd)"
PY312="${RESEARCH_PYTHON:-$HOME/.venvs/research/bin/python}"
BUILD="$STAGE/ctl_timing_01/evidence/m12p_b08"
FREEZE="$BUILD/freeze_v3.json"
B08_SOURCE_SHA=7b1281bc4aa73950b33088adc9d9ae5bbd827422ec702c71d1d3b791f352214f
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

step() { printf '\n== %s\n' "$*"; }

step "1. software encoder: handoff tests + policy coverage (Python $("$PY312" -V 2>&1))"
(cd "$HERE/software" && "$PY312" -m pytest -q test_general.py test_coverage.py test_policy_coverage.py)

step "2. target policy: select_policy.py reproduces policy.json"
(cd "$HERE/policy" && "$PY312" select_policy.py >/dev/null)
git -C "$HERE" diff --exit-code -- policy/policy.json

step "3. switch constants: derive.py reproduces constants.json (byte-exact proof vs pad_read inside)"
(cd "$HERE/vectors" && "$PY312" derive.py >/dev/null)
git -C "$HERE" diff --exit-code -- vectors/constants.json

step "4. P4: make_m12.py --policy regenerates the m12p_b08 source byte for byte"
python3 "$STAGE/m12_fullsize/make_m12.py" "$SCRATCH/m12p" --policy >/dev/null
got="$(sha256sum "$SCRATCH/m12p/response_only.p4" | cut -d' ' -f1)"
[ "$got" = "$B08_SOURCE_SHA" ] || { echo "regenerated source $got != $B08_SOURCE_SHA"; exit 1; }
echo "source $got"

step "5. model gate: retained logs restored (hash-verified), v3 summary recomputed (no --write)"
python3 "$HERE/restore_retained_logs.py"
(cd "$STAGE/ctl_timing_01" && python3 model_summary.py evidence/m12p_b08 --v3 --enforce | tail -1)

step "6. freeze: every block config belongs to the frozen candidate"
for c in "$HERE"/hw/config/rc01_m12p_b08_*.json; do
  python3 "$HW/freeze_gate.py" check "$FREEZE" --config "$c" >/dev/null
  echo "ok $(basename "$c")"
done

if [ "${1:-}" = "--readout" ]; then
  [ $# -ge 3 ] || { echo "usage: reproduce.sh --readout BLOCK_DIR CONFIG [ARMS]"; exit 2; }
  step "7. independent hardware readout of $(basename "$2")"
  "$PY312" "$HERE/analysis/hw_read_readout.py" "$2" --config "$3" ${4:+--arms "$4"} --out "$SCRATCH/readout.json"
  "$PY312" -m pytest -q "$HERE/analysis/tests/test_readout.py"
fi
echo; echo "reproduce.sh: all offline steps passed"
