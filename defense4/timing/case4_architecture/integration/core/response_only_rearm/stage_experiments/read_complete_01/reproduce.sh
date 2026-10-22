#!/usr/bin/env bash
# read_complete_01: one entry point that re-derives every offline result and re-checks the recorded evidence.
#
#   bash reproduce.sh                                # offline, the two-READ-target candidate (CANDIDATE=c25 default)
#   CANDIDATE=c24 bash reproduce.sh                  # c25's P4 with the uncorrected disposition text (historical)
#   CANDIDATE=c12 bash reproduce.sh                  # the preserved rotate4 checkpoint
#   CANDIDATE=c20 bash reproduce.sh                  # the faithful segmented READ 377->401 delivery candidate
#   CANDIDATE=b08 bash reproduce.sh                  # the earlier range-only candidate (b08, historical)
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
CANDIDATE="${CANDIDATE:-c25}"
# GATE_PIN: the commit whose driver tree recomputes this candidate's model gate. The shared driver module
# seg61_02/read_policy_expect.py gained the per-native SHAPES map for the two-READ builds, and model_profile.py changed
# with c20 (33e21fd07), so c12 recomputes at the last commit before c20 (83498d4c1) and c20 at c432d195e.
GATE_PIN=""
TWO_READ=0
case "$CANDIDATE" in
  c25|c24) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read"; TWO_READ=1
       SOURCE_SHA=61f9af0fa141a1b4d0a93938893119909e792c1e98e1665156e0011969aadc07 ;;
  c12) GEN_ARGS="--policy --c3 cimg --shapes passthrough"; GATE_PIN=83498d4c1
       SOURCE_SHA=742089cbe7629b754b47418245da9c22f1c2dc4949d8bd8a9f7e4bebaff8bbe5 ;;
  c20) GEN_ARGS="--policy --c3 cimg --shapes passthrough --segmented-full"; GATE_PIN=c432d195e
       SOURCE_SHA=1e94c31d80e6708ab31ca117f066d15f5ec23244fc6f7bf7b9ca68dc81a2a27b ;;
  b08) GEN_ARGS="--policy"
       SOURCE_SHA=7b1281bc4aa73950b33088adc9d9ae5bbd827422ec702c71d1d3b791f352214f ;;
  *) echo "unknown CANDIDATE $CANDIDATE (c25 | c24 | c12 | c20 | b08)"; exit 2 ;;
esac
BUILD="$STAGE/ctl_timing_01/evidence/m12p_$CANDIDATE"
FREEZE="$BUILD/freeze_v3.json"
SCRATCH="$(mktemp -d)"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
cleanup() {
  if [ -d "$SCRATCH/pin" ]; then git -C "$REPO" worktree remove --force "$SCRATCH/pin" >/dev/null 2>&1 || true; fi
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }

step "1. software encoder: handoff tests + policy coverage (Python $("$PY312" -V 2>&1))"
(cd "$HERE/software" && "$PY312" -m pytest -q test_general.py test_coverage.py test_policy_coverage.py)

step "2. target policy: select_policy.py reproduces policy.json"
(cd "$HERE/policy" && "$PY312" select_policy.py >/dev/null)
git -C "$HERE" diff --exit-code -- policy/policy.json

step "3. switch constants: derive.py reproduces constants.json (byte-exact proof vs pad_read inside)"
(cd "$HERE/vectors" && "$PY312" derive.py >/dev/null)
git -C "$HERE" diff --exit-code -- vectors/constants.json vectors/constants_segmented.json

if [ "$TWO_READ" = 1 ]; then
  step "3b. two-READ constants and templates: derive_two_read.py / make_two_read_templates.py reproduce them"
  (cd "$HERE/vectors" && "$PY312" make_two_read_templates.py >/dev/null && "$PY312" derive_two_read.py >/dev/null)
  git -C "$HERE" diff --exit-code -- vectors/two_read_templates.json vectors/constants_two_read.json
  step "3c. two-READ generator tests (interpreter: byte-exact construction, N/E admission and mapping)"
  (cd "$STAGE/m12_fullsize" && "$PY312" -m pytest -q tests/test_two_read_pad.py tests/test_two_read_ne.py | tail -1)
fi

step "4. P4: make_m12.py $GEN_ARGS regenerates the m12p_$CANDIDATE source byte for byte"
python3 "$STAGE/m12_fullsize/make_m12.py" "$SCRATCH/m12p" $GEN_ARGS >/dev/null
got="$(sha256sum "$SCRATCH/m12p/response_only.p4" | cut -d' ' -f1)"
[ "$got" = "$SOURCE_SHA" ] || { echo "regenerated source $got != $SOURCE_SHA"; exit 1; }
echo "source $got"
if [ "$CANDIDATE" = c25 ]; then
  # the declared profile too (scope, shapes, images, generator hash): c24 differs only in its uncorrected scope text.
  # Recording the artifacts fills supported_profile.candidate.{build, artifact_sha256}; only those two are normalized.
  python3 - "$SCRATCH/m12p/response_only.inputs.json" "$BUILD/response_only.inputs.json" <<'EOF'
import json, sys
def norm(path):
    d = json.load(open(path))
    cand = d['supported_profile']['candidate']
    cand.pop('build'); cand.pop('artifact_sha256')
    return d
a, b = norm(sys.argv[1]), norm(sys.argv[2])
if a != b:
    sys.exit('regenerated profile differs from the recorded one: %s' % sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k)))
EOF
  echo "profile response_only.inputs.json identical (artifact pins and build path normalized)"
fi

step "5. model gate: retained logs restored (hash-verified), v3 summary recomputed (no --write)"
if [ -n "$GATE_PIN" ]; then
  git -C "$REPO" worktree prune
  git -C "$REPO" worktree add --detach "$SCRATCH/pin" "$GATE_PIN" >/dev/null
  PIN_STAGE="$SCRATCH/pin/${STAGE#$REPO/}"
  echo "recomputing at $GATE_PIN (detached worktree, removed on exit)"
  python3 "$PIN_STAGE/read_complete_01/restore_retained_logs.py"
  (cd "$PIN_STAGE/ctl_timing_01" && python3 model_summary.py "evidence/m12p_$CANDIDATE" --v3 --enforce | tail -1)
else
  python3 "$HERE/restore_retained_logs.py"
  (cd "$STAGE/ctl_timing_01" && python3 model_summary.py "evidence/m12p_$CANDIDATE" --v3 --enforce | tail -1)
fi

step "6. freeze: every block config belongs to the frozen candidate"
if [ -f "$FREEZE" ] && ls "$HERE"/hw/config/rc01_m12p_${CANDIDATE}_*.json >/dev/null 2>&1; then
  for c in "$HERE"/hw/config/rc01_m12p_${CANDIDATE}_*.json; do
    python3 "$HW/freeze_gate.py" check "$FREEZE" --config "$c" >/dev/null
    echo "ok $(basename "$c")"
  done
else
  echo "no freeze yet for m12p_$CANDIDATE (configs present: $(ls "$HERE"/hw/config/rc01_m12p_${CANDIDATE}_*.json 2>/dev/null | wc -l)); skipping"
fi

if [ "${1:-}" = "--readout" ]; then
  [ $# -ge 3 ] || { echo "usage: reproduce.sh --readout BLOCK_DIR CONFIG [ARMS]"; exit 2; }
  step "7. independent hardware readout of $(basename "$2")"
  "$PY312" "$HERE/analysis/hw_read_readout.py" "$2" --config "$3" ${4:+--arms "$4"} --out "$SCRATCH/readout.json"
  "$PY312" -m pytest -q "$HERE/analysis/tests/test_readout.py"
fi
echo; echo "reproduce.sh: all offline steps passed"
