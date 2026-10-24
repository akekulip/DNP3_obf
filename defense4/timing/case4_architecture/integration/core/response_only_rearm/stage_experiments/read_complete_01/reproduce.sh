#!/usr/bin/env bash
# read_complete_01: one entry point that re-derives every offline result and re-checks the recorded evidence.
#
#   bash reproduce.sh                                # offline relay READ reference (CANDIDATE=c30 default)
#   bash reproduce.sh --candidate-info                # selected directory, exact flags/hash and evidence tier only
#   CANDIDATE=c48 bash reproduce.sh                    # integrated timestamp-bearing SEL-751 profile, all16 model gates
#   CANDIDATE=c26 bash reproduce.sh                  # c25 + behavior-preserving resource reduction (--reduce)
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
CANDIDATE="${CANDIDATE:-c30}"
# GATE_PIN: the commit whose driver tree recomputes this candidate's model gate. The shared driver module
# seg61_02/read_policy_expect.py gained the per-native SHAPES map for the two-READ builds, and model_profile.py changed
# with c20 (33e21fd07), so c12 recomputes at the last commit before c20 (83498d4c1) and c20 at c432d195e.
GATE_PIN=""
TWO_READ=0
RELAY_READ=0
EVIDENCE_TIER="historical software endpoint profile (offline only)"
BUILD_SUFFIX="$CANDIDATE"
case "$CANDIDATE" in
  c48) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry --read-handshake --headroom --relay --relay-sbo --relay-ts"
       TWO_READ=1; RELAY_READ=1; BUILD_SUFFIX=c48_sdk9132
       SOURCE_SHA=902a84bf1714d15788b707b7c23b86c4abe8f66a4ba8395d1d52f0377a2eae66
       EVIDENCE_TIER="integrated SEL-751 timestamp profile; qualification requires recorded gates" ;;
  c30) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry --read-handshake --headroom --relay"
       TWO_READ=1; RELAY_READ=1; BUILD_SUFFIX=c30_sdk9132
       SOURCE_SHA=b006752236a7d1cccab461a010b2b68a3ea7b5629b1097c926ebacd348126de2
       EVIDENCE_TIER="relay READ reference; legacy software SBO" ;;
  c26) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read --reduce"; TWO_READ=1
       SOURCE_SHA=21b98f5182edb08725b92c5d8875f75abc9da22f673f2710579b9b5ab5124fd1 ;;
  c25|c24) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read"; TWO_READ=1
       SOURCE_SHA=61f9af0fa141a1b4d0a93938893119909e792c1e98e1665156e0011969aadc07 ;;
  c12) GEN_ARGS="--policy --c3 cimg --shapes passthrough"; GATE_PIN=83498d4c1
       SOURCE_SHA=742089cbe7629b754b47418245da9c22f1c2dc4949d8bd8a9f7e4bebaff8bbe5 ;;
  c20) GEN_ARGS="--policy --c3 cimg --shapes passthrough --segmented-full"; GATE_PIN=c432d195e
       SOURCE_SHA=1e94c31d80e6708ab31ca117f066d15f5ec23244fc6f7bf7b9ca68dc81a2a27b ;;
  b08) GEN_ARGS="--policy"
       SOURCE_SHA=7b1281bc4aa73950b33088adc9d9ae5bbd827422ec702c71d1d3b791f352214f ;;
  *) echo "unknown CANDIDATE $CANDIDATE (c48 | c30 | c26 | c25 | c24 | c12 | c20 | b08)"; exit 2 ;;
esac
BUILD="$STAGE/ctl_timing_01/evidence/m12p_$BUILD_SUFFIX"
FREEZE="$BUILD/freeze_v3.json"
if [ "${1:-}" = --candidate-info ]; then
  [ $# = 1 ] || { echo "--candidate-info takes no other arguments" >&2; exit 2; }
  python3 - "$CANDIDATE" "$BUILD" "$SOURCE_SHA" "$GEN_ARGS" "$EVIDENCE_TIER" <<'EOF'
import json, shlex, sys
print(json.dumps(dict(candidate=sys.argv[1], build=sys.argv[2], source_sha256=sys.argv[3],
                     generator_args=shlex.split(sys.argv[4]), evidence_tier=sys.argv[5]), indent=2))
EOF
  exit 0
fi
if [ $# -gt 0 ] && [ "$1" != --readout ]; then
  echo "unknown argument $1 (use --candidate-info or --readout BLOCK_DIR CONFIG [ARMS])" >&2
  exit 2
fi
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

if [ "$RELAY_READ" = 1 ]; then
  step "2. preserved relay READ targets: 141/158 (no new target selection)"
  "$PY312" - "$HERE/vectors/constants_two_read_relay.json" <<'EOF'
import json, sys
assert json.load(open(sys.argv[1]))['policy_targets'] == [141, 158], 'relay targets changed'
EOF
else
  step "2. target policy: select_policy.py reproduces policy.json"
  (cd "$HERE/policy" && "$PY312" select_policy.py >/dev/null)
  git -C "$HERE" diff --exit-code -- policy/policy.json
fi

step "3. switch constants: derive.py reproduces constants.json (byte-exact proof vs pad_read inside)"
(cd "$HERE/vectors" && "$PY312" derive.py >/dev/null)
git -C "$HERE" diff --exit-code -- vectors/constants.json vectors/constants_segmented.json

if [ "$TWO_READ" = 1 ]; then
  if [ "$RELAY_READ" = 1 ]; then
    step "3b. relay constants/templates: retained native samples, exact encoding and nonempty coverage"
    (cd "$HERE/vectors" && "$PY312" make_two_read_templates_relay.py >/dev/null && "$PY312" derive_two_read_relay.py >/dev/null)
    git -C "$HERE" diff --exit-code -- vectors/two_read_templates_relay.json vectors/constants_two_read_relay.json
  else
    step "3b. two-READ constants and templates: derive_two_read.py / make_two_read_templates.py reproduce them"
    (cd "$HERE/vectors" && "$PY312" make_two_read_templates.py >/dev/null && "$PY312" derive_two_read.py >/dev/null)
    git -C "$HERE" diff --exit-code -- vectors/two_read_templates.json vectors/constants_two_read.json
  fi
  step "3c. two-READ generator tests (interpreter: byte-exact construction, N/E admission and mapping)"
  (cd "$STAGE/m12_fullsize" && "$PY312" -m pytest -q tests/test_two_read_pad.py tests/test_two_read_ne.py | tail -1)
fi

step "4. P4: make_m12.py $GEN_ARGS regenerates the m12p_$CANDIDATE source byte for byte"
python3 "$STAGE/m12_fullsize/make_m12.py" "$SCRATCH/m12p" $GEN_ARGS >/dev/null
got="$(sha256sum "$SCRATCH/m12p/response_only.p4" | cut -d' ' -f1)"
[ "$got" = "$SOURCE_SHA" ] || { echo "regenerated source $got != $SOURCE_SHA"; exit 1; }
echo "source $got"
if [ "$CANDIDATE" = c48 ]; then
  step "4b. integrated relay generator, checksum, admission and boundary regressions"
  (cd "$STAGE/m12_fullsize" && "$PY312" -m pytest -q tests)
  python3 "$STAGE/m12_fullsize/check_generator_identity.py"
  python3 - "$SCRATCH/m12p/response_only.inputs.json" "$BUILD/response_only.inputs.json" <<'EOF'
import json, sys
def norm(path):
    d = json.load(open(path))
    candidate = d['supported_profile']['candidate']
    candidate.pop('build')
    candidate.pop('artifact_sha256')
    return d
if norm(sys.argv[1]) != norm(sys.argv[2]):
    sys.exit('regenerated integrated relay profile differs from the recorded profile')
EOF
fi
if [ "$CANDIDATE" = c26 ]; then
  python3 "$STAGE/m12_fullsize/check_generator_identity.py" | tail -1
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
  echo "profile response_only.inputs.json identical, generator identity included (artifact pins and build path normalized)"
fi
if [ "$CANDIDATE" = c25 ]; then
  # the declared profile too (scope, shapes, images, generator hash): c24 differs only in its uncorrected scope text.
  # Recording the artifacts fills supported_profile.candidate.{build, artifact_sha256}; only those two are normalized.
  # The generator was split into m12gen/ after 0c475ebc2 (byte-identical outputs, m12_fullsize/check_generator_identity.py),
  # so the recorded generator_sha256 is checked against make_m12.py AT 0c475ebc2 and the generator-identity fields are
  # normalized in the comparison with the current generator.
  rec_gen="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["generator_sha256"])' "$BUILD/response_only.inputs.json")"
  pin_gen="$(git -C "$REPO" show "0c475ebc2:${STAGE#$REPO/}/m12_fullsize/make_m12.py" | sha256sum | cut -d' ' -f1)"
  [ "$rec_gen" = "$pin_gen" ] || { echo "recorded generator_sha256 $rec_gen != make_m12.py at 0c475ebc2 ($pin_gen)"; exit 1; }
  echo "recorded generator_sha256 = make_m12.py at 0c475ebc2"
  python3 - "$SCRATCH/m12p/response_only.inputs.json" "$BUILD/response_only.inputs.json" <<'EOF'
import json, sys
def norm(path):
    d = json.load(open(path))
    cand = d['supported_profile']['candidate']
    cand.pop('build'); cand.pop('artifact_sha256')
    d.pop('generator_sha256'); d.pop('generator_files', None)
    return d
a, b = norm(sys.argv[1]), norm(sys.argv[2])
if a != b:
    sys.exit('regenerated profile differs from the recorded one: %s' % sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k)))
EOF
  echo "profile response_only.inputs.json identical (artifact pins, build path and generator identity normalized)"
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
  (cd "$STAGE/ctl_timing_01" && python3 model_summary.py "evidence/m12p_$BUILD_SUFFIX" --v3 --enforce | tail -1)
fi

step "6. freeze: every block config belongs to the frozen candidate"
if [ -f "$FREEZE" ] && ls "$HERE"/hw/config/rc01_m12p_${CANDIDATE}_*.json >/dev/null 2>&1; then
  # Compiler artifacts (compile_*/out/) are git-ignored by design (case4_architecture/build.py). In a fresh checkout
  # they are absent, so the freeze binding of the artifact BYTES cannot be checked without recompiling; that case is
  # reported as NOT CHECKED (never as ok). Any changed file, or any missing file outside compile_*/out/, fails.
  for c in "$HERE"/hw/config/rc01_m12p_${CANDIDATE}_*.json; do
    if out="$(python3 "$HW/freeze_gate.py" check "$FREEZE" --config "$c" 2>&1)"; then
      echo "ok $(basename "$c")"
    elif echo "$out" | grep -q '^freeze check: FAILED 0 changed' \
         && ! echo "$out" | grep '^  missing ' | grep -vq '/compile_[a-z0-9_]*/out/'; then
      echo "NOT CHECKED $(basename "$c"): only git-ignored compiler artifacts are missing (compile with $STAGE/../../../../build.py to check the binding)"
      FREEZE_UNCHECKED=1
    else
      echo "$out"; echo "freeze check FAILED for $(basename "$c")"; exit 1
    fi
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
echo
if [ "${FREEZE_UNCHECKED:-0}" = 1 ]; then
  echo "reproduce.sh: all offline steps passed EXCEPT the freeze binding of compiler artifacts, which was NOT CHECKED (absent)"
else
  echo "reproduce.sh: all offline steps passed"
fi
