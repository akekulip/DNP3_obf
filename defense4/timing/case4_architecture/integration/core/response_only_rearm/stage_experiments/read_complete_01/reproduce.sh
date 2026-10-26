#!/usr/bin/env bash
# read_complete_01: one entry point that re-derives every offline result and re-checks the recorded evidence.
#
#   bash reproduce.sh                                # offline relay READ reference (CANDIDATE=c30 default)
#   bash reproduce.sh --candidate-info                # selected directory, exact flags/hash and evidence tier only
#   CANDIDATE=c48 bash reproduce.sh                    # integrated timestamp-bearing SEL-751 profile, all16 model gates
#   CANDIDATE=c49 bash reproduce.sh                    # canonical profile keys for the same guarded relay profile
#   CANDIDATE=c50 bash reproduce.sh                    # bounded FIN owner-phase retry repair
#   CANDIDATE=c51 bash reproduce.sh                    # qualified half-closed RST admission (physical SEL-751 candidate)
#   CANDIDATE=c52 bash reproduce.sh                    # relay FIN+PSH+ACK close (current physical SEL-751 candidate)
#   CANDIDATE=c60 bash reproduce.sh                    # response-ready ACK then D; requires all 17 model drivers
#   CANDIDATE=c67 bash reproduce.sh                    # deadline-free ACK+D, retained-request retry suppression, 17-driver gate
#   CANDIDATE=c62 bash reproduce.sh                    # single-bank response-ready timing; 17-driver gate
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
GEN_PIN=""
# FREEZE_PIN: the commit whose harness tree the candidate's freeze was checked against when its blocks ran. Later
# edits to frozen harness files (protocol/hw_vepa, rearm_01/hw) would otherwise fail the freeze check of a measured
# baseline; step 6 then checks the configs in a detached worktree at FREEZE_PIN.
FREEZE_PIN=""
TWO_READ=0
RELAY_READ=0
EVIDENCE_TIER="historical software endpoint profile (offline only)"
BUILD_SUFFIX="$CANDIDATE"
case "$CANDIDATE" in
  c68) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry --read-handshake --headroom --relay --relay-sbo --relay-ts --response-ready-timing --strip-telemetry"
       TWO_READ=1; RELAY_READ=1; BUILD_SUFFIX=c68_sdk9132
       SOURCE_SHA=825b7e6da3c24dd1705d43f1d921dbd2184a99fe47f75f4de1d2d372e160b289
       EVIDENCE_TIER="SEL-751 candidate without switch telemetry; visible CLRT is reported data" ;;
  c67) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry --read-handshake --headroom --relay --relay-sbo --relay-ts --response-ready-timing"
       TWO_READ=1; RELAY_READ=1; BUILD_SUFFIX=c67_sdk9132
       GEN_PIN=a4ebbecbe; GATE_PIN=a4ebbecbe; FREEZE_PIN=a4ebbecbe
       SOURCE_SHA=e8565de7c317124b2c3377ce02fc2a932d4f86e1625ed224ec9fed550d6d2ec1
       EVIDENCE_TIER="deadline-free response-ready SEL-751 candidate; qualification requires all 17 models and physical evidence" ;;
  c62) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry --read-handshake --headroom --relay --relay-sbo --relay-ts --response-ready-timing"
       TWO_READ=1; RELAY_READ=1; BUILD_SUFFIX=c62_sdk9132; GEN_PIN=4004c7b62; GATE_PIN=4004c7b62
       SOURCE_SHA=569f6461d7f587e225513623dc953c26b568892300370d074de6b2f2ed341b27
       EVIDENCE_TIER="single-bank response-ready SEL-751 candidate; requires all 17 models and physical evidence" ;;
  c60) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry --read-handshake --headroom --relay --relay-sbo --relay-ts --response-ready-timing"
       TWO_READ=1; RELAY_READ=1; BUILD_SUFFIX=c60_sdk9132; GEN_PIN=a08b52f7d
       SOURCE_SHA=618724c6a7a4ff44f0bbc7ff99c9adf1fa52cb33248fc15ecd58e4787eb7ec72
       EVIDENCE_TIER="rejected response-ready candidate: response completion split across stages 7 and 8" ;;
  c52) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry --read-handshake --headroom --relay --relay-sbo --relay-ts"
       TWO_READ=1; RELAY_READ=1; BUILD_SUFFIX=c52_sdk9132; FREEZE_PIN=ee7b7f47f; GEN_PIN=ee7b7f47f; GATE_PIN=ee7b7f47f
       SOURCE_SHA=8f37f70240ffa03daf887349e5e52a6abf7e32eb4b43ec559e35077902e3dce4
       EVIDENCE_TIER="integrated SEL-751 timestamp profile; qualification requires recorded gates" ;;
  c51) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry --read-handshake --headroom --relay --relay-sbo --relay-ts"
       TWO_READ=1; RELAY_READ=1; BUILD_SUFFIX=c51_sdk9132
       SOURCE_SHA=3fe7087971f165942f8af1c94cceab5d0bef163d5d83708957d03fc270065598
       EVIDENCE_TIER="integrated SEL-751 timestamp profile; qualification requires recorded gates" ;;
  c50) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry --read-handshake --headroom --relay --relay-sbo --relay-ts"
       TWO_READ=1; RELAY_READ=1; BUILD_SUFFIX=c50_sdk9132
       SOURCE_SHA=1c4138ede50aaea8a662f0fba4db6b6dac2916cad46679b5d16599d34f67f43b
       EVIDENCE_TIER="integrated SEL-751 timestamp profile; qualification requires recorded gates" ;;
  c49) GEN_ARGS="--policy --c3 cimg --shapes passthrough --two-read --reduce --ack-retry --read-handshake --headroom --relay --relay-sbo --relay-ts"
       TWO_READ=1; RELAY_READ=1; BUILD_SUFFIX=c49_sdk9132
       SOURCE_SHA=995386583fc373e9a770b22e50194b49c246afc0e1c5789ccd099d9ae0b31bc2
       EVIDENCE_TIER="integrated SEL-751 timestamp profile; qualification requires recorded gates" ;;
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
  *) echo "unknown CANDIDATE $CANDIDATE (c68 | c67 | c62 | c60 | c52 | c51 | c50 | c49 | c48 | c30 | c26 | c25 | c24 | c12 | c20 | b08)"; exit 2 ;;
esac
BUILD="$STAGE/ctl_timing_01/evidence/m12p_$BUILD_SUFFIX"
FREEZE="$BUILD/freeze_v3.json"
if [ "$CANDIDATE" = c68 ]; then FREEZE="$BUILD/freeze_v3_04.json"; fi
if [ "${1:-}" = --candidate-info ]; then
  [ $# = 1 ] || { echo "--candidate-info takes no other arguments" >&2; exit 2; }
  python3 - "$CANDIDATE" "$BUILD" "$SOURCE_SHA" "$GEN_ARGS" "$EVIDENCE_TIER" "$FREEZE_PIN" "$GEN_PIN" "$GATE_PIN" <<'EOF'
import json, shlex, sys
print(json.dumps(dict(candidate=sys.argv[1], build=sys.argv[2], source_sha256=sys.argv[3],
                     generator_args=shlex.split(sys.argv[4]), evidence_tier=sys.argv[5],
                     freeze_pin=sys.argv[6] or None, generator_pin=sys.argv[7] or None, gate_pin=sys.argv[8] or None), indent=2))
EOF
  exit 0
fi
if [ $# -gt 0 ] && [ "$1" != --readout ]; then
  echo "unknown argument $1 (use --candidate-info or --readout BLOCK_DIR CONFIG [ARMS])" >&2
  exit 2
fi
if [ "$CANDIDATE" = c68 ] && [ ! -f "$FREEZE" ]; then
  echo "required current freeze missing: $FREEZE" >&2
  exit 1
fi
SCRATCH="$(mktemp -d)"
REPO="$(git -C "$HERE" rev-parse --show-toplevel)"
cleanup() {
  for w in pin fpin hpin; do
    if [ -d "$SCRATCH/$w" ]; then git -C "$REPO" worktree remove --force "$SCRATCH/$w" >/dev/null 2>&1 || true; fi
  done
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
GEN_STAGE="$STAGE"
if [ -n "$GEN_PIN" ]; then
  git -C "$REPO" worktree add --detach "$SCRATCH/fpin" "$GEN_PIN" >/dev/null
  GEN_STAGE="$SCRATCH/fpin/${STAGE#$REPO/}"
  echo "regenerating the frozen baseline with its recorded generator at $GEN_PIN"
fi
python3 "$GEN_STAGE/m12_fullsize/make_m12.py" "$SCRATCH/m12p" $GEN_ARGS >/dev/null
got="$(sha256sum "$SCRATCH/m12p/response_only.p4" | cut -d' ' -f1)"
[ "$got" = "$SOURCE_SHA" ] || { echo "regenerated source $got != $SOURCE_SHA"; exit 1; }
echo "source $got"
if [ "$CANDIDATE" = c48 ] || [ "$CANDIDATE" = c49 ] || [ "$CANDIDATE" = c50 ] || [ "$CANDIDATE" = c51 ] || [ "$CANDIDATE" = c52 ] || [ "$CANDIDATE" = c60 ] || [ "$CANDIDATE" = c62 ] || [ "$CANDIDATE" = c67 ] || [ "$CANDIDATE" = c68 ]; then
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
  if [ "$GATE_PIN" = "$GEN_PIN" ] && [ -d "$SCRATCH/fpin" ]; then
    PIN_STAGE="$SCRATCH/fpin/${STAGE#$REPO/}"
  else
    git -C "$REPO" worktree add --detach "$SCRATCH/pin" "$GATE_PIN" >/dev/null
    PIN_STAGE="$SCRATCH/pin/${STAGE#$REPO/}"
  fi
  echo "recomputing at $GATE_PIN (detached worktree, removed on exit)"
  python3 "$PIN_STAGE/read_complete_01/restore_retained_logs.py"
  (cd "$PIN_STAGE/ctl_timing_01" && python3 model_summary.py "evidence/m12p_$BUILD_SUFFIX" --v3 --enforce | tail -1)
else
  python3 "$HERE/restore_retained_logs.py"
  (cd "$STAGE/ctl_timing_01" && python3 model_summary.py "evidence/m12p_$BUILD_SUFFIX" --v3 --enforce | tail -1)
fi

step "6. freeze: every block config belongs to the frozen candidate"
F_HERE="$HERE"; F_HW="$HW"; F_BUILD="$BUILD"; F_FREEZE="$FREEZE"
if [ -n "$FREEZE_PIN" ]; then
  if [ ! -d "$SCRATCH/fpin" ]; then
    git -C "$REPO" worktree add --detach "$SCRATCH/fpin" "$FREEZE_PIN" >/dev/null
  fi
  F_HERE="$SCRATCH/fpin/${HERE#$REPO/}"; F_HW="$SCRATCH/fpin/${HW#$REPO/}"; F_BUILD="$SCRATCH/fpin/${BUILD#$REPO/}"
  F_FREEZE="$F_BUILD/freeze_v3.json"
  echo "checking the measured baseline's freeze at $FREEZE_PIN (detached worktree, removed on exit)"
fi
if [ -f "$F_FREEZE" ] && ls "$F_HERE"/hw/config/rc01_m12p_${CANDIDATE}_*.json >/dev/null 2>&1; then
  # Compiler artifacts (compile_*/out/) are git-ignored by design (case4_architecture/build.py). In a fresh checkout
  # they are absent, so the freeze binding of the artifact BYTES cannot be checked without recompiling; that case is
  # reported as NOT CHECKED (never as ok). Any changed file, or any missing file outside compile_*/out/, fails.
  for c in "$F_HERE"/hw/config/rc01_m12p_${CANDIDATE}_*.json; do
    # A later block set has its own freeze beside freeze_v3.json (c52: freeze_v3_ref2.json for reference_rest);
    # check each config against the live freeze that names it.
    f="$F_FREEZE"
    for g in "$F_BUILD"/freeze_v3_*.json; do
      case "$g" in *SUPERSEDED*|*UNUSED*) continue ;; esac
      [ -f "$g" ] && grep -q "/$(basename "$c")\"" "$g" && f="$g"
    done
    if out="$(python3 "$F_HW/freeze_gate.py" check "$f" --config "$c" 2>&1)"; then
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
  echo "no freeze yet for m12p_$CANDIDATE (configs present: $(ls "$F_HERE"/hw/config/rc01_m12p_${CANDIDATE}_*.json 2>/dev/null | wc -l)); skipping"
fi

if [ "$CANDIDATE" = c68 ]; then
  step "6b. original c68 before/after freeze at its recorded revision 789092c2d"
  git -C "$REPO" worktree add --detach "$SCRATCH/hpin" 789092c2d >/dev/null
  python3 - "$REPO" "$SCRATCH/hpin" "${STAGE#$REPO/}" "${HW#$REPO/}" <<'EOF'
import hashlib, json, os, pathlib, shutil, subprocess, sys
live, pinned = map(pathlib.Path, sys.argv[1:3])
stage = pathlib.Path(sys.argv[3])
build = stage / 'ctl_timing_01/evidence/m12p_c68_sdk9132'
freeze = json.loads((pinned / build / 'freeze_v3_03.json').read_text())
# The original commit omitted these compiler artifacts. Supply only the exact
# frozen bytes now retained by this checkout; never substitute code files.
for name, record in freeze['files'].items():
    destination = pinned / name
    if destination.exists():
        continue
    if '/compile_local/out/' not in name:
        raise SystemExit('missing historical source: ' + name)
    source = live / name
    if hashlib.sha256(source.read_bytes()).hexdigest() != record['sha256']:
        raise SystemExit('historical compiler artifact hash differs: ' + name)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
# Step 5 verified these raw bytes against Git-retained archives and manifests.
# Link them into this disposable checkout for the original gate's read-only checks.
summary = json.loads((pinned / build / 'model_summary_v3.json').read_text())
for run in summary['latest_by_driver'].values():
    directory = stage / 'ctl_timing_01/evidence' / run
    for source in [live / directory / 'model.out'] + sorted((live / directory).glob('model_*.log')):
        destination = pinned / directory / source.name
        if not destination.exists():
            os.link(source, destination)
for name in freeze['candidate']['configs']:
    subprocess.run([sys.executable, str(pinned / sys.argv[4] / 'freeze_gate.py'), 'check',
                    str(pinned / build / 'freeze_v3_03.json'), '--config', str(pinned / name)], check=True)
EOF
fi

if [ "$CANDIDATE" = c67 ] || [ "$CANDIDATE" = c68 ]; then
  step "7. physical evidence: reproduce recorded wire reports, including recorded failures"
  "$PY312" "$HERE/analysis/replay_physical.py" --candidate "$CANDIDATE" --out "$SCRATCH/physical_replay.json"
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
