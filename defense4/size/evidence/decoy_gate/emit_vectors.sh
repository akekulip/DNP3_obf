#!/usr/bin/env bash
#
# emit_vectors.sh — rebuild the decoy-gate C++ suites (READ + SBO) with JSON-vector emission and
# extract the committed machine-readable vectors the observer scorer parses. SOFTWARE ONLY: no
# hardware, no relay, no switch, no networking, no git. Isolated build in /tmp; the shared
# opendnp3 checkout is never modified.
#
# Resolution (no hardcoded home paths):
#   * opendnp3 source (read-only): $OPENDNP3_SRC, else sibling opendnp3-community / opendnp3.
#   * work dir: $DECOY_GATE_WORK, else reuse an existing /tmp/decoy_gate.* with a build cache
#     (fast incremental relink), else a fresh mktemp dir (cold build).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$SCRIPT_DIR/out/vectors"
mkdir -p "$OUT"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

resolve_src() {
    if [[ -n "${OPENDNP3_SRC:-}" && -f "$OPENDNP3_SRC/cpp/tests/unit/CMakeLists.txt" ]]; then
        echo "$OPENDNP3_SRC"; return 0
    fi
    local parent; parent="$(cd "$REPO_ROOT/.." && pwd)"
    for cand in "$parent/opendnp3-community" "$parent/opendnp3"; do
        [[ -f "$cand/cpp/tests/unit/CMakeLists.txt" ]] && { echo "$cand"; return 0; }
    done
    echo "ERROR: opendnp3 source not found. Set OPENDNP3_SRC." >&2; return 1
}
SRC="$(resolve_src)"

pick_work() {
    if [[ -n "${DECOY_GATE_WORK:-}" ]]; then echo "$DECOY_GATE_WORK"; return 0; fi
    local d
    for d in /tmp/decoy_gate.*; do
        [[ -f "$d/opendnp3-iso/build-decoy/CMakeCache.txt" ]] && { echo "$d"; return 0; }
    done
    mktemp -d -t decoy_gate.XXXXXX
}
WORK="$(pick_work)"
ISO="$WORK/opendnp3-iso"
BUILD="$ISO/build-decoy"
UNIT="$ISO/cpp/tests/unit"
echo "opendnp3 source (read-only) : $SRC"
echo "isolated work dir           : $WORK"

# ensure the isolated copy exists (cold path); the shared tree is untouched
if [[ ! -d "$UNIT" ]]; then
    mkdir -p "$ISO"
    rsync -a --delete --exclude='build' --exclude='build-*' --exclude='.git' "$SRC/" "$ISO/"
fi

# vendor the (modified) decoy-gate sources into the isolated copy's unit-test tree
cp -f "$SCRIPT_DIR/src/DecoyGateCommandHandler.h"           "$UNIT/utils/DecoyGateCommandHandler.h"
cp -f "$SCRIPT_DIR/tests/TestDecoyGateEndpoint.cpp"         "$UNIT/TestDecoyGateEndpoint.cpp"
cp -f "$SCRIPT_DIR/tests/TestDecoyGateMasterAcceptance.cpp" "$UNIT/TestDecoyGateMasterAcceptance.cpp"
cp -f "$SCRIPT_DIR/tests/TestDecoyGateReadSize.cpp"         "$UNIT/TestDecoyGateReadSize.cpp"
cp -f "$SCRIPT_DIR/tests/TestDecoyGateRoundTrip.cpp"        "$UNIT/TestDecoyGateRoundTrip.cpp"

# add the standalone target if missing (idempotent; unittests target left pristine)
if ! grep -q "add_executable(decoy_gate" "$UNIT/CMakeLists.txt"; then
    cat "$SCRIPT_DIR/patches/standalone_target.patch" | patch -p1 -d "$ISO" >/dev/null 2>&1 || true
fi

# configure (only if no cache) + incremental build of just the standalone target
if [[ ! -f "$BUILD/CMakeCache.txt" ]]; then
    cmake -S "$ISO" -B "$BUILD" -DDNP3_TESTS=ON -DCMAKE_BUILD_TYPE=Release >"$OUT/build.log" 2>&1
fi
echo "building decoy_gate (isolated, incremental) ..."
cmake --build "$BUILD" --target decoy_gate -j"$(nproc)" >>"$OUT/build.log" 2>&1
BIN="$BUILD/cpp/tests/unit/decoy_gate"
echo "binary                      : $BIN"

# run READ + SBO suites, capture full stdout
"$BIN" "DecoyGateReadTestSuite*"      --success >"$OUT/read_run_stdout.txt" 2>&1 || true
"$BIN" "DecoyGateRoundTripTestSuite*" --success >"$OUT/sbo_run_stdout.txt"  2>&1 || true

# split the ##VEC## lines into read_vectors.json / sbo_vectors.json with provenance
OPENDNP3_HEAD="$(cd "$SRC" && git rev-parse HEAD 2>/dev/null || echo unknown)"
python3 "$SCRIPT_DIR/../observer_scoring/split_vectors.py" \
    --read "$OUT/read_run_stdout.txt" --sbo "$OUT/sbo_run_stdout.txt" --outdir "$OUT" \
    --src "$SRC" --head "$OPENDNP3_HEAD" --iso "$ISO"

echo "vectors written to          : $OUT"
ls -l "$OUT"/*.json
