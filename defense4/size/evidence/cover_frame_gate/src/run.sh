#!/usr/bin/env bash
#
# Build + run the DNP3 address-scoped cover-frame endpoint-discard experiment against the
# REAL OpenDNP3 (community fork) link layer, then run the independent Python generator/
# CRC cross-check. Software-only: no hardware, no physical relay, no switch.
#
# The OpenDNP3 fork is treated as an external, out-of-tree build dependency. This script
# adds a *temporary* standalone Catch target to its unit-test CMakeLists (compiling only
# our file + the LinkLayerTest fixture + Catch main — NONE of the other 40 unit-test
# files), builds it, runs it, then RESTORES the fork's tree to its prior state. Nothing is
# committed or pushed to the fork. A copy of the test source + the CMake patch are vendored
# into ../ (the cover_frame_gate/ evidence dir).
#
# No absolute paths: the size-probe worktree root is resolved with `git rev-parse`, and the
# OpenDNP3 fork is its sibling `opendnp3-community`.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_DIR="$(dirname "$SCRIPT_DIR")"                 # .../cover_frame_gate
EVID="$GATE_DIR/evidence"
WORKTREE_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
OPENDNP3="$(dirname "$WORKTREE_ROOT")/opendnp3-community"
BUILD="$OPENDNP3/build"
UNIT="$OPENDNP3/cpp/tests/unit"
CML="$UNIT/CMakeLists.txt"

export COVER_FRAME_OUT="$EVID"
mkdir -p "$EVID"

echo "worktree_root = $WORKTREE_ROOT"
echo "opendnp3      = $OPENDNP3"
[ -f "$OPENDNP3/CMakeLists.txt" ] || { echo "ERROR: OpenDNP3 fork not found at $OPENDNP3"; exit 2; }
[ -d "$BUILD" ] || { echo "ERROR: OpenDNP3 build dir not found at $BUILD (configure it first)"; exit 2; }

cleanup() {
    # Always restore the fork's tree, even on failure.
    [ -f "$CML.coverframe.bak" ] && mv -f "$CML.coverframe.bak" "$CML"
    rm -f "$UNIT/TestCoverFrameGate.cpp"
}
trap cleanup EXIT

# 1. Vendor the test source into the fork's unit tree (temporary).
cp "$SCRIPT_DIR/test_cover_frame_gate.cpp" "$UNIT/TestCoverFrameGate.cpp"

# 2. Append a standalone Catch target to the unit CMakeLists (temporary; back it up).
cp "$CML" "$CML.coverframe.bak"
cat >> "$CML" <<'CMAKE'

# --- TEMPORARY: cover-frame endpoint-discard gate experiment (added out-of-tree) ---
add_executable(coverframetests
    ./main.cpp
    ./TestCoverFrameGate.cpp
    ./utils/LinkLayerTest.cpp
)
target_compile_features(coverframetests PRIVATE cxx_std_14)
target_link_libraries(coverframetests PRIVATE catch dnp3mocks)
target_include_directories(coverframetests PRIVATE ./ ../../lib/src)
CMAKE

# Save the CMake change as a vendored patch (evidence).
diff -u "$CML.coverframe.bak" "$CML" > "$EVID/cmake_unittests.patch" || true

# 3. Reconfigure (so the Makefile generator learns the new target), then build only it.
echo "=== reconfiguring ==="
cmake -S "$OPENDNP3" -B "$BUILD" 2>&1 | tee "$EVID/cmake_configure.log"
echo "=== building coverframetests ==="
cmake --build "$BUILD" --target coverframetests -j"$(nproc)" 2>&1 | tee "$EVID/build.log"

# 4. Run it, capturing stdout (all cases are tagged [coverframe]).
BIN="$BUILD/cpp/tests/unit/coverframetests"
echo "=== running $BIN ==="
set +e
"$BIN" 2>&1 | tee "$EVID/cpp_test_stdout.txt"
CPP_RC=${PIPESTATUS[0]}
set -e

# 5. Environment + version evidence.
{
    echo "date_utc: $(date -u +%FT%TZ)"
    echo "os: $(uname -srmo)"
    echo "compiler: $(c++ --version | head -1)"
    echo "cmake: $(cmake --version | head -1)"
    echo "python: $(python3 --version 2>&1)"
    echo "opendnp3_repo: $OPENDNP3"
    echo "opendnp3_version: 3.1.2 (community fork of dnp3/opendnp3)"
    echo "opendnp3_commit: $(git -C "$OPENDNP3" rev-parse HEAD)"
    echo "opendnp3_branch: $(git -C "$OPENDNP3" rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)"
} > "$EVID/env.txt"

# 6. Independent Python generator / CRC verifier / size measurer / cross-check.
echo "=== running gen_and_measure.py ==="
set +e
python3 "$SCRIPT_DIR/gen_and_measure.py" 2>&1 | tee "$EVID/gen_and_measure_stdout.txt"
PY_RC=${PIPESTATUS[0]}
set -e

echo "=== done: cpp_rc=$CPP_RC py_rc=$PY_RC ==="
# The C++ Catch run returning nonzero means an INVARIANT or a locked prediction failed
# (a real finding, reported — not tuned away). Surface both return codes.
if [ "$CPP_RC" -ne 0 ]; then exit "$CPP_RC"; fi
exit "$PY_RC"
