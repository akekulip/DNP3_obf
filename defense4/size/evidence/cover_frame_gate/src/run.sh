#!/usr/bin/env bash
#
# Build + run the DNP3 cover-frame gate against the REAL OpenDNP3 community fork, SOFTWARE ONLY
# (no hardware, no relay, no switch). Two standalone Catch targets are added out-of-tree:
#
#   coverframetests  (test_cover_frame_gate.cpp)  — COMPONENT test:
#        "OpenDNP3 3.1.2 link-layer address-filter compatibility"
#        real LinkLayerParser + LinkLayer address filter, MOCK transport above.
#
#   fulltxntests     (test_full_transaction.cpp)  — FULL SOFTWARE TRANSACTION:
#        real master MContext <-> real outstation OContext, wired in one process, with the real
#        link address filter on the delivery path and optional cover-frame injection.
#
# Isolation + safety:
#   * A DEDICATED build dir (build-coverframe, gitignored by the fork) is used so a parallel
#     session's `build/` and its uncommitted edits are not disturbed.
#   * Each target compiles ONLY our file(s) + the needed unit-test util .cpp + Catch main; it
#     does NOT compile any other session's test files.
#   * The fork's unit CMakeLists is backed up (in its CURRENT state, preserving other-session
#     edits), appended to, then RESTORED on exit. Our two vendored .cpp are removed on exit.
#     Nothing is committed or pushed to the fork.
#
# No absolute paths: the size-probe worktree root is resolved with `git rev-parse`; the fork is
# its sibling `opendnp3-community`. All evidence files are path-sanitized before the script ends.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATE_DIR="$(dirname "$SCRIPT_DIR")"                 # .../cover_frame_gate
EVID="$GATE_DIR/evidence"
WORKTREE_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
OPENDNP3="$(dirname "$WORKTREE_ROOT")/opendnp3-community"
BUILD="${COVER_BUILD_DIR:-$OPENDNP3/build-coverframe}"
UNIT="$OPENDNP3/cpp/tests/unit"
CML="$UNIT/CMakeLists.txt"

export COVER_FRAME_OUT="$EVID"
mkdir -p "$EVID"

echo "worktree_root = $WORKTREE_ROOT"
echo "opendnp3      = $OPENDNP3"
echo "build_dir     = $BUILD"
[ -f "$OPENDNP3/CMakeLists.txt" ] || { echo "ERROR: OpenDNP3 fork not found at $OPENDNP3"; exit 2; }

cleanup() {
    # Always restore the fork: remove our vendored tests, restore the (other-session) CMakeLists.
    [ -f "$CML.coverframe.bak" ] && mv -f "$CML.coverframe.bak" "$CML"
    rm -f "$UNIT/TestCoverFrameGate.cpp" "$UNIT/TestFullTransaction.cpp"
}
trap cleanup EXIT

# 1. Vendor both test sources into the fork's unit tree (temporary).
cp "$SCRIPT_DIR/test_cover_frame_gate.cpp" "$UNIT/TestCoverFrameGate.cpp"
cp "$SCRIPT_DIR/test_full_transaction.cpp" "$UNIT/TestFullTransaction.cpp"

# 2. Append two standalone Catch targets (back up the CURRENT CMakeLists first).
cp "$CML" "$CML.coverframe.bak"
cat >> "$CML" <<'CMAKE'

# --- TEMPORARY: cover-frame gate experiments (added out-of-tree; removed by run.sh) ---
add_executable(coverframetests
    ./main.cpp
    ./TestCoverFrameGate.cpp
    ./utils/LinkLayerTest.cpp
)
target_compile_features(coverframetests PRIVATE cxx_std_14)
target_link_libraries(coverframetests PRIVATE catch dnp3mocks)
target_include_directories(coverframetests PRIVATE ./ ../../lib/src)

add_executable(fulltxntests
    ./main.cpp
    ./TestFullTransaction.cpp
    ./utils/LinkLayerTest.cpp
    ./utils/MasterTestFixture.cpp
    ./utils/OutstationTestObject.cpp
    ./utils/BufferHelpers.cpp
    ./utils/CopyableBuffer.cpp
)
target_compile_features(fulltxntests PRIVATE cxx_std_14)
target_link_libraries(fulltxntests PRIVATE catch dnp3mocks)
target_include_directories(fulltxntests PRIVATE ./ ../../lib/src)
CMAKE

# Save the CMake change as a vendored patch (evidence).
diff -u "$CML.coverframe.bak" "$CML" > "$EVID/cmake_unittests.patch" || true

# 3. Configure + build only our two targets.
echo "=== configuring ($BUILD) ==="
cmake -S "$OPENDNP3" -B "$BUILD" -DDNP3_TESTS=ON 2>&1 | tee "$EVID/cmake_configure.log"
echo "=== building coverframetests + fulltxntests ==="
cmake --build "$BUILD" --target coverframetests fulltxntests -j"$(nproc)" 2>&1 | tee "$EVID/build.log"

# 4. Run the component test.
CF_BIN="$BUILD/cpp/tests/unit/coverframetests"
echo "=== running coverframetests ==="
set +e
"$CF_BIN" 2>&1 | tee "$EVID/cpp_test_stdout.txt"
CF_RC=${PIPESTATUS[0]}
set -e

# 5. Run the full-transaction test.
FT_BIN="$BUILD/cpp/tests/unit/fulltxntests"
echo "=== running fulltxntests ==="
set +e
"$FT_BIN" 2>&1 | tee "$EVID/full_transaction_stdout.txt"
FT_RC=${PIPESTATUS[0]}
set -e

# 6. Environment + version evidence (no absolute paths).
{
    echo "date_utc: $(date -u +%FT%TZ)"
    echo "os: $(uname -srmo)"
    echo "compiler: $(c++ --version | head -1)"
    echo "cmake: $(cmake --version | head -1)"
    echo "python: $(python3 --version 2>&1)"
    echo "opendnp3_repo: <sibling of worktree: opendnp3-community>"
    echo "opendnp3_version: 3.1.2 (community fork of dnp3/opendnp3)"
    echo "opendnp3_commit: $(git -C "$OPENDNP3" rev-parse HEAD)"
    echo "opendnp3_branch: $(git -C "$OPENDNP3" rev-parse --abbrev-ref HEAD 2>/dev/null || echo detached)"
} > "$EVID/env.txt"

# 7. Independent Python generator / CRC verifier (frames + sizes) and the convergence demo.
echo "=== running gen_and_measure.py ==="
set +e
python3 "$SCRIPT_DIR/gen_and_measure.py" 2>&1 | tee "$EVID/gen_and_measure_stdout.txt"
PY_RC=${PIPESTATUS[0]}
echo "=== running convergence.py ==="
python3 "$SCRIPT_DIR/convergence.py" 2>&1 | tee "$EVID/convergence_stdout.txt"
CV_RC=${PIPESTATUS[0]}
set -e

# 8. Sanitize absolute paths out of every evidence file (fail-closed on any /home/ leak).
echo "=== sanitizing evidence paths ==="
for f in "$EVID"/*; do
    [ -f "$f" ] || continue
    sed -i -e "s#$BUILD#<BUILD>#g" -e "s#$OPENDNP3#<OPENDNP3>#g" -e "s#$WORKTREE_ROOT#<REPO_ROOT>#g" \
           -e "s#/home/[A-Za-z0-9_.-]*#<HOME>#g" "$f" 2>/dev/null || true
done
if grep -rIl "/home/" "$EVID" >/dev/null 2>&1; then
    echo "ERROR: absolute /home path leaked into evidence:"; grep -rIn "/home/" "$EVID" | head
    LEAK=1
else
    LEAK=0
fi

# 9. sha256 of sources + key machine-readable outputs (relative paths only).
{
    for p in \
        "$SCRIPT_DIR/test_cover_frame_gate.cpp" \
        "$SCRIPT_DIR/test_full_transaction.cpp" \
        "$SCRIPT_DIR/gen_and_measure.py" \
        "$SCRIPT_DIR/convergence.py" \
        "$SCRIPT_DIR/run.sh" \
        "$EVID/results_table.csv" \
        "$EVID/full_transaction_results.csv" \
        "$EVID/convergence_sizes.csv" \
        "$EVID/frames_hex.json" \
        "$EVID/convergence_result.json"; do
        [ -f "$p" ] && sha256sum "$p" | sed -e "s#$SCRIPT_DIR#../src#g" -e "s#$EVID#.#g"
    done
} > "$EVID/sha256sums.txt"

echo "=== done: coverframe_rc=$CF_RC fulltxn_rc=$FT_RC py_rc=$PY_RC convergence_rc=$CV_RC path_leak=$LEAK ==="
# Nonzero from any Catch run means a locked prediction/invariant failed (a real finding, reported).
[ "$LEAK" -eq 0 ] || exit 3
[ "$CF_RC" -eq 0 ] || exit "$CF_RC"
[ "$FT_RC" -eq 0 ] || exit "$FT_RC"
[ "$PY_RC" -eq 0 ] || exit "$PY_RC"
exit "$CV_RC"
