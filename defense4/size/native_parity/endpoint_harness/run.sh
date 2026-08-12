#!/usr/bin/env bash
#
# Native-parity endpoint harness — SBO (native multi-CROB CommandSet) + READ size derivation
# + endpoint semantics, software-only evidence.
#
# SOFTWARE ONLY: no hardware, no physical relay, no switch, no networking. Crafted APDU bytes
# and native opendnp3 CommandSet serializations are driven straight into a REAL opendnp3 master
# context and a REAL opendnp3 outstation context (the production SELECT/OPERATE + SBO state
# machine, the CommandSet serializer, and the static-read path).
#
# ISOLATION: this does NOT build inside the shared opendnp3 checkout and does NOT modify it. It
# rsyncs a private, throwaway COPY of the opendnp3 source into a work dir OUTSIDE any tracked
# tree, adds ONE standalone CMake target there, and builds only that target. The shared "fork"
# is left exactly as it was; nothing is pushed and no git state is touched.
#
# Resolution rules (no hardcoded home paths):
#   * opendnp3 source (read-only): $OPENDNP3_SRC, else a sibling of the repo root named
#     opendnp3-community / opendnp3.
#   * work/build dir (isolated):   $NP_WORK, else a fresh mktemp dir.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$SCRIPT_DIR/evidence"
mkdir -p "$OUT"

# repo root = endpoint_harness -> native_parity -> size -> defense4 -> <repo>
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

resolve_src() {
    if [[ -n "${OPENDNP3_SRC:-}" && -f "$OPENDNP3_SRC/cpp/tests/unit/CMakeLists.txt" ]]; then
        echo "$OPENDNP3_SRC"; return 0
    fi
    local parent; parent="$(cd "$REPO_ROOT/.." && pwd)"
    for cand in "$parent/opendnp3-community" "$parent/opendnp3"; do
        if [[ -f "$cand/cpp/tests/unit/CMakeLists.txt" ]]; then echo "$cand"; return 0; fi
    done
    echo "ERROR: opendnp3 source not found. Set OPENDNP3_SRC to an opendnp3 checkout." >&2
    return 1
}

SRC="$(resolve_src)"
WORK="${NP_WORK:-$(mktemp -d -t native_parity.XXXXXX)}"
ISO="$WORK/opendnp3-iso"
BUILD="$ISO/build-np"
UNIT="$ISO/cpp/tests/unit"
echo "opendnp3 source (read-only) : $SRC"
echo "isolated work dir           : $WORK"

# 1) private isolated COPY of the source (exclude build dirs + .git); shared tree untouched
mkdir -p "$ISO"
rsync -a --delete --exclude='build' --exclude='build-*' --exclude='.git' "$SRC/" "$ISO/"

# 2) vendor the native-parity sources into the isolated copy's unit-test tree
cp -f "$SCRIPT_DIR/outstation/NativeParityCommandHandler.h" "$UNIT/utils/NativeParityCommandHandler.h"
cp -f "$SCRIPT_DIR/master/NativeParityPlan.h"               "$UNIT/utils/NativeParityPlan.h"
cp -f "$SCRIPT_DIR/tests/NativeParityHelpers.h"             "$UNIT/utils/NativeParityHelpers.h"
cp -f "$SCRIPT_DIR/tests/TestNativeParitySBO.cpp"           "$UNIT/TestNativeParitySBO.cpp"
cp -f "$SCRIPT_DIR/tests/TestNativeParitySemantics.cpp"     "$UNIT/TestNativeParitySemantics.cpp"
cp -f "$SCRIPT_DIR/tests/TestNativeParityReadSize.cpp"      "$UNIT/TestNativeParityReadSize.cpp"

# 3) add ONE standalone target to the isolated copy (idempotent). Compiles only Catch2 main +
#    the test utils + the three native-parity suites, so it is independent of concurrent edits.
python3 - "$UNIT/CMakeLists.txt" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
if "add_executable(native_parity" not in s:
    s += '''
# ---- native-parity endpoint gate: STANDALONE target (isolated) --------------------------
set(native_parity_src
    ./main.cpp
    ./utils/APDUHelpers.cpp
    ./utils/APDUHexBuilders.cpp
    ./utils/BufferHelpers.cpp
    ./utils/CopyableBuffer.cpp
    ./utils/DNPHelpers.cpp
    ./utils/LinkHex.cpp
    ./utils/LinkLayerTest.cpp
    ./utils/MasterTestFixture.cpp
    ./utils/MockTransportSegment.cpp
    ./utils/OutstationTestObject.cpp
    ./utils/ProtocolUtil.cpp
    ./utils/TransportTestObject.cpp
    ./TestNativeParitySBO.cpp
    ./TestNativeParitySemantics.cpp
    ./TestNativeParityReadSize.cpp
)
add_executable(native_parity ${native_parity_src})
target_compile_features(native_parity PRIVATE cxx_std_14)
target_link_libraries(native_parity PRIVATE catch dnp3mocks)
target_include_directories(native_parity PRIVATE ./ ../../lib/src)
set_target_properties(native_parity PROPERTIES FOLDER cpp/tests)
'''
    open(p, "w").write(s)
    print("standalone native_parity target added to isolated copy")
else:
    print("standalone native_parity target already present")
PY

# 4) configure + build ONLY the standalone target in the isolated copy
if [[ ! -f "$BUILD/CMakeCache.txt" ]]; then
    cmake -S "$ISO" -B "$BUILD" -DDNP3_TESTS=ON -DCMAKE_BUILD_TYPE=Release >"$OUT/build.log" 2>&1
fi
echo "building native_parity (isolated) ..."
cmake --build "$BUILD" --target native_parity -j"$(nproc)" >>"$OUT/build.log" 2>&1
BIN="$BUILD/cpp/tests/unit/native_parity"
echo "binary                      : $BIN"

# 5) environment + input provenance
{
    echo "date_utc            : $(date -u +%FT%TZ)"
    echo "host                : $(uname -a)"
    echo "g++                 : $(g++ --version | head -1)"
    echo "cmake               : $(cmake --version | head -1)"
    echo "opendnp3 describe   : $(git -C "$SRC" describe --tags 2>/dev/null || echo n/a)"
    echo "opendnp3 HEAD       : $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo n/a)"
    echo "build model         : ISOLATED copy of the source; shared opendnp3 tree untouched"
    echo "native_parity mtime : $(date -u -r "$BIN" +%FT%TZ)"
} >"$OUT/env.txt"

sha256sum \
    "$SCRIPT_DIR/outstation/NativeParityCommandHandler.h" \
    "$SCRIPT_DIR/master/NativeParityPlan.h" \
    "$SCRIPT_DIR/tests/NativeParityHelpers.h" \
    "$SCRIPT_DIR/tests/TestNativeParitySBO.cpp" \
    "$SCRIPT_DIR/tests/TestNativeParitySemantics.cpp" \
    "$SCRIPT_DIR/tests/TestNativeParityReadSize.cpp" \
    | sed "s#$SCRIPT_DIR/##" >"$OUT/sha256.txt"

# 6) run each suite, capture raw output (a clean FAIL is still recorded); track overall pass
FAILED=0
run_suite() {
    local filter="$1" file="$2"
    echo "== $filter ==" | tee "$OUT/$file"
    if "$BIN" "$filter" -s 2>&1 | tee -a "$OUT/$file"; then
        echo "SUITE_EXIT=0" | tee -a "$OUT/$file"
    else
        echo "SUITE_EXIT=$?" | tee -a "$OUT/$file"
        FAILED=1
    fi
}
run_suite "NativeParitySBOTestSuite*"       sbo.txt
run_suite "NativeParitySemanticsTestSuite*" semantics.txt
run_suite "NativeParityReadTestSuite*"      read.txt

# 7) collect committed ##VEC## byte-vectors and derive the size tables
grep -h '^##VEC##' "$OUT/sbo.txt" "$OUT/read.txt" | sed 's/^##VEC## //' >"$OUT/vectors.jsonl" || true
python3 "$SCRIPT_DIR/derive_sizes.py" "$OUT/vectors.jsonl" "$OUT/derived_sizes.json" | tee "$OUT/derived_sizes.txt"

echo "done. evidence in $OUT/  (isolated build under $WORK)"
if [[ "$FAILED" -ne 0 ]]; then
    echo "OVERALL: FAIL (a suite reported failures)"; exit 1
fi
echo "OVERALL: PASS"
