#!/usr/bin/env bash
#
# Configured inert-decoy endpoint gate (SBO round trip + READ) — software-only evidence.
#
# SOFTWARE ONLY: no hardware, no physical relay, no switch, no networking. Crafted APDU bytes
# are driven straight into a REAL opendnp3 master context and a REAL opendnp3 outstation context
# (the C++ production SELECT/OPERATE + SBO state machine and static-read path).
#
# ISOLATION (important): this does NOT build inside the shared opendnp3 checkout and does NOT
# modify it. It rsyncs a private, throwaway COPY of the opendnp3 source into a work dir OUTSIDE
# any tracked tree, adds ONE standalone CMake target there, and builds only that target. So the
# build is immune to concurrent edits in the shared opendnp3 tree, and the shared tree (the
# "fork") is left exactly as it was. Nothing is pushed anywhere and no git state is touched.
#
# Resolution rules (no hardcoded absolute home paths):
#   * opendnp3 source (read-only): $OPENDNP3_SRC, else a sibling of the repo root named
#     opendnp3-community / opendnp3.
#   * work/build dir (isolated):   $DECOY_GATE_WORK, else a fresh mktemp dir.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$SCRIPT_DIR/out"
mkdir -p "$OUT" "$SCRIPT_DIR/patches"

# repo root = decoy_gate -> evidence -> size -> defense4 -> <repo>
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
WORK="${DECOY_GATE_WORK:-$(mktemp -d -t decoy_gate.XXXXXX)}"
ISO="$WORK/opendnp3-iso"
BUILD="$ISO/build-decoy"
UNIT="$ISO/cpp/tests/unit"
echo "opendnp3 source (read-only) : $SRC"
echo "isolated work dir           : $WORK"

# 1) private isolated COPY of the source (exclude build dirs + .git); the shared tree is untouched
mkdir -p "$ISO"
rsync -a --delete --exclude='build' --exclude='build-*' --exclude='.git' "$SRC/" "$ISO/"

# 2) vendor the four decoy-gate sources into the isolated copy's unit-test tree
cp -f "$SCRIPT_DIR/src/DecoyGateCommandHandler.h"           "$UNIT/utils/DecoyGateCommandHandler.h"
cp -f "$SCRIPT_DIR/tests/TestDecoyGateEndpoint.cpp"         "$UNIT/TestDecoyGateEndpoint.cpp"
cp -f "$SCRIPT_DIR/tests/TestDecoyGateMasterAcceptance.cpp" "$UNIT/TestDecoyGateMasterAcceptance.cpp"
cp -f "$SCRIPT_DIR/tests/TestDecoyGateReadSize.cpp"         "$UNIT/TestDecoyGateReadSize.cpp"
cp -f "$SCRIPT_DIR/tests/TestDecoyGateRoundTrip.cpp"        "$UNIT/TestDecoyGateRoundTrip.cpp"

# 3) add ONE standalone target to the isolated copy (idempotent). The unittests target is left
#    pristine; the decoy_gate target compiles only Catch2 main + test utils + the four suites.
python3 - "$UNIT/CMakeLists.txt" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
# defensively strip any prior injection into the unittests target (from earlier harness versions)
for line in [
    "        ./utils/DecoyGateCommandHandler.h\n",
    "    ./TestDecoyGateEndpoint.cpp\n",
    "    ./TestDecoyGateMasterAcceptance.cpp\n",
    "    ./TestDecoyGateReadSize.cpp\n",
    "    ./TestDecoyGateRoundTrip.cpp\n",
]:
    s = s.replace(line, "", 1)
if "add_executable(decoy_gate" not in s:
    s += '''
# ---- configured inert-decoy gate: STANDALONE target (isolated) --------------------------
# Compiles ONLY Catch2 main + the test utils + the four decoy-gate suites. It deliberately
# does NOT pull in the other Test*.cpp, so it is independent of any concurrent edits to the
# rest of the unit-test tree and builds fast. Software only.
set(decoy_gate_src
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
    ./TestDecoyGateEndpoint.cpp
    ./TestDecoyGateMasterAcceptance.cpp
    ./TestDecoyGateReadSize.cpp
    ./TestDecoyGateRoundTrip.cpp
)
add_executable(decoy_gate ${decoy_gate_src})
target_compile_features(decoy_gate PRIVATE cxx_std_14)
target_link_libraries(decoy_gate PRIVATE catch dnp3mocks)
target_include_directories(decoy_gate PRIVATE ./ ../../lib/src)
set_target_properties(decoy_gate PROPERTIES FOLDER cpp/tests)
'''
    open(p, "w").write(s)
    print("standalone decoy_gate target added to isolated copy")
else:
    print("standalone decoy_gate target already present")
PY

# 4) configure + build ONLY the standalone target in the isolated copy
if [[ ! -f "$BUILD/CMakeCache.txt" ]]; then
    cmake -S "$ISO" -B "$BUILD" -DDNP3_TESTS=ON -DCMAKE_BUILD_TYPE=Release >"$OUT/build.log" 2>&1
fi
echo "building decoy_gate (isolated) ..."
cmake --build "$BUILD" --target decoy_gate -j"$(nproc)" >>"$OUT/build.log" 2>&1
BIN="$BUILD/cpp/tests/unit/decoy_gate"
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
    echo "decoy_gate mtime    : $(date -u -r "$BIN" +%FT%TZ)"
} >"$OUT/env.txt"

sha256sum \
    "$SCRIPT_DIR/src/DecoyGateCommandHandler.h" \
    "$SCRIPT_DIR/tests/TestDecoyGateEndpoint.cpp" \
    "$SCRIPT_DIR/tests/TestDecoyGateMasterAcceptance.cpp" \
    "$SCRIPT_DIR/tests/TestDecoyGateReadSize.cpp" \
    "$SCRIPT_DIR/tests/TestDecoyGateRoundTrip.cpp" \
    "$SCRIPT_DIR/patches/standalone_target.patch" \
    | sed "s#$SCRIPT_DIR/##" >"$OUT/sha256.txt"

# 6) run each suite, capture raw output (a clean FAIL is still recorded)
run_suite() {
    local filter="$1" file="$2"
    echo "== $filter ==" | tee "$OUT/$file"
    if "$BIN" "$filter" -s 2>&1 | tee -a "$OUT/$file"; then
        echo "SUITE_EXIT=0" | tee -a "$OUT/$file"
    else
        echo "SUITE_EXIT=$?" | tee -a "$OUT/$file"
    fi
}
run_suite "DecoyGateRoundTripTestSuite*" partA_roundtrip.txt
run_suite "DecoyGateEndpointTestSuite*"  partA_endpoint.txt
run_suite "DecoyGateMasterTestSuite*"    partA_master.txt
run_suite "DecoyGateReadTestSuite*"      partB_read.txt

echo "done. evidence in $OUT/  (isolated build under $WORK)"
