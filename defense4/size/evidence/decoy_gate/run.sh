#!/usr/bin/env bash
#
# Build + run the configured-inert-decoy endpoint gate (Part A endpoint, Part A
# master acceptance, Part B READ) against the local opendnp3-community stack, and
# capture raw evidence. SOFTWARE ONLY: no hardware, no physical relay, no switch.
#
# Resolution rules (no hardcoded absolute home paths):
#   * opendnp3 source: $OPENDNP3_SRC, else a sibling of the repo root named
#     opendnp3-community / opendnp3, else error.
#   * build dir: $OPENDNP3_SRC/build (OUT of this repo's tracked tree).
#
# The three vendored test .cpp and the handler .h under this directory are the
# source of truth; they are copied into the opendnp3 unit-test tree, wired into
# the unittests target idempotently, built, and run. Nothing is pushed anywhere.
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
BUILD="${OPENDNP3_BUILD:-$SRC/build}"
UNIT="$SRC/cpp/tests/unit"
echo "opendnp3 source : $SRC"
echo "build dir       : $BUILD"

# 1) vendor sources into the opendnp3 unit-test tree (idempotent copy)
cp -f "$SCRIPT_DIR/src/DecoyGateCommandHandler.h"                "$UNIT/utils/DecoyGateCommandHandler.h"
cp -f "$SCRIPT_DIR/tests/TestDecoyGateEndpoint.cpp"              "$UNIT/TestDecoyGateEndpoint.cpp"
cp -f "$SCRIPT_DIR/tests/TestDecoyGateMasterAcceptance.cpp"      "$UNIT/TestDecoyGateMasterAcceptance.cpp"
cp -f "$SCRIPT_DIR/tests/TestDecoyGateReadSize.cpp"              "$UNIT/TestDecoyGateReadSize.cpp"

# 2) wire them into the unittests target (idempotent)
python3 - "$UNIT/CMakeLists.txt" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()
hdr = "./utils/DecoyGateCommandHandler.h"
srcs = ["./TestDecoyGateEndpoint.cpp", "./TestDecoyGateMasterAcceptance.cpp", "./TestDecoyGateReadSize.cpp"]
changed = False
if hdr not in s:
    s = s.replace("./utils/APDUHelpers.h",
                  "    " + hdr + "\n    ./utils/APDUHelpers.h", 1)
    changed = True
if srcs[0] not in s:
    inject = "".join("    %s\n" % x for x in srcs)
    s = s.replace("    ./main.cpp\n", "    ./main.cpp\n" + inject, 1)
    changed = True
if changed:
    open(p, "w").write(s)
    print("CMakeLists.txt: injected decoy-gate sources")
else:
    print("CMakeLists.txt: already wired")
PY

# 3) configure if needed, then build the unittests target incrementally
if [[ ! -f "$BUILD/CMakeCache.txt" ]]; then
    cmake -S "$SRC" -B "$BUILD" -DDNP3_TESTS=ON >"$OUT/build.log" 2>&1
fi
echo "building unittests ..."
cmake --build "$BUILD" --target unittests -j"$(nproc)" >>"$OUT/build.log" 2>&1
BIN="$BUILD/cpp/tests/unit/unittests"
echo "binary          : $BIN"

# 4) environment + input provenance
{
    echo "date_utc            : $(date -u +%FT%TZ)"
    echo "host                : $(uname -a)"
    echo "g++                 : $(g++ --version | head -1)"
    echo "cmake               : $(cmake --version | head -1)"
    echo "opendnp3 describe   : $(git -C "$SRC" describe --tags 2>/dev/null || echo n/a)"
    echo "opendnp3 HEAD       : $(git -C "$SRC" rev-parse HEAD 2>/dev/null || echo n/a)"
    echo "unittests mtime     : $(date -u -r "$BIN" +%FT%TZ)"
} >"$OUT/env.txt"

sha256sum \
    "$SCRIPT_DIR/src/DecoyGateCommandHandler.h" \
    "$SCRIPT_DIR/tests/TestDecoyGateEndpoint.cpp" \
    "$SCRIPT_DIR/tests/TestDecoyGateMasterAcceptance.cpp" \
    "$SCRIPT_DIR/tests/TestDecoyGateReadSize.cpp" \
    | sed "s#$SCRIPT_DIR/##" >"$OUT/sha256.txt"

# 5) run each suite, capture raw output (a clean FAIL is still recorded)
run_suite() {
    local filter="$1" file="$2"
    echo "== $filter ==" | tee "$OUT/$file"
    if "$BIN" "$filter" -s 2>&1 | tee -a "$OUT/$file"; then
        echo "SUITE_EXIT=0" | tee -a "$OUT/$file"
    else
        echo "SUITE_EXIT=$?" | tee -a "$OUT/$file"
    fi
}
run_suite "DecoyGateEndpointTestSuite*"   partA_endpoint.txt
run_suite "DecoyGateMasterTestSuite*"     partA_master.txt
run_suite "DecoyGateReadTestSuite*"       partB_read.txt

# 6) vendor the CMake wiring as a patch (the .cpp/.h are vendored under this dir)
git -C "$SRC" diff -- cpp/tests/unit/CMakeLists.txt >"$SCRIPT_DIR/patches/CMakeLists_unittests.patch" || true

echo "done. evidence in $OUT/"
