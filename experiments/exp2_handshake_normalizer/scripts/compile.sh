#!/usr/bin/env bash
set -uo pipefail
export SDE=/home/philip/bf-sde-9.13.1
export SDE_INSTALL=$SDE/install
export PATH=$SDE_INSTALL/bin:$PATH
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}
HERE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$HERE/p4src/handshake_normalizer.p4"
OUT="$HERE/build"
rm -rf "$OUT"; mkdir -p "$OUT"
echo "bf-p4c: $(bf-p4c --version 2>&1 | head -1)"
echo "src sha256: $(sha256sum "$SRC" | cut -d' ' -f1)"
echo "cmd: bf-p4c --std p4-16 --target tofino --arch tna -g -o $OUT $SRC"
bf-p4c --std p4-16 --target tofino --arch tna -g -o "$OUT" "$SRC" 2>"$OUT/compile.stderr" 1>"$OUT/compile.stdout"
rc=$?
echo "exit: $rc"
echo "--- stderr (errors/warnings) ---"; cat "$OUT/compile.stderr"
exit $rc
