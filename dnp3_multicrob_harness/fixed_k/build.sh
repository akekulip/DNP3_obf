#!/bin/bash
# Reproducible build of the hardened persistent SBO master. Does NOT commit the binary.
# OpenDNP3: prebuilt libopendnp3.so + headers from the opendnp3-community tree.
set -euo pipefail
REPO="${OPENDNP3_REPO:-/home/philip/Projects/opendnp3-community}"
HERE="$(cd "$(dirname "$0")" && pwd)"
LIB="$REPO/build/cpp/lib"
INC="$REPO/cpp/lib/include"
[ -f "$LIB/libopendnp3.so" ] || { echo "libopendnp3.so not found under $LIB"; exit 1; }
g++ -std=c++14 -O2 -Wall -I "$INC" "$HERE/nsbo_master.cpp" \
    -L "$LIB" -lopendnp3 -lpthread -Wl,-rpath,"$LIB" -o "$HERE/nsbo_master"
echo "built $HERE/nsbo_master"
echo "  g++:       $(g++ --version | head -1)"
echo "  libopendnp3.so sha256: $(sha256sum "$LIB/libopendnp3.so" | cut -d' ' -f1)"
