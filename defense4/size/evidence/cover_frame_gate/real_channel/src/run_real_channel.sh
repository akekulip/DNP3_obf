#!/usr/bin/env bash
#
# REAL persistent-stack DNP3-over-TCP loopback evidence (software only; no hardware, no relay,
# no switch). Compiles rt_loopback.cpp OUT-OF-TREE against the prebuilt community-fork library
# and runs it on 127.0.0.1, capturing the live loopback with dumpcap and dissecting with tshark.
#
# This does NOT modify the OpenDNP3 fork at all (no vendored test, no CMakeLists edit): it links
# the already-built libopendnp3.so. If that library is absent it builds ONLY the `opendnp3`
# target into an isolated build dir. Nothing is committed or pushed.
#
# Paths: the fork is resolved as the sibling `opendnp3-community` of the size-probe repo root, or
# from $OPENDNP3_DIR if set. No absolute paths are written into any evidence file.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RC_DIR="$(dirname "$SCRIPT_DIR")"                 # .../cover_frame_gate/real_channel
EVID="$RC_DIR/evidence"
# repo root = 6 dirs up from src: real_channel/cover_frame_gate/evidence/size/defense4/<root>
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../../../.." && pwd)"
OPENDNP3="${OPENDNP3_DIR:-$(dirname "$REPO_ROOT")/opendnp3-community}"
mkdir -p "$EVID"

[ -f "$OPENDNP3/CMakeLists.txt" ] || { echo "ERROR: OpenDNP3 fork not found at $OPENDNP3"; exit 2; }
echo "opendnp3 = $OPENDNP3"

# --- locate (or build) the prebuilt library + dependency includes ---
FORK_BUILD=""
for b in build build-verify build-merged build-coverframe; do
    [ -f "$OPENDNP3/$b/cpp/lib/libopendnp3.so" ] && { FORK_BUILD="$OPENDNP3/$b"; break; }
done
if [ -z "$FORK_BUILD" ]; then
    echo "no prebuilt libopendnp3.so found; configuring an isolated build (this is slow)"
    FORK_BUILD="$(mktemp -d)/odnp3-build"
    cmake -S "$OPENDNP3" -B "$FORK_BUILD" -DDNP3_TESTS=OFF >/dev/null
    cmake --build "$FORK_BUILD" --target opendnp3 -j"$(nproc)" >/dev/null
fi
LIBDIR="$FORK_BUILD/cpp/lib"
INC_ODNP3="$OPENDNP3/cpp/lib/include"
INC_SER="$FORK_BUILD/_deps/ser4cpp-src/src"
INC_EXE="$FORK_BUILD/_deps/exe4cpp-src/src"
echo "fork_build = $FORK_BUILD"

# --- compile rt_loopback OUT-OF-TREE into an isolated /tmp build dir ---
BUILD="$(mktemp -d)"
BIN="$BUILD/rt_loopback"
g++ -std=c++14 -O2 -pthread \
    -I"$INC_ODNP3" -I"$INC_SER" -I"$INC_EXE" \
    "$SCRIPT_DIR/rt_loopback.cpp" -o "$BIN" \
    -L"$LIBDIR" -lopendnp3 -Wl,-rpath,"$LIBDIR"
echo "built $BIN"

# --- helper: capture one loopback run and dissect it ---
run_capture() {
    local tag="$1" port="$2"; shift 2
    local pcap="$EVID/cap_${tag}.pcapng"
    rm -f "$pcap"
    dumpcap -q -i lo -f "tcp port $port" -w "$pcap" -a duration:12 >/dev/null 2>&1 &
    local dpid=$!
    sleep 0.6
    # env for the harness is passed by the caller via exported RT_* vars
    RT_SERVER_PORT="$port" RT_TAG="$tag" "$@" "$BIN" 2>/dev/null | grep '^{' > "$EVID/rt_${tag}.json"
    sleep 0.6
    kill "$dpid" 2>/dev/null; wait "$dpid" 2>/dev/null
    echo "  $tag: $(cat "$EVID/rt_${tag}.json")" >&2
    echo "$pcap"   # ONLY the pcap path on stdout (captured by the caller)
}

echo "=== 1) BASELINE: READ + SBO, one integrity fragment ==="
BPCAP="$(run_capture baseline 20801 env RT_NPOINTS=4 RT_MAXTXFRAG=2048 RT_DO_READ=1 RT_DO_SBO=1)"
# TCP control-flow map (handshake / ACKs / data / FIN / RST)
tshark -r "$BPCAP" -o tcp.relative_sequence_numbers:true \
  -T fields -e frame.number -e tcp.srcport -e tcp.dstport -e tcp.flags.str \
  -e tcp.seq -e tcp.ack -e tcp.len -E header=y -E separator='  ' 2>/dev/null > "$EVID/tcp_flow_baseline.txt"
# DNP3 dissection of the response fragment (real link CRC + transport control)
tshark -r "$BPCAP" -d "tcp.port==20801,dnp3" -Y "frame.number==6" -O dnp3 2>/dev/null \
  | grep -E 'Data Link Layer|Control:|Destination|Source|checksum|Transport Control|Final|First|Sequence:|Application Layer|Application Control' \
  > "$EVID/dnp3_baseline.txt"

echo "=== 2) FRAGMENTATION: 40 points -> response spans multiple transport segments ==="
FPCAP="$(run_capture frag 20805 env RT_NPOINTS=40 RT_MAXTXFRAG=2048 RT_DO_READ=1 RT_DO_SBO=0)"
tshark -r "$FPCAP" -d "tcp.port==20805,dnp3" -Y "tcp.srcport==20805 && dnp3" -O dnp3 2>/dev/null \
  | grep -E 'Data Link Layer, Len|Transport Control|Final:|First:|Sequence:|Reassembled DNP length|Application Layer|Application Control' \
  > "$EVID/transport_reassembly_frag.txt"
# out->master TCP segmentation of the reassembled response
tshark -r "$FPCAP" -Y "tcp.srcport==20805 && tcp.len>0" \
  -T fields -e frame.number -e tcp.seq -e tcp.len -E header=y 2>/dev/null > "$EVID/tcp_segments_frag.txt"

echo "=== 3) environment ==="
{
    echo "date_utc: $(date -u +%FT%TZ)"
    echo "os: $(uname -srmo)"
    echo "compiler: $(c++ --version | head -1)"
    echo "cmake: $(cmake --version | head -1)"
    echo "tshark: $(tshark --version 2>/dev/null | head -1)"
    echo "opendnp3_repo: <sibling of size-probe: opendnp3-community>"
    echo "opendnp3_version: 3.1.2 (community fork of dnp3/opendnp3)"
    echo "opendnp3_commit: $(git -C "$OPENDNP3" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "harness: rt_loopback.cpp (out-of-tree; links prebuilt libopendnp3.so; fork unmodified)"
} > "$EVID/env.txt"

# --- sanitize any absolute path out of the TEXT evidence (binary pcaps skipped) ---
for f in "$EVID"/*.txt "$EVID"/*.json; do
    [ -f "$f" ] || continue
    sed -i -e "s#$BUILD#<BUILD>#g" -e "s#$FORK_BUILD#<FORK_BUILD>#g" -e "s#$OPENDNP3#<OPENDNP3>#g" \
           -e "s#$REPO_ROOT#<REPO_ROOT>#g" -e "s#/home/[A-Za-z0-9_.-]*#<HOME>#g" "$f" 2>/dev/null || true
done
LEAK=0
grep -rIl "/home/" "$EVID"/*.txt "$EVID"/*.json >/dev/null 2>&1 && { echo "ERROR: /home leak"; LEAK=1; }

# --- sha256 of sources + key evidence (relative names only) ---
{
    for p in "$SCRIPT_DIR/rt_loopback.cpp" "$SCRIPT_DIR/cover_injector.py" "$SCRIPT_DIR/run_real_channel.sh" \
             "$EVID/rt_baseline.json" "$EVID/rt_frag.json" \
             "$EVID/tcp_flow_baseline.txt" "$EVID/transport_reassembly_frag.txt"; do
        [ -f "$p" ] && sha256sum "$p" | sed -e "s#$SCRIPT_DIR#../src#g" -e "s#$EVID#.#g"
    done
} > "$EVID/sha256sums.txt"

rm -rf "$BUILD"
echo "=== done (path_leak=$LEAK). evidence in $EVID ==="
exit "$LEAK"
