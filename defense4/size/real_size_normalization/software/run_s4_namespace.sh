#!/usr/bin/env bash
# Gate S4 rootless network-namespace runner for the packet-preserving fixed-cell
# bridge. Builds the four-namespace topology, runs both L2 shims across a cell
# link with an independent observer, and drives native DNP3/TCP endpoints.
#
#   master ns  m_ep 10.44.0.1/24  02:44:00:00:00:01
#     <-> vision shim ns   v_in | v_out 02:00:00:00:00:01
#     <-> parent test link  l_left | l_right   (cell_link + observer here)
#     <-> ufispace shim ns  u_out 02:00:00:00:00:02 | u_in
#     <-> relay ns  r_ep 10.44.0.2/24  02:44:00:00:00:02
#
# Software only: rootless user+net namespaces, veth, AF_PACKET. No Vision, no
# Tofino, no P4/BFRT, no physical relay. See S4_SOFTWARE_SPEC.md.
set -euo pipefail

MODE="pipeline"
OUT=""
EXCHANGES=5
CONNECTIONS=1
DURATION=20
TIMEOUT=90
FAULT_PLAN=""

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; }

# Outer invocation: parse args, then re-exec once into a fresh rootless
# user+net namespace (the parent test netns), passing state through the env.
if [[ "${S4_INNER:-}" != "1" ]]; then
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --mode) MODE="$2"; shift 2;;
      --out) OUT="$2"; shift 2;;
      --exchanges) EXCHANGES="$2"; shift 2;;
      --connections) CONNECTIONS="$2"; shift 2;;
      --duration) DURATION="$2"; shift 2;;
      --timeout) TIMEOUT="$2"; shift 2;;
      --fault-plan) FAULT_PLAN="$2"; shift 2;;
      -h|--help) usage; exit 0;;
      *) echo "unknown argument: $1" >&2; exit 2;;
    esac
  done
  if [[ -z "$OUT" ]]; then echo "--out DIR is required" >&2; exit 2; fi
  REPO="$(cd "$(dirname "$0")/../../../.." && pwd)"
  mkdir -p "$OUT"
  exec unshare --user --map-root-user --net --fork \
    env S4_INNER=1 S4_REPO="$REPO" S4_OUT="$OUT" S4_MODE="$MODE" \
        S4_EXCHANGES="$EXCHANGES" S4_CONNECTIONS="$CONNECTIONS" \
        S4_DURATION="$DURATION" S4_TIMEOUT="$TIMEOUT" S4_FAULT_PLAN="$FAULT_PLAN" \
    bash "$0"
fi

# ---------------------------------------------------------------------------
# Inner: mapped-root inside a fresh parent network namespace.
# ---------------------------------------------------------------------------
REPO="$S4_REPO"; OUT="$S4_OUT"; MODE="$S4_MODE"
EXCHANGES="$S4_EXCHANGES"; CONNECTIONS="$S4_CONNECTIONS"
DURATION="$S4_DURATION"; TIMEOUT="$S4_TIMEOUT"
cd "$REPO"
export PYTHONPATH="$REPO"
mkdir -p "$OUT"
PY=python3
EP=defense4.size.real_size_normalization.software.dnp3_endpoint
SHIM=defense4.size.real_size_normalization.software.l2_shim
LINK=defense4.size.real_size_normalization.software.cell_link
CAP=defense4.size.real_size_normalization.software.packet_capture

HOLDERS=()
cleanup() {
  local rc=$?
  # Components are already stopped and waited for by the time we reach here;
  # only the idle netns holders remain. Do not broadcast a second kill that
  # could race a component's evidence flush.
  for pid in "${HOLDERS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  if [[ -n "${KEYFILE:-}" && -f "${KEYFILE:-}" ]]; then rm -f "$KEYFILE"; fi
  return $rc
}
trap cleanup EXIT

hold_ns() { unshare --net sleep "$((TIMEOUT + 30))" >/dev/null 2>&1 & echo $!; }
ns() { local pid="$1"; shift; nsenter -t "$pid" -n -F "$@"; }
harden() {  # $1=pid $2=dev : best-effort IPv6 + offload disable
  ns "$1" sysctl -w "net.ipv6.conf.$2.disable_ipv6=1" >/dev/null 2>&1 || true
  ns "$1" ethtool -K "$2" tx off rx off tso off gso off gro off >/dev/null 2>&1 || true
}

# --- baseline mode: direct veth master<->relay, no shims (latency reference) ---
if [[ "$MODE" == "baseline" ]]; then
  MASTER_NS=$(hold_ns); HOLDERS+=("$MASTER_NS")
  RELAY_NS=$(hold_ns);  HOLDERS+=("$RELAY_NS")
  sleep 0.2
  ip link add m_ep type veth peer name r_ep
  ip link set m_ep netns "$MASTER_NS"
  ip link set r_ep netns "$RELAY_NS"
  ns "$MASTER_NS" ip link set m_ep address 02:44:00:00:00:01
  ns "$RELAY_NS"  ip link set r_ep address 02:44:00:00:00:02
  ns "$MASTER_NS" ip addr add 10.44.0.1/24 dev m_ep
  ns "$RELAY_NS"  ip addr add 10.44.0.2/24 dev r_ep
  harden "$MASTER_NS" m_ep; harden "$RELAY_NS" r_ep
  ns "$MASTER_NS" ip link set lo up; ns "$MASTER_NS" ip link set m_ep up
  ns "$RELAY_NS"  ip link set lo up; ns "$RELAY_NS"  ip link set r_ep up
  ns "$RELAY_NS" $PY -m "$EP" --role relay --host 10.44.0.2 --port 20000 \
    --exchanges "$EXCHANGES" --connections "$CONNECTIONS" \
    --log "$OUT/relay.jsonl" >"$OUT/relay.json" 2>"$OUT/relay.err" &
  RELAY_PID=$!
  sleep 0.5
  for i in $(seq 1 "$CONNECTIONS"); do
    ns "$MASTER_NS" $PY -m "$EP" --role master --host 10.44.0.2 --port 20000 \
      --exchanges "$EXCHANGES" --log "$OUT/master.$i.jsonl" \
      >"$OUT/master.$i.json" 2>>"$OUT/master.err"
  done
  wait "$RELAY_PID" || true
  echo "baseline complete"; exit 0
fi

# --- pipeline mode: four namespaces + two shims + link + observer ------------
MASTER_NS=$(hold_ns);  HOLDERS+=("$MASTER_NS")
VISION_NS=$(hold_ns);  HOLDERS+=("$VISION_NS")
UFI_NS=$(hold_ns);     HOLDERS+=("$UFI_NS")
RELAY_NS=$(hold_ns);   HOLDERS+=("$RELAY_NS")
sleep 0.2

# veth pairs
ip link add m_ep type veth peer name v_in       # master <-> vision (trusted)
ip link add v_out type veth peer name l_left    # vision <-> parent link (observed)
ip link add u_out type veth peer name l_right   # ufispace <-> parent link (observed)
ip link add u_in type veth peer name r_ep       # ufispace <-> relay (trusted)

ip link set m_ep netns "$MASTER_NS"
ip link set v_in netns "$VISION_NS"
ip link set v_out netns "$VISION_NS"
ip link set u_out netns "$UFI_NS"
ip link set u_in netns "$UFI_NS"
ip link set r_ep netns "$RELAY_NS"
# l_left, l_right stay in the parent test namespace.

# MACs: endpoints carry inner addresses; shims carry the observed-side outer MACs.
ns "$MASTER_NS" ip link set m_ep address 02:44:00:00:00:01
ns "$RELAY_NS"  ip link set r_ep address 02:44:00:00:00:02
ns "$VISION_NS" ip link set v_out address 02:00:00:00:00:01
ns "$UFI_NS"    ip link set u_out address 02:00:00:00:00:02

# IPs only on the two endpoints.
ns "$MASTER_NS" ip addr add 10.44.0.1/24 dev m_ep
ns "$RELAY_NS"  ip addr add 10.44.0.2/24 dev r_ep

harden "$MASTER_NS" m_ep; harden "$RELAY_NS" r_ep
harden "$VISION_NS" v_in; harden "$VISION_NS" v_out
harden "$UFI_NS" u_in;    harden "$UFI_NS" u_out
harden "$$" l_left >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.l_left.disable_ipv6=1 >/dev/null 2>&1 || true
sysctl -w net.ipv6.conf.l_right.disable_ipv6=1 >/dev/null 2>&1 || true

# bring everything up
ns "$MASTER_NS" ip link set lo up; ns "$MASTER_NS" ip link set m_ep up
ns "$RELAY_NS"  ip link set lo up; ns "$RELAY_NS"  ip link set r_ep up
ns "$VISION_NS" ip link set lo up; ns "$VISION_NS" ip link set v_in up; ns "$VISION_NS" ip link set v_out up
ns "$UFI_NS"    ip link set lo up; ns "$UFI_NS"    ip link set u_in up; ns "$UFI_NS"    ip link set u_out up
ip link set lo up; ip link set l_left up; ip link set l_right up

# runtime key: 64 random bytes, 0600, unlinked at teardown; never logged.
KEYFILE="$OUT/runtime.key"
( umask 077; head -c 64 /dev/urandom > "$KEYFILE" )
chmod 600 "$KEYFILE"

START_NS=$($PY -c 'import time; print(time.monotonic_ns() + 3_000_000_000)')
READY="$OUT/ready"; mkdir -p "$READY"

# cell link bridges the observed segment in the parent namespace.
LINK_FAULT_ARG=()
if [[ -n "${S4_FAULT_PLAN:-}" ]]; then LINK_FAULT_ARG=(--fault-plan "$S4_FAULT_PLAN"); fi
$PY -m "$LINK" --iface-a l_left --iface-b l_right --duration "$DURATION" \
  --metrics-json "$OUT/link.metrics.json" --ready-file "$READY/link.ready" \
  "${LINK_FAULT_ARG[@]}" >"$OUT/link.out" 2>"$OUT/link.err" &
LINK_PID=$!

# independent observer on the Vision-side outer interface.
$PY -m "$CAP" --iface l_left --duration "$DURATION" \
  --pcap "$OUT/observer_l_left.pcap" --jsonl "$OUT/observer_l_left.jsonl" \
  --csv "$OUT/observer_l_left.csv" --metrics-json "$OUT/observer.metrics.json" \
  --ready-file "$READY/observer.ready" >"$OUT/observer.out" 2>"$OUT/observer.err" &
OBS_PID=$!

# both shims, phase-locked on the shared monotonic origin.
ns "$VISION_NS" $PY -m "$SHIM" --role vision --inner-iface v_in --outer-iface v_out \
  --key-file "$KEYFILE" --start-monotonic-ns "$START_NS" --duration-s "$DURATION" \
  --metrics-json "$OUT/vision.metrics.json" --pcap-prefix "$OUT/vision" \
  --ready-file "$READY/vision.ready" >"$OUT/vision.out" 2>"$OUT/vision.err" &
VIS_PID=$!

ns "$UFI_NS" $PY -m "$SHIM" --role ufispace --inner-iface u_in --outer-iface u_out \
  --key-file "$KEYFILE" --start-monotonic-ns "$START_NS" --duration-s "$DURATION" \
  --metrics-json "$OUT/ufispace.metrics.json" --pcap-prefix "$OUT/ufispace" \
  --ready-file "$READY/ufispace.ready" >"$OUT/ufispace.out" 2>"$OUT/ufispace.err" &
UFI_PID=$!

# wait for every component's ready file before starting endpoints.
$PY -c "
import sys
from defense4.size.real_size_normalization.software.runner_support import wait_for_ready_files
paths=['$READY/link.ready','$READY/observer.ready','$READY/vision.ready','$READY/ufispace.ready']
sys.exit(0 if wait_for_ready_files(paths, timeout_s=15) else 1)
" || { echo 'components did not become ready' >&2; exit 1; }

# relay endpoint, then master, over the cellized L2 bridge.
ns "$RELAY_NS" $PY -m "$EP" --role relay --host 10.44.0.2 --port 20000 \
  --exchanges "$EXCHANGES" --connections "$CONNECTIONS" \
  --log "$OUT/relay.jsonl" >"$OUT/relay.json" 2>"$OUT/relay.err" &
RELAY_PID=$!
sleep 0.5
MASTER_RC=0
for i in $(seq 1 "$CONNECTIONS"); do
  ns "$MASTER_NS" timeout "$TIMEOUT" $PY -m "$EP" --role master --host 10.44.0.2 --port 20000 \
    --exchanges "$EXCHANGES" --log "$OUT/master.$i.jsonl" \
    >"$OUT/master.$i.json" 2>>"$OUT/master.err" || MASTER_RC=$?
done
wait "$RELAY_PID" 2>/dev/null || true

# Drain: let the shims run a few more epochs so the final in-flight forward
# frames (last ACK/FIN captured at the trusted boundary) are cellized, carried,
# and decoded before shutdown, avoiding tail truncation of the transcript.
sleep "${S4_DRAIN:-3}"

# Stop each component by the real pid it published in its ready file (the actual
# python process, independent of nsenter/subshell wrapping), so SIGTERM always
# reaches the clean-shutdown path.
for name in vision ufispace link observer; do
  p=$(cat "$READY/$name.ready" 2>/dev/null || true)
  [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true
done
# Completion barrier: each component writes its metrics file as its LAST action
# (after flushing pcaps), so wait on those files rather than on shell pids.
$PY -c "
import sys
from defense4.size.real_size_normalization.software.runner_support import wait_for_ready_files
m=['$OUT/vision.metrics.json','$OUT/ufispace.metrics.json','$OUT/link.metrics.json','$OUT/observer.metrics.json']
sys.exit(0 if wait_for_ready_files(m, timeout_s=20) else 1)
" || echo 'warning: some component metrics were not flushed in time' >&2
for pid in "$VIS_PID" "$UFI_PID" "$LINK_PID" "$OBS_PID"; do wait "$pid" 2>/dev/null || true; done
echo "pipeline complete master_rc=$MASTER_RC"
echo "$MASTER_RC" > "$OUT/master_rc.txt"
exit 0
