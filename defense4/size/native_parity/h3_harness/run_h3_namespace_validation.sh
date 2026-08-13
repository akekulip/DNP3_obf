#!/bin/bash
# run_h3_namespace_validation.sh -- offline, namespace-to-namespace H3 validation (NO switch, NO relay).
#
# Builds two SEPARATE network namespaces connected by a veth pair, rootless (via user+net namespaces,
# no sudo), disables TCP timestamps in both, runs the H3 software outstation in one namespace and the
# H3 software master in the other, and captures both veth ends on ONE host kernel clock.
#
#   master ns (parent)  10.9.0.1  veth_m <----> veth_o  10.9.0.2  outstation ns (PID-held child)
#
# SINGLE-CLOCK METHOD: both tcpdumps run on this one host; packet timestamps come from the same host
# kernel (SO_TIMESTAMP) regardless of namespace, so cross-interface deltas are on one clock.
#
# Usage: run_h3_namespace_validation.sh <OUTDIR> [N_TRANSACTIONS] [APP_DELAY_MS]
set -euo pipefail

HARNESS_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="${1:?usage: run_h3_namespace_validation.sh <OUTDIR> [N] [APP_DELAY_MS]}"
N="${2:-25}"
APP_DELAY_MS="${3:-5}"
mkdir -p "$OUTDIR"

if [ -z "${H3_IN_NS:-}" ]; then
  # Re-exec the whole script inside a fresh user+net+pid+mount namespace where we are mapped-root.
  export H3_IN_NS=1 HARNESS_DIR OUTDIR N APP_DELAY_MS
  exec unshare --user --map-root-user --net --fork --pid --mount-proc "$0" "$OUTDIR" "$N" "$APP_DELAY_MS"
fi

# ---- we are now mapped-root inside the MASTER network namespace ----
SETUP_LOG="$OUTDIR/setup.log"
: > "$SETUP_LOG"
log() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$SETUP_LOG"; }

export PYTHONPATH="$HARNESS_DIR"
PY=python3

cleanup() {
  set +e
  [ -n "${OPID:-}" ] && kill -TERM "$OPID" 2>/dev/null
  sleep 0.4
  [ -n "${MTCP:-}" ] && kill "$MTCP" 2>/dev/null
  [ -n "${OTCP:-}" ] && kill "$OTCP" 2>/dev/null
  [ -n "${CPID:-}" ] && kill "$CPID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

log "master ns: bringing up lo, disabling tcp timestamps"
ip link set lo up
sysctl -w net.ipv4.tcp_timestamps=0 >/dev/null

# Hold the outstation network namespace open in a child process (joined by PID, no /run/netns).
setsid unshare --net -- sleep 100000 &
CPID=$!
sleep 0.4
log "outstation ns holder PID=$CPID"

# veth pair: veth_m stays in master ns, veth_o is moved into the outstation ns by PID.
ip link add veth_m type veth peer name veth_o
ip link set veth_o netns "$CPID"
ip addr add 10.9.0.1/24 dev veth_m
ip link set veth_m up
nsenter -t "$CPID" -n sysctl -w net.ipv4.tcp_timestamps=0 >/dev/null
nsenter -t "$CPID" -n ip link set lo up
nsenter -t "$CPID" -n ip addr add 10.9.0.2/24 dev veth_o
nsenter -t "$CPID" -n ip link set veth_o up

log "master-ns   tcp_timestamps=$(cat /proc/sys/net/ipv4/tcp_timestamps)"
log "outstat-ns  tcp_timestamps=$(nsenter -t "$CPID" -n cat /proc/sys/net/ipv4/tcp_timestamps)"
nsenter -t "$CPID" -n ping -c1 -W1 10.9.0.1 >/dev/null 2>&1 && log "veth link up (ping OK)" || log "WARN ping failed"

# Captures FIRST (must catch the SYN / SYN-ACK). dumpcap works rootless in the userns; tcpdump does
# not (its privilege drop / setgroups is denied in a single-mapping user namespace).
log "starting captures with dumpcap (single host kernel clock)"
dumpcap -q -i veth_m -w "$OUTDIR/master_facing.pcap" -f tcp 2>"$OUTDIR/capture_master.log" &
MTCP=$!
nsenter -t "$CPID" -n dumpcap -q -i veth_o -w "$OUTDIR/outstation_facing.pcap" -f tcp \
  2>"$OUTDIR/capture_outstation.log" &
OTCP=$!
sleep 1.0

# Outstation in the outstation namespace.
log "starting outstation (outstation ns)"
nsenter -t "$CPID" -n env PYTHONPATH="$HARNESS_DIR" "$PY" "$HARNESS_DIR/h3_outstation.py" \
  --bind 10.9.0.2 --port 20000 --app-delay-ms "$APP_DELAY_MS" \
  --counters "$OUTDIR/outstation_counters.json" --ready-file "$OUTDIR/.outstation_ready" \
  >"$OUTDIR/outstation.log" 2>&1 &
OPID=$!
for _ in $(seq 1 50); do [ -f "$OUTDIR/.outstation_ready" ] && break; sleep 0.1; done
log "outstation ready"

# Master in the master namespace.
log "running master: $N SELECT->OPERATE SBO transactions"
"$PY" "$HARNESS_DIR/h3_master.py" --dst 10.9.0.2 --port 20000 --src 10.9.0.1 \
  --n "$N" --log "$OUTDIR/master_txn_log.json" >"$OUTDIR/master.log" 2>&1

log "master done; stopping outstation (dumps final counters)"
kill -TERM "$OPID" 2>/dev/null || true
wait "$OPID" 2>/dev/null || true
sleep 0.8   # let tcpdump -U flush the tail
kill "$MTCP" "$OTCP" 2>/dev/null || true
wait "$MTCP" "$OTCP" 2>/dev/null || true

log "counters: $(cat "$OUTDIR/outstation_counters.json" | tr -d '\n' | tr -s ' ')"
log "captures: master=$(ls -l "$OUTDIR/master_facing.pcap" | awk '{print $5}')B outstation=$(ls -l "$OUTDIR/outstation_facing.pcap" | awk '{print $5}')B"
log "DONE"
