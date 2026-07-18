#!/usr/bin/env bash
# phase04b_local_campaign.sh -- PRIVILEGED local paired campaign on an isolated veth+netns.
# Same source transactions/order/seed across conditions; only the loaded DCRN object changes.
# Conditions: NATIVE (no DCRN) / DCRN_FIXED / DCRN_COMMON_BOUNDED. (OLD_APPLICATION_SCHEDULER is the
# Phase-02 app-write baseline, characterized in Phase 02; DCRN's advantage is that it works below TCP.)
# Authoritative capture on the client-side veth (external-observer vantage, sec 6).
#   sudo SPEC=/abs/spec.json FIXED=/abs/phase04b_dcrn.o BOUNDED=/abs/phase04b_dcrn_bounded.o \
#        OUTDIR=/tmp/phase04b_campaign_local RUNS=3 bash scripts/phase04b_local_campaign.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; HARNESS="$(cd "$DIR/.." && pwd)"
: "${SPEC:?set SPEC}"; : "${FIXED:?set FIXED}"; : "${BOUNDED:?set BOUNDED}"
: "${OUTDIR:=/tmp/phase04b_campaign_local}"; : "${RUNS:=3}"
NS=dcrn-srv; R=vdcrn0; S=vdcrn1; RIP=10.244.0.1; SIP=10.244.0.2; PORT=20000
mkdir -p "$OUTDIR"

cleanup() {
  ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$R" 2>/dev/null || true
  rm -f /sys/fs/bpf/tc/globals/dcrn_ctr /sys/fs/bpf/tc/globals/dcrn_flows 2>/dev/null || true
}
trap cleanup EXIT
cleanup

echo "[camp] setup veth $R($RIP) <-> $S($NS,$SIP)"
ip netns add "$NS"; ip link add "$R" type veth peer name "$S"; ip link set "$S" netns "$NS"
ip addr add "$RIP/24" dev "$R"; ip link set "$R" up
ip netns exec "$NS" ip addr add "$SIP/24" dev "$S"; ip netns exec "$NS" ip link set "$S" up
ip netns exec "$NS" ip link set lo up

detach() { ip netns exec "$NS" bash -c "tc filter del dev $S ingress 2>/dev/null; tc filter del dev $S egress 2>/dev/null; rm -f /sys/fs/bpf/tc/globals/dcrn_ctr /sys/fs/bpf/tc/globals/dcrn_flows 2>/dev/null" || true; }
attach() { ip netns exec "$NS" bash -c "
  mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
  tc qdisc replace dev $S root fq; tc qdisc add dev $S clsact 2>/dev/null || true
  tc filter add dev $S ingress bpf da obj $1 sec ingress
  tc filter add dev $S egress  bpf da obj $1 sec egress"; }

run_cond() {  # $1 name  $2 bpf-obj-or-empty
  local cond="$1" obj="${2:-}"
  local cap="$OUTDIR/${cond}.pcap"
  echo "[camp] === $cond (runs=$RUNS) ==="
  detach
  ip netns exec "$NS" tc qdisc replace dev "$S" root fq
  if [ -n "$obj" ]; then attach "$obj"; fi
  tcpdump -i "$R" -w "$cap" "tcp port $PORT" >/dev/null 2>&1 & local cp=$!; sleep 1
  for r in $(seq 1 "$RUNS"); do
    ip netns exec "$NS" python3 "$HARNESS/phase05_rig_replay.py" --role server --spec "$SPEC" --iface "$S" \
       >/dev/null 2>&1 & local sv=$!; sleep 1
    python3 "$HARNESS/phase05_rig_replay.py" --role client --spec "$SPEC" --hulk-ip "$SIP" >/dev/null 2>&1 || true
    kill "$sv" 2>/dev/null || true; sleep 0.3
  done
  sleep 1; kill "$cp" 2>/dev/null || true; wait "$cp" 2>/dev/null || true
  echo "[camp]   -> $cap"
}

run_cond NATIVE ""
run_cond DCRN_FIXED "$FIXED"
run_cond DCRN_COMMON_BOUNDED "$BOUNDED"
detach
echo "[camp] campaign captures in $OUTDIR"
