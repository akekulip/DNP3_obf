#!/usr/bin/env bash
# phase04b_local_e2e.sh -- PRIVILEGED local end-to-end DCRN Gate-B run on an isolated veth+netns.
# Server (phase05_rig_replay) runs in a network namespace on vdcrn1 with DCRN attached; client runs in
# the root namespace; the AUTHORITATIVE capture is on the client-side veth vdcrn0 (external-observer
# vantage, sec 6). Measures whether DCRN's EDT stamps are ENFORCED on real dual-case traffic. Fully
# self-contained and trap-cleaned. corrective.md sec 10 (Gate B), sec 6 (vantage).
#   sudo BPF_OBJ=/abs/phase04b_dcrn.o SPEC=/abs/spec.json OUT=/abs/cap.pcap bash scripts/phase04b_local_e2e.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; HARNESS="$(cd "$DIR/.." && pwd)"
: "${BPF_OBJ:?set BPF_OBJ}"; : "${SPEC:?set SPEC}"; : "${OUT:=/tmp/phase04b_e2e/dcrn_fixed.pcap}"
NS=dcrn-srv; R=vdcrn0; S=vdcrn1; RIP=10.244.0.1; SIP=10.244.0.2; PORT=20000
mkdir -p "$(dirname "$OUT")"

cleanup() {
  ip netns pids "$NS" 2>/dev/null | xargs -r kill 2>/dev/null || true
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$R" 2>/dev/null || true
  rm -f /sys/fs/bpf/tc/globals/dcrn_ctr /sys/fs/bpf/tc/globals/dcrn_flows 2>/dev/null || true
}
trap cleanup EXIT
cleanup   # idempotent start

echo "[e2e] setup veth $R (root, $RIP) <-> $S ($NS, $SIP)"
ip netns add "$NS"
ip link add "$R" type veth peer name "$S"
ip link set "$S" netns "$NS"
ip addr add "$RIP/24" dev "$R"; ip link set "$R" up
ip netns exec "$NS" ip addr add "$SIP/24" dev "$S"
ip netns exec "$NS" ip link set "$S" up
ip netns exec "$NS" ip link set lo up

echo "[e2e] attach DCRN (fixed) on server-side $S inside $NS + fq root (EDT enforce)"
# Do qdisc + BOTH filter attaches in ONE netns-exec shell so the pinned maps (.pinning=2 ->
# /sys/fs/bpf/tc/globals/) are shared between the ingress and egress programs. Separate `ip netns
# exec` calls get separate mount namespaces (separate bpffs), which would NOT share the maps.
# (On the real rig root netns this quirk does not arise; a plain attach shares the pinned maps.)
ip netns exec "$NS" bash -c "
  mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
  tc qdisc replace dev $S root fq
  tc qdisc add dev $S clsact
  tc filter add dev $S ingress bpf da obj $BPF_OBJ sec ingress
  tc filter add dev $S egress  bpf da obj $BPF_OBJ sec egress
  tc filter show dev $S egress | sed 's/^/[e2e]   /'
"

echo "[e2e] start authoritative capture on client-side $R -> $OUT"
if command -v tcpdump >/dev/null 2>&1; then
  tcpdump -i "$R" -w "$OUT" "tcp port $PORT" >/tmp/phase04b_e2e/cap.log 2>&1 & CAP=$!
else
  dumpcap -i "$R" -f "tcp port $PORT" -w "$OUT" >/tmp/phase04b_e2e/cap.log 2>&1 & CAP=$!
fi
sleep 1
kill -0 "$CAP" 2>/dev/null || { echo "[e2e] CAPTURE FAILED:"; cat /tmp/phase04b_e2e/cap.log; }

echo "[e2e] start replay server in $NS (native per-profile structure)"
ip netns exec "$NS" python3 "$HARNESS/phase05_rig_replay.py" --role server --spec "$SPEC" --iface "$S" \
   >/tmp/phase04b_e2e/server.log 2>&1 & SRV=$!
sleep 3
echo "[e2e] server listening?"; ip netns exec "$NS" ss -ltn 2>/dev/null | grep -E ":$PORT" || echo "[e2e]   (nothing on :$PORT)"
echo "[e2e] server.log tail:"; tail -5 /tmp/phase04b_e2e/server.log 2>/dev/null | sed 's/^/[e2e]   /' || true

echo "[e2e] run replay client (root ns) -> $SIP"
python3 "$HARNESS/phase05_rig_replay.py" --role client --spec "$SPEC" --hulk-ip "$SIP" \
   | tee /tmp/phase04b_e2e/client.json || true

sleep 1; kill "$CAP" 2>/dev/null || true; wait "$CAP" 2>/dev/null || true
kill "$SRV" 2>/dev/null || true
echo "[e2e] capture -> $OUT ; client result in /tmp/phase04b_e2e/client.json"
