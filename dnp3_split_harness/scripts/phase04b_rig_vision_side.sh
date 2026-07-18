#!/usr/bin/env bash
# phase04b_rig_vision_side.sh -- runs ON Vision (the master/observer). Captures the authoritative
# external-observer trace on Vision's NIC while replaying the DNP3 client against Hulk for one
# condition. The DNP3 filter lives INSIDE this script, so no BPF filter string crosses the SSH
# command line (avoids nested-quote breakage). Run under sudo (tcpdump needs root):
#   sudo OUT=/abs/cond.pcap RUNS=5 HULK_IP=10.10.54.158 SPEC=/abs/spec.json IFACE=eno1 \
#        bash scripts/phase04b_rig_vision_side.sh
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"; HARNESS="$(cd "$DIR/.." && pwd)"
: "${OUT:?set OUT}"; : "${HULK_IP:?set HULK_IP}"; : "${SPEC:?set SPEC}"
: "${RUNS:=5}"; : "${IFACE:=eno1}"; PORT=20000
mkdir -p "$(dirname "$OUT")"

tcpdump -i "$IFACE" -w "$OUT" "tcp port $PORT" >/tmp/phase04b_rig_cap.log 2>&1 &
CAP=$!
sleep 1
if ! kill -0 "$CAP" 2>/dev/null; then echo "CAPTURE_FAILED"; cat /tmp/phase04b_rig_cap.log; exit 3; fi

ok=0
for r in $(seq 1 "$RUNS"); do
  if python3 "$HARNESS/phase05_rig_replay.py" --role client --spec "$SPEC" --hulk-ip "$HULK_IP" >/dev/null 2>&1; then
    ok=$((ok + 1))
  fi
done

sleep 1
kill "$CAP" 2>/dev/null || true
wait "$CAP" 2>/dev/null || true
echo "RIG_CAPTURE_DONE out=$OUT runs_ok=$ok/$RUNS bytes=$(stat -c%s "$OUT" 2>/dev/null || echo 0)"
