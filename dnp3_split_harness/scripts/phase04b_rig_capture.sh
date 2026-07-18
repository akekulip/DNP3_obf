#!/usr/bin/env bash
# phase04b_rig_capture.sh -- start/stop the authoritative capture on the Vision observer NIC.
# The DNP3 filter lives here so no filter string crosses the SSH command line. tcpdump needs root
# (run under sudo). setsid fully detaches tcpdump so the SSH session returns immediately.
#   sudo bash scripts/phase04b_rig_capture.sh start /abs/out.pcap
#   sudo bash scripts/phase04b_rig_capture.sh stop  /abs/out.pcap
set -uo pipefail
IFACE="${IFACE:-eno1}"; PORT=20000; PIDF=/tmp/phase04b_rig_cap.pid
case "${1:-}" in
  start)
    OUT="$2"; mkdir -p "$(dirname "$OUT")"; rm -f "$OUT"
    setsid tcpdump -i "$IFACE" -w "$OUT" "tcp port $PORT" </dev/null >/tmp/phase04b_rig_cap.log 2>&1 &
    echo $! > "$PIDF"; sleep 1
    if kill -0 "$(cat "$PIDF")" 2>/dev/null; then echo "CAP_STARTED pid=$(cat "$PIDF") out=$OUT"
    else echo "CAP_FAILED"; cat /tmp/phase04b_rig_cap.log; exit 3; fi
    ;;
  stop)
    OUT="${2:-/dev/null}"
    [ -f "$PIDF" ] && kill "$(cat "$PIDF")" 2>/dev/null || true
    sleep 1
    echo "CAP_STOPPED bytes=$(stat -c%s "$OUT" 2>/dev/null || echo 0)"
    ;;
  *) echo "usage: $0 start|stop <out.pcap>"; exit 2 ;;
esac
