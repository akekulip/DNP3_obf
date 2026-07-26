#!/bin/bash
# cwi.sh — run one cold/warm/idle cell with a capture that can actually see blocker frames.
#
#   ./cwi.sh --cell C1 --connections 30
#   ./cwi.sh --cell C2 --connections 20 --polls 5
#   ./cwi.sh --cell C3 --polls 100 --period-ms 400
#   ./cwi.sh --cell C4 --idle-s 5 --trials 20
#
# The capture filter admits ethertype 0x88C1 so the token-isolation check is NOT vacuous
# (directive §9). v1 captured only "host ... and tcp port 20000" and then searched that pcap for
# 0x88C1, which excluded blocker frames by construction and could never have failed.
set -o errexit -o nounset -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CELL=""; IF="${IF:-enp59s0f0np0}"; RELAY="${RELAY:-192.168.10.7}"; ARGS=()
DUR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --cell) CELL="$2"; ARGS+=("$1" "$2"); shift 2;;
    --duration) DUR="$2"; shift 2;;
    --out) OUT="$2"; shift 2;;
    -h|--help) sed -n '2,14p' "$0"; exit 0;;
    *) ARGS+=("$1"); shift;;
  esac
done
[[ -n "$CELL" ]] || { echo "need --cell C1|C2|C3|C4"; exit 2; }
OUT="${OUT:-$HERE/cwi_${CELL}.pcap}"

# estimate a capture duration long enough for the cell, unless one was given
if [[ -z "$DUR" ]]; then
  case "$CELL" in
    C1) DUR=90;; C2) DUR=180;; C3) DUR=90;; C4) DUR=900;;
  esac
fi

CAP_FILTER="(host ${RELAY} and tcp port 20000) or ether proto 0x88c1"
echo "== cell ${CELL}: capturing ${DUR}s on ${IF} -> ${OUT}"
echo "   filter: ${CAP_FILTER}"
rm -f "$OUT"
sg wireshark -c "dumpcap -i ${IF} -f '${CAP_FILTER}' -s 0 -a duration:${DUR} -w ${OUT}" \
  >"$HERE/.dumpcap_${CELL}.log" 2>&1 &
DPID=$!
cleanup() { kill "$DPID" 2>/dev/null || true; }
trap cleanup INT TERM
sleep 3

echo "== polling"
python3 "$HERE/cwi_poll.py" "${ARGS[@]}" --sidecar "$HERE/cwi_${CELL}.labels.json" || RC=$?
RC="${RC:-0}"

echo "== waiting for capture to close"
wait "$DPID" 2>/dev/null || true
ls -l "$OUT"
sha256sum "$OUT" | awk '{print "   sha256 "$1}'
echo "== poller exit=${RC}"
exit "$RC"
