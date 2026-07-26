#!/bin/bash
# run.sh — one measurement run: start a capture, drive the polls, leave a .pcap behind.
#
#   ./run.sh native                 20 polls, no hold      -> native.pcap
#   ./run.sh protected              20 polls, hold at G     -> protected.pcap   (asks for sudo)
#   ./run.sh native 50              50 polls
#   ./run.sh protected 50 64        50 polls, K=64 tokens
#
# Capture runs unprivileged through the 'wireshark' group; only the token injection needs root.
set -o errexit -o nounset -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE="${1:?usage: run.sh native|protected [n] [k]}"
N="${2:-20}"
K="${3:-64}"
IF="${IF:-enp59s0f0np0}"
OUT="${OUT:-$HERE/${MODE}.pcap}"
RELAY="${RELAY:-192.168.10.7}"

case "$MODE" in native|protected) ;; *) echo "mode must be native or protected"; exit 2;; esac

# capture long enough for warmup + N polls at 0.4 s, plus slack
DUR=$(python3 -c "print(int((${N}+1)*0.4 + 12))")

echo "== capturing on ${IF} for ${DUR}s -> ${OUT}"
rm -f "$OUT"
sg wireshark -c "dumpcap -i ${IF} -f 'host ${RELAY} and tcp port 20000' -a duration:${DUR} -w ${OUT}" \
  >"$HERE/.dumpcap.log" 2>&1 &
sleep 3

echo "== polling (${MODE}, n=${N})"
if [[ "$MODE" == "protected" ]]; then
  sudo python3 "$HERE/poll.py" --mode protected --n "$N" --k "$K" --iface "$IF"
else
  python3 "$HERE/poll.py" --mode native --n "$N"
fi

echo "== waiting for the capture to close"
wait
ls -l "$OUT"
echo
echo "Now measure it:   $HERE/clrt.py $OUT"
echo "Or compare both:  $HERE/clrt.py $HERE/native.pcap $HERE/protected.pcap"
