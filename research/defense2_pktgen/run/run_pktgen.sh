#!/bin/bash
# run_pktgen.sh — one measurement run (pktgen variant): capture, drive the polls, leave a .pcap.
#
#   ./run_pktgen.sh native            20 polls, pktgen app disabled -> native.pcap
#   ./run_pktgen.sh protected         20 polls, pktgen app enabled  -> protected.pcap
#   ./run_pktgen.sh native 50         50 polls
#
# NO host token injection and NO sudo in either mode — the switch generates the blocker
# reservoir internally. Enable/disable the pktgen app in the setup script.
#
# The capture filter ALSO admits ether proto 0x88c1 so this Vision-facing capture can PROVE
# token isolation: zero 0x88C1 frames must appear here (functional gate 4).
set -o errexit -o nounset -o pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

MODE="${1:?usage: run_pktgen.sh native|protected [n]}"
N="${2:-20}"
IF="${IF:-enp59s0f0np0}"
OUT="${OUT:-$HERE/${MODE}.pcap}"
RELAY="${RELAY:-192.168.10.7}"

case "$MODE" in native|protected) ;; *) echo "mode must be native or protected"; exit 2;; esac

# capture long enough for warmup + N polls at 0.4 s, plus slack
DUR=$(python3 -c "print(int((${N}+1)*0.4 + 12))")

echo "== capturing on ${IF} for ${DUR}s -> ${OUT}"
rm -f "$OUT"
sg wireshark -c "dumpcap -i ${IF} -f '(host ${RELAY} and tcp port 20000) or ether proto 0x88c1' -a duration:${DUR} -w ${OUT}" \
  >"$HERE/.dumpcap.log" 2>&1 &
sleep 3

echo "== polling (${MODE}, n=${N})  [no host injection, no sudo]"
python3 "$HERE/poll_pktgen.py" --mode "$MODE" --n "$N"

echo "== waiting for the capture to close"
wait
ls -l "$OUT"
echo
echo "Token isolation check (must be 0): "
sg wireshark -c "tshark -r $OUT -Y 'eth.type==0x88c1' 2>/dev/null | wc -l" || true
echo
echo "Now measure it:   $HERE/clrt.py $OUT"
echo "Or compare both:  $HERE/clrt.py $HERE/native.pcap $HERE/protected.pcap"
