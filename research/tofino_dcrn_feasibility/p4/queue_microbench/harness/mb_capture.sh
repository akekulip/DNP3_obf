#!/usr/bin/env bash
# mb_capture.sh — Vision-side capture wrapper for queue_microbench (run on VISION, dp8 iface).
# Captures the obfuscated output stream: chaff/tick cover frames (ether proto 0x88b6) AND
# graduated reals + fail-open background (udp). Writes a pcap for mb_parse.py.
#
# Usage:  sudo ./mb_capture.sh <iface> <out.pcap> [seconds]
#   e.g.  sudo ./mb_capture.sh enp59s0f0np0 runs/a_isolated_pktgen.pcap 20
#
# Notes:
#  - capture on the PHYSICAL dp8 NIC, not a macvlan (M2 lesson: macvlan misses hairpinned frames).
#  - -w writes raw pcap (no truncation); mb_parse.py reads the full frame for size + MAGIC.
#  - if you need residence time, also capture Hulk-tx and pass it to mb_parse.py --tx-pcap
#    (requires PTP-synced clocks or a single-host hairpin rig).
set -euo pipefail
IFACE="${1:?usage: mb_capture.sh <iface> <out.pcap> [seconds]}"
OUT="${2:?usage: mb_capture.sh <iface> <out.pcap> [seconds]}"
SECS="${3:-20}"
mkdir -p "$(dirname "$OUT")"
echo "capture: iface=$IFACE out=$OUT secs=$SECS filter='ether proto 0x88b6 or udp'"
timeout "$SECS" tcpdump -i "$IFACE" -w "$OUT" -s 0 'ether proto 0x88b6 or udp' || true
echo "capture done: $(ls -l "$OUT")"
