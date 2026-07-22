#!/usr/bin/env bash
# mb_capture.sh — HULK-side hairpin capture for queue_microbench (Vision/dp8 is down).
# dp9 is BOTH generator (Hulk tx) and observe (switch egresses shaped output back to Hulk).
# We capture INBOUND ONLY (-Q in) so the pcap holds only the switch's shaped output, not Hulk's
# own outbound generated frames (they share the same physical dp9 link). Captures the obfuscated
# stream: chaff/tick cover (ether proto 0x88b6) AND graduated/shaped reals + fail-open (udp).
#
# Usage:  sudo ./mb_capture.sh <iface> <out.pcap> [seconds]
#   e.g.  sudo ./mb_capture.sh enp59s0f0np0 runs/a_shaper_R100.pcap 20
#
# Notes:
#  - capture on the PHYSICAL dp9 NIC, not a macvlan (M2 lesson: macvlan misses hairpinned frames).
#  - -Q in isolates the returned shaped output from Hulk's own tx on the shared dp9 link.
#  - -w writes raw pcap (no truncation); mb_parse.py reads the full frame for size + MAGIC.
set -euo pipefail
IFACE="${1:?usage: mb_capture.sh <iface> <out.pcap> [seconds]}"
OUT="${2:?usage: mb_capture.sh <iface> <out.pcap> [seconds]}"
SECS="${3:-20}"
mkdir -p "$(dirname "$OUT")"
echo "capture: iface=$IFACE out=$OUT secs=$SECS dir=IN filter='ether proto 0x88b6 or udp'"
timeout "$SECS" tcpdump -i "$IFACE" -Q in -w "$OUT" -s 0 'ether proto 0x88b6 or udp' || true
echo "capture done: $(ls -l "$OUT")"
