#!/usr/bin/env bash
# mb_run_hulk.sh — run ON HULK as root (via sudo -S). Overlaps an INBOUND-only hairpin capture
# on dp9 with a generation run, so the pcap holds only the switch's shaped output.
# args: IFACE OUT_PCAP CAP_SECS COUNT BURST INTERVAL_MS DPORTS...
set -u
IFACE="$1"; OUT="$2"; SECS="$3"; COUNT="$4"; BURST="$5"; IVL="$6"; shift 6; DPORTS="$*"
GEN=/home/decps/queue_microbench/harness/mb_gen_raw.py
mkdir -p "$(dirname "$OUT")"
timeout "$SECS" tcpdump -i "$IFACE" -Q in -w "$OUT" -s0 'ether proto 0x88b6 or udp' 2>/dev/null &
TPID=$!
sleep 2                                   # let tcpdump attach before traffic
python3 "$GEN" --iface "$IFACE" --dports $DPORTS --count "$COUNT" --burst "$BURST" --interval-ms "$IVL"
wait "$TPID" 2>/dev/null
echo "pcap: $(ls -l "$OUT" 2>/dev/null | awk '{print $5" bytes "$9}')"
echo "inbound_frames_total: $(tcpdump -r "$OUT" -nn 2>/dev/null | wc -l)"
