#!/usr/bin/env bash
# Native (unmodified, single-segment) Class 0 polling of BOTH devices, INTERLEAVED.
#
# Blocks alternate SEL-751 / ION7550 so a drift in ambient conditions cannot land on one
# device and not the other -- the same reason the D-sweep campaign interleaves its arms
# (CONSENSUS §9: session-to-session drift on this relay exceeds the effect being measured).
#
# NATIVE ONLY: no --split-read anywhere here. The induced Case A observable is a separate
# experiment and must not be mixed into a distribution labelled "native".
#
# Each block is its own TCP connection, so the FIRST poll of a block is connection-cold
# (the SEL-751's cold poll runs ~25 ms against a ~3 ms steady state) -- the analysis marks
# poll index 0 of every block so it can be excluded from a steady-state distribution.
set -uo pipefail

OUT="${OUT:-/home/decps/native_clrt}"
ROUNDS="${ROUNDS:-4}"
N="${N:-25}"
GAP="${GAP:-0.4}"
mkdir -p "$OUT"

for r in $(seq 1 "$ROUNDS"); do
  for arm in "sel751:192.168.10.7:0" "ion7550:192.168.10.8:10"; do
    NAME="${arm%%:*}"; REST="${arm#*:}"; IP="${REST%%:*}"; DEST="${REST#*:}"
    echo "[$(date -u +%H:%M:%S)] round $r  $NAME  $IP dest=$DEST  n=$N" >&2
    # every block keeps its OWN capture: the pcap is the primary evidence and the JSON is
    # derived from it, so blocks must not share one path
    sg wireshark -c "python3 /home/decps/probe_ack_mode.py --relay $IP --dest $DEST \
        --n $N --gap $GAP --pcap-out $OUT/${NAME}_r${r}.pcap" \
        > "$OUT/${NAME}_r${r}.json" 2>&1
  done
done
echo "[$(date -u +%H:%M:%S)] done -> $OUT" >&2
ls -1 "$OUT"/*.json | wc -l
