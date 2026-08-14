#!/usr/bin/env bash
# Regenerate ALL derived artifacts (transaction CSVs, size-verdict CSV, verdict JSON) from the raw pcaps.
# Deterministic (fixed RNG seeds). Run from the repo root. Figures: run scripts/fig*.py after.
set -euo pipefail
RP="${RESEARCH_PYTHON:-/home/philip/.venvs/research/bin/python}"
FIN=defense4/size/native_parity/evidence/E_FINAL
S=$FIN/scripts; RAW=$FIN/raw_pcaps; C=$FIN/csv
# --- timing transaction CSVs (CLRT) ---
$RP $S/clrt_extract.py $RAW/e1_native.pcap ALL native   > $C/native_txn.csv
$RP $S/clrt_extract.py $RAW/e2_def_read.pcap ALL defended > $C/defended_read_txn.csv
$RP $S/clrt_extract.py $RAW/e2_def.pcap ALL defended     > $C/defended_txn.csv
# --- BOR SBO timing CSVs ---
for J in 2 6 12; do $RP $S/sbo_timing.py $RAW/sbo_j$J.pcap "J=${J}ms" $C/sbo_j$J.csv; done
# --- size-verdict CSV (TCP-seq reconstruction + DNP3 CRC + checksum) ---
{ $RP $S/size_reconstruct.py $RAW/e1_native_size_shapeoff.pcap READ native
  $RP $S/size_reconstruct.py $RAW/e2_def_read.pcap READ defended   | grep -v '^pcap,'
  $RP $S/size_reconstruct.py $RAW/e2_def.pcap SELECT defended      | grep -v '^pcap,'
  for J in 2 6 12; do $RP $S/size_reconstruct.py $RAW/sbo_j$J.pcap OPERATE defended | grep -v '^pcap,'; done
} > $C/size_verdict.csv
# --- stats + verdict JSON ---
$RP $S/e4e5_analysis.py >/dev/null
echo "reproduce: regenerated CSVs + verdict_stats.json from raw pcaps"
