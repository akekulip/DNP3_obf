#!/usr/bin/env bash
# run_separation.sh - which quantity governs the master-visible OPERATE response-to-ACK interval?
#
# The design section gives it as O = R - A, the difference of the two control-lane offsets. The
# read lane's configured CLRT_new is a different quantity entirely. Nothing measured so far can
# tell them apart, because campaign_v1 set R - A = 4 ms and CLRT_new = 4 ms, and the release-tail
# sweep held both at 4 ms as well. Wherever two parameters are equal, no experiment distinguishes
# them; this one makes them differ.
#
# Two series, crossed on the one axis each holds fixed.
#
#   sep_O   R - A walks 4, 8, 12 ms with CLRT_new pinned at 4 ms.
#           If O governs, the measured interval follows R - A. If CLRT_new governs, it stays 4.
#
#   sep_C   CLRT_new walks 2, 4, 8, 12 ms with R - A pinned at 8 ms.
#           If CLRT_new governs, the measured interval follows it. If O governs, it stays 8.
#
# Read-lane hold D_A stays at 20 ms throughout so the read lane is a constant, and A stays at
# 16 ms, the smallest offset the control plane admits with the campaign's {2,6,12} ms codebook.
# All six points were probed for admissibility before this ran; all six configure PASS.
#
# n_sbo is large and n_read small: OPERATE is the measurement here, not READ.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
LOG="$ROOT/RUN_SEP.log"
MANIFEST="$ROOT/blocks_sep.csv"

N_READ=60; N_SBO=80
D_A=20
A=16
PASSES=3

: > "$LOG"
echo "tag,pass,series,mode,D_A_ms,CLRT_new_ms,D_ms,A_ms,R_ms,j_set,n_read,n_sbo,seed,status" > "$MANIFEST"

run_block () {   # tag series mode D_A D_R A R seed pass
  local tag="$1" series="$2" mode="$3" da="$4" dr="$5" a="$6" r="$7" seed="$8" pass="$9"
  local status="ok"
  if ! "$HERE/tail_block.sh" "$tag" "$mode" "$da" "$dr" "$a" "$r" "$N_READ" "$N_SBO" "$seed" \
        "2 6 12" >> "$LOG" 2>&1; then
    status="failed"; echo "  !! $tag failed" >> "$LOG"
  fi
  local d=""; [ "$mode" = "D4" ] && d=$((da + dr))
  echo "$tag,$pass,$series,$mode,$da,$dr,$d,$a,$r,\"2 6 12\",$N_READ,$N_SBO,$seed,$status" >> "$MANIFEST"
}

seed=20270918
start=$(date +%s)
echo "separation series: does the OPERATE response-to-ACK follow R-A or CLRT_new?" >> "$LOG"

for pass in $(seq 1 $PASSES); do
  echo "== pass $pass ==" >> "$LOG"
  seed=$((seed + 1000))
  run_block "soff_p${pass}_a" baseline OFF 0 0 0 0 $seed "$pass"

  # O walks, CLRT_new pinned at 4
  for r in 20 24 28; do
    seed=$((seed + 1))
    run_block "so_p${pass}_r${r}" sep_O D4 "$D_A" 4 "$A" "$r" "$seed" "$pass"
  done

  # CLRT_new walks, O pinned at 8 (A=16, R=24)
  for c in 2 8 12; do
    seed=$((seed + 1))
    run_block "sc_p${pass}_c${c}" sep_C D4 "$D_A" "$c" "$A" 24 "$seed" "$pass"
  done

  seed=$((seed + 1))
  run_block "soff_p${pass}_z" baseline OFF 0 0 0 0 $seed "$pass"
done

echo "done in $(( ($(date +%s) - start) / 60 )) min; ok=$(grep -c ',ok$' "$MANIFEST") failed=$(grep -c ',failed$' "$MANIFEST")" >> "$LOG"
