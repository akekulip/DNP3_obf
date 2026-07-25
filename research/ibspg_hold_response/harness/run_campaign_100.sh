#!/bin/bash
# Gate 12.9 — 100 reps at a fixed G. One RESULT line per rep into reps12.log.
set -u
OUTDIR=/home/philip/Projects/DNP3/research/ibspg_hold_response/evidence/part12/rep_campaign_100
LOG=$OUTDIR/reps12.log
: > "$LOG"
for i in $(seq 1 100); do
  r=$(K=64 G_MS=${G_MS:-20} SCENARIO=normal RESP_DELAY_MS=0.5 RUNID=rep$(printf %03d $i) \
      OUT=$OUTDIR timeout 300 bash part12_trial.sh 2>/dev/null | tail -1)
  echo "rep=$i $r" >> "$LOG"
done
echo "CAMPAIGN_DONE reps=$(grep -c '^rep=' "$LOG")" >> "$LOG"
