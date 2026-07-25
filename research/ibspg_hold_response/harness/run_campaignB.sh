#!/bin/bash
# Gate 12.9 campaign B — 100 reps, G randomized over the swept targets.
# Captures: exact command, start/end timestamps, per-rep RESULT, and the campaign exit code.
set -u
RUNDIR=/home/philip/Projects/DNP3/research/ibspg_hold_response/evidence/part12/campaignB_randomG
LOG=$RUNDIR/repsB.log
META=$RUNDIR/campaign_meta.txt
GVALS=(1 2 5 10 17 20 25 40)
: > "$LOG"
{ echo "command: bash run_campaignB.sh"
  echo "trial_command_template: K=64 G_MS=<G> SCENARIO=normal RESP_DELAY_MS=0.5 RUNID=repB<NNN> OUT=$RUNDIR bash part12_trial.sh"
  echo "g_values_randomized_over: ${GVALS[*]}"
  echo "start_utc: $(date -u +%FT%T.%NZ)"; } > "$META"
rc_any=0
for i in $(seq 1 100); do
  g=${GVALS[$(( (i * 7 + 3) % 8 ))]}      # deterministic permutation: reproducible, no RNG state
  r=$(K=64 G_MS=$g SCENARIO=normal RESP_DELAY_MS=0.5 RUNID=repB$(printf %03d $i) \
      OUT=$RUNDIR timeout 300 bash part12_trial.sh 2>/dev/null | tail -1)
  rc=$?
  [ "$rc" != "0" ] && rc_any=$rc
  echo "rep=$i g_ms=$g rc=$rc $r" >> "$LOG"
done
{ echo "end_utc: $(date -u +%FT%T.%NZ)"
  echo "reps_logged: $(grep -c '^rep=' "$LOG")"
  echo "campaign_exit_code: $rc_any"; } >> "$META"
echo "CAMPAIGN_DONE reps=$(grep -c '^rep=' "$LOG") exit=$rc_any" >> "$LOG"
exit $rc_any
