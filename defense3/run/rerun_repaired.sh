#!/usr/bin/env bash
# =============================================================================
#  rerun_repaired.sh — rerun the synthetic gates on the REPAIRED build, with
#  external packet capture at the observation point and doubled repetitions.
#
#  WHY THIS EXISTS. REPORT.md §9.8's stale-response PASS was withdrawn after the
#  2026-07-30 audit: the harness never read back the stale injector's own
#  generator counters, and the single bypass timestamp landed 200 us from where
#  that injector was scheduled, so the evidence could not say which of the two
#  RESPONSES the switch had held. Rescoring the old run with the repaired
#  analyzer now returns FAIL on F-09, not merely INDETERMINATE. Three things
#  therefore change here, and all three are load-bearing:
#
#    1. THE BUILD IS REPAIRED. -DD3_REPAIR_R1 authorises the RESPONSE marker
#       against the full seq/ack/port predicate before the stateful write, so an
#       unauthorised RESPONSE carries delta 0 and cannot mark. -DD3_REPAIR_R3
#       drops host-injected 0x88C1 frames instead of enqueuing them.
#    2. THE HARNESS READS BACK APP 4. Without it the case is unscorable, which
#       is exactly what happened.
#    3. EXTERNAL CAPTURE. Every synthetic gate result so far has been read out
#       of registers and counters inside the same chip that produced it. A pcap
#       on the master-facing port is the first independent check that the ACK
#       really does leave before the RESPONSE.
#
#  Repetitions are doubled (gate 3: 5 -> 10 transactions; gate 4: 3 -> 6 per
#  case) so the boundary cases are not being judged on three samples.
#
#  RESTORATION. Every intermediate mode runs with D3_SKIP_RESTORE=1 so the
#  repaired build survives between gates; the LAST step restores through the one
#  existing copy of that code. If this script dies mid-way the switch is left on
#  the repaired synthetic build and `run_defense3.sh --restore-only` puts it
#  back — that is the same contract every other runner here has.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D3="$(cd "$HERE/.." && pwd)"
SW_HOST="${SW_HOST:-decps@10.10.54.81}"
VI_HOST="${VI_HOST:-decps@10.10.54.19}"
VI_IF="${VI_IF:-enp59s0f0np0}"            # Vision's dp9-facing NIC
PROG_REPAIR="case_a_defense3_repair_candidate"
SWAP="/home/decps/d3/swap_generic.sh"
CONF_REPAIR="/home/decps/d3/d3_synth_repair_abs.conf"
CONF_FOUND="/home/decps/d3/d3_abs.conf"   # what the switch was running when we arrived
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10"
RUNTS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$D3/evidence/repaired/$RUNTS}"
G3_TXNS="${G3_TXNS:-10}"                  # doubled from 5
G4_REPS="${G4_REPS:-6}"                   # doubled from 3
MODES="${MODES:-gate2 gate3 gate4}"

mkdir -p "$OUT"
log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }

log "=== RERUN ON THE REPAIRED BUILD ==="
log "out=$OUT  modes=$MODES  g3_txns=$G3_TXNS  g4_reps=$G4_REPS"

# ---- 1. what is loaded now, so the restore target is recorded, not assumed ---
PRE="$($SSH "$SW_HOST" "ps -o args= -C bf_switchd | head -1" || true)"
log "pre-state: $PRE"
echo "$PRE" > "$OUT/pre_state.txt"

# ---- 2. swap to the repaired synthetic build --------------------------------
log "--- swapping to the repaired SYNTHETIC build ---"
$SSH "$SW_HOST" "bash $SWAP $CONF_REPAIR d3_synth_repair_switchd.log" 2>&1 \
  | tee -a "$OUT/swap.log"
LOADED="$($SSH "$SW_HOST" "ps -o args= -C bf_switchd | head -1")"
grep -q "d3_synth_repair_abs.conf" <<<"$LOADED" \
  || { log "ABORT: the repaired conf is not the loaded one: $LOADED"; exit 1; }
[ "$($SSH "$SW_HOST" "pgrep -cx bf_switchd")" = "1" ] \
  || { log "ABORT: not exactly one bf_switchd"; exit 1; }
log "loaded OK: $LOADED"

# ---- 3. each gate, wrapped in an external capture ---------------------------
for MODE in $MODES; do
  CAP="/tmp/d3_${MODE}_$RUNTS.pcap"
  log "--- $MODE: starting capture on $VI_HOST:$VI_IF -> $CAP ---"
  # dumpcap under sg wireshark: Vision has no passwordless sudo, and the user is
  # in the wireshark group, which is what makes an unprivileged capture possible.
  $SSH "$VI_HOST" "/home/decps/d3cap.sh start $VI_IF $CAP" | tee -a "$OUT/run.log"

  log "--- $MODE: running ---"
  set +e
  PROG="$PROG_REPAIR" D3_SKIP_RESTORE=1 D3_NO_TMUX=1 \
    G3_TXNS="$G3_TXNS" G4_REPS="$G4_REPS" \
    "$HERE/run_defense3.sh" --"$MODE" > "$OUT/${MODE}_runner.log" 2>&1
  RC=$?
  set -e
  log "$MODE runner exit=$RC (log: $OUT/${MODE}_runner.log)"

  sleep 2
  $SSH "$VI_HOST" "/home/decps/d3cap.sh stop $VI_IF $CAP" \
      | tee -a "$OUT/run.log" || true
  scp -q "$VI_HOST:$CAP" "$OUT/" && log "captured -> $OUT/$(basename "$CAP")"
done

# ---- 4. pull the evidence tree ----------------------------------------------
log "--- pulling evidence ---"
$SSH "$SW_HOST" "ls -d /home/decps/d3gate2/evidence/* 2>/dev/null | tail -5" \
  | tee -a "$OUT/run.log" || true

# ---- 5. put the switch back to the state we FOUND it in --------------------
# NOT run_defense3.sh --restore-only: that restores to DEFENSE 2, and this switch
# was found running the Defense 3 LIVE build. Restoring to a different program
# than the one we displaced would be a silent state change, so the found conf is
# recorded in pre_state.txt above and reloaded here.
if [ "${D3_NO_RESTORE:-0}" = "1" ]; then
  log "D3_NO_RESTORE=1 — leaving the repaired build loaded. You own the restore."
else
  log "--- restoring the switch to the conf it was found on ---"
  $SSH "$SW_HOST" "bash $SWAP $CONF_FOUND d3_restore_switchd.log" 2>&1 \
    | tee -a "$OUT/restore.log"
  POST="$($SSH "$SW_HOST" "ps -o args= -C bf_switchd | head -1")"
  echo "$POST" > "$OUT/post_state.txt"
  if grep -q "$(basename "$CONF_FOUND")" <<<"$POST" \
     && [ "$($SSH "$SW_HOST" "pgrep -cx bf_switchd")" = "1" ]; then
    log "RESTORED: $POST"
  else
    log "!! RESTORE DID NOT VERIFY. now: $POST"
    exit 1
  fi
fi

log "=== DONE ==="
