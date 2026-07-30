#!/usr/bin/env bash
# =============================================================================
#  live_r1_campaign.sh — the REPAIRED build against the PHYSICAL SEL-751.
#
#  Everything measured in REPORT.md §10 and §11 was collected on the build that
#  carries both state-ordering defects. R1 has since been repaired and validated
#  on silicon, but only in the SYNTHETIC build, where every packet is generated
#  inside the chip. This runs the repaired LIVE build against the real relay,
#  which is the one thing the repair had not been subjected to.
#
#  WHAT IS DIFFERENT FROM THE ORIGINAL CAMPAIGN, and why:
#    * the program is case_a_defense3_repair_candidate (R1 + R3, full telemetry,
#      11/12 stages, critical path 10), not the frozen one;
#    * polls per block are DOUBLED (40, was 20), so each arm carries 160
#      transactions instead of 80;
#    * per-block pcaps are kept, as before — block.py already captures at the
#      master, which is the observation point every number is quoted from.
#  Everything else is held fixed: same arms, same interleaving, same 200 ms poll
#  gap, same D values, same analysis. The comparison is only meaningful if the
#  campaign design does not move with the build.
#
#  RESTORATION: the switch is returned to the conf it was found on and verified.
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D3="$(cd "$HERE/.." && pwd)"
SW="${SW_HOST:-decps@10.10.54.81}"
VI="${VI_HOST:-decps@10.10.54.19}"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10"
PROG="case_a_defense3_repair_candidate"
CONF_REPAIR="/home/decps/d3/d3_live_repair_abs.conf"
CONF_FOUND="/home/decps/d3/d3_abs.conf"
SWAP="/home/decps/d3/swap_generic.sh"
ROUNDS="${ROUNDS:-4}"; NPOLL="${NPOLL:-40}"; GAP="${GAP:-0.2}"; DSETUP="${DSETUP:-2}"
RUNTS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$D3/evidence/physical_repaired/$RUNTS}"
mkdir -p "$OUT"
log(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }

SWENV='cd /home/decps/d3 && export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install; export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}; export PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$SDE_INSTALL/lib/python3.8/site-packages:$PYTHONPATH;'

log "=== LIVE CAMPAIGN ON THE REPAIRED BUILD ==="
log "prog=$PROG rounds=$ROUNDS npoll=$NPOLL gap=$GAP  -> $((ROUNDS*NPOLL*6)) attempted"
log "out=$OUT"

PRE="$($SSH "$SW" "ps -o args= -C bf_switchd | head -1" || true)"
echo "$PRE" > "$OUT/pre_state.txt"; log "pre-state: $PRE"

# ---- 1. load the repaired live build -----------------------------------------
log "--- swapping to the repaired LIVE build ---"
$SSH "$SW" "bash $SWAP $CONF_REPAIR d3_live_repair_switchd.log" 2>&1 | tee -a "$OUT/swap.log"
LOADED="$($SSH "$SW" "ps -o args= -C bf_switchd | head -1")"
grep -q "d3_live_repair_abs.conf" <<<"$LOADED" || { log "ABORT: wrong conf: $LOADED"; exit 1; }
[ "$($SSH "$SW" "pgrep -cx bf_switchd")" = "1" ] || { log "ABORT: not one daemon"; exit 1; }
log "loaded: $LOADED"

# ---- 2. the LIVE control plane, with the reservoir left ARMED ----------------
# --arm-blockers is the step whose absence made the first physical Stage 3 run
# with an empty Q_BLOCK: --config alone configures pktgen app 1 and the mandatory
# cleanup disarms it again on the way out.
log "--- configuring the live path (--config --arm-blockers) ---"
$SSH "$SW" "$SWENV python3 case_a_defense3_fixed_ack_delay_setup.py \
     --prog $PROG --config --arm-blockers --d-ms $DSETUP" \
     > "$OUT/setup.log" 2>&1 || { log "ABORT: setup failed, see setup.log"; tail -20 "$OUT/setup.log"; exit 1; }
grep -cE "^\[FAIL\]" "$OUT/setup.log" > "$OUT/setup_fails.txt" || true
log "setup FAILs: $(cat "$OUT/setup_fails.txt")"

# ---- 3. the relay must actually be reachable before any claim is made --------
log "--- checking the relay through the switch ---"
if $SSH "$VI" "ping -c3 -W2 192.168.10.7 >/dev/null 2>&1 && timeout 3 bash -c 'echo > /dev/tcp/192.168.10.7/20000'" 2>/dev/null; then
  log "relay reachable on 192.168.10.7:20000"
else
  log "ABORT: the relay is NOT reachable through the switch — nothing below would mean anything"
  $SSH "$VI" "ping -c2 -W2 192.168.10.7 2>&1 | tail -2" | tee -a "$OUT/run.log" || true
  exit 1
fi

# ---- 4. the campaign ---------------------------------------------------------
log "--- campaign: $ROUNDS rounds x 6 arms x $NPOLL polls ---"
D3_PROG="$PROG" "$D3/harness/campaign.sh" "$OUT/dsweep_blocks.jsonl" \
    "$ROUNDS" "$NPOLL" "$GAP" 2>&1 | tee -a "$OUT/campaign.log" || true
log "blocks written: $(wc -l < "$OUT/dsweep_blocks.jsonl" 2>/dev/null || echo 0)"

# ---- 5. pull the per-block captures ------------------------------------------
log "--- pulling per-block pcaps ---"
mkdir -p "$OUT/pcaps"
scp -q "$VI:~/d3phys/blk_r*.pcap" "$OUT/pcaps/" 2>/dev/null || true
log "pcaps: $(ls "$OUT/pcaps" 2>/dev/null | wc -l)"

# ---- 6. restore --------------------------------------------------------------
if [ "${D3_NO_RESTORE:-0}" = "1" ]; then
  log "D3_NO_RESTORE=1 — leaving the repaired build loaded."
else
  log "--- restoring the switch to the conf it was found on ---"
  $SSH "$SW" "bash $SWAP $CONF_FOUND d3_restore_switchd.log" 2>&1 | tee -a "$OUT/restore.log"
  POST="$($SSH "$SW" "ps -o args= -C bf_switchd | head -1")"; echo "$POST" > "$OUT/post_state.txt"
  if grep -q "$(basename "$CONF_FOUND")" <<<"$POST" && [ "$($SSH "$SW" "pgrep -cx bf_switchd")" = "1" ]; then
    log "RESTORED: $POST"
  else
    log "!! RESTORE DID NOT VERIFY: $POST"; exit 1
  fi
fi
log "=== DONE ==="
