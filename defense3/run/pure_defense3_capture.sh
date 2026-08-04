#!/usr/bin/env bash
# =============================================================================
#  pure_defense3_capture.sh — ONE armed Defense 3 block against the physical
#  SEL-751, captured at the MASTER (Vision), which is where a passive observer
#  actually sits.
#
#  This is deliberately NOT the D-sweep campaign: no native arm, no interleaving,
#  no D values other than the one asked for. Every transaction in the resulting
#  pcap is defended, so the capture is a pure Defense 3 artifact.
#
#  Sequence, all of it the proven live path:
#    1. swap the switch to the LIVE core build   (d3_final.conf -> case_a_defense3)
#    2. configure the live path WITH the reservoir left armed (--arm-blockers;
#       omitting it is what once produced a run with an empty Q_BLOCK)
#    3. refuse to continue unless the relay answers through the switch
#    4. setarm.py D 1  — D through the single parameter authority, state cleared
#    5. block.py on Vision — dumpcap first, then N Class-0 READs on ONE session
#    6. read the switch counters, so the pcap is not the only witness
#    7. pull the pcap, read the compiled per-stage resource usage, and LEAVE THE
#       SWITCH ON DEFENSE 3 (Philip's instruction 2026-08-04). The pre-state is
#       still recorded, so the restore target is known; restoring is a separate,
#       deliberate act: run_defense3.sh --restore-only
#
#  Env: D_MS (default 16, > native CLRT so the hold conceals fully), NPOLL
#  (default 60, the ">= 50 reads" requirement with margin), GAP (default 0.2 s).
# =============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
D3="$(cd "$HERE/.." && pwd)"
SW="${SW_HOST:-decps@10.10.54.81}"
VI="${VI_HOST:-decps@10.10.54.19}"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10"
PROG="${D3_PROG:-case_a_defense3}"
CONF_LIVE="/home/decps/d3/d3_final.conf"
SWAP="/home/decps/d3/swap_generic.sh"
D_MS="${D_MS:-16}"; NPOLL="${NPOLL:-60}"; GAP="${GAP:-0.2}"
LBL="pured3"
RUNTS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$D3/evidence/pure_defense3/$RUNTS}"
mkdir -p "$OUT"
log(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }

SWENV='cd /home/decps/d3 && export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install; export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}; export PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$SDE_INSTALL/lib/python3.8/site-packages:$PYTHONPATH;'

log "=== PURE DEFENSE 3 CAPTURE  D=${D_MS} ms  polls=${NPOLL}  gap=${GAP}s -> $OUT"

# ---- 0. record what we found, so the restore target is read and not assumed --
PRE="$($SSH "$SW" "ps -o args= -C bf_switchd | head -1")"
echo "$PRE" > "$OUT/pre_state.txt"
CONF_FOUND="$(grep -o 'conf-file [^ ]*' <<<"$PRE" | awk '{print $2}')"
log "found: $CONF_FOUND"
[ -n "$CONF_FOUND" ] || { log "ABORT: could not read the loaded conf"; exit 1; }

# The switch is LEFT ON DEFENSE 3 by instruction. On exit we only record the state we
# are leaving behind, so the next session knows exactly what is loaded and what the
# restore target would be. Restoring is deliberate: run_defense3.sh --restore-only
final_state() {
  POST="$($SSH "$SW" "ps -o args= -C bf_switchd | head -1" || true)"
  echo "$POST" > "$OUT/post_state.txt"
  log "SWITCH LEFT ON: $(grep -o 'conf-file [^ ]*' <<<"$POST")"
  log "   restore target if needed: $CONF_FOUND  (run_defense3.sh --restore-only)"
}
trap final_state EXIT INT TERM HUP

# ---- 1. load the live build --------------------------------------------------
log "--- swapping to the LIVE build ($CONF_LIVE) ---"
$SSH "$SW" "bash $SWAP $CONF_LIVE d3_pured3_switchd.log" 2>&1 | tee -a "$OUT/swap.log"
LOADED="$($SSH "$SW" "ps -o args= -C bf_switchd | head -1")"
grep -q "$(basename "$CONF_LIVE")" <<<"$LOADED" || { log "ABORT: wrong conf loaded: $LOADED"; exit 1; }
[ "$($SSH "$SW" "pgrep -cx bf_switchd")" = "1" ] || { log "ABORT: not exactly one bf_switchd"; exit 1; }
log "loaded OK"

# ---- 2. live control plane, reservoir left ARMED -----------------------------
log "--- setup --config --arm-blockers ---"
$SSH "$SW" "$SWENV python3 case_a_defense3_fixed_ack_delay_setup.py \
     --prog $PROG --config --arm-blockers --d-ms $D_MS" > "$OUT/setup.log" 2>&1
NF=$(grep -cE "^\[FAIL\]" "$OUT/setup.log" || true)
log "setup FAIL lines: $NF"
[ "$NF" = "0" ] || { log "ABORT: setup reported failures"; tail -15 "$OUT/setup.log"; exit 1; }

# ---- 3. the relay must answer through the switch ----------------------------
if $SSH "$VI" "ping -c3 -W2 192.168.10.7 >/dev/null 2>&1 && timeout 3 bash -c 'echo > /dev/tcp/192.168.10.7/20000'" 2>/dev/null; then
  log "relay reachable through the switch"
else
  log "ABORT: relay not reachable — nothing captured would mean anything"; exit 1
fi

# ---- 4. arm this block: D via the parameter authority, state cleared --------
SA=$($SSH "$SW" "$SWENV python3 setarm.py $D_MS 1 41" 2>&1 | grep -o 'SETARM .*' | head -1)
echo "$SA" > "$OUT/setarm.json"
log "setarm: $(cut -c1-160 <<<"$SA")"
grep -q '"policy_ok": true' <<<"$SA" || { log "ABORT: parameter policy rejected D=$D_MS"; exit 1; }

# ---- 5. the capture + the READs, at the master ------------------------------
log "--- capturing at Vision: $NPOLL Class-0 READs on one session ---"
BK=$($SSH "$VI" "cd ~/d3phys && python3 block.py $LBL $NPOLL $GAP" 2>&1 | grep -o 'BLOCK .*' | head -1)
echo "$BK" > "$OUT/block.json"
log "block: $(cut -c1-200 <<<"$BK")"

# ---- 6. the switch's own witness -------------------------------------------
CT=$($SSH "$SW" "$SWENV python3 read_counters.py 541" 2>&1 | grep -o 'CTR .*' | head -1)
echo "$CT" > "$OUT/counters.json"
log "counters: $(cut -c1-200 <<<"$CT")"

# ---- 7. pull the pcap -------------------------------------------------------
scp -q "$VI:~/d3phys/blk_${LBL}.pcap" "$OUT/pure_defense3_D${D_MS}ms.pcap" 2>/dev/null \
  && log "pcap: $OUT/pure_defense3_D${D_MS}ms.pcap ($(stat -c%s "$OUT/pure_defense3_D${D_MS}ms.pcap" 2>/dev/null) bytes)" \
  || log "!! pcap copy FAILED"

# ---- 8. per-stage resource usage of the build that produced this capture ----
log "--- pulling the compiled resource reports for the loaded build ---"
mkdir -p "$OUT/resources"
for f in resources.json mau.resources.log table_summary.log phv_allocation_summary_1.log; do
  scp -q "$SW:/home/decps/d3/build_final_core/pipe/logs/$f" "$OUT/resources/" 2>/dev/null \
    || scp -q "$SW:/home/decps/d3/build_final_core/pipe/$f" "$OUT/resources/" 2>/dev/null || true
done
log "resource files: $(ls "$OUT/resources" 2>/dev/null | tr '\n' ' ')"

log "=== capture done; switch intentionally LEFT ON DEFENSE 3 ==="
