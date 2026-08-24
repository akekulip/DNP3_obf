#!/usr/bin/env bash
# =============================================================================
#  bringup_runner.sh — Defense 4 Case-A bounded hardware bring-up (runs on gambit).
#
#  Two modes:
#    --self-test  READ-ONLY. Stages the harness, then reads switch-side evidence off
#                 whatever build is currently loaded (Defense 3) to prove the evidence
#                 reader's plumbing works. Changes NOTHING on the switch or the relay.
#                 This is the safe gate to run BEFORE the live bring-up.
#    --bringup    The full bounded bring-up: snapshot -> start detached watchdog ->
#                 load Defense 4 (OFF) -> apply setup -> drive 1 OFF / 17 D1 / 5 D2 /
#                 10 D4 / 1 fail-open, one real relay READ each, collecting switch +
#                 wire evidence -> restore Defense 3 -> verify forwarding -> write the
#                 watchdog completion marker. Restores Defense 3 on ANY exit (trap),
#                 and the independent switch-side watchdog restores it even if this
#                 process is SIGKILLed (a shell trap cannot catch SIGKILL — the
#                 watchdog is what covers that).
#
#  Physical SEL-751 stays READ-only throughout (only DNP3 READs are ever sent).
# =============================================================================
set -Euo pipefail

MODE=""
case "${1:-}" in
  --self-test) MODE="self-test" ;;
  --bringup)   MODE="bringup" ;;
  *) echo "usage: $0 --self-test | --bringup"; exit 2 ;;
esac

# ---- identities / paths -----------------------------------------------------
SW="${SW_HOST:-decps@10.10.54.81}"
VI="${VI_HOST:-decps@10.10.54.19}"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5"
SCP="scp -o BatchMode=yes -o ConnectTimeout=10"

SDE="/home/decps/Downloads/bf-sde-9.13.2"
SWENV="export SDE=$SDE; export SDE_INSTALL=\$SDE/install; export LD_LIBRARY_PATH=\$SDE_INSTALL/lib:\${LD_LIBRARY_PATH:-}; export PYTHONPATH=\$SDE_INSTALL/lib/python3.8/site-packages/tofino:\$SDE_INSTALL/lib/python3.8/site-packages:\${PYTHONPATH:-};"

SWAP="/home/decps/d3/swap_generic.sh"
D3_CONF="/home/decps/d3/d3_final.conf"
D3_PROG="case_a_defense3"
D4_CONF="/home/decps/d4_build/defense4_caseA.conf"
D4_PROG="defense4_caseA"
RELAY_IP="192.168.10.7"

STAGE="/home/decps/d4_build"
CTRL="$STAGE/control"
MARKER="$STAGE/d4_complete.marker"
WD_DEADLINE="${WD_DEADLINE:-1200}"      # watchdog hard deadline (s)

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"       # -> DNP3 repo root
D3SETUP="$REPO/defense3/setup/case_a_defense3_fixed_ack_delay_setup.py"
D4SETUP="$REPO/defense4/timing/control/defense4_caseA_setup.py"
D4CONF_LOCAL="$HERE/defense4_caseA.conf"
ROLLBACK_LOCAL="$HERE/rollback_defense3.sh"
WATCHDOG_LOCAL="$HERE/watchdog.sh"
BLOCK_LOCAL="$REPO/defense3/harness/block.py"

RUNTS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-$REPO/defense4/timing/evidence/bringup_$RUNTS}"
mkdir -p "$OUT"
log(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log" >&2; }
die(){ log "FATAL: $*"; exit 1; }

# base64 transport avoids the nested-quote mangling that has bitten this project.
sw(){ local b64; b64="$(printf '%s' "$*" | base64 -w0)"; $SSH "$SW" "echo $b64 | base64 -d | bash -s"; }
setup_sw(){ # run the D4 setup op on the switch (authorized), args in $*
  sw "$SWENV cd $CTRL && DEFENSE4_HW_AUTHORIZED=1 python3 defense4_caseA_setup.py $*"; }

loaded_prog(){ sw 'pid=$(pgrep -ox bf_switchd); conf=$(tr "\0" "\n" < /proc/$pid/cmdline 2>/dev/null | awk "/^--conf-file\$/{getline;print;exit}"); python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[\"p4_devices\"][0][\"p4_programs\"][0][\"program-name\"])" "$conf" 2>/dev/null' | tail -1; }
daemon_count(){ sw 'pgrep -cx bf_switchd || echo 0' | tail -1; }
relay_reachable(){ $SSH "$VI" "ping -c2 -W2 $RELAY_IP >/dev/null 2>&1 && timeout 3 bash -c 'echo > /dev/tcp/$RELAY_IP/20000'" >/dev/null 2>&1; }

# ---- staging (both modes) ---------------------------------------------------
stage_harness(){
  log "staging harness -> $SW:$STAGE and $VI:~/d3phys"
  sw "mkdir -p $CTRL $STAGE" >/dev/null
  $SCP "$D4SETUP" "$D3SETUP" "$SW:$CTRL/" >/dev/null || die "stage setup failed"
  $SCP "$D4CONF_LOCAL" "$SW:$D4_CONF" >/dev/null || die "stage conf failed"
  $SCP "$ROLLBACK_LOCAL" "$WATCHDOG_LOCAL" "$SW:$STAGE/" >/dev/null || die "stage rollback/watchdog failed"
  sw "chmod +x $STAGE/rollback_defense3.sh $STAGE/watchdog.sh" >/dev/null
  $SSH "$VI" "mkdir -p ~/d3phys" >/dev/null
  $SCP "$BLOCK_LOCAL" "$VI:~/d3phys/block.py" >/dev/null || die "stage block.py failed"
  log "staging complete"
}

# =============================================================================
#  SELF-TEST — read-only. Prove the evidence reader works on the live build.
# =============================================================================
if [[ "$MODE" == "self-test" ]]; then
  log "=== READ-ONLY reader self-test (no state change) ==="
  prog="$(loaded_prog)"; n="$(daemon_count)"
  log "loaded program: $prog   daemons: $n"
  [[ "$n" == "1" ]] || die "expected exactly one bf_switchd, saw $n"
  relay_reachable && log "relay reachable through the switch" || log "WARN: relay not reachable (reader test still valid)"
  stage_harness
  log "reading switch-side evidence off the LIVE build ($prog) ..."
  # bind the reader to whatever program is actually loaded
  setup_sw "evidence-dump --program $prog" 2>&1 | tee "$OUT/selftest_evidence.txt" | grep -E '^EVIDENCE|RESULT' || true
  if grep -q '^EVIDENCE ' "$OUT/selftest_evidence.txt"; then
    log "READER SELF-TEST PASS — evidence reader plumbing works on live hardware"
    log "evidence: $OUT/selftest_evidence.txt"
    exit 0
  fi
  log "READER SELF-TEST FAIL — evidence line not produced; see $OUT/selftest_evidence.txt"
  exit 1
fi

# =============================================================================
#  BRINGUP — the full bounded live bring-up.
# =============================================================================
# The transaction schedule: (mode, D_A, D_R, count). D_A/D_R are tick values with a
# zero low byte (256 ns quantum). D2: D_A=0. D3: D_R=0. D4/D1: both > 0.
SCHED=(
  "OFF 0 0 1"
  "D1 0x8000 0x8000 17"     # crosses the 16-generation rollover (17 > 16)
  "D2 0 0x8000 5"
  "D4 0x8000 0x8000 10"
  "FAIL_OPEN 0 0 1"
)

ROLLED_BACK=0
rollback(){
  [[ "$ROLLED_BACK" == "1" ]] && { log "rollback already done"; return 0; }
  ROLLED_BACK=1
  log "=== ROLLBACK: restoring Defense 3 on the switch ==="
  sw "bash $STAGE/rollback_defense3.sh" 2>&1 | tee -a "$OUT/rollback.log" || true
  local prog n; prog="$(loaded_prog)"; n="$(daemon_count)"
  if [[ "$prog" == "$D3_PROG" && "$n" == "1" ]]; then
    log "Defense 3 restored (prog=$prog, 1 daemon)"
    if relay_reachable; then
      log "forwarding verified (relay reachable through the switch)"
      # completion marker: written ONLY here, after D3 restored + forwarding verified.
      sw "date -u +%Y-%m-%dT%H:%M:%SZ > $MARKER" >/dev/null 2>&1 || true
      log "watchdog completion marker written -> watchdog stands down"
      return 0
    fi
    log "WARN: Defense 3 restored but forwarding NOT verified — marker NOT written (watchdog stays armed)"
    return 1
  fi
  log "ERROR: rollback did NOT verify (prog=$prog n=$n) — marker NOT written (watchdog will force-restore)"
  return 1
}
on_exit(){ local rc=$?; trap - EXIT; log "on_exit rc=$rc — rolling back"; rollback || rc=$(( rc==0?1:rc )); exit "$rc"; }
trap on_exit EXIT
trap 'log "SIGINT";  exit 130' INT
trap 'log "SIGTERM"; exit 143' TERM
trap 'log "SIGHUP";  exit 129' HUP

log "=== DEFENSE 4 CASE-A BOUNDED BRING-UP ($RUNTS) ==="

# ---- 0. preflight (read-only) ----------------------------------------------
[[ "$(loaded_prog)" == "$D3_PROG" ]] || die "switch is not on Defense 3 at start; refusing"
[[ "$(daemon_count)" == "1" ]] || die "not exactly one bf_switchd at start"
relay_reachable || die "relay not reachable at start — a bring-up would be meaningless"
sw "test -s /home/decps/d4_build/build9132/pipe/tofino.bin" || die "D4 tofino.bin not staged"
log "preflight OK: D3 loaded, 1 daemon, relay reachable, D4 build staged"
stage_harness

# record what we found (the pre-state snapshot)
sw "ps -o args= -C bf_switchd | head -1" > "$OUT/pre_state.txt" 2>/dev/null || true
log "pre-state recorded"

# ---- 1. start the INDEPENDENT detached watchdog ON THE SWITCH ---------------
rm -f "$OUT/.marker_seen"
sw "rm -f $MARKER; setsid nohup bash $STAGE/watchdog.sh $WD_DEADLINE $MARKER $STAGE/rollback_defense3.sh >/dev/null 2>&1 & echo armed" >/dev/null
sleep 1
if sw "pgrep -f 'watchdog.sh $WD_DEADLINE' >/dev/null && echo alive" | grep -q alive; then
  log "watchdog armed on the switch (deadline ${WD_DEADLINE}s), verified alive"
else
  die "watchdog did not come up — refusing to load Defense 4 without the safety net"
fi

# ---- 2. load Defense 4 (OFF), pktgen disabled -------------------------------
log "--- loading Defense 4 ($D4_PROG) via swap_generic.sh ---"
sw "bash $SWAP $D4_CONF d4_bringup_switchd_$RUNTS.log" 2>&1 | tee -a "$OUT/load.log" || true
[[ "$(loaded_prog)" == "$D4_PROG" ]] || die "Defense 4 did not load (prog=$(loaded_prog))"
[[ "$(daemon_count)" == "1" ]] || die "not exactly one daemon after load"
log "Defense 4 loaded"

# ---- 3. apply + verify setup in OFF -----------------------------------------
log "--- configuring setup (mode OFF, pktgen disabled) ---"
setup_sw "configure --mode OFF" 2>&1 | tee "$OUT/setup_off.txt" | grep -E 'RESULT' || true
grep -q 'RESULT: PASS' "$OUT/setup_off.txt" || die "OFF setup did not PASS — aborting"

# ---- 4. drive the schedule --------------------------------------------------
JSONL="$OUT/transactions.jsonl"; : > "$JSONL"
TXN=0; FIRST_PROTECTED_DONE=0; VERDICT="PASS"
for row in "${SCHED[@]}"; do
  read -r M DA DR CNT <<<"$row"
  for ((r=0;r<CNT;r++)); do
    TXN=$((TXN+1))
    log "--- txn #$TXN mode=$M D_A=$DA D_R=$DR ---"
    # (a) set the mode/params
    if ! setup_sw "configure --mode $M --d-a $DA --d-r $DR" > "$OUT/cfg_${TXN}.txt" 2>&1 || ! grep -q 'RESULT: PASS' "$OUT/cfg_${TXN}.txt"; then
      log "ABORT: configure failed for txn #$TXN (mode $M)"; VERDICT="FAIL"; break 2
    fi
    # (b) pre evidence
    setup_sw "evidence-dump --program $D4_PROG" 2>/dev/null | grep '^EVIDENCE ' | sed 's/^EVIDENCE //' > "$OUT/ev_pre_${TXN}.json" || true
    # (c) ONE real relay READ from Vision, with capture
    $SSH "$VI" "cd ~/d3phys && python3 block.py t${TXN} 1 0.2" > "$OUT/block_${TXN}.txt" 2>&1 || true
    grep '^BLOCK ' "$OUT/block_${TXN}.txt" | sed 's/^BLOCK //' > "$OUT/block_${TXN}.json" || true
    # (d) post evidence
    setup_sw "evidence-dump --program $D4_PROG" 2>/dev/null | grep '^EVIDENCE ' | sed 's/^EVIDENCE //' > "$OUT/ev_post_${TXN}.json" || true

    # (e) score this txn (python: deltas + first-protected strict check)
    STRICT=0
    [[ "$M" != "OFF" && "$M" != "FAIL_OPEN" && "$FIRST_PROTECTED_DONE" == "0" ]] && STRICT=1
    python3 "$HERE/score_txn.py" "$TXN" "$M" "$STRICT" \
        "$OUT/ev_pre_${TXN}.json" "$OUT/ev_post_${TXN}.json" "$OUT/block_${TXN}.json" \
        >> "$JSONL" 2> "$OUT/score_${TXN}.txt" || true
    tail -1 "$JSONL" | tee -a "$OUT/run.log"
    if [[ "$STRICT" == "1" ]]; then
      FIRST_PROTECTED_DONE=1
      if grep -q '"strict_pass": true' <(tail -1 "$JSONL"); then
        log "FIRST PROTECTED READ: strict evidence PASS"
      else
        log "ABORT: first protected READ failed strict evidence — see $OUT/score_${TXN}.txt"
        VERDICT="FAIL"; break 2
      fi
    fi
    # hard aborts on any TM drop / escape flagged by the scorer
    if grep -q '"hard_abort": true' <(tail -1 "$JSONL"); then
      log "ABORT: hard-abort condition on txn #$TXN"; VERDICT="FAIL"; break 2
    fi
  done
done

log "=== schedule complete: $TXN transactions driven, provisional verdict=$VERDICT ==="
# the EXIT trap now restores Defense 3, verifies forwarding, and writes the marker.
[[ "$VERDICT" == "PASS" ]] && exit 0 || exit 1
