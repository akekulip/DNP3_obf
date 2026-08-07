#!/usr/bin/env bash
# =============================================================================
#  run_campaign.sh — Defense 4 corrected experiment engine (runs on gambit).
#
#  Drives a block SPEC through the corrected harness on the LIVE defense4_caseA binary
#  (harness-only work; the P4 is not reloaded). For each block:
#     set-policy (mode + delays, refuses while a txn is active) ->
#     clear-evidence -> evidence-dump PRE -> sustained campaign_driver on Vision ->
#     evidence-dump POST -> score_campaign.
#  Fixed-function state is established ONCE (initialize) at the start, never per poll.
#
#  SAFETY: a detached switch-side watchdog (verify+retry+escalate) is armed for the whole
#  run; EXIT/INT/TERM/HUP roll back to a FORWARDING Defense 3. On success the switch is left
#  running Defense 4 only if KEEP_D4=1 (default) AND forwarding verifies; the completion
#  marker (which stands the watchdog down) is written ONLY after that final state is verified.
#  Physical SEL-751 stays READ-only.
#
#  Inputs (env): SPEC=<block spec file>  OUT=<evidence dir>  [WD_DEADLINE=1800]
#    [INIT_MODE=OFF] [KEEP_D4=1] [POLL_MS=400]
#  SPEC lines:  <label> <mode> <d_a_ms> <d_r_ms> <N> <gap_s> [seq_start]   ('#' comments ok)
# =============================================================================
set -Euo pipefail

SPEC="${SPEC:?set SPEC=<block spec file>}"
OUT="${OUT:?set OUT=<evidence dir>}"
WD_DEADLINE="${WD_DEADLINE:-1800}"
INIT_MODE="${INIT_MODE:-OFF}"
KEEP_D4="${KEEP_D4:-1}"
POLL_MS="${POLL_MS:-400}"

SW="${SW_HOST:-decps@10.10.54.81}"
VI="${VI_HOST:-decps@10.10.54.19}"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5"
SCP="scp -o BatchMode=yes -o ConnectTimeout=10"
SWENV="export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=\$SDE/install; export LD_LIBRARY_PATH=\$SDE_INSTALL/lib:\${LD_LIBRARY_PATH:-}; export PYTHONPATH=\$SDE_INSTALL/lib/python3.8/site-packages/tofino:\$SDE_INSTALL/lib/python3.8/site-packages:\${PYTHONPATH:-};"
CTRL=/home/decps/d4_build/control
STAGE=/home/decps/d4_build
D4_PROG=defense4_caseA
RELAY_IP=192.168.10.7
MARKER=$STAGE/d4_complete.marker
COMMIT_BIN_SHA=97175e7dc1a77c3cdbe235baa13b906e18d3227bf09cb84cfacfee6f0a928a19

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
mkdir -p "$OUT"
log(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log" >&2; }
die(){ log "FATAL: $*"; exit 1; }
sw(){ local b64; b64="$(printf '%s' "$*" | base64 -w0)"; $SSH "$SW" "echo $b64 | base64 -d | bash -s"; }
setup_sw(){ sw "$SWENV cd $CTRL && DEFENSE4_HW_AUTHORIZED=1 python3 defense4_caseA_setup.py $*"; }
loaded_prog(){ sw 'pid=$(pgrep -ox bf_switchd); conf=$(tr "\0" "\n" < /proc/$pid/cmdline 2>/dev/null | awk "/^--conf-file\$/{getline;print;exit}"); python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[\"p4_devices\"][0][\"p4_programs\"][0][\"program-name\"])" "$conf" 2>/dev/null' | tail -1; }
relay_ok(){ $SSH "$VI" "ping -c2 -W2 $RELAY_IP >/dev/null 2>&1 && timeout 3 bash -c 'echo > /dev/tcp/$RELAY_IP/20000'" >/dev/null 2>&1; }
dump(){ setup_sw "evidence-dump --program $D4_PROG" 2>/dev/null | grep '^EVIDENCE ' | sed 's/^EVIDENCE //'; }

ROLLED=0
rollback(){ [ "$ROLLED" = 1 ] && return 0; ROLLED=1
  log "=== ROLLBACK to Defense 3 ==="; sw "bash $STAGE/rollback_defense3.sh" 2>&1 | tee -a "$OUT/rollback.log" || true
  if [ "$(loaded_prog)" = case_a_defense3 ] && relay_ok; then log "Defense 3 restored + forwarding verified"; else log "WARN: rollback did not verify"; fi
}
on_exit(){ local rc=$?; trap - EXIT
  if [ "$rc" = 0 ] && [ "$KEEP_D4" = 1 ]; then
    if [ "$(loaded_prog)" = "$D4_PROG" ] && relay_ok; then
      log "success: leaving Defense 4 running (forwarding verified); standing watchdog down"
      sw "date -u +%Y-%m-%dT%H:%M:%SZ > $MARKER" >/dev/null 2>&1 || true
    else log "success but D4 state unverified -> rolling back for safety"; rollback; sw "date -u +%Y-%m-%dT%H:%M:%SZ > $MARKER" >/dev/null 2>&1 || true; fi
  else
    rollback; sw "date -u +%Y-%m-%dT%H:%M:%SZ > $MARKER" >/dev/null 2>&1 || true
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'log "SIGINT"; exit 130' INT
trap 'log "SIGTERM"; exit 143' TERM
trap 'log "SIGHUP"; exit 129' HUP

log "=== CAMPAIGN spec=$SPEC out=$OUT init=$INIT_MODE keep_d4=$KEEP_D4 ==="
# preflight: D4 loaded, binary matches the committed blob, relay reachable
[ "$(loaded_prog)" = "$D4_PROG" ] || die "switch is not running $D4_PROG"
GOTBIN="$(sw 'sha256sum /home/decps/d4_fix_build/out/defense4_caseA/pipe/tofino.bin | cut -d" " -f1' | tail -1)"
[ "$GOTBIN" = "$COMMIT_BIN_SHA" ] || die "loaded binary sha mismatch ($GOTBIN)"
relay_ok || die "relay not reachable"
log "preflight OK: $D4_PROG loaded, binary sha matches, relay reachable"

# stage the current harness (idempotent) to switch + Vision
$SCP "$REPO/defense4/timing/control/defense4_caseA_setup.py" "$REPO/defense3/setup/case_a_defense3_fixed_ack_delay_setup.py" "$SW:$CTRL/" >/dev/null
$SCP "$HERE/rollback_defense3.sh" "$HERE/watchdog.sh" "$SW:$STAGE/" >/dev/null
sw "chmod +x $STAGE/rollback_defense3.sh $STAGE/watchdog.sh" >/dev/null
$SCP "$HERE/campaign_driver.py" "$VI:~/d3phys/" >/dev/null

# arm the detached watchdog
sw "rm -f $MARKER $STAGE/WATCHDOG_ESCALATION; setsid nohup bash $STAGE/watchdog.sh $WD_DEADLINE $MARKER $STAGE/rollback_defense3.sh >/dev/null 2>&1 & echo armed" >/dev/null
sleep 1
sw "ps -eo args | grep -F watchdog.sh | grep -v grep >/dev/null && echo alive" | grep -q alive || die "watchdog did not arm"
log "watchdog armed (deadline ${WD_DEADLINE}s)"

# initialize fixed-function state ONCE
log "--- initialize (mode $INIT_MODE) ---"
setup_sw "initialize --mode $INIT_MODE --poll-ms $POLL_MS" > "$OUT/initialize.txt" 2>&1
grep -q 'RESULT: PASS' "$OUT/initialize.txt" || die "initialize did not PASS"

RESULTS="$OUT/blocks.jsonl"; : > "$RESULTS"
BN=0
# read the spec on fd 3 so ssh inside the loop cannot consume it from stdin
while read -r label mode da dr N gap seqstart budget _rest <&3; do
  case "$label" in ''|'#'*) continue;; esac
  BN=$((BN+1)); seqstart="${seqstart:-0}"
  log "--- block $BN: $label mode=$mode D_A=${da}ms D_R=${dr}ms N=$N gap=$gap seq0=$seqstart budget=${budget:-default} ---"
  # set policy (refuses if a txn is active); OFF/FAIL_OPEN ignore da/dr
  polargs="--mode $mode --poll-ms $POLL_MS"
  [ "$mode" != OFF ] && [ "$mode" != FAIL_OPEN ] && polargs="$polargs --d-a-ms $da --d-r-ms $dr"
  [ -n "${budget:-}" ] && polargs="$polargs --budget $budget"
  if ! setup_sw "set-policy $polargs" > "$OUT/policy_${label}.txt" 2>&1 || ! grep -q 'RESULT: PASS' "$OUT/policy_${label}.txt"; then
    log "ABORT: set-policy failed for $label"; tail -3 "$OUT/policy_${label}.txt" | tee -a "$OUT/run.log"; exit 1
  fi
  setup_sw "clear-evidence" > "$OUT/clear_${label}.txt" 2>&1 || true
  dump > "$OUT/ev_pre_${label}.json"
  $SSH -n "$VI" "cd ~/d3phys && python3 campaign_driver.py $label $N $gap $mode $da $dr $seqstart" \
      2>&1 | grep '^CAMPAIGN ' | sed 's/^CAMPAIGN //' > "$OUT/block_${label}.json" || true
  dump > "$OUT/ev_post_${label}.json"
  # expected protected polls (0 for OFF/FAIL_OPEN)
  exp="$N"; { [ "$mode" = OFF ] || [ "$mode" = FAIL_OPEN ]; } && exp=0
  python3 "$HERE/score_campaign.py" "$OUT/block_${label}.json" "$OUT/ev_pre_${label}.json" "$OUT/ev_post_${label}.json" "$exp" >> "$RESULTS" 2>>"$OUT/score_err.log" || true
  tail -1 "$RESULTS" | python3 -c "import sys,json;d=json.load(sys.stdin);print('   verdict=%s hard=%s responded=%s/%s'%(d.get('verdict'),d.get('hard_anomalies'),d.get('responded'),d.get('sent')))" | tee -a "$OUT/run.log" || true
done 3< "$SPEC"

# collect pcaps + manifest
log "--- collecting pcaps + manifest ---"
mkdir -p "$OUT/pcaps"
while read -r label mode da dr N gap seqstart _rest <&3; do
  case "$label" in ''|'#'*) continue;; esac
  $SCP "$VI:~/d3phys/blk_${label}.pcap" "$OUT/pcaps/" >/dev/null 2>&1 || true
done 3< "$SPEC"
log "pcaps: $(ls "$OUT/pcaps" 2>/dev/null | wc -l)"
bash "$HERE/make_manifest.sh" "$OUT" >/dev/null 2>&1 || true

log "=== CAMPAIGN complete: $BN blocks -> $RESULTS ==="
exit 0
