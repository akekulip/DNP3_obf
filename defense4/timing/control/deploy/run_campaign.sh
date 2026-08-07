#!/usr/bin/env bash
# =============================================================================
#  run_campaign.sh — Defense 4 fail-closed experiment engine (runs on gambit).
#
#  Drives a block SPEC through the harness on the LIVE defense4_caseA binary (harness-only work;
#  the P4 is not reloaded). Per block:
#     set-policy (refuses while a txn is active) -> clear-evidence -> evidence-dump PRE ->
#     sustained campaign_driver on Vision -> copy the block PCAP -> evidence-dump POST ->
#     score_campaign (scenario-aware, fail-closed).
#  Fixed-function state is established ONCE (initialize) at the start, never per poll.
#
#  FAIL-CLOSED: no `|| true` on any required operation. A driver crash, an empty/invalid block JSON,
#  an evidence-dump failure, a missing/empty PCAP, a scorer hard anomaly, a PCAP name/count mismatch,
#  or a manifest that fails `sha256sum -c` aborts the run, preserves partial evidence, performs the
#  safety path, and exits nonzero. The SHA256SUMS manifest is generated only after the switch state
#  and run.log are final, then verified with `sha256sum -c`.
#
#  SAFETY (live only): a detached switch-side watchdog (verify+retry+escalate) is armed for the whole
#  run; EXIT/INT/TERM/HUP roll back to a FORWARDING Defense 3. On success the switch is left running
#  Defense 4 only if KEEP_D4=1 (default) AND forwarding verifies; the completion marker (which stands
#  the watchdog down) is written ONLY after that final state is verified. Physical SEL-751 READ-only.
#
#  DRY_RUN=1 replaces every switch/driver/scp call with local fixtures under DRY_FIXTURES, so the full
#  orchestration control flow (failure propagation, PCAP validation, manifest ordering, sha256sum -c,
#  abort/safety path) is exercised offline with no ssh. This is how Phase 1 proves the engine without
#  touching the live switch.
#
#  Inputs (env): SPEC=<block spec file>  OUT=<evidence dir>  [WD_DEADLINE=1800]
#    [INIT_MODE=OFF] [KEEP_D4=1] [POLL_MS=400] [DRY_RUN=0] [DRY_FIXTURES=<dir>]
#  SPEC lines:  <label> <mode> <d_a_ms> <d_r_ms> <N> <gap_s> [seq_start] [budget] [scenario]
#               ('#' comments and blank lines ignored; scenario default = normal)
# =============================================================================
set -Euo pipefail

SPEC="${SPEC:?set SPEC=<block spec file>}"
OUT="${OUT:?set OUT=<evidence dir>}"
WD_DEADLINE="${WD_DEADLINE:-1800}"
INIT_MODE="${INIT_MODE:-OFF}"
KEEP_D4="${KEEP_D4:-1}"
POLL_MS="${POLL_MS:-400}"
DRY_RUN="${DRY_RUN:-0}"
DRY_FIXTURES="${DRY_FIXTURES:-}"

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
mkdir -p "$OUT" "$OUT/pcaps"
log(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log" >&2; }
# flog: finalize-phase logging AFTER run.log is frozen -> must NOT touch run.log (it is being hashed)
flog(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/finalize.out" >&2; }
die(){ log "FATAL: $*"; RUN_FAILED=1; exit 1; }
RUN_FAILED=0
abort(){ log "ABORT: $*"; RUN_FAILED=1; exit 1; }

# ---- switch/driver primitives (overridden by DRY_RUN) --------------------------------------------
sw(){ local b64; b64="$(printf '%s' "$*" | base64 -w0)"; $SSH "$SW" "echo $b64 | base64 -d | bash -s"; }
setup_sw(){ sw "$SWENV cd $CTRL && DEFENSE4_HW_AUTHORIZED=1 python3 defense4_caseA_setup.py $*"; }
loaded_prog(){ sw 'pid=$(pgrep -ox bf_switchd); conf=$(tr "\0" "\n" < /proc/$pid/cmdline 2>/dev/null | awk "/^--conf-file\$/{getline;print;exit}"); python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[\"p4_devices\"][0][\"p4_programs\"][0][\"program-name\"])" "$conf" 2>/dev/null' | tail -1; }
relay_ok(){ $SSH "$VI" "ping -c2 -W2 $RELAY_IP >/dev/null 2>&1 && timeout 3 bash -c 'echo > /dev/tcp/$RELAY_IP/20000'" >/dev/null 2>&1; }
loaded_bin_sha(){ sw "sha256sum /home/decps/d4_fix_build/out/defense4_caseA/pipe/tofino.bin" | awk '{print $1}' | tail -1; }
# dump <phase:pre|post> <label> -> the switch evidence JSON on stdout
dump(){ setup_sw "evidence-dump --program $D4_PROG" 2>/dev/null | grep '^EVIDENCE ' | sed 's/^EVIDENCE //'; }
# driver_run <label> <N> <gap> <mode> <da> <dr> <seqstart> -> the raw block JSON on stdout
driver_run(){ $SSH -n "$VI" "cd ~/d3phys && python3 campaign_driver.py $1 $2 $3 $4 $5 $6 $7" 2>>"$OUT/driver_${1}.err" | grep '^CAMPAIGN ' | sed 's/^CAMPAIGN //'; }
# copy_pcap <label> -> places $OUT/pcaps/blk_<label>.pcap locally
copy_pcap(){ $SCP "$VI:~/d3phys/blk_${1}.pcap" "$OUT/pcaps/blk_${1}.pcap" >/dev/null 2>&1; }

if [ "$DRY_RUN" = 1 ]; then
  [ -n "$DRY_FIXTURES" ] && [ -d "$DRY_FIXTURES" ] || { echo "DRY_RUN needs DRY_FIXTURES=<dir>" >&2; exit 2; }
  log "DRY_RUN: switch/driver calls served from $DRY_FIXTURES (no ssh)"
  loaded_prog(){ echo "$D4_PROG"; }
  loaded_bin_sha(){ echo "$COMMIT_BIN_SHA"; }
  relay_ok(){ return 0; }
  setup_sw(){ echo "RESULT: PASS (dry $*)"; }
  # dump <phase> <label>: serve the recorded pre/post evidence fixture
  dump(){ cat "$DRY_FIXTURES/ev_${1}_${2}.json"; }
  driver_run(){ cat "$DRY_FIXTURES/block_${1}.json"; }
  copy_pcap(){ [ -f "$DRY_FIXTURES/blk_${1}.pcap" ] && cp "$DRY_FIXTURES/blk_${1}.pcap" "$OUT/pcaps/blk_${1}.pcap"; }
fi

# ---- finalize: run once from on_exit, AFTER the switch state and run.log are final --------------
EXPECTED_PCAPS=""   # space-separated blk_<label>.pcap names the spec should have produced
finalize(){
  # (1) validate PCAP count + names against the spec (a missing/empty PCAP fails the run)
  if [ -n "$EXPECTED_PCAPS" ]; then
    local miss=0 n=0
    for name in $EXPECTED_PCAPS; do
      n=$((n+1))
      if [ ! -f "$OUT/pcaps/$name" ]; then flog "PCAP missing: $name"; miss=1
      elif [ ! -s "$OUT/pcaps/$name" ]; then flog "PCAP empty: $name"; miss=1; fi
    done
    local got; got="$(ls "$OUT/pcaps" 2>/dev/null | grep -c '\.pcap$' || true)"
    if [ "$got" != "$n" ]; then flog "PCAP count mismatch: got $got expected $n"; miss=1; fi
    [ "$miss" = 1 ] && RUN_FAILED=1
    flog "PCAP validation: expected $n, present $got"
  fi
  # (2) run.log is now frozen -> manifest hashes it; use flog (finalize.out) for anything after
  flog "finalizing evidence manifest over closed files"
  if ! bash "$HERE/make_manifest.sh" "$OUT" > "$OUT/manifest.out" 2>&1; then
    flog "make_manifest FAILED"; RUN_FAILED=1
  fi
  # (3) verify; verify output is written AFTER the manifest so it is not one of the hashed files
  if ( cd "$OUT" && sha256sum -c SHA256SUMS ) > "$OUT/manifest_verify.out" 2>&1; then
    flog "sha256sum -c PASS"
  else
    flog "sha256sum -c FAILED (see manifest_verify.out)"; RUN_FAILED=1
  fi
}

ROLLED=0
rollback(){ [ "$ROLLED" = 1 ] && return 0; ROLLED=1
  log "=== ROLLBACK to Defense 3 ==="
  if ! sw "bash $STAGE/rollback_defense3.sh" >> "$OUT/rollback.log" 2>&1; then log "WARN: rollback command errored"; fi
  if [ "$(loaded_prog)" = case_a_defense3 ] && relay_ok; then log "Defense 3 restored + forwarding verified"; else log "WARN: rollback did not verify"; fi
}
on_exit(){ local rc=$?; trap - EXIT
  [ "$RUN_FAILED" = 1 ] && rc=1
  if [ "$DRY_RUN" = 1 ]; then
    log "DRY_RUN: no switch state change"
  elif [ "$rc" = 0 ] && [ "$KEEP_D4" = 1 ]; then
    if [ "$(loaded_prog)" = "$D4_PROG" ] && relay_ok; then
      log "success: leaving Defense 4 running (forwarding verified); standing watchdog down"
      sw "date -u +%Y-%m-%dT%H:%M:%SZ > $MARKER" >/dev/null 2>&1 || log "WARN: could not write completion marker"
    else
      log "success but D4 state unverified -> rolling back for safety"; rollback
      sw "date -u +%Y-%m-%dT%H:%M:%SZ > $MARKER" >/dev/null 2>&1 || true
    fi
  else
    rollback; sw "date -u +%Y-%m-%dT%H:%M:%SZ > $MARKER" >/dev/null 2>&1 || true
  fi
  # run.log is final from here on
  finalize
  exit "$rc"
}
trap on_exit EXIT
trap 'log "SIGINT"; RUN_FAILED=1; exit 130' INT
trap 'log "SIGTERM"; RUN_FAILED=1; exit 143' TERM
trap 'log "SIGHUP"; RUN_FAILED=1; exit 129' HUP

log "=== CAMPAIGN spec=$SPEC out=$OUT init=$INIT_MODE keep_d4=$KEEP_D4 dry=$DRY_RUN ==="
# preflight: D4 loaded, binary matches the committed blob, relay reachable
[ "$(loaded_prog)" = "$D4_PROG" ] || die "switch is not running $D4_PROG"
GOTBIN="$(loaded_bin_sha)"
[ "$GOTBIN" = "$COMMIT_BIN_SHA" ] || die "loaded binary sha mismatch ($GOTBIN)"
relay_ok || die "relay not reachable"
log "preflight OK: $D4_PROG loaded, binary sha matches, relay reachable"

if [ "$DRY_RUN" != 1 ]; then
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
fi

# initialize fixed-function state ONCE
log "--- initialize (mode $INIT_MODE) ---"
setup_sw "initialize --mode $INIT_MODE --poll-ms $POLL_MS" > "$OUT/initialize.txt" 2>&1
grep -q 'RESULT: PASS' "$OUT/initialize.txt" || die "initialize did not PASS"

RESULTS="$OUT/blocks.jsonl"; : > "$RESULTS"
BN=0
# read the spec on fd 3 so ssh inside the loop cannot consume it from stdin
while read -r label mode da dr N gap seqstart budget scenario _rest <&3; do
  case "$label" in ''|'#'*) continue;; esac
  BN=$((BN+1)); seqstart="${seqstart:-0}"; scenario="${scenario:-normal}"
  EXPECTED_PCAPS="$EXPECTED_PCAPS blk_${label}.pcap"
  log "--- block $BN: $label mode=$mode D_A=${da}ms D_R=${dr}ms N=$N gap=$gap seq0=$seqstart budget=${budget:-default} scenario=$scenario ---"

  # set policy (refuses if a txn is active); OFF/FAIL_OPEN ignore da/dr
  polargs="--mode $mode --poll-ms $POLL_MS"
  [ "$mode" != OFF ] && [ "$mode" != FAIL_OPEN ] && polargs="$polargs --d-a-ms $da --d-r-ms $dr"
  [ -n "${budget:-}" ] && [ "$budget" != "-" ] && polargs="$polargs --budget $budget"
  if ! setup_sw "set-policy $polargs" > "$OUT/policy_${label}.txt" 2>&1 || ! grep -q 'RESULT: PASS' "$OUT/policy_${label}.txt"; then
    tail -3 "$OUT/policy_${label}.txt" | tee -a "$OUT/run.log" >&2; abort "set-policy failed for $label"
  fi
  setup_sw "clear-evidence" > "$OUT/clear_${label}.txt" 2>&1 || abort "clear-evidence failed for $label"

  # PRE evidence (must be non-empty valid JSON)
  dump pre "$label" > "$OUT/ev_pre_${label}.json"
  [ -s "$OUT/ev_pre_${label}.json" ] || abort "empty PRE evidence for $label"

  # sustained driver -> block JSON (must be non-empty valid JSON)
  driver_run "$label" "$N" "$gap" "$mode" "$da" "$dr" "$seqstart" > "$OUT/block_${label}.json"
  if [ ! -s "$OUT/block_${label}.json" ] || ! python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$OUT/block_${label}.json" 2>/dev/null; then
    abort "driver produced no valid block JSON for $label"
  fi

  # copy + validate this block's PCAP immediately (fail-closed)
  copy_pcap "$label"
  [ -s "$OUT/pcaps/blk_${label}.pcap" ] || abort "missing/empty PCAP for $label"

  # POST evidence
  dump post "$label" > "$OUT/ev_post_${label}.json"
  [ -s "$OUT/ev_post_${label}.json" ] || abort "empty POST evidence for $label"

  # expected protected polls (0 for OFF/FAIL_OPEN)
  exp="$N"; { [ "$mode" = OFF ] || [ "$mode" = FAIL_OPEN ]; } && exp=0
  ep_arg=""; [ "$exp" != 0 ] && ep_arg="--expected-protected $exp"
  # score (fail-closed): nonzero exit here is a real anomaly -> abort the campaign, preserve evidence
  if python3 "$HERE/score_campaign.py" "$OUT/block_${label}.json" "$OUT/ev_pre_${label}.json" "$OUT/ev_post_${label}.json" \
        --scenario "$scenario" --mode "$mode" --n-expected "$N" $ep_arg --pcap "$OUT/pcaps/blk_${label}.pcap" \
        >> "$RESULTS" 2>>"$OUT/score_err.log"; then
    tail -1 "$RESULTS" | python3 -c "import sys,json;d=json.load(sys.stdin);print('   verdict=%s responded=%s/%s'%(d.get('verdict'),d.get('responded'),d.get('sent')))" | tee -a "$OUT/run.log" >&2
  else
    sc_rc=$?
    tail -1 "$RESULTS" 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);print('   SCORER FAIL: %s'%(d.get('hard_anomalies') or d.get('error')))" 2>/dev/null | tee -a "$OUT/run.log" >&2 || true
    abort "scorer hard anomaly (exit $sc_rc) on $label"
  fi
done 3< "$SPEC"

log "--- all $BN blocks scored clean; pcaps: $(ls "$OUT/pcaps" 2>/dev/null | grep -c '\.pcap$') ---"
log "=== CAMPAIGN complete: $BN blocks -> $RESULTS ==="
exit 0
