#!/usr/bin/env bash
# =============================================================================
#  run_campaign.sh — Defense 4 fail-closed experiment engine (runs on gambit).
#
#  Drives a block SPEC through the harness on the LIVE defense4_caseA binary (harness-only work; the
#  P4 is not reloaded). Per block:
#     set-policy (refuses while a txn is active) -> clear-evidence -> evidence-dump PRE ->
#     sustained campaign_driver on Vision (master-facing full-Ethernet capture) ->
#     relay-facing capture (paired) -> copy captures via a temp name, VALIDATE structurally, rename ->
#     evidence-dump POST -> score_campaign (scenario-aware, fail-closed) ->
#     pair_bytes (relay-ingress vs master-egress) when a paired relay capture exists.
#  After the loop, analyze_campaign runs BEFORE the campaign is declared successful.
#
#  FAIL-CLOSED. `set -Eeuo pipefail`. No `|| true` on any required op. A stale/nonempty OUT dir is
#  refused. Every ssh/scp/init/watchdog/driver/capture/dump/scorer/analyzer/comparator/state/manifest
#  operation is checked; a failure aborts, preserves partial evidence, runs the safety path, and exits
#  nonzero. Captures are copied to a temp name, validated by pcap magic, then renamed. The SHA256SUMS
#  manifest is generated in finalize() AFTER the switch state and run.log are final; finalize() runs
#  BEFORE the process exit code is chosen, so any extra/missing PCAP, manifest generation/verification
#  failure, unverified final state, marker failure, or rollback-verification failure forces a nonzero
#  exit.
#
#  SAFETY (live only): a detached switch-side watchdog is armed for the whole run; EXIT/INT/TERM/HUP
#  roll back to a FORWARDING Defense 3. On success the switch is left running Defense 4 only if
#  KEEP_D4=1 AND forwarding verifies; the completion marker is written only after that is verified.
#  Physical SEL-751 READ-only.
#
#  DRY_RUN=1 serves every switch/driver/capture call from local fixtures under DRY_FIXTURES (no ssh),
#  exercising the full control flow offline. This is how Phase 1 proves the engine without the switch.
#
#  Inputs (env): SPEC=<spec>  OUT=<fresh evidence dir>  [WD_DEADLINE=1800] [INIT_MODE=OFF]
#    [KEEP_D4=1] [POLL_MS=400] [DRY_RUN=0] [DRY_FIXTURES=<dir>] [CAP_IFACE_MASTER] [CAP_IFACE_RELAY]
#    [TEST_INJECT_EXTRA_PCAP=<name>]  (test-only: drops a stray pcap so finalize's extra-pcap check fires)
#  SPEC lines:  <label> <mode> <d_a_ms> <d_r_ms> <N> <gap_s> [seq_start] [budget] [scenario] [expect_neg]
# =============================================================================
set -Eeuo pipefail

SPEC="${SPEC:?set SPEC=<block spec file>}"
OUT="${OUT:?set OUT=<evidence dir>}"
WD_DEADLINE="${WD_DEADLINE:-1800}"
INIT_MODE="${INIT_MODE:-OFF}"
KEEP_D4="${KEEP_D4:-1}"
POLL_MS="${POLL_MS:-400}"
DRY_RUN="${DRY_RUN:-0}"
DRY_FIXTURES="${DRY_FIXTURES:-}"
CAP_IFACE_MASTER="${CAP_IFACE_MASTER:-enp59s0f0np0}"
CAP_IFACE_RELAY="${CAP_IFACE_RELAY:-enp59s0f1np1}"
# CAPTURE_MODE: "dual" = master + relay-facing capture with paired byte comparison (software
# outstation, Phase 2); "master" = master-facing capture only (physical SEL-751, which has no
# relay-facing capture point). Byte identity is a software-outstation claim, so the physical campaign
# runs master-only and does not assert paired byte identity.
CAPTURE_MODE="${CAPTURE_MODE:-dual}"
TEST_INJECT_EXTRA_PCAP="${TEST_INJECT_EXTRA_PCAP:-}"

SW="${SW_HOST:-decps@10.10.54.81}"
VI="${VI_HOST:-decps@10.10.54.19}"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5"
SCP="scp -o BatchMode=yes -o ConnectTimeout=10"
SWENV="export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=\$SDE/install; export LD_LIBRARY_PATH=\$SDE_INSTALL/lib:\${LD_LIBRARY_PATH:-}; export PYTHONPATH=\$SDE_INSTALL/lib/python3.8/site-packages/tofino:\$SDE_INSTALL/lib/python3.8/site-packages:\${PYTHONPATH:-};"
CTRL=/home/decps/d4_build/control
STAGE=/home/decps/d4_build
D4_PROG=defense4_caseA
RELAY_IP="${RELAY_IP:-192.168.10.7}"
MASTER_IP="${MASTER_IP:-192.168.10.1}"
MARKER=$STAGE/d4_complete.marker
COMMIT_BIN_SHA=97175e7dc1a77c3cdbe235baa13b906e18d3227bf09cb84cfacfee6f0a928a19
P4_SRC_REL=defense4/timing/p4/defense4_caseA.p4

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../../.." && pwd)"
RP="${RESEARCH_PYTHON:-}"
if [ -z "$RP" ]; then RP="$(command -v python3)"; fi   # scapy needed for pair_bytes; resolve, never hardcode a home path

# ---- refuse a stale / nonempty OUT dir (never let old evidence satisfy a failed copy) ----
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null || true)" ]; then
  echo "run_campaign: OUT exists and is nonempty ($OUT); refusing to reuse a stale evidence dir" >&2
  exit 2
fi
mkdir -p "$OUT/pcaps" "$OUT/pcaps_relay" "$OUT/pair" "$OUT/meta"

log(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log" >&2; }
flog(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/finalize.out" >&2; }
RUN_FAILED=0
die(){ log "FATAL: $*"; RUN_FAILED=1; exit 1; }
abort(){ log "ABORT: $*"; RUN_FAILED=1; exit 1; }

# pcap magic validation (classic pcap + pcapng), used for every copied capture
valid_pcap(){ python3 - "$1" <<'PY'
import sys
try:
    m=open(sys.argv[1],'rb').read(4)
except Exception:
    sys.exit(1)
ok={b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d',b'\x0a\x0d\x0d\x0a'}
import os
sys.exit(0 if (m in ok and os.path.getsize(sys.argv[1])>=24) else 1)
PY
}

# ---- switch/driver primitives (overridden by DRY_RUN) --------------------------------------------
sw(){ local b64; b64="$(printf '%s' "$*" | base64 -w0)"; $SSH "$SW" "echo $b64 | base64 -d | bash -s"; }
setup_sw(){ sw "$SWENV cd $CTRL && DEFENSE4_HW_AUTHORIZED=1 python3 defense4_caseA_setup.py $*"; }
loaded_prog(){ sw 'pid=$(pgrep -ox bf_switchd); conf=$(tr "\0" "\n" < /proc/$pid/cmdline 2>/dev/null | awk "/^--conf-file\$/{getline;print;exit}"); python3 -c "import json,sys;print(json.load(open(sys.argv[1]))[\"p4_devices\"][0][\"p4_programs\"][0][\"program-name\"])" "$conf" 2>/dev/null' | tail -1; }
relay_ok(){ $SSH "$VI" "ping -c2 -W2 $RELAY_IP >/dev/null 2>&1 && timeout 3 bash -c 'echo > /dev/tcp/$RELAY_IP/20000'" >/dev/null 2>&1; }
# the sha of the binary the RUNNING pipeline actually loaded (derived from the loaded conf's
# pipeline config path, not a disk file), so the preflight cannot be fooled by a fix binary that was
# compiled but never deployed
loaded_bin_sha(){ sw 'pid=$(pgrep -ox bf_switchd); conf=$(tr "\0" "\n" < /proc/$pid/cmdline 2>/dev/null | awk "/^--conf-file\$/{getline;print;exit}"); binp=$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(d[\"p4_devices\"][0][\"p4_programs\"][0][\"p4_pipelines\"][0][\"config\"])" "$conf" 2>/dev/null); sha256sum "$binp" 2>/dev/null | cut -d" " -f1' | tail -1; }
dump(){ setup_sw "evidence-dump --program $D4_PROG" 2>/dev/null | grep '^EVIDENCE ' | sed 's/^EVIDENCE //'; }
driver_run(){ $SSH -n "$VI" "cd ~/d3phys && python3 campaign_driver.py $1 $2 $3 $4 $5 $6 $7" 2>>"$OUT/driver_${1}.err" | grep '^CAMPAIGN ' | sed 's/^CAMPAIGN //'; }
fetch_master_pcap(){ $SCP "$VI:~/d3phys/blk_${1}.pcap" "$2" >/dev/null 2>&1; }
fetch_relay_pcap(){ $SCP "$VI:~/d3phys/blk_${1}_relay.pcap" "$2" >/dev/null 2>&1; }   # Phase 2 dual capture
offload_record(){ # <iface> <phase-file> ; enforce GRO/GSO/TSO/LRO off, record settings
  $SSH "$VI" "ethtool -k $1 2>/dev/null | grep -E 'generic-receive-offload|generic-segmentation-offload|tcp-segmentation-offload|large-receive-offload|rx-checksumming|tx-checksumming'" > "$2" 2>/dev/null || true
  if grep -Eq ': on' "$2"; then return 1; fi
}

if [ "$DRY_RUN" = 1 ]; then
  [ -n "$DRY_FIXTURES" ] && [ -d "$DRY_FIXTURES" ] || { echo "DRY_RUN needs DRY_FIXTURES=<dir>" >&2; exit 2; }
  log "DRY_RUN: switch/driver/capture served from $DRY_FIXTURES (no ssh)"
  loaded_prog(){ echo "$D4_PROG"; }
  loaded_bin_sha(){ echo "$COMMIT_BIN_SHA"; }
  relay_ok(){ return 0; }
  setup_sw(){ echo "RESULT: PASS (dry $*)"; }
  dump(){ cat "$DRY_FIXTURES/ev_${1}_${2}.json"; }
  driver_run(){ cat "$DRY_FIXTURES/block_${1}.json"; }
  fetch_master_pcap(){ [ -f "$DRY_FIXTURES/blk_${1}.pcap" ] && cp "$DRY_FIXTURES/blk_${1}.pcap" "$2"; }
  fetch_relay_pcap(){ [ -f "$DRY_FIXTURES/blk_${1}_relay.pcap" ] && cp "$DRY_FIXTURES/blk_${1}_relay.pcap" "$2"; }
  offload_record(){ printf 'generic-receive-offload: off\ngeneric-segmentation-offload: off\ntcp-segmentation-offload: off\nlarge-receive-offload: off\n' > "$2"; }
fi

# ---- finalize: run once from on_exit, AFTER the switch state and run.log are final --------------
EXPECTED_PCAPS=""
finalize(){
  # (0) a test hook can drop a stray pcap so the extra-pcap detection is exercised
  [ -n "$TEST_INJECT_EXTRA_PCAP" ] && : > "$OUT/pcaps/$TEST_INJECT_EXTRA_PCAP"
  # (1) validate PCAP set: every expected present+valid, and NO unexpected pcap
  local n=0
  for name in $EXPECTED_PCAPS; do
    n=$((n+1))
    if [ ! -s "$OUT/pcaps/$name" ]; then flog "PCAP missing/empty: $name"; RUN_FAILED=1
    elif ! valid_pcap "$OUT/pcaps/$name"; then flog "PCAP invalid: $name"; RUN_FAILED=1; fi
  done
  for f in "$OUT"/pcaps/*.pcap; do
    [ -e "$f" ] || continue
    local base; base="$(basename "$f")"
    case " $EXPECTED_PCAPS " in *" $base "*) : ;; *) flog "UNEXPECTED pcap in evidence: $base"; RUN_FAILED=1 ;; esac
  done
  local got; got="$(ls "$OUT"/pcaps/*.pcap 2>/dev/null | wc -l)"
  flog "PCAP validation: expected $n, present $got"
  # (2) run.log frozen -> manifest hashes it; use flog (finalize.out) after this
  flog "generating manifest over closed files"
  if ! bash "$HERE/make_manifest.sh" "$OUT" > "$OUT/manifest.out" 2>&1; then flog "make_manifest FAILED"; RUN_FAILED=1; fi
  if ( cd "$OUT" && sha256sum -c SHA256SUMS ) > "$OUT/manifest_verify.out" 2>&1; then flog "sha256sum -c PASS"
  else flog "sha256sum -c FAILED"; RUN_FAILED=1; fi
}

ROLLED=0
rollback(){ [ "$ROLLED" = 1 ] && return 0; ROLLED=1
  log "=== ROLLBACK to Defense 3 ==="
  sw "bash $STAGE/rollback_defense3.sh" >> "$OUT/rollback.log" 2>&1 || log "WARN: rollback command errored"
  if [ "$(loaded_prog)" = case_a_defense3 ] && relay_ok; then log "Defense 3 restored + forwarding verified"
  else log "WARN: rollback did not verify"; RUN_FAILED=1; fi
}
on_exit(){ local rc=$?; trap - EXIT
  if [ "$DRY_RUN" = 1 ]; then
    log "DRY_RUN: no switch state change"
  elif [ "$rc" = 0 ] && [ "$KEEP_D4" = 1 ]; then
    if [ "$(loaded_prog)" = "$D4_PROG" ] && relay_ok; then
      log "success: leaving Defense 4 running (forwarding verified); standing watchdog down"
      sw "date -u +%Y-%m-%dT%H:%M:%SZ > $MARKER" >/dev/null 2>&1 || { log "WARN: completion marker not written"; RUN_FAILED=1; }
    else log "success but D4 state unverified -> rolling back for safety"; rollback; RUN_FAILED=1; fi
  else
    rollback
  fi
  # finalize BEFORE choosing the exit code, so a finalize/manifest failure changes the result
  finalize
  [ "$RUN_FAILED" = 1 ] && rc=1
  exit "$rc"
}
trap on_exit EXIT
trap 'log "SIGINT"; RUN_FAILED=1; exit 130' INT
trap 'log "SIGTERM"; RUN_FAILED=1; exit 143' TERM
trap 'log "SIGHUP"; RUN_FAILED=1; exit 129' HUP

log "=== CAMPAIGN spec=$SPEC out=$OUT init=$INIT_MODE keep_d4=$KEEP_D4 dry=$DRY_RUN ==="

# ---- provenance: copy the exact spec + record hashes/commit/env/tools/ifaces/offload ----
cp "$SPEC" "$OUT/spec.txt"
{ echo "commit=$(cd "$REPO" && git rev-parse HEAD 2>/dev/null || echo NA)"
  echo "branch=$(cd "$REPO" && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo NA)"
  echo "p4_source_sha256=$(sha256sum "$REPO/$P4_SRC_REL" 2>/dev/null | awk '{print $1}')"
  echo "expected_binary_sha256=$COMMIT_BIN_SHA"
  echo "uname=$(uname -a)"
  echo "python3=$(python3 --version 2>&1)"
  echo "research_python=$RP ($($RP --version 2>&1))"
  echo "scapy=$($RP -c 'import scapy;print(scapy.__version__)' 2>&1)"
  echo "tcpdump=$(command -v tcpdump && tcpdump --version 2>&1 | head -1 || echo NA)"
  echo "cap_iface_master=$CAP_IFACE_MASTER cap_iface_relay=$CAP_IFACE_RELAY"
  echo "relay_ip=$RELAY_IP master_ip=$MASTER_IP dry=$DRY_RUN"
} > "$OUT/meta/provenance.txt"
# Byte identity (dual mode) needs segment boundaries intact, so offloads MUST be off there. A
# master-only physical CLRT campaign times single-segment responses, where GRO has nothing to
# coalesce; if offloads cannot be disabled (no sudo), record them and account for it rather than abort.
if ! offload_record "$CAP_IFACE_MASTER" "$OUT/meta/offload_master.txt"; then
  if [ "$CAPTURE_MODE" = dual ]; then
    abort "offloads enabled on $CAP_IFACE_MASTER (GRO/GSO/TSO/LRO must be off for byte identity)"
  else
    log "NOTE: offloads on $CAP_IFACE_MASTER; master-only single-segment CLRT capture, offloads ACCOUNTED (recorded) not disabled"
    echo "offload_note=on_but_accounted_single_segment_clrt" >> "$OUT/meta/offload_master.txt"
  fi
fi
if [ "$CAPTURE_MODE" = dual ]; then
  offload_record "$CAP_IFACE_RELAY" "$OUT/meta/offload_relay.txt" || abort "offloads enabled on $CAP_IFACE_RELAY"
fi

# ---- preflight ----
[ "$(loaded_prog)" = "$D4_PROG" ] || die "switch is not running $D4_PROG"
GOTBIN="$(loaded_bin_sha)"
echo "loaded_binary_sha256=$GOTBIN" >> "$OUT/meta/provenance.txt"
[ "$GOTBIN" = "$COMMIT_BIN_SHA" ] || die "loaded binary sha mismatch ($GOTBIN)"
relay_ok || die "relay not reachable"
log "preflight OK: $D4_PROG loaded, binary sha matches, relay reachable"

if [ "$DRY_RUN" != 1 ]; then
  $SCP "$REPO/defense4/timing/control/defense4_caseA_setup.py" "$REPO/defense3/setup/case_a_defense3_fixed_ack_delay_setup.py" "$SW:$CTRL/" >/dev/null || die "stage setup scripts failed"
  $SCP "$HERE/rollback_defense3.sh" "$HERE/watchdog.sh" "$SW:$STAGE/" >/dev/null || die "stage rollback/watchdog failed"
  sw "chmod +x $STAGE/rollback_defense3.sh $STAGE/watchdog.sh" >/dev/null || die "chmod staged scripts failed"
  $SCP "$HERE/campaign_driver.py" "$VI:~/d3phys/" >/dev/null || die "stage driver failed"
  sw "rm -f $MARKER $STAGE/WATCHDOG_ESCALATION; setsid nohup bash $STAGE/watchdog.sh $WD_DEADLINE $MARKER $STAGE/rollback_defense3.sh >/dev/null 2>&1 & echo armed" >/dev/null || die "arm watchdog failed"
  sleep 1
  sw "ps -eo args | grep -F watchdog.sh | grep -v grep >/dev/null && echo alive" | grep -q alive || die "watchdog did not arm"
  log "watchdog armed (deadline ${WD_DEADLINE}s)"
fi

log "--- initialize (mode $INIT_MODE) ---"
setup_sw "initialize --mode $INIT_MODE --poll-ms $POLL_MS" > "$OUT/initialize.txt" 2>&1 || abort "initialize command failed"
grep -q 'RESULT: PASS' "$OUT/initialize.txt" || die "initialize did not PASS"

RESULTS="$OUT/blocks.jsonl"; : > "$RESULTS"
BN=0
while read -r label mode da dr N gap seqstart budget scenario expectneg _rest <&3; do
  case "$label" in ''|'#'*) continue;; esac
  BN=$((BN+1)); seqstart="${seqstart:-0}"; scenario="${scenario:-normal}"
  EXPECTED_PCAPS="$EXPECTED_PCAPS blk_${label}.pcap"
  log "--- block $BN: $label mode=$mode D_A=${da}ms D_R=${dr}ms N=$N gap=$gap seq0=$seqstart budget=${budget:-default} scenario=$scenario ---"

  polargs="--mode $mode --poll-ms $POLL_MS"
  [ "$mode" != OFF ] && [ "$mode" != FAIL_OPEN ] && polargs="$polargs --d-a-ms $da --d-r-ms $dr"
  [ -n "${budget:-}" ] && [ "$budget" != "-" ] && polargs="$polargs --budget $budget"
  setup_sw "set-policy $polargs" > "$OUT/policy_${label}.txt" 2>&1 || { tail -3 "$OUT/policy_${label}.txt" | tee -a "$OUT/run.log" >&2; abort "set-policy failed for $label"; }
  grep -q 'RESULT: PASS' "$OUT/policy_${label}.txt" || abort "set-policy did not PASS for $label"
  setup_sw "clear-evidence" > "$OUT/clear_${label}.txt" 2>&1 || abort "clear-evidence failed for $label"

  dump pre "$label" > "$OUT/ev_pre_${label}.json" || abort "PRE evidence-dump failed for $label"
  [ -s "$OUT/ev_pre_${label}.json" ] || abort "empty PRE evidence for $label"

  driver_run "$label" "$N" "$gap" "$mode" "$da" "$dr" "$seqstart" > "$OUT/block_${label}.json" || abort "driver failed for $label"
  { [ -s "$OUT/block_${label}.json" ] && python3 -c "import json,sys;json.load(open(sys.argv[1]))" "$OUT/block_${label}.json"; } 2>/dev/null || abort "driver produced no valid block JSON for $label"

  # copy master-facing capture via temp name, validate structurally, then rename
  fetch_master_pcap "$label" "$OUT/pcaps/.blk_${label}.pcap.tmp" || abort "fetch master pcap failed for $label"
  { [ -s "$OUT/pcaps/.blk_${label}.pcap.tmp" ] && valid_pcap "$OUT/pcaps/.blk_${label}.pcap.tmp"; } || abort "invalid master pcap for $label"
  mv "$OUT/pcaps/.blk_${label}.pcap.tmp" "$OUT/pcaps/blk_${label}.pcap"
  # paired relay-facing capture (dual mode only: software outstation). The physical SEL-751 has no
  # relay-facing capture point, so master-only mode does not attempt it and asserts no byte identity.
  if [ "$CAPTURE_MODE" = dual ]; then
    if fetch_relay_pcap "$label" "$OUT/pcaps_relay/.blk_${label}_relay.pcap.tmp" && [ -s "$OUT/pcaps_relay/.blk_${label}_relay.pcap.tmp" ]; then
      valid_pcap "$OUT/pcaps_relay/.blk_${label}_relay.pcap.tmp" || abort "invalid relay pcap for $label"
      mv "$OUT/pcaps_relay/.blk_${label}_relay.pcap.tmp" "$OUT/pcaps_relay/blk_${label}_relay.pcap"
    else
      rm -f "$OUT/pcaps_relay/.blk_${label}_relay.pcap.tmp"
    fi
  fi

  dump post "$label" > "$OUT/ev_post_${label}.json" || abort "POST evidence-dump failed for $label"
  [ -s "$OUT/ev_post_${label}.json" ] || abort "empty POST evidence for $label"

  exp="$N"; { [ "$mode" = OFF ] || [ "$mode" = FAIL_OPEN ]; } && exp=0
  scargs=(--scenario "$scenario" --mode "$mode" --label "$label" --n-expected "$N" --pcap "$OUT/pcaps/blk_${label}.pcap")
  [ "$mode" != OFF ] && [ "$mode" != FAIL_OPEN ] && scargs+=(--d-a-ms "$da" --d-r-ms "$dr")
  [ "$exp" != 0 ] && scargs+=(--expected-protected "$exp")
  [ -n "${expectneg:-}" ] && [ "$expectneg" != "-" ] && scargs+=(--expect-negative "$expectneg")
  if python3 "$HERE/score_campaign.py" "$OUT/block_${label}.json" "$OUT/ev_pre_${label}.json" "$OUT/ev_post_${label}.json" "${scargs[@]}" >> "$RESULTS" 2>>"$OUT/score_err.log"; then
    tail -1 "$RESULTS" | python3 -c "import sys,json;d=json.load(sys.stdin);print('   verdict=%s responded=%s/%s'%(d.get('verdict'),d.get('responded'),d.get('sent')))" | tee -a "$OUT/run.log" >&2
  else
    sc_rc=$?
    tail -1 "$RESULTS" 2>/dev/null | python3 -c "import sys,json;d=json.load(sys.stdin);print('   SCORER FAIL: %s'%(d.get('hard_anomalies') or d.get('error')))" 2>/dev/null | tee -a "$OUT/run.log" >&2 || true
    abort "scorer hard anomaly (exit $sc_rc) on $label"
  fi

  # paired byte comparison when a relay-facing capture exists
  if [ -s "$OUT/pcaps_relay/blk_${label}_relay.pcap" ]; then
    # preserve the intended-byte record IN the evidence dir (so it is hashed), from the software
    # outstation (live) or the fixture (dry)
    if [ "$DRY_RUN" = 1 ] && [ -s "$DRY_FIXTURES/intended.jsonl" ]; then cp "$DRY_FIXTURES/intended.jsonl" "$OUT/intended_${label}.jsonl"; fi
    intended_arg=(); [ -s "$OUT/intended_${label}.jsonl" ] && intended_arg=(--intended "$OUT/intended_${label}.jsonl")
    if ! "$RP" "$HERE/pair_bytes.py" --ingress "$OUT/pcaps_relay/blk_${label}_relay.pcap" --egress "$OUT/pcaps/blk_${label}.pcap" \
          --relay-ip "$RELAY_IP" --master-ip "$MASTER_IP" --offloads off "${intended_arg[@]}" --out "$OUT/pair/pair_${label}.json" >/dev/null 2>>"$OUT/pair_err.log"; then
      abort "paired byte comparison FAILED for $label"
    fi
  fi
done 3< "$SPEC"

# analyzer must pass BEFORE the campaign is declared successful (no manifest yet -> no --require-manifest)
log "--- analyze (fail-closed, condition-aware) ---"
"$RP" "$HERE/analyze_campaign.py" "$OUT" "$OUT/analysis.json" --spec "$OUT/spec.txt" >/dev/null 2>>"$OUT/analyze_err.log" || abort "analyzer failed"

log "--- all $BN blocks scored + analyzed clean; master pcaps: $(ls "$OUT"/pcaps/*.pcap 2>/dev/null | wc -l), relay pcaps: $(ls "$OUT"/pcaps_relay/*.pcap 2>/dev/null | wc -l), pairs: $(ls "$OUT"/pair/*.json 2>/dev/null | wc -l) ---"
log "=== CAMPAIGN complete: $BN blocks -> $RESULTS ==="
exit 0
