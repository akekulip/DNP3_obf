#!/usr/bin/env bash
# Manual fail-closed campaign (no watchdog/rollback trap), so a scorer flag never costs the D4
# deployment. Per block: set-policy -> clear-evidence -> dump PRE -> driver -> copy pcap -> dump POST
# -> score. Then analyze + manifest. Switch stays on whatever the last block sets (order D4 last).
set -uo pipefail
OUT="${1:?OUT}"; SPEC="${2:?SPEC}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
DEPLOY=$REPO/defense4/timing/control/deploy
RP="${RESEARCH_PYTHON:-$HOME/.venvs/research/bin/python}"
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5"
SW=decps@10.10.54.81; VI=decps@10.10.54.19
SWENV='export SDE=/home/decps/Downloads/bf-sde-9.13.2; export SDE_INSTALL=$SDE/install; export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}; export PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$SDE_INSTALL/lib/python3.8/site-packages:${PYTHONPATH:-};'
CTRL=/home/decps/d4_build/control
sw(){ local b64; b64="$(printf '%s' "$*" | base64 -w0)"; $SSH -n "$SW" "echo $b64 | base64 -d | bash -s"; }
setup_sw(){ sw "$SWENV cd $CTRL && DEFENSE4_HW_AUTHORIZED=1 python3 defense4_caseA_setup.py $*"; }
dump(){ setup_sw "evidence-dump --program defense4_caseA" 2>/dev/null | grep '^EVIDENCE ' | sed 's/^EVIDENCE //'; }

mkdir -p "$OUT/pcaps"; : > "$OUT/blocks.jsonl"; cp "$SPEC" "$OUT/spec.txt"
log(){ printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" | tee -a "$OUT/run.log"; }
log "=== manual campaign start: spec=$SPEC ==="
while read -r label mode da dr N gap seqstart budget scenario expectneg _rest <&3; do
  case "$label" in ''|'#'*) continue;; esac
  seqstart="${seqstart:-0}"; scenario="${scenario:-normal}"
  log "block $label mode=$mode da=$da dr=$dr N=$N"
  polargs="--mode $mode --poll-ms 400"
  [ "$mode" != OFF ] && [ "$mode" != FAIL_OPEN ] && polargs="$polargs --d-a-ms $da --d-r-ms $dr"
  setup_sw "set-policy $polargs" > "$OUT/policy_${label}.txt" 2>&1
  grep -q 'RESULT: PASS' "$OUT/policy_${label}.txt" || { log "  set-policy FAILED $label"; continue; }
  setup_sw "clear-evidence" > "$OUT/clear_${label}.txt" 2>&1
  dump > "$OUT/ev_pre_${label}.json"
  $SSH -n "$VI" "cd ~/d3phys && python3 campaign_driver.py $label $N $gap $mode $da $dr $seqstart" 2>>"$OUT/driver.err" | grep '^CAMPAIGN ' | sed 's/^CAMPAIGN //' > "$OUT/block_${label}.json"
  $SSH -n "$VI" "cp ~/d3phys/blk_${label}.pcap /tmp/blk_${label}.pcap" 2>/dev/null
  scp -o BatchMode=yes "$VI:/tmp/blk_${label}.pcap" "$OUT/pcaps/blk_${label}.pcap" >/dev/null 2>&1
  dump > "$OUT/ev_post_${label}.json"
  exp="$N"; { [ "$mode" = OFF ] || [ "$mode" = FAIL_OPEN ]; } && exp=0
  scargs=(--scenario "$scenario" --mode "$mode" --label "$label" --n-expected "$N" --pcap "$OUT/pcaps/blk_${label}.pcap")
  [ "$mode" != OFF ] && [ "$mode" != FAIL_OPEN ] && scargs+=(--d-a-ms "$da" --d-r-ms "$dr")
  [ "$exp" != 0 ] && scargs+=(--expected-protected "$exp")
  if python3 "$DEPLOY/score_campaign.py" "$OUT/block_${label}.json" "$OUT/ev_pre_${label}.json" "$OUT/ev_post_${label}.json" "${scargs[@]}" >> "$OUT/blocks.jsonl" 2>>"$OUT/score.err"; then
    v=$(tail -1 "$OUT/blocks.jsonl" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d['verdict'],'resp',d.get('responded'),'/',d.get('sent'),'bypass',d.get('delta_cf_RESP_BYPASS'))")
    log "  scored: $v"
  else
    log "  scored: FAIL ($(tail -1 "$OUT/blocks.jsonl" | python3 -c "import sys,json;print(json.load(sys.stdin).get('hard_anomalies'))" 2>/dev/null))"
  fi
done 3< "$SPEC"
log "=== analyze + manifest ==="
"$RP" "$DEPLOY/analyze_campaign.py" "$OUT" "$OUT/analysis.json" --spec "$OUT/spec.txt" > "$OUT/analyze.out" 2>&1 && log "analyze PASS" || log "analyze FAIL"
# finalize run.log THEN manifest
log "=== campaign complete ==="
bash "$DEPLOY/make_manifest.sh" "$OUT" > "$OUT/manifest.out" 2>&1
( cd "$OUT" && sha256sum -c SHA256SUMS ) > "$OUT/manifest_verify.out" 2>&1 && echo "MANIFEST VERIFIES" || echo "MANIFEST FAILED"
