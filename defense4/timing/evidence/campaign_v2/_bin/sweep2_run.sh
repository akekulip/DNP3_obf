#!/usr/bin/env bash
# sweep2_run.sh — the campaign_v2 hardware policy sweep, on the corrected request-anchored build.
#
# The point set is campaign_v1's, point for point, so the two sweeps compare directly and the
# effect of request anchoring is visible across the whole policy space rather than at one setting.
# One point is added: sw_D4_20_8, the policy campaign_v2 actually ships, which campaign_v1's set
# does not contain.
#
# Three points establish the operating envelope rather than a release policy. sw_off is the relay
# unmodified. sw_D2_0_24 and sw_D3_20_0 select modes the decision tables no longer carry entries
# for, so nothing is held and the timing is native; they are the control that says the holding is
# done by the D4 entries and not by the switch merely being in the path. They run with the anchor
# knob clear, which makes them a control for it too.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$HERE/sweep2.log"
NREAD=${1:-300}; NSBO=${2:-30}
log(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG"; }

#      tag              mode  D_A  D_R
POINTS="
sw_off                  OFF   0    0
sw_D2_0_24              D2    0    24
sw_D3_20_0              D3    20   0
sw_D4_04_4              D4    4    4
sw_D4_12_4              D4    12   4
sw_D4_20_4              D4    20   4
sw_D4_28_4              D4    28   4
sw_D4_30_4              D4    30   4
sw_D4_32_4              D4    32   4
sw_D4_34_4              D4    34   4
sw_D4_36_4              D4    36   4
sw_D4_23_1              D4    23   1
sw_D4_22_2              D4    22   2
sw_D4_20_8              D4    20   8
sw_D4_16_8              D4    16   8
sw_D4_12_12             D4    12   12
sw_D4_08_16             D4    8    16
sw_D4_04_20             D4    4    20
sw_D4_02_22             D4    2    22
"

log "=== sweep2 START n_read=$NREAD n_sbo=$NSBO (control lane held at A=20 R=28) ==="
SEED=5000; NFAIL=0; NOK=0
while read -r TAG MODE DA DR; do
  [ -z "${TAG:-}" ] && continue
  SEED=$((SEED+1))
  if bash "$HERE/sweep2_block.sh" "$TAG" "$MODE" "$DA" "$DR" "$NREAD" "$NSBO" "$SEED" >>"$LOG" 2>&1; then
    NOK=$((NOK+1))
  else
    log "  $TAG FAILED, retrying once"
    if bash "$HERE/sweep2_block.sh" "$TAG" "$MODE" "$DA" "$DR" "$NREAD" "$NSBO" "$SEED" >>"$LOG" 2>&1; then
      NOK=$((NOK+1))
    else
      # A refused point is a finding, not an error: the control plane refuses a set it cannot
      # install, and which sets it refuses is part of what a policy sweep reports.
      log "  $TAG FAILED TWICE (refused or unusable); recorded as absent"; NFAIL=$((NFAIL+1))
    fi
  fi
done <<< "$POINTS"
log "=== sweep2 COMPLETE: $NOK points captured, $NFAIL absent ==="

# Restore the shipped policy before leaving the switch, and prove it took. The restore capture is
# named sw_restore, which the validator excludes: it is a policy restoration, not a sweep point.
log "restoring the shipped policy D_A=20 D_R=8 anchor_req=1"
bash "$HERE/sweep2_block.sh" sw_restore D4 20 8 60 6 9999 >>"$LOG" 2>&1 \
  && log "restore OK" || log "RESTORE FAILED - the switch is left on the last sweep point"

# Collect and publish.
DS="$(cd "$HERE/.." && pwd)/sweep"
mkdir -p "$DS/raw_pcaps" "$DS/app_jsonl"
PW="$(. ~/.lab_env 2>/dev/null; printf %s "$SSHPASS")"
VI="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.166"
$VI "echo '$PW' | sudo -S -p '' chmod 644 /tmp/sweep2/*.pcap 2>/dev/null; true" >/dev/null 2>&1
scp -o BatchMode=yes -q decps@10.10.54.166:/tmp/sweep2/'*.pcap'  "$DS/raw_pcaps/" 2>/dev/null
scp -o BatchMode=yes -q decps@10.10.54.166:/tmp/sweep2/'*.jsonl' "$DS/app_jsonl/" 2>/dev/null
log "collected $(ls "$DS"/raw_pcaps/*.pcap 2>/dev/null | wc -l) captures"
RP=~/.venvs/research/bin/python; [ -x "$RP" ] || RP=python3
"$RP" "$HERE/finalize_sweep.py" 2>&1 | tee -a "$LOG"
