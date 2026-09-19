#!/usr/bin/env bash
# campaign2_run.sh [n_sessions] [n_read] [n_sbo]
#
# campaign_v2: the corrected, request-anchored build, collected in campaign_v1's own shape so the
# two datasets are directly comparable -- 22 sessions of 6 blocks, 400 READ and 40 SBO per block,
# 132 captures and 63,360 exchanges, with the arm order rotated across four patterns so no arm
# always follows the same predecessor.
#
# Differences from campaign_v1/_bin/campaign_5h.sh, all deliberate:
#   - it calls the hardened block runner, which proves the size carve off and the anchor state set
#     from a hardware readback and aborts on a missing, short, or still-open capture;
#   - sessions run back to back rather than on a fixed 15-minute slot, because the added readbacks
#     make a session longer than that slot; the window is still several hours, so the drift the
#     slot cadence was there to sample is still sampled;
#   - a failed block is retried once before the session is marked incomplete, and a session that
#     loses a block is kept on disk and named in the log rather than silently averaged over.
set -uo pipefail
BIN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DSROOT="$(cd "$BIN/.." && pwd)"
LOG="$BIN/campaign2.log"; HB="$BIN/HEARTBEAT.txt"
BLOCK="$BIN/campaign2_block.sh"
PW="$(. ~/.lab_env 2>/dev/null; printf %s "$SSHPASS")"
VI="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.166"
RP=~/.venvs/research/bin/python
[ -x "$RP" ] || RP=python3

NSESS=${1:-22}; NREAD=${2:-400}; NSBO=${3:-40}
ORD0="OFF D4 D4 OFF D4 OFF"; ORD1="D4 OFF OFF D4 OFF D4"
ORD2="OFF OFF D4 D4 OFF D4"; ORD3="D4 D4 OFF OFF D4 OFF"
log(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG"; }
heal_ip(){ $VI "ip -br addr show enp59s0f0np0 | grep -q 192.168.10.1 || (echo '$PW' | sudo -S -p '' ip addr add 192.168.10.1/24 dev enp59s0f0np0)" >/dev/null 2>&1; }

START=$(date +%s)
log "=== campaign2 START sessions=$NSESS n_read=$NREAD n_sbo=$NSBO  D_A=20 D_R=8 anchor_req=1 ==="
for IDX in $(seq 1 "$NSESS"); do
  SESS=$(printf "s%02d" "$IDX")
  case $((IDX % 4)) in 0) ORD=$ORD0;; 1) ORD=$ORD1;; 2) ORD=$ORD2;; 3) ORD=$ORD3;; esac
  log "--- $SESS start (order: $ORD) ---"
  heal_ip
  $VI "mkdir -p /tmp/$SESS; find /tmp/$SESS -maxdepth 1 -type f -delete" >/dev/null 2>&1
  BI=1; ORDER_CSV=""; SEED_CSV=""; NFAIL=0
  for MODE in $ORD; do
    SEED=$((IDX*1000+BI))
    if ! bash "$BLOCK" "$SESS" "b$BI" "$MODE" "$NREAD" "$NSBO" "$SEED" >>"$LOG" 2>&1; then
      log "  $SESS b$BI FAILED, retrying once"
      if ! bash "$BLOCK" "$SESS" "b$BI" "$MODE" "$NREAD" "$NSBO" "$SEED" >>"$LOG" 2>&1; then
        log "  $SESS b$BI FAILED TWICE, left out of this session"; NFAIL=$((NFAIL+1))
      fi
    fi
    ORDER_CSV="${ORDER_CSV:+$ORDER_CSV,}$MODE"; SEED_CSV="${SEED_CSV:+$SEED_CSV,}$SEED"
    BI=$((BI+1))
  done
  DSS="$DSROOT/$SESS"; mkdir -p "$DSS/raw_pcaps" "$DSS/app_jsonl"
  $VI "echo '$PW' | sudo -S -p '' chmod 644 /tmp/$SESS/*.pcap 2>/dev/null; true" >/dev/null 2>&1
  scp -o BatchMode=yes -q decps@10.10.54.166:/tmp/$SESS/'*.pcap' "$DSS/raw_pcaps/" 2>/dev/null
  scp -o BatchMode=yes -q decps@10.10.54.166:/tmp/$SESS/'*.jsonl' "$DSS/app_jsonl/" 2>/dev/null
  NP=$(ls "$DSS"/raw_pcaps/*.pcap 2>/dev/null | wc -l); NJ=$(ls "$DSS"/app_jsonl/*.jsonl 2>/dev/null | wc -l)
  if [ "$NP" -eq 6 ] && [ "$NJ" -eq 6 ]; then
    RES=$("$RP" "$BIN/finalize_session.py" "$DSS" "$ORDER_CSV" "$SEED_CSV" 2>>"$LOG")
    log "$SESS DONE pcaps=$NP jsonl=$NJ  $RES"
  else
    log "$SESS INCOMPLETE pcaps=$NP jsonl=$NJ failed_blocks=$NFAIL (kept for inspection)"
  fi
  DONE=$(ls -d "$DSROOT"/s[0-9][0-9] 2>/dev/null | wc -l)
  printf "last=%s at %s | sessions_on_disk=%s | elapsed=%ss\n" \
    "$SESS" "$(date -u +%FT%TZ)" "$DONE" "$(( $(date +%s) - START ))" > "$HB"
done
log "=== campaign2 COMPLETE: $(ls -d "$DSROOT"/s[0-9][0-9] 2>/dev/null | wc -l) sessions, $(ls "$DSROOT"/s[0-9][0-9]/raw_pcaps/*.pcap 2>/dev/null | wc -l) captures, $(( $(date +%s) - START ))s ==="
