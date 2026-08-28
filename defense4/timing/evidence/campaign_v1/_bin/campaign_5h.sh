#!/usr/bin/env bash
# campaign_5h.sh — collect DNP3 READ+SBO sessions for ~5h, one session every ~15 min.
# Self-heals Vision's relay IP, tolerates a failed block/session, freezes provenance per session.
set -u
BIN="$(cd "$(dirname "$0")" && pwd)"
DSROOT="$(cd "$BIN/.." && pwd)"
LOG="$BIN/campaign_5h.log"; HB="$BIN/HEARTBEAT.txt"
BLOCK="$BIN/campaign_block.sh"
PW="$(. ~/.lab_env 2>/dev/null; printf %s "$SSHPASS")"
VI="ssh -o BatchMode=yes -o ConnectTimeout=10 decps@10.10.54.166"
RP=~/.venvs/research/bin/python
DUR=${1:-18000}      # seconds (5h)
INTERVAL=${2:-900}   # session cadence
NREAD=${3:-400}; NSBO=${4:-40}
START=$(date +%s); END=$((START+DUR)); IDX=${5:-2}
ORD0="OFF D4 D4 OFF D4 OFF"; ORD1="D4 OFF OFF D4 OFF D4"
ORD2="OFF OFF D4 D4 OFF D4"; ORD3="D4 D4 OFF OFF D4 OFF"
log(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a "$LOG"; }
heal_ip(){ $VI "ip -br addr show enp59s0f0np0 | grep -q 192.168.10.1 || (echo '$PW' | sudo -S -p '' ip addr add 192.168.10.1/24 dev enp59s0f0np0)" >/dev/null 2>&1; }
clean_remote(){ $VI "mkdir -p /tmp/$1; find /tmp/$1 -maxdepth 1 -type f -delete" >/dev/null 2>&1; }

log "=== campaign_5h START dur=${DUR}s interval=${INTERVAL}s nread=$NREAD nsbo=$NSBO ==="
while :; do
  NOW=$(date +%s); [ "$NOW" -ge "$END" ] && { log "=== window elapsed, stopping ==="; break; }
  SESS=$(printf "s%02d" "$IDX")
  case $((IDX % 4)) in 0) ORD=$ORD0;; 1) ORD=$ORD1;; 2) ORD=$ORD2;; 3) ORD=$ORD3;; esac
  SLOT_START=$NOW
  log "--- $SESS start (order: $ORD) ---"
  heal_ip
  clean_remote "$SESS"
  BI=1; ORDER_CSV=""; SEED_CSV=""
  for MODE in $ORD; do
    SEED=$((IDX*1000+BI))
    bash "$BLOCK" "$SESS" "b$BI" "$MODE" "$NREAD" "$NSBO" "$SEED" >>"$LOG" 2>&1
    ORDER_CSV="${ORDER_CSV:+$ORDER_CSV,}$MODE"; SEED_CSV="${SEED_CSV:+$SEED_CSV,}$SEED"
    BI=$((BI+1))
  done
  DSS="$DSROOT/$SESS"; mkdir -p "$DSS/raw_pcaps" "$DSS/app_jsonl"
  scp -q decps@10.10.54.166:/tmp/$SESS/'*.pcap' "$DSS/raw_pcaps/" 2>/dev/null
  scp -q decps@10.10.54.166:/tmp/$SESS/'*.jsonl' "$DSS/app_jsonl/" 2>/dev/null
  NP=$(ls "$DSS"/raw_pcaps/*.pcap 2>/dev/null | wc -l); NJ=$(ls "$DSS"/app_jsonl/*.jsonl 2>/dev/null | wc -l)
  if [ "$NP" -ge 1 ] && [ "$NJ" -ge 1 ]; then
    RES=$("$RP" "$BIN/finalize_session.py" "$DSS" "$ORDER_CSV" "$SEED_CSV" 2>>"$LOG")
    log "$SESS DONE pcaps=$NP jsonl=$NJ  $RES"
  else
    log "$SESS INCOMPLETE pcaps=$NP jsonl=$NJ (kept for inspection)"
  fi
  DONE=$(ls -d "$DSROOT"/s[0-9][0-9] 2>/dev/null | wc -l)
  printf "last=%s at %s | sessions_on_disk=%s | window_ends=%s\n" \
    "$SESS" "$(date -u +%FT%TZ)" "$DONE" "$(date -u -d @$END +%FT%TZ)" > "$HB"
  IDX=$((IDX+1))
  NOW=$(date +%s); SLEEP=$((SLOT_START+INTERVAL-NOW))
  [ "$SLEEP" -lt 0 ] && SLEEP=0
  [ $((NOW+SLEEP)) -ge "$END" ] && { log "=== next slot beyond window, stopping ==="; break; }
  [ "$SLEEP" -gt 0 ] && { log "$SESS sleeping ${SLEEP}s to next slot"; sleep "$SLEEP"; }
done
log "=== campaign_5h COMPLETE: $(ls -d "$DSROOT"/s[0-9][0-9] 2>/dev/null | wc -l) sessions on disk ==="
