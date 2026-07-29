#!/usr/bin/env bash
# =============================================================================
#  AUTHORED OFF-SWITCH — NOT YET RUN. Nothing here has been executed against
#  hardware. The switch is running the proven dnp3_timing_normalizer_pktgen and
#  must stay that way until Philip loads four_queue_oracle.p4 himself.
#
#  RUNS ON HULK. Drives >= 100 four-queue dequeue oracle trials end to end:
#  per trial it starts tcpdump on the dp11-facing NIC, runs one trial via
#  run/four_queue_oracle.py, stops tcpdump, and drops a pcap + a JSON record
#  into evidence/four_queue_oracle/.
#
#  Needs sudo on Hulk (AF_PACKET injection and tcpdump). It never addresses dp9
#  (Vision) or dp64 (the SEL-751 relay leg).
#
#  Validate the whole path WITHOUT hardware first:
#      DRYRUN=1 ./run_four_queue_oracle.sh
# =============================================================================
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

# ---- configuration (override via environment) -------------------------------
IFACE="${IFACE:-enp59s0f0np0}"          # Hulk NIC facing dp11
OUTDIR="${OUTDIR:-$ROOT/evidence/four_queue_oracle}"
PYTHON="${PYTHON:-python3}"
DRYRUN="${DRYRUN:-0}"
SETTLE_MS="${SETTLE_MS:-50}"
DRAIN_MS="${DRAIN_MS:-500}"
CAP_SETTLE="${CAP_SETTLE:-0.5}"         # seconds to let tcpdump start / flush

# The command prefix that runs four_queue_oracle_setup.py ON THE SWITCH.
# Example:
#   CP_CMD="ssh decps@10.10.54.81 PYTHONPATH=/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages:/home/decps/Downloads/bf-sde-9.13.2/install/lib/python3.8/site-packages/tofino python3.8 /home/decps/fqo/four_queue_oracle_setup.py"
CP_CMD="${CP_CMD:-}"

# ---- the trial plan ---------------------------------------------------------
# "mode:k:release_order:count". Defaults total 130 trials (>= the required 100).
#
# The first block is the PRIMARY EVIDENCE: unshaped, fully preloaded, K=64,
# batch release. The lo-first / hi-first blocks are the RELEASE-SKEW CONTROLS —
# the strict-priority verdict is only sound if the observed order is INVARIANT
# across all three (see the report and the setup script header).
#
# reservoir:1 is included for completeness ONLY. It passes TRIVIALLY here and is
# NOT evidence about reservoir depth — a preloaded non-recirculating oracle
# cannot reproduce the K=1 empty-gap failure. See the report's Scoping section.
#
# The three late-injection modes need the drain stretched with a shaper
# (SHAPER_PPS); unshaped they are meaningless, and the runner records a warning.
PLAN_DEFAULT=(
  "reservoir:64:batch:60"
  "reservoir:64:lo-first:15"
  "reservoir:64:hi-first:15"
  "resp_waiting:64:batch:20"
  "reservoir:1:batch:10"
  "late_ack_preempt:64:batch:4"
  "empty_ack_queue:64:batch:3"
  "empty_resp_queue:64:batch:3"
)
IFS=' ' read -r -a PLAN <<< "${PLAN:-${PLAN_DEFAULT[*]}}"

SHAPER_PPS="${SHAPER_PPS:-}"            # set for the late-injection modes

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { log "FATAL: $*"; exit 1; }

[[ -n "$CP_CMD" || "$DRYRUN" == "1" ]] || \
  die "CP_CMD is required (the command that runs four_queue_oracle_setup.py on the switch). Set DRYRUN=1 to validate without hardware."

mkdir -p "$OUTDIR"
SUMMARY="$OUTDIR/run_summary.jsonl"
: > "$SUMMARY"

log "four-queue dequeue oracle"
log "  iface   : $IFACE   outdir: $OUTDIR"
log "  dryrun  : $DRYRUN"
log "  plan    : ${PLAN[*]}"
[[ -n "$SHAPER_PPS" ]] && log "  shaper  : ${SHAPER_PPS} pps (late-injection modes)"

# ---- capture helpers --------------------------------------------------------
# The [t]cpdump bracket trick: 'pkill -f tcpdump' would match this script's own
# command line and kill the driver. Bracketing the first character makes the
# pattern not match itself.
stop_capture() {
  if [[ "$DRYRUN" == "1" ]]; then return 0; fi
  sudo pkill -f "[t]cpdump -i $IFACE" >/dev/null 2>&1 || true
  sleep "$CAP_SETTLE"
}

start_capture() {
  local pcap="$1"
  if [[ "$DRYRUN" == "1" ]]; then
    log "  DRYRUN capture -> $pcap"
    return 0
  fi
  # ether proto 0x88C2 == the oracle ethertype. Nothing else is captured, so the
  # pcap contains exactly the dequeue sequence and nothing to filter out later.
  sudo tcpdump -i "$IFACE" -s 128 -w "$pcap" 'ether proto 0x88C2' \
       >/dev/null 2>&1 &
  sleep "$CAP_SETTLE"
}

trap 'stop_capture' EXIT

# ---- optional one-time shaper configuration ---------------------------------
if [[ -n "$SHAPER_PPS" ]]; then
  log "configuring drain shaper at ${SHAPER_PPS} pps"
  if [[ "$DRYRUN" == "1" ]]; then
    log "  DRYRUN cp: --shaper --drain-shaper-pps $SHAPER_PPS"
  else
    $CP_CMD --shaper --drain-shaper-pps "$SHAPER_PPS" || \
      log "WARN: shaper configuration returned non-zero"
  fi
fi

# ---- main loop --------------------------------------------------------------
trial=0
n_ok=0; n_invalid=0; n_err=0

for spec in "${PLAN[@]}"; do
  IFS=':' read -r mode k rel count <<< "$spec"
  log "=== block: mode=$mode k=$k release=$rel count=$count ==="
  for ((i=0; i<count; i++)); do
    trial=$((trial+1))
    tag="$(printf 'trial_%04d_%s_k%s_%s' "$trial" "$mode" "$k" "$rel")"
    pcap="$OUTDIR/$tag.pcap"
    json="$OUTDIR/$tag.json"

    start_capture "$pcap"

    set +e
    args=( "$ROOT/run/four_queue_oracle.py"
           --iface "$IFACE" --trial-id "$trial" --mode "$mode" --k "$k"
           --release-order "$rel" --settle-ms "$SETTLE_MS" --drain-ms "$DRAIN_MS"
           --out "$json" )
    [[ -n "$SHAPER_PPS" ]] && args+=( --shaper-pps "$SHAPER_PPS" )
    if [[ "$DRYRUN" == "1" ]]; then
      args+=( --dry-run )
      "$PYTHON" "${args[@]}" > "$OUTDIR/$tag.stdout" 2>&1
    else
      args+=( --cp-cmd "$CP_CMD" )
      sudo -E "$PYTHON" "${args[@]}" > "$OUTDIR/$tag.stdout" 2>&1
    fi
    rc=$?
    set -e

    stop_capture

    case "$rc" in
      0) n_ok=$((n_ok+1));      status="OK" ;;
      3) n_invalid=$((n_invalid+1)); status="INVALID" ;;
      *) n_err=$((n_err+1));    status="ERROR" ;;
    esac
    log "  $tag -> $status (rc=$rc)"

    # one line per trial into the run summary
    grep -h '^FQTRIAL ' "$OUTDIR/$tag.stdout" 2>/dev/null | sed 's/^FQTRIAL //' \
      >> "$SUMMARY" || true
  done
done

log "-------------------------------------------------------------"
log "trials: $trial   OK: $n_ok   INVALID: $n_invalid   ERROR: $n_err"
log "evidence: $OUTDIR"
log ""
log "Now evaluate the DEQUEUE ORDER offline (this driver does not judge it):"
log "  python3 $ROOT/analysis/analyze_four_queue_oracle.py --evidence-dir $OUTDIR"
log ""
log "Reminder: an INVALID trial means a queue was not demonstrably nonempty at"
log "release. It is NOT an ordering failure and must not be scored as one."
