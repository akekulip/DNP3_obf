#!/usr/bin/env bash
# =============================================================================
#  shaper_preload_microbench.sh — establish that the PORT-level gate actually
#  gates, BEFORE any oracle trial is run.
#
#  The whole revised oracle rests on one assumption: a max-rate shaper on the
#  port that owns the four queues holds every frame until a single write
#  reopens it. That assumption has three failure modes, and this benchmark
#  measures all three instead of assuming any of them.
#
#    1. LOWEST USABLE RATE / BURST. tf1.tm.port.sched_shaping max_rate and
#       max_burst_size may be quantized, clamped, or rejected at their minima.
#       The readback is compared against what was written; a silent clamp is a
#       STOP, not a warning.
#
#    2. ESCAPES WHILE CLOSED. A max-rate token bucket REFILLS WHILE IDLE, so at
#       injection time up to max_burst_size of credit is already banked and that
#       many frames leave immediately. This is the single biggest threat to a
#       clean release boundary. The benchmark injects with the gate closed,
#       waits, and counts what reached the host. The only acceptable answer is
#       ZERO.
#
#    3. RELEASE LATENCY. How long after the single release write the first frame
#       appears at the host, and how long the drain takes. Measured for BOTH
#       --gate-open-mode disarm (max_rate_enable=False, bucket removed from the
#       path) and rate (max_rate raised, bucket stays armed), so the choice of
#       release actuator is evidence-based rather than argued.
#
#  IF NO (rate, burst) COMBINATION GIVES ZERO ESCAPES, STOP AND REPORT. Do not
#  improvise a workaround. The predefined fallback is a P4 change — a fifth
#  gating queue Q_GATE at the top of the priority order, released by a
#  register-controlled termination — and that is a separate, gated step.
#
#  PRECONDITIONS: four_queue_oracle.p4 LOADED; run/oracle_inject present on Hulk
#  with CAP_NET_RAW. This script never loads a program and never calls sudo on
#  Hulk. Restoration of Defense 2 is owned by run_four_queue_oracle.sh, which is
#  the intended entry point (--microbench).
#
#  Validate the whole path with no hardware:  DRYRUN=1 ./shaper_preload_microbench.sh
# =============================================================================
set -Eeuo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"

SW_HOST="${SW_HOST:-decps@10.10.54.81}"
HULK_HOST="${HULK_HOST:-hulk}"
SSH_OPTS="${SSH_OPTS:--o BatchMode=yes -o ConnectTimeout=10}"
SDE="${SDE:-/home/decps/Downloads/bf-sde-9.13.2}"
SP="$SDE/install/lib/python3.8/site-packages"
PYPATH="$SP:$SP/tofino"
ORACLE_SETUP_REMOTE="${ORACLE_SETUP_REMOTE:-/home/decps/fqo/four_queue_oracle_setup.py}"
INJECT_BIN_REMOTE="${INJECT_BIN_REMOTE:-/home/decps/fqo/oracle_inject}"
HULK_IFACE="${HULK_IFACE:-enp59s0f0np0}"

OUTDIR="${OUTDIR:-$ROOT/evidence/four_queue_oracle}"
DRYRUN="${DRYRUN:-0}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
MBDIR="$OUTDIR/microbench_$TS"
RESULTS="$MBDIR/results.jsonl"

# Candidate gate settings, tried in order. The first with ZERO escapes wins.
# PPS first: in packet units a burst of 0 or 1 is unambiguous. BPS entries are
# the fallback if PPS max_rate cannot be driven low enough.
CANDIDATES=(
  "PPS:1:0"
  "PPS:1:1"
  "PPS:0:0"
  "BPS:1:0"
  "BPS:1:1"
)
[[ -n "${MB_CANDIDATES:-}" ]] && IFS=' ' read -r -a CANDIDATES <<< "$MB_CANDIDATES"

# How many frames to inject per probe, and how long to wait before deciding
# nothing escaped. 130 == the real trial load (64+64+1+1).
PROBE_FRAMES="${PROBE_FRAMES:-130}"
HOLD_DWELL_S="${HOLD_DWELL_S:-3}"   # gate closed, frames injected, nothing may leave

log() { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
die() { log "FATAL: $*"; exit 1; }

mkdir -p "$MBDIR"
: > "$RESULTS"

sw() {
  if [[ "$DRYRUN" == "1" ]]; then log "DRYRUN sw: ${1:0:110}..."; return 0; fi
  local b64; b64="$(printf '%s' "$*" | base64 -w0)"
  # shellcheck disable=SC2086
  ssh $SSH_OPTS "$SW_HOST" "echo $b64 | base64 -d | bash -s"
}
hulk() {
  if [[ "$DRYRUN" == "1" ]]; then log "DRYRUN hulk: ${1:0:110}..."; return 0; fi
  local b64; b64="$(printf '%s' "$*" | base64 -w0)"
  # shellcheck disable=SC2086
  ssh $SSH_OPTS "$HULK_HOST" "echo $b64 | base64 -d | bash -s"
}
cp_cmd() {
  cat <<EOF
export SDE=$SDE
export SDE_INSTALL=\$SDE/install
export LD_LIBRARY_PATH=\$SDE_INSTALL/lib:\${LD_LIBRARY_PATH:-}
PYTHONPATH=$PYPATH python3.8 $ORACLE_SETUP_REMOTE $*
EOF
}

# Count oracle frames in a pcap without scapy or tcpdump on this host: the
# repo's own analyzer already has a dependency-free pcap reader.
count_frames() {
  local pcap="$1"
  if [[ "$DRYRUN" == "1" ]]; then echo 0; return 0; fi
  python3 - "$pcap" "$ROOT/analysis/analyze_four_queue_oracle.py" <<'PY'
import sys, importlib.util
spec = importlib.util.spec_from_file_location("azr", sys.argv[2])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
try:
    # load_frames() = the stdlib pcap reader with the analyzer's own scapy
    # fallback, so this counts exactly what the analyzer would count.
    frames = m.load_frames(sys.argv[1])
except Exception:
    print(-1); raise SystemExit(0)
print(sum(1 for f in frames if m.parse_oracle_frame(f)))
PY
}

echo ""
echo "==============================================================="
echo " PORT-SHAPER PRELOAD MICROBENCHMARK"
echo " outdir : $MBDIR"
echo " probe  : $PROBE_FRAMES frames, ${HOLD_DWELL_S}s dwell with the gate CLOSED"
echo " gate   : tf1.tm.port.sched_shaping + tf1.tm.port.sched_cfg on dp8"
echo "==============================================================="
echo ""

WINNER=""
for cand in "${CANDIDATES[@]}"; do
  IFS=':' read -r unit rate burst <<< "$cand"
  tag="mb_${unit}_r${rate}_b${burst}"
  log "=== candidate unit=$unit max_rate=$rate max_burst_size=$burst ==="

  # ---- 1. can the gate even be written at these values? -------------------
  sw "$(cp_cmd --reset-counters)" >"$MBDIR/$tag.reset.txt" 2>&1 || true
  set +e
  sw "$(cp_cmd --gate-close --gate-unit "$unit" --gate-rate "$rate" --gate-burst "$burst")" \
     >"$MBDIR/$tag.close.txt" 2>&1
  closerc=$?
  set -e
  if [[ $closerc -ne 0 ]]; then
    log "  REJECTED or clamped (rc=$closerc) — see $MBDIR/$tag.close.txt"
    printf '{"candidate":"%s","writable":false,"rc":%d}\n' "$cand" "$closerc" >>"$RESULTS"
    continue
  fi
  log "  gate written and readback matched"

  # ---- 2. escapes while closed -------------------------------------------
  hulk "nohup tcpdump -i $HULK_IFACE -s 128 -w /tmp/$tag.hold.pcap 'ether proto 0x88C2' \
        >/dev/null 2>&1 & sleep 1" || true
  hulk "$INJECT_BIN_REMOTE --iface $HULK_IFACE --trial-id 900 \
        --schedule ablock:$((PROBE_FRAMES/2)),rblock:$((PROBE_FRAMES/2)),ack:1,resp:1 \
        --seed 900" >"$MBDIR/$tag.inject.json" 2>"$MBDIR/$tag.inject.err" \
    || { log "  injection failed"; continue; }
  sleep "$HOLD_DWELL_S"
  hulk "pkill -f '[t]cpdump -i $HULK_IFACE' >/dev/null 2>&1 || true; sleep 0.5" || true
  [[ "$DRYRUN" == "1" ]] || scp $SSH_OPTS "$HULK_HOST:/tmp/$tag.hold.pcap" \
      "$MBDIR/$tag.hold.pcap" >/dev/null 2>&1 || true
  escaped="$(count_frames "$MBDIR/$tag.hold.pcap")"
  log "  frames that ESCAPED while the gate was closed: $escaped (must be 0)"

  # occupancy proves the frames really are parked rather than dropped
  sw "$(cp_cmd --preload-gate-check)" >"$MBDIR/$tag.gatecheck.txt" 2>&1 || true

  # ---- 3. release latency, both open modes --------------------------------
  for openmode in disarm rate; do
    hulk "nohup tcpdump -i $HULK_IFACE -s 128 --time-stamp-precision=nano \
          -w /tmp/$tag.$openmode.pcap 'ether proto 0x88C2' >/dev/null 2>&1 & sleep 1" || true
    t_write_ns="$(date +%s%N)"
    sw "$(cp_cmd --gate-open --gate-open-mode "$openmode")" \
       >"$MBDIR/$tag.$openmode.open.txt" 2>&1 || true
    sleep 1
    hulk "pkill -f '[t]cpdump -i $HULK_IFACE' >/dev/null 2>&1 || true; sleep 0.5" || true
    [[ "$DRYRUN" == "1" ]] || scp $SSH_OPTS "$HULK_HOST:/tmp/$tag.$openmode.pcap" \
        "$MBDIR/$tag.$openmode.pcap" >/dev/null 2>&1 || true
    got="$(count_frames "$MBDIR/$tag.$openmode.pcap")"
    log "  open-mode=$openmode : $got frame(s) released (t_write=$t_write_ns)"
    printf '{"candidate":"%s","open_mode":"%s","released":%s,"t_write_ns":"%s"}\n' \
      "$cand" "$openmode" "${got:-0}" "$t_write_ns" >>"$RESULTS"
    # re-close for the next open-mode probe
    sw "$(cp_cmd --gate-close --gate-unit "$unit" --gate-rate "$rate" --gate-burst "$burst")" \
       >/dev/null 2>&1 || true
  done

  printf '{"candidate":"%s","writable":true,"escaped_while_closed":%s,"probe_frames":%d}\n' \
    "$cand" "${escaped:-−1}" "$PROBE_FRAMES" >>"$RESULTS"

  if [[ "${escaped:-1}" == "0" && -z "$WINNER" ]]; then
    WINNER="$cand"
    log "  *** CANDIDATE ACCEPTED: $cand gives ZERO escapes ***"
  fi
done

# leave the gate OPEN so no traffic is stranded behind a closed shaper
sw "$(cp_cmd --gate-open --gate-open-mode disarm)" >"$MBDIR/final_open.txt" 2>&1 || true

echo ""
echo "==============================================================="
if [[ -n "$WINNER" ]]; then
  IFS=':' read -r u r b <<< "$WINNER"
  echo " RESULT: usable gate found -> unit=$u max_rate=$r max_burst_size=$b"
  echo ""
  echo " Use it for the pilot:"
  echo "     GATE_UNIT=$u GATE_RATE=$r GATE_BURST=$b \\"
  echo "       $HERE/run_four_queue_oracle.sh --pilot"
  echo " results: $RESULTS"
  echo "==============================================================="
  exit 0
fi
cat <<EOF
 RESULT: **NO CANDIDATE GAVE A CLEAN BOUNDARY.**

 STOP. Do not improvise around this. Every candidate either could not be
 written at its minimum, or let at least one frame escape while the gate was
 closed. A gate that leaks cannot support the acceptance criterion "no
 target-role frame escapes before release", so the port shaper is not a usable
 global release event on this switch.

 The PREDEFINED fallback is a P4 change and therefore a SEPARATE GATED STEP:
     Q_GATE > Q_ABLOCK > Q_ACK > Q_RBLOCK > Q_RESP
 populate the four target queues while Q_GATE is backlogged, then release all
 four through one register-controlled termination of Q_GATE.

 results: $RESULTS
===============================================================
EOF
exit 2
