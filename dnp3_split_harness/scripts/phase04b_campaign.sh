#!/usr/bin/env bash
# phase04b_campaign.sh -- Gate C full paired campaign (corrective.md sec 10-11). PI-run.
# ONLY after Gate B (phase04b_smoke.sh) passes. Runs the four paired conditions on the SAME source
# transactions/order/seeds, capturing on the authoritative vantage, then hands the PCAPs to the
# unprivileged analysis + attacker eval. Conditions:
#   A NATIVE                    -- no DCRN, no app scheduler
#   B OLD_APPLICATION_SCHEDULER -- Phase-02 application-write delay (no BPF)
#   C DCRN_FIXED                -- DCRN eBPF, fixed target
#   D DCRN_COMMON_BOUNDED       -- DCRN eBPF, bounded target
#
#   sudo IFACE=<iface> BPF_OBJ=/abs/phase04b_dcrn.o BPF_OBJ_BOUNDED=/abs/phase04b_dcrn_bounded.o \
#        VANTAGE_IFACE=<observer> SERVER=<ip> RUNS=5 SESSIONS=100 RUN_DIR=/tmp/phase04b_campaign \
#        bash scripts/phase04b_campaign.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS="$(cd "$DIR/.." && pwd)"
# shellcheck source=phase04b_common.sh
. "$DIR/phase04b_common.sh"
: "${VANTAGE_IFACE:=$IFACE}"; : "${SERVER:=127.0.0.1}"
: "${BPF_OBJ_BOUNDED:=}"; : "${RUNS:=5}"; : "${SESSIONS:=100}"; : "${TXNS:=5}"

mkdir -p "$RUN_DIR"
cleanup_bpf() { IFACE="$IFACE" RUN_DIR="$RUN_DIR" bash "$DIR/phase04b_cleanup.sh" >/dev/null 2>&1 || true; }
trap cleanup_bpf EXIT

run python3 "$HARNESS/phase04b_dcrn_harness.py" build --out "$RUN_DIR/spec.json" --max-per-pcap "$TXNS"

capture_condition() {  # $1=condition-name $2=bpf-obj-or-empty
  local cond="$1" obj="${2:-}" cap="$RUN_DIR/${cond}.pcap"
  log "=== condition $cond (runs=$RUNS sessions=$SESSIONS) ==="
  if [ -n "$obj" ]; then
    IFACE="$IFACE" BPF_OBJ="$obj" RUN_DIR="$RUN_DIR" bash "$DIR/phase04b_prepare.sh"
  else
    cleanup_bpf   # ensure no DCRN attached for NATIVE / OLD_APPLICATION_SCHEDULER
  fi
  if [ "$DRYRUN" != "1" ]; then dumpcap -i "$VANTAGE_IFACE" -f "tcp port 20000" -w "$cap" & local cp=$!; sleep 1; fi
  echo "  [replay $RUNS runs x $SESSIONS sessions via phase05_rig_replay.py server+client; SERVER=$SERVER]"
  echo "  [condition B additionally sets the Phase-02 timing_policy application-write delay]"
  if [ "$DRYRUN" != "1" ]; then sleep 1; kill "${cp:-0}" 2>/dev/null || true; fi
  [ -n "$obj" ] && cleanup_bpf || true
  echo "$cap"
}

capture_condition NATIVE ""                     >/dev/null
capture_condition OLD_APPLICATION_SCHEDULER ""  >/dev/null
capture_condition DCRN_FIXED "$BPF_OBJ"         >/dev/null
[ -n "$BPF_OBJ_BOUNDED" ] && capture_condition DCRN_COMMON_BOUNDED "$BPF_OBJ_BOUNDED" >/dev/null || \
  log "BPF_OBJ_BOUNDED unset: skipping bounded condition (set it to run P2)"

log "campaign captures written under $RUN_DIR. Now (unprivileged):"
echo "  python3 $HARNESS/phase04b_dcrn_analyze.py --run-dir $RUN_DIR"
echo "  python3 $HARNESS/phase04b_dcrn_attacker_eval.py --run-dir $RUN_DIR"
