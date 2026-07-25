#!/usr/bin/env bash
# 06_run_protected.sh — produce the PROTECTED capture (interval normalized to G).
# Directive §19 MODE A: two-sided replay of validated frames through the loaded
# normalizer with the reservoir ON (hold_resp, K>=64); the response is held
# queue-resident until t_ack+G, so the captured ACK->response interval becomes G.
set -o errexit -o nounset -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
source "$(dirname "${BASH_SOURCE[0]}")/lib/trial.sh"

usage() {
  cat <<EOF
Usage: 06_run_protected.sh [--trials N] [--g-ms G] [--k K] [--runid ID] [--dry-run] [--help]

MODE A safe replay through the loaded ${PROG}. Holds each RESPONSE to t_ack+G via the
blocker reservoir (K>=64, review C4). Sets + verifies G on chip first (review D1 tick
alignment), fires both injectors (W2 rc gate), captures to a protected pcap + manifest.
Env: TRIALS (default ${TRIALS}), G_MS (default ${G_MS}), K (default ${K}).
EOF
}
while [[ $# -gt 0 ]]; do case "$1" in
  -h|--help) usage; exit 0;;
  --trials) TRIALS="$2"; shift 2;;
  --g-ms) G_MS="$2"; shift 2;;
  --k) K="$2"; shift 2;;
  --runid) RUNID="$2"; shift 2;;
  --dry-run) DRYRUN=1; shift;;
  *) die "unknown arg: $1";;
esac; done
export DRYRUN
log_init run_protected

run_replay_trial protected
log "RUN_PROTECTED: done — RUNID=${TRIAL_RUNID}"
log "  next: verify with  08_verify.py --runid ${TRIAL_RUNID}   then  09_analyze_clrt.py --pcap ${PCAP} --g-ms ${G_MS}"
