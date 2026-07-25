#!/usr/bin/env bash
# 05_run_native.sh — produce the NATIVE (un-normalized) reference capture.
# Directive §19: MODE A (safe replay, default) replays validated real SEL-751 frames
# with the reservoir OFF (bypass) so the switch forwards everything unheld — the
# captured ACK->response interval IS the device's native fingerprint.
# MODE B (live, opt-in) polls the physical relay read-only (Class-0 READ only).
set -o errexit -o nounset -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
source "$(dirname "${BASH_SOURCE[0]}")/lib/trial.sh"

usage() {
  cat <<EOF
Usage: 05_run_native.sh [--trials N] [--runid ID] [--dry-run] [--help]
       MODE=live 05_run_native.sh ...      (optional live read-only relay poll)

MODE=replay (DEFAULT, meeting mode): two-sided replay of validated READ/ACK/RESPONSE
  frames through the loaded switch in BYPASS (no hold); captures the native interval.
MODE=live (explicit opt-in): ${SEL_IP} Class-0 READ + Request-Link-Status ONLY.
  PROHIBITED: DIRECT_OPERATE, OPERATE, SELECT, WRITE, restart, config change,
  password guessing, relay IP change. No control operation is ever issued.
Env: TRIALS (default ${TRIALS}), G_MS, K.
EOF
}
MODE_RUN="${MODE:-replay}"
while [[ $# -gt 0 ]]; do case "$1" in
  -h|--help) usage; exit 0;;
  --trials) TRIALS="$2"; shift 2;;
  --runid) RUNID="$2"; shift 2;;
  --dry-run) DRYRUN=1; shift;;
  *) die "unknown arg: $1";;
esac; done
export DRYRUN
log_init run_native

if [[ "${MODE_RUN}" == "live" ]]; then
  log "MODE B (LIVE READ-ONLY): polling physical relay ${SEL_IP} — Class-0 READ ONLY."
  log "  Evidence level: physical-relay-generated capture (label accordingly)."
  RELAY_IFACE="$(detect_vis_relay_iface)"
  RID="${RUNID:-native_live_$(_TS)}"
  "${SCRIPTS_DIR}/04_start_capture.sh" --host vision --mode live --runid "${RID}" \
      --out "${REPO_ROOT}/${EVID_DIR}/${RID}.pcap" $( [[ "${DRYRUN}" == "1" ]] && echo --dry-run )
  # read-only multipoll from the relay-subnet source; link addr is the master's
  logcmd "vis: multipoll.py ${VIS_RELAY_ADDR} ${SEL_IP} ${TRIALS}   (Class-0 READ func 1 only)"
  if [[ "${DRYRUN}" != "1" ]]; then
    # multipoll.py asserts func byte == 0x01 (READ) per frame; it can issue nothing else.
    host_plain "${VIS}" "cd ${HOST_STAGE_DIR} 2>/dev/null; python3 multipoll.py ${VIS_RELAY_ADDR} ${SEL_IP} ${TRIALS}" \
      | tee -a "${LOGFILE}" || log "WARN: live poll returned nonzero (relay session may need config)"
  fi
  "${SCRIPTS_DIR}/07_stop_capture.sh" --runid "${RID}" --txn "${TRIALS}" \
      $( [[ "${DRYRUN}" == "1" ]] && echo --dry-run )
  log "RUN_NATIVE (live): done — pcap ${REPO_ROOT}/${EVID_DIR}/${RID}.pcap"
  exit 0
fi

# MODE A (default): replay-through-switch in bypass
run_replay_trial native
log "RUN_NATIVE (replay): done — RUNID=${TRIAL_RUNID}"
log "  next: analyze with  09_analyze_clrt.py --pcap ${PCAP}"
