#!/usr/bin/env bash
# 04_start_capture.sh — start a full-frame PCAP capture on the detected interface.
# Directive §20: snaplen 0, full frames, epoch ts, -U, filter admits the token
# ethertype so the isolation check is a real observation (not vacuous).
set -o errexit -o nounset -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

CAPFILTER='(tcp port 20000) or (ether proto 0x88c1)'
usage() {
  cat <<EOF
Usage: 04_start_capture.sh [--host vision|hulk] [--iface IFACE] [--mode replay|live]
                           [--out LOCAL.pcap] [--runid ID] [--foreground] [--dry-run]

Starts tcpdump (-s 0 -U, epoch ts, filter: ${CAPFILTER}) on:
  MODE replay (default): the data-plane interface (${VIS_DATA_IFACE} on Vision, dp9),
                         where the normalized traffic flows through the switch.
  MODE live            : the auto-detected relay-facing interface (holds ${VIS_RELAY_ADDR}).
Writes a capture-state file for 07_stop_capture.sh. --foreground blocks until Ctrl+C
then stops+manifests cleanly (directive §20). Default host is Vision.
EOF
}
HOST=vision; IFACE=""; MODE=replay; OUT=""; RUNID=""; FG=0
while [[ $# -gt 0 ]]; do case "$1" in
  -h|--help) usage; exit 0;;
  --host) HOST="$2"; shift 2;;
  --iface) IFACE="$2"; shift 2;;
  --mode) MODE="$2"; shift 2;;
  --out) OUT="$2"; shift 2;;
  --runid) RUNID="$2"; shift 2;;
  --foreground) FG=1; shift;;
  --dry-run) DRYRUN=1; shift;;
  *) die "unknown arg: $1";;
esac; done
export DRYRUN
log_init start_capture

RUNID="${RUNID:-tf_$(_TS)}"
mkdir -p "${REPO_ROOT}/${EVID_DIR}"
OUT="${OUT:-${REPO_ROOT}/${EVID_DIR}/${RUNID}.pcap}"

# choose capture host + interface
if [[ "${HOST}" == "vision" ]]; then
  TARGET="${VIS}"
  if [[ -z "${IFACE}" ]]; then
    if [[ "${MODE}" == "live" ]]; then IFACE="$(detect_vis_relay_iface)"; else IFACE="${VIS_DATA_IFACE}"; fi
  fi
elif [[ "${HOST}" == "hulk" ]]; then
  TARGET="${HULK}"; IFACE="${IFACE:-${HULK_DATA_IFACE}}"
else
  die "unknown --host ${HOST}"
fi
REMOTE_PCAP="/tmp/tf_cap_${RUNID}.pcap"
CAPSTATE="${REPO_ROOT}/${EVID_DIR}/${RUNID}.capstate"

log "capture host=${HOST} (${TARGET}) iface=${IFACE} mode=${MODE}"
log "  remote pcap=${REMOTE_PCAP}  local dest=${OUT}"
START_EPOCH="$(date +%s.%N)"

# W1: remove any prior remote pcap before starting (no stale bytes)
sudo_fn() { if [[ "${HOST}" == "vision" ]]; then vis_sudo "$@"; else hulk_sudo "$@"; fi; }
sudo_fn "rm -f ${REMOTE_PCAP}"
# -Q in removes the capturing host's own outbound copies; -s 0 = full frames; -U = unbuffered
sudo_fn "nohup tcpdump -i ${IFACE} -Q in -s 0 -nn -U -w ${REMOTE_PCAP} '${CAPFILTER}' >/tmp/tf_cap_${RUNID}.stderr 2>&1 & echo \$! > /tmp/tf_cap_${RUNID}.pid; sleep 1; true"

# persist the state so 07 (or a trap) can stop + collect it
if [[ "${DRYRUN}" != "1" ]]; then
  cat > "${CAPSTATE}" <<EOF
RUNID=${RUNID}
HOST=${HOST}
TARGET=${TARGET}
IFACE=${IFACE}
MODE=${MODE}
REMOTE_PCAP=${REMOTE_PCAP}
LOCAL_PCAP=${OUT}
FILTER=${CAPFILTER}
START_EPOCH=${START_EPOCH}
EOF
  log "  capture-state -> ${CAPSTATE}"
fi

if [[ "${FG}" == "1" ]]; then
  log "CAPTURING in the foreground. Press Ctrl+C to stop cleanly and write the manifest."
  trap 'echo; "${SCRIPTS_DIR}/07_stop_capture.sh" --runid "${RUNID}"; exit 0' INT TERM
  if [[ "${DRYRUN}" == "1" ]]; then log "DRYRUN: would block here until Ctrl+C, then run 07_stop_capture."; exit 0; fi
  while true; do sleep 1; done
else
  log "capture started (background). Stop with: 07_stop_capture.sh --runid ${RUNID}"
fi
