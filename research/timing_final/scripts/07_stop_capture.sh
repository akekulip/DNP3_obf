#!/usr/bin/env bash
# 07_stop_capture.sh — stop the capture, fetch the PCAP, write a JSON manifest.
# Directive §20: record host/iface/start/end/filter/packet-count/sha256/commit/G/txn.
# W1: abort if the scp of the pcap fails (never silently accept a missing capture).
set -o errexit -o nounset -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() {
  cat <<EOF
Usage: 07_stop_capture.sh --runid ID [--g-ms G] [--txn N] [--dry-run] [--help]

Reads the capture-state written by 04_start_capture.sh, stops tcpdump cleanly on the
capture host, scp's the pcap back (ABORTS if scp fails — W1), verifies it is readable,
and writes <pcap>.manifest.json with host, iface, start/end, filter, packet count,
SHA-256, source commit, G and transaction count.
EOF
}
RUNID=""; G_MS="${G_MS:-}"; TXN=""
while [[ $# -gt 0 ]]; do case "$1" in
  -h|--help) usage; exit 0;;
  --runid) RUNID="$2"; shift 2;;
  --g-ms) G_MS="$2"; shift 2;;
  --txn) TXN="$2"; shift 2;;
  --dry-run) DRYRUN=1; shift;;
  *) die "unknown arg: $1";;
esac; done
export DRYRUN
[[ -n "${RUNID}" ]] || die "give --runid (from 04_start_capture.sh)"
log_init stop_capture

CAPSTATE="${REPO_ROOT}/${EVID_DIR}/${RUNID}.capstate"
if [[ "${DRYRUN}" == "1" ]]; then
  log "DRYRUN: would read ${CAPSTATE}, stop tcpdump on the capture host, scp the pcap back,"
  log "        verify readability, and write <pcap>.manifest.json (host/iface/times/filter/"
  log "        count/sha256/commit/G/txn)."
  logcmd "host-sudo: pkill -f tcpdump...; scp remote:/tmp/tf_cap_${RUNID}.pcap -> local; tcpdump -r <pcap> | wc -l"
  exit 0
fi
[[ -f "${CAPSTATE}" ]] || die "no capture-state ${CAPSTATE} — was 04_start_capture run with this --runid?"
# shellcheck disable=SC1090
source "${CAPSTATE}"

sudo_fn() { if [[ "${HOST}" == "vision" ]]; then vis_sudo "$@"; else hulk_sudo "$@"; fi; }

log "stopping capture on ${HOST} (${TARGET}) iface=${IFACE}"
sudo_fn "pkill -f 'tcpdump.*${REMOTE_PCAP}' 2>/dev/null; sleep 0.5; true"
END_EPOCH="$(date +%s.%N)"

# W1: scp MUST succeed
if ! scp_from "${TARGET}" "${REMOTE_PCAP}" "${LOCAL_PCAP}"; then
  die "scp of ${REMOTE_PCAP} failed — capture NOT collected (W1). Trial artifacts must not be trusted."
fi
[[ -s "${LOCAL_PCAP}" ]] || die "fetched pcap ${LOCAL_PCAP} is empty — capture produced no bytes (§25: 'no packets in PCAP')."

# readability + packet count (§20 'verify the resulting file is readable')
if command -v tcpdump >/dev/null 2>&1; then
  PKTS="$(tcpdump -r "${LOCAL_PCAP}" -nn 2>/dev/null | wc -l | tr -d ' ')" || die "pcap ${LOCAL_PCAP} not readable by tcpdump"
else
  PKTS="unknown(no-local-tcpdump)"
fi
SHA="$(sha256sum "${LOCAL_PCAP}" | awk '{print $1}')"
COMMIT="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"

MANIFEST="${LOCAL_PCAP%.pcap}.manifest.json"
cat > "${MANIFEST}" <<EOF
{
  "runid": "${RUNID}",
  "host": "${HOST}",
  "target": "${TARGET}",
  "interface": "${IFACE}",
  "mode": "${MODE}",
  "filter": "${FILTER}",
  "start_epoch": "${START_EPOCH}",
  "end_epoch": "${END_EPOCH}",
  "pcap": "${LOCAL_PCAP}",
  "packet_count": "${PKTS}",
  "sha256": "${SHA}",
  "source_commit": "${COMMIT}",
  "g_ms": "${G_MS:-unset}",
  "transaction_count": "${TXN:-unset}",
  "program": "${PROG}"
}
EOF
log "  pcap: ${LOCAL_PCAP}  (${PKTS} pkts, sha ${SHA:0:12})"
log "  manifest: ${MANIFEST}"
log "STOP_CAPTURE: PASS"
