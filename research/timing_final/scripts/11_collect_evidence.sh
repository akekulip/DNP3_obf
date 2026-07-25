#!/usr/bin/env bash
# 11_collect_evidence.sh — assemble the evidence chain for a run into one place.
# Directive §16 Diagram 6 (raw PCAP -> transactions -> CLRT -> figures -> claim)
# and §20 (manifests). Read-only aggregation; writes SHA256SUMS.
set -o errexit -o nounset -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() {
  cat <<EOF
Usage: 11_collect_evidence.sh [--native-runid ID] [--protected-runid ID] [--dry-run]

Gathers pcaps + manifests + transactions.csv/summary.json/validation.json +
before/after counters + verify JSON + figures for the named run(s) under
${EVID_DIR}/collected/<timestamp>/ and writes SHA256SUMS over them.
EOF
}
NATID=""; PROTID=""
while [[ $# -gt 0 ]]; do case "$1" in
  -h|--help) usage; exit 0;;
  --native-runid) NATID="$2"; shift 2;;
  --protected-runid) PROTID="$2"; shift 2;;
  --dry-run) DRYRUN=1; shift;;
  *) die "unknown arg: $1";;
esac; done
export DRYRUN
log_init collect_evidence

ED="${REPO_ROOT}/${EVID_DIR}"
DEST="${ED}/collected/$(_TS)"
run_local mkdir -p "${DEST}"

gather() {
  local rid="$1" tag="$2"
  [[ -z "${rid}" ]] && return 0
  log "gathering ${tag} runid=${rid}"
  local pat
  for pat in "${rid}.pcap" "${rid}.manifest.json" "${rid}.plan.json" \
             "${rid}.before.json" "${rid}.after.json" "${rid}.verify.json" \
             "${rid}.transactions.csv" "${rid}.summary.json" "${rid}.validation.json" \
             "${rid}.inject.vision.json" "${rid}.inject.hulk.json"; do
    if [[ -f "${ED}/${pat}" ]]; then
      run_local cp -f "${ED}/${pat}" "${DEST}/"
      log "  + ${pat}"
    fi
  done
}
gather "${NATID}" native
gather "${PROTID}" protected
# figures
if [[ -d "${ED}/figures" ]]; then run_local cp -rf "${ED}/figures" "${DEST}/"; log "  + figures/"; fi

if [[ "${DRYRUN}" != "1" ]]; then
  ( cd "${DEST}" && find . -type f ! -name SHA256SUMS -exec sha256sum {} \; > SHA256SUMS )
  log "  wrote ${DEST}/SHA256SUMS"
fi
log "COLLECT_EVIDENCE: done -> ${DEST}"
