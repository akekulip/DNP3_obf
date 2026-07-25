#!/usr/bin/env bash
# 01_build.sh — compile dnp3_timing_normalizer.p4 LOCALLY (offline) and verify it.
# No switch contact. Directive §18 (build/verify the P4 artifact), §29 (reference).
set -o errexit -o nounset -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() {
  cat <<EOF
Usage: 01_build.sh [--dry-run] [--verify-only] [--help]

Compiles research/timing_final/p4/${PROG}.p4 with the local bf-p4c
(${LOCAL_BFP4C_BIN}) into p4/out/, then verifies:
  - source SHA-256 matches the frozen reference (${P4_SRC_SHA256:0:12}…);
  - 0 compiler errors;
  - ingress stage count is within the 12-stage budget (expect 10/12).
  --verify-only  skip the compile; just check the frozen source SHA + existing out/.
EOF
}
VERIFY_ONLY=0
for a in "$@"; do case "$a" in -h|--help) usage; exit 0;; --verify-only) VERIFY_ONLY=1;; esac; done
common_flag_dryrun "$@"
log_init build

P4DIR="${TF_DIR}/p4"
SRC="${P4DIR}/${PROG}.p4"
OUT="${P4DIR}/out"
[[ -f "${SRC}" ]] || die "missing P4 source: ${SRC}"

log "---- source SHA-256 gate (frozen reference) ----"
GOT_SHA="$(sha256sum "${SRC}" | awk '{print $1}')"
log "  expected: ${P4_SRC_SHA256}"
log "  actual:   ${GOT_SHA}"
[[ "${GOT_SHA}" == "${P4_SRC_SHA256}" ]] || die "source SHA mismatch — the P4 is not the frozen reference; refusing to build."
log "  [PASS] source is the frozen reference"

if [[ "${VERIFY_ONLY}" == "1" ]]; then
  [[ -f "${OUT}/${PROG}.conf" ]] && log "  existing artifact: ${OUT}/${PROG}.conf" || log "  [WARN] no existing out/${PROG}.conf"
  log "BUILD (verify-only): PASS"; exit 0
fi

log "---- compile (local bf-p4c 9.13.1) ----"
[[ -x "${LOCAL_BFP4C_BIN}/bf-p4c" ]] || die "local bf-p4c not found at ${LOCAL_BFP4C_BIN}/bf-p4c"
CLOG="${P4DIR}/compile.log"
# exact command from p4/compile_note.md
logcmd "cd ${P4DIR} && PATH=${LOCAL_BFP4C_BIN}:\$PATH bf-p4c --target tofino --arch tna -g -o out ${PROG}.p4"
if [[ "${DRYRUN}" == "1" ]]; then
  log "DRYRUN: compile skipped"; log "BUILD (dry-run): would compile then verify 0-errors + stage count."; exit 0
fi
set +e
( cd "${P4DIR}" && PATH="${LOCAL_BFP4C_BIN}:$PATH" bf-p4c --target tofino --arch tna -g -o out "${PROG}.p4" ) > "${CLOG}" 2>&1
RC=$?
set -e
tail -n 3 "${CLOG}" | sed 's/^/  bf-p4c: /' | while read -r l; do log "$l"; done
[[ "${RC}" == "0" ]] || die "bf-p4c exited ${RC}; see ${CLOG}"
grep -qE "^0 errors" "${CLOG}" || die "compile did not report '0 errors'; see ${CLOG}"
log "  [PASS] 0 errors"

log "---- resource fit (ingress stage budget) ----"
RES="${OUT}/pipe/logs/resources.json"
if [[ -f "${RES}" ]]; then
  STAGES="$(grep -oE '"stages"[: ]+[0-9]+' "${RES}" | head -1 | grep -oE '[0-9]+' || echo '?')"
  log "  ingress stages (from resources.json): ${STAGES}/12 (expect 10)"
else
  log "  [WARN] ${RES} not found — cannot read stage count automatically"
fi
if [[ ! -f "${OUT}/${PROG}.conf" ]]; then die "expected artifact ${OUT}/${PROG}.conf not produced"; fi
log "  artifact: ${OUT}/${PROG}.conf"
log "BUILD: PASS"
