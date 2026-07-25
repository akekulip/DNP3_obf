#!/usr/bin/env bash
# 02_load.sh — GUARDED bf_switchd swap to load dnp3_timing_normalizer on the switch.
# Snapshots the current switch state first (§26 'before loading'), requires explicit
# confirmation before changing the program (§18 step 3), then swaps and verifies the
# binding. Reversible via 12_restore.sh. Directive §18, §26.
set -o errexit -o nounset -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() {
  cat <<EOF
Usage: 02_load.sh [--dry-run] [--yes] [--help]

Loads '${PROG}' onto the Tofino by a gated bf_switchd swap (displaces whatever is
loaded — normally '${SW_RESTORE_PROG}'). Steps:
  1. snapshot current bf_switchd PID, bound program, port + queue state, git state
     -> ${EVID_DIR}/pre_load/;
  2. ASK for explicit confirmation (or pass --yes) before changing the switch program;
  3. stage the compiled artifact to ${SW_TIMING_DIR} and (re)launch bf_switchd via
     \$SW_TIMING_LAUNCH;
  4. verify exactly one bf_switchd bound to '${PROG}'.
This is the one step that changes the switch. Reverse it with: make restore.
EOF
}
ASSUME_YES=0
for a in "$@"; do case "$a" in -h|--help) usage; exit 0;; --yes) ASSUME_YES=1;; esac; done
common_flag_dryrun "$@"
log_init load

SNAP="${REPO_ROOT}/${EVID_DIR}/pre_load"
run_local mkdir -p "${SNAP}"

log "---- (1) snapshot current switch state (§26 before-load) ----"
if [[ "${DRYRUN}" == "1" ]]; then
  logcmd "sw-sudo: pgrep -a bf_switchd  > pre_load/bf_switchd.txt"
  logcmd "sw: bfrt p4_name + port + queue readback  > pre_load/binding.txt"
  logcmd "local: git rev-parse HEAD + status  > pre_load/git_state.txt"
else
  sw_sudo "pgrep -a bf_switchd" > "${SNAP}/bf_switchd.txt" 2>&1 || true
  sw "ps -o pid,cmd -C bf_switchd 2>/dev/null" >> "${SNAP}/bf_switchd.txt" 2>&1 || true
  ( git -C "${REPO_ROOT}" rev-parse HEAD; git -C "${REPO_ROOT}" status --short ) > "${SNAP}/git_state.txt" 2>&1 || true
  log "  snapshot written to ${SNAP}/"
fi

log "---- (2) confirmation gate (§18 step 3) ----"
log "  ABOUT TO CHANGE THE SWITCH PROGRAM to '${PROG}' on ${SW_IP}."
log "  This displaces the currently loaded program. Restore with: make restore."
if [[ "${ASSUME_YES}" != "1" && "${DRYRUN}" != "1" ]]; then
  read -r -p "  Type 'load' to proceed, anything else to abort: " REPLY
  [[ "${REPLY}" == "load" ]] || die "aborted by operator (no change made)."
elif [[ "${DRYRUN}" == "1" ]]; then
  log "  DRYRUN: confirmation prompt skipped (would require typing 'load')."
else
  log "  --yes given: proceeding without interactive prompt."
fi

log "---- (3) stage compiled artifact + launch script ----"
OUT="${TF_DIR}/p4/out"
[[ -d "${OUT}" || "${DRYRUN}" == "1" ]] || die "no compiled artifact at ${OUT} — run 01_build.sh first."
sw "mkdir -p ${SW_TIMING_DIR}"
# push the whole out/ tree (conf + pipe/) so bf_switchd can bind it (recursive)
scp_dir_to "${SW}" "${OUT}" "${SW_TIMING_DIR}/"
log "  staged ${OUT} -> ${SW}:${SW_TIMING_DIR}/out"

log "---- (3b) swap bf_switchd ----"
# The exact launch command is lab-provided (like launch_mb.sh). We stop the current
# bf_switchd then run \$SW_TIMING_LAUNCH, which must bring bf_switchd up on the
# ${PROG} conf. If SW_TIMING_LAUNCH is not present the operator must supply it.
add_cleanup "log 'if the swap left no bf_switchd bound, run: make restore'"
if [[ "${DRYRUN}" == "1" ]]; then
  logcmd "sw-sudo: pkill -x bf_switchd"
  logcmd "sw-sudo: bash ${SW_TIMING_LAUNCH}   # (re)launch bf_switchd on ${PROG}"
else
  sw "test -f ${SW_TIMING_LAUNCH}" || die "launch script ${SW_TIMING_LAUNCH} not on the switch — stage it (operator-provided, like launch_mb.sh) and retry. No change made."
  sw_sudo "pkill -x bf_switchd 2>/dev/null; sleep 1; true"
  sw_sudo "nohup bash ${SW_TIMING_LAUNCH} >/tmp/timing_switchd.log 2>&1 & sleep 8; true"
fi

log "---- (4) verify exactly one bf_switchd bound to ${PROG} ----"
if [[ "${DRYRUN}" == "1" ]]; then
  log "  DRYRUN: would assert pgrep -xc bf_switchd == 1 and bound program == ${PROG}."
  log "LOAD (dry-run): OK"; exit 0
fi
BFCOUNT="$(sw_sudo 'pgrep -xc bf_switchd' 2>/dev/null | tr -d '\r' || echo 0)"
[[ "${BFCOUNT}" == "1" ]] || die "expected exactly one bf_switchd, found ${BFCOUNT} — inspect /tmp/timing_switchd.log; run make restore."
BOUND="$(sw "python3 - <<'PY' 2>/dev/null | tr -d '\r'
import bfrt_grpc.client as gc
i=gc.ClientInterface('${SW_GRPC}',client_id=98,device_id=0,notifications=None)
try:
    i.bind_pipeline_config('${PROG}'); print('${PROG}')
except Exception as e:
    print('NOT_${PROG}:%s'%str(e)[:50])
PY")"
[[ "${BOUND}" == "${PROG}" ]] || die "bf_switchd is up but not bound to ${PROG} (got '${BOUND}') — run make restore."
log "  [PASS] one bf_switchd bound to ${PROG}"
log "LOAD: PASS — next: make configure-tm"
