#!/usr/bin/env bash
# demo_all.sh — the ONE guarded combined demonstration (directive §18).
# Runs the full arc for the meeting and NEVER leaves a background capture or
# generator running (traps + restore offer). Safe replay (MODE A) by default.
set -o errexit -o nounset -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"
source "$(dirname "${BASH_SOURCE[0]}")/lib/trial.sh"

usage() {
  cat <<EOF
Usage: demo_all.sh [--mode replay|live] [--trials N] [--g-ms G] [--yes] [--dry-run]

Guarded combined demo (§18):
  1 preflight  2 show topology  3 ASK before changing the switch program
  4 build/verify  5 load  6 configure TM + G  7 start capture
  8 small native demo  9 small protected demo  10 stop captures cleanly
  11 verify identity + timing  12 short summary  13 offer restoration
  14 never leave background captures/generators running.
--yes skips the interactive confirmations (for scripted use). MODE A (replay) default.
EOF
}
MODE_RUN="${MODE:-replay}"; ASSUME_YES=0
while [[ $# -gt 0 ]]; do case "$1" in
  -h|--help) usage; exit 0;;
  --mode) MODE_RUN="$2"; shift 2;;
  --trials) TRIALS="$2"; shift 2;;
  --g-ms) G_MS="$2"; shift 2;;
  --yes) ASSUME_YES=1; shift;;
  --dry-run) DRYRUN=1; shift;;
  *) die "unknown arg: $1";;
esac; done
export DRYRUN
log_init demo_all

# ---- 14: guarantee cleanup on ANY exit (§18.14) ----------------------------
DEMO_CLEANED=0
final_cleanup() {
  [[ "${DEMO_CLEANED}" == "1" ]] && return 0
  DEMO_CLEANED=1
  log "---- demo cleanup (never leave captures/generators running) ----"
  run_cleanup
  # belt-and-braces: signal any stray injector/tcpdump
  if [[ "${DRYRUN}" != "1" ]]; then
    vis_sudo  "pkill -f p13_inject.py 2>/dev/null; pkill -f tcpdump 2>/dev/null; true" || true
    hulk_sudo "pkill -f p13_inject.py 2>/dev/null; pkill -f tcpdump 2>/dev/null; true" || true
  fi
}
trap final_cleanup EXIT INT TERM

TS="$(_TS)"
NATID="demo_native_${TS}"; PROTID="demo_protected_${TS}"
G_MS="${G_MS:-25}"; TRIALS="${TRIALS:-10}"

log "==== STEP 1: preflight ===="
"${SCRIPTS_DIR}/00_preflight.sh" $( [[ "${DRYRUN}" == "1" ]] && echo --dry-run )

log "==== STEP 2/3: topology shown above — CONFIRM switch program change ===="
log "  The demo will load '${PROG}' (displacing '${SW_RESTORE_PROG}'), run ${TRIALS} native +"
log "  ${TRIALS} protected transactions at G=${G_MS} ms, then OFFER to restore."
if [[ "${ASSUME_YES}" != "1" && "${DRYRUN}" != "1" ]]; then
  read -r -p "  Type 'go' to proceed: " REPLY
  [[ "${REPLY}" == "go" ]] || die "aborted by operator (no change made)."
fi

log "==== STEP 4: build/verify P4 ===="
"${SCRIPTS_DIR}/01_build.sh" --verify-only $( [[ "${DRYRUN}" == "1" ]] && echo --dry-run )

log "==== STEP 5: load ===="
"${SCRIPTS_DIR}/02_load.sh" $( [[ "${ASSUME_YES}" == "1" ]] && echo --yes ) $( [[ "${DRYRUN}" == "1" ]] && echo --dry-run )

log "==== STEP 6: configure TM + guard G ===="
run_local env DRYRUN="${DRYRUN}" G_MS="${G_MS}" python3 "${SCRIPTS_DIR}/03_configure_tm.py" --all --g-ms "${G_MS}" \
  $( [[ "${DRYRUN}" == "1" ]] && echo --dry-run )

log "==== STEP 7/8: capture + small NATIVE demo (bypass) ===="
RUNID="${NATID}" TRIALS="${TRIALS}" run_replay_trial native
NAT_PCAP="${PCAP}"; NAT_PREFIX="${PCAP%.pcap}"

log "==== STEP 9: small PROTECTED demo (hold_resp, G=${G_MS} ms) ===="
RUNID="${PROTID}" TRIALS="${TRIALS}" run_replay_trial protected
PROT_PCAP="${PCAP}"; PROT_PREFIX="${PCAP%.pcap}"; PROT_RUNID="${TRIAL_RUNID}"

log "==== STEP 10: captures stopped (handled by each trial) ===="

log "==== STEP 11: verify identity + timing ===="
run_local env DRYRUN="${DRYRUN}" G_MS="${G_MS}" python3 "${SCRIPTS_DIR}/08_verify.py" \
  --runid "${PROT_RUNID}" --g-ms "${G_MS}" $( [[ "${DRYRUN}" == "1" ]] && echo --dry-run ) || VERIFY_RC=$?
log "  analyzing native + protected CLRT (W3 tshark-gated)"
run_local env DRYRUN="${DRYRUN}" python3 "${SCRIPTS_DIR}/09_analyze_clrt.py" --pcap "${NAT_PCAP}" --label native \
  $( [[ "${DRYRUN}" == "1" ]] && echo --dry-run ) || true
run_local env DRYRUN="${DRYRUN}" python3 "${SCRIPTS_DIR}/09_analyze_clrt.py" --pcap "${PROT_PCAP}" --label protected --g-ms "${G_MS}" \
  $( [[ "${DRYRUN}" == "1" ]] && echo --dry-run ) || true

log "==== STEP 12: short summary ===="
log "  native pcap:    ${NAT_PCAP}"
log "  protected pcap: ${PROT_PCAP}   (G = ${G_MS} ms)"
log "  verify JSON:    ${PROT_PREFIX%.*}.verify.json"
log "  (figures: make figures NATIVE_PREFIX=${NAT_PREFIX} PROTECTED_PREFIX=${PROT_PREFIX})"

log "==== STEP 13: offer restoration ===="
if [[ "${ASSUME_YES}" == "1" || "${DRYRUN}" == "1" ]]; then
  log "  (non-interactive) run 'make restore' to return the switch to ${SW_RESTORE_PROG}."
else
  read -r -p "  Restore the switch to ${SW_RESTORE_PROG} now? [y/N]: " REPLY
  if [[ "${REPLY}" == "y" || "${REPLY}" == "Y" ]]; then
    "${SCRIPTS_DIR}/12_restore.sh"
  else
    log "  Left ${PROG} loaded. Restore later with: make restore"
  fi
fi
log "DEMO_ALL: complete"
