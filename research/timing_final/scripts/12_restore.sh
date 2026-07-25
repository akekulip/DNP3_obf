#!/usr/bin/env bash
# 12_restore.sh — always preserve the lab (directive §26). Idempotent: safe to run
# more than once. Stops generators + captures, checks for leftover token/transaction
# state, collects final counters, restores queue_microbench, and verifies the switch,
# hosts and Vision's relay address are healthy. Writes a restoration report.
set -o errexit -o nounset -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() {
  cat <<EOF
Usage: 12_restore.sh [--dry-run] [--help]

Restores the testbed after a timing run:
  - kill any injector/tcpdump left on Vision, Hulk (and any staged BFRT client);
  - read final on-chip counters + check no blocker token / active transaction remains;
  - restore ${SW_RESTORE_PROG} via ${SW_RESTORE_LAUNCH};
  - verify exactly one bf_switchd bound to ${SW_RESTORE_PROG};
  - verify switch/Vision/Hulk reachable and Vision retains ${VIS_RELAY_ADDR};
  - write ${EVID_DIR}/final_state/restoration_report.txt.
Idempotent — running it again when already clean is a no-op that re-verifies.
EOF
}
for a in "$@"; do case "$a" in -h|--help) usage; exit 0;; esac; done
common_flag_dryrun "$@"
log_init restore

FS="${REPO_ROOT}/${EVID_DIR}/final_state"
run_local mkdir -p "${FS}"
REPORT="${FS}/restoration_report.txt"
FAIL=0
say() { log "$1"; [[ "${DRYRUN}" == "1" ]] || echo "$1" >> "${REPORT}"; }

[[ "${DRYRUN}" == "1" ]] || : > "${REPORT}"
say "DNP3 timing-normalizer restoration report — $(date -Is)"
say "======================================================================"

# ---- 1. stop generators + captures (idempotent: pkill returns nonzero if none) --
say "[1] stopping injectors + captures on Vision/Hulk"
vis_sudo  "pkill -f '[p]13_inject.py' 2>/dev/null; pkill -f '[t]cpdump' 2>/dev/null; true"
hulk_sudo "pkill -f '[p]13_inject.py' 2>/dev/null; pkill -f '[t]cpdump' 2>/dev/null; true"
say "    injectors/tcpdump signalled (no error if none were running)"

# ---- 2. final counters + residue check (before restoring the microbench) --------
say "[2] reading final on-chip state (token/transaction residue)"
if [[ "${DRYRUN}" == "1" ]]; then
  logcmd "sw: p13_read.py --tag final (reg_tag active bit, reg_deadline armed marker)"
  say "    (dry-run) would assert reg_deadline armed==0 and no live blocker reservoir"
else
  FINAL="$(sw "python3 ${SW_READ_DIR:-/home/decps/timing_final_cp}/p13_read.py --prog ${PROG} --regs ${TF_REGS} --counters ${TF_CTRS} --tag final 2>&1 | grep P13READ" 2>&1 || echo '')"
  if [[ -n "${FINAL}" ]]; then
    echo "${FINAL}" > "${FS}/final_counters.json"
    ARMED="$(python3 -c "import json,sys
try:
    j=json.loads(open('${FS}/final_counters.json').read().split('P13READ ',1)[1])
    print(1 if j.get('derived',{}).get('deadline_armed') else 0)
except Exception: print('na')" 2>/dev/null || echo na)"
    say "    reg_deadline armed = ${ARMED} (expect 0 = no transaction held)"
    [[ "${ARMED}" == "1" ]] && { say "    WARN: a transaction appears still armed — inspect before reuse"; }
  else
    say "    NOTE: could not read final counters (program may already be restored)"
  fi
fi

# ---- 3. restore queue_microbench ------------------------------------------------
say "[3] restoring ${SW_RESTORE_PROG}"
if [[ "${DRYRUN}" == "1" ]]; then
  logcmd "sw-sudo: pkill -x bf_switchd; bash ${SW_RESTORE_LAUNCH}"
  say "    (dry-run) would swap bf_switchd back to ${SW_RESTORE_PROG}"
else
  BOUND_NOW="$(sw "python3 - <<'PY' 2>/dev/null | tr -d '\r'
try:
    import bfrt_grpc.client as gc
    i=gc.ClientInterface('${SW_GRPC}',client_id=97,device_id=0,notifications=None)
    i.bind_pipeline_config('${SW_RESTORE_PROG}'); print('${SW_RESTORE_PROG}')
except Exception: print('other')
PY" || echo other)"
  if [[ "${BOUND_NOW}" == "${SW_RESTORE_PROG}" ]]; then
    say "    already bound to ${SW_RESTORE_PROG} — idempotent no-op (re-verifying only)"
  else
    sw_sudo "pkill -x bf_switchd 2>/dev/null; sleep 1; true"
    sw_sudo "nohup bash ${SW_RESTORE_LAUNCH} >/tmp/restore_mb.log 2>&1 & sleep 8; true"
    say "    relaunched bf_switchd via ${SW_RESTORE_LAUNCH}"
  fi
fi

# ---- 4. verify exactly one bf_switchd bound to queue_microbench -----------------
say "[4] verifying switch state"
if [[ "${DRYRUN}" != "1" ]]; then
  BFCOUNT="$(sw_sudo 'pgrep -xc bf_switchd' 2>/dev/null | tr -d '\r' | grep -vE 'RUN:' | grep -oE '[0-9]+' | tail -1 || echo 0)"
  BFCOUNT="${BFCOUNT:-0}"
  if [[ "${BFCOUNT}" == "1" ]]; then say "    exactly one bf_switchd: OK"; else say "    FAIL: bf_switchd count=${BFCOUNT}"; FAIL=1; fi
  BOUND="$(sw "python3 - <<'PY' 2>/dev/null | tr -d '\r'
try:
    import bfrt_grpc.client as gc
    i=gc.ClientInterface('${SW_GRPC}',client_id=96,device_id=0,notifications=None)
    i.bind_pipeline_config('${SW_RESTORE_PROG}'); print('${SW_RESTORE_PROG}')
except Exception as e: print('NOT:%s'%str(e)[:40])
PY" || echo NOT)"
  if [[ "${BOUND}" == "${SW_RESTORE_PROG}" ]]; then say "    bound to ${SW_RESTORE_PROG}: OK"; else say "    FAIL: bound=${BOUND}"; FAIL=1; fi
else
  say "    (dry-run) would assert one bf_switchd bound to ${SW_RESTORE_PROG}"
fi

# ---- 5. reachability + Vision relay address ------------------------------------
say "[5] verifying hosts + Vision relay address"
if [[ "${DRYRUN}" != "1" ]]; then
  ping1 "${SW_IP}"   && say "    switch ${SW_IP}: OK"   || { say "    FAIL: switch unreachable"; FAIL=1; }
  ping1 "${VIS_IP}"  && say "    Vision ${VIS_IP}: OK"  || { say "    FAIL: Vision unreachable"; FAIL=1; }
  ping1 "${HULK_IP}" && say "    Hulk ${HULK_IP}: OK"   || { say "    FAIL: Hulk unreachable"; FAIL=1; }
  if host_plain "${VIS}" "ip -o -4 addr show | grep -q ' ${VIS_RELAY_ADDR}/'"; then
    say "    Vision retains ${VIS_RELAY_ADDR}: OK"
  else
    say "    FAIL: Vision lost ${VIS_RELAY_ADDR}"; FAIL=1
  fi
else
  say "    (dry-run) would ping all three hosts and confirm Vision holds ${VIS_RELAY_ADDR}"
fi

say "======================================================================"
if [[ "${FAIL}" == "0" ]]; then
  say "RESTORATION: PASS"
  log "RESTORE: PASS — report ${REPORT}"
else
  say "RESTORATION: FAIL — see items above"
  die "RESTORE: FAIL — see ${REPORT}"
fi
