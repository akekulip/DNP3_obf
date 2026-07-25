#!/usr/bin/env bash
# trial.sh — shared MODE-A replay-trial engine for 05_run_native / 06_run_protected.
#
# One trial: build the plan locally -> stage injector+plan to Vision/Hulk -> reset
# counters -> (skew gate) -> read counters (before) -> start capture -> fire BOTH
# injectors against ONE shared start epoch -> wait -> stop+fetch capture -> read
# counters (after). Two-sided injection (READ from Vision/dp9 dir0; ACK+RESPONSE +
# blocker tokens from Hulk/dp11 dir1) exactly as the validated p13 harness does, so
# the ACK->response interval carries no cross-host clock error.
#
# Review fixes baked in here:
#   W1  RUNID mandatory/timestamped; prior artifacts rm'd at trial start; scp gated.
#   W2  injector return codes captured; trial ABORTS (verify=FAIL reason=injector_rc)
#       if either injector exits non-zero.
#   token-gen  the plan is built with --selftest, which asserts each blocker token's
#       gen byte == the guarded READ's DNP3 app-control byte (0xC0..0xCF) before use.
#
# Requires common.sh already sourced. Call:  run_replay_trial <native|protected>
# Sets globals for the caller: TRIAL_RUNID PLAN PCAP BJSON AJSON INJV INJH KEFF

run_replay_trial() {
  local kind="$1"          # native | protected
  local mode
  case "${kind}" in
    native)    mode="bypass";    RUN_K=0 ;;              # no reservoir; nothing held
    protected) mode="hold_resp"; RUN_K="${K:-64}" ;;     # reservoir holds the RESPONSE to t_ack+G
    *) die "run_replay_trial: kind must be native|protected (got ${kind})" ;;
  esac

  # C4: protected trials need a real reservoir
  if [[ "${kind}" == "protected" && "${RUN_K}" -lt 64 ]]; then
    die "K=${RUN_K} < 64 — the blocker reservoir is too shallow (review C4). Set K>=64."
  fi

  local HARNESS="${REPO_ROOT}/${HARNESS_DIR}"
  local INJECT="${HARNESS}/p13_inject.py"
  local READER="${HARNESS}/p13_read.py"
  local SETUP="${REPO_ROOT}/research/ibspg_paired/control/ibspg_paired_setup.py"
  local RPY="python3"
  local HOSTDIR="${HOST_STAGE_DIR:-/home/decps/timing_final}"
  local SW_RD="${SW_READ_DIR:-/home/decps/timing_final_cp}"

  TRIAL_RUNID="${RUNID:-${kind}_$(_TS)}"
  local NTXN="${TRIALS:-10}"
  local G_NS; G_NS="$(awk "BEGIN{printf \"%d\", ${G_MS:-25} * 1000000}")"

  local ED="${REPO_ROOT}/${EVID_DIR}"
  mkdir -p "${ED}"
  PLAN="${ED}/${TRIAL_RUNID}.plan.json"
  PCAP="${ED}/${TRIAL_RUNID}.pcap"
  BJSON="${ED}/${TRIAL_RUNID}.before.json"
  AJSON="${ED}/${TRIAL_RUNID}.after.json"
  INJV="${ED}/${TRIAL_RUNID}.inject.vision.json"
  INJH="${ED}/${TRIAL_RUNID}.inject.hulk.json"

  # W1: clear any prior artifacts for this RUNID (no stale bytes/verdicts)
  log "[trial ${kind}] RUNID=${TRIAL_RUNID} mode=${mode} K=${RUN_K} G=${G_MS:-25}ms NTXN=${NTXN}"
  run_local rm -f "${PLAN}" "${PCAP}" "${BJSON}" "${AJSON}" "${INJV}" "${INJH}" \
                  "${PCAP%.pcap}.manifest.json" "${PCAP%.pcap}".{transactions.csv,summary.json,validation.json}

  # ---- build the plan locally (offline) + selftest (asserts token gen) ----
  local NTXN_ARG=""; [[ "${NTXN}" != "0" ]] && NTXN_ARG="--ntxn ${NTXN}"
  logcmd "local: p13_inject.py --build-plan --selftest --mode ${mode} --k ${RUN_K} ..."
  if [[ "${DRYRUN}" != "1" ]]; then
    if ! "${RPY}" "${INJECT}" --build-plan --selftest --mode "${mode}" --k "${RUN_K}" \
        --budget "${BUDGET:-2000000}" ${NTXN_ARG} \
        --txn-period-ms "${TXN_PERIOD_MS:-250}" --tok-lead-ms "${TOK_LEAD_MS:-20}" \
        --ack-lead-ms "${ACK_LEAD_MS:-70}" --resp-delay-ms "${RESP_DELAY_MS:-2}" \
        --runid "${TRIAL_RUNID}" --spec "${REPO_ROOT}/${REPLAY_SPEC}" \
        --frames "${REPO_ROOT}/${REPLAY_FRAMES}" --out "${PLAN}" >>"${LOGFILE}" 2>&1; then
      die "plan build/selftest failed (token-gen or schedule invalid) — see ${LOGFILE}"
    fi
    KEFF="$(${RPY} -c "import json;print(json.load(open('${PLAN}'))['k'])")"
    DUR_MS="$(${RPY} -c "import json;print(int(json.load(open('${PLAN}'))['schedule']['duration_ms']))" 2>/dev/null || echo 8000)"
  else
    KEFF="${RUN_K}"; DUR_MS="${DUR_MS:-8000}"
  fi
  log "  plan=${PLAN} effective K=${KEFF} schedule=${DUR_MS}ms"

  # ---- stage injector + plan onto both hosts ------------------------------
  host_plain "${VIS}"  "mkdir -p ${HOSTDIR}"
  host_plain "${HULK}" "mkdir -p ${HOSTDIR}"
  scp_to "${VIS}"  "${INJECT}" "${PLAN}" "${HOSTDIR}/"
  scp_to "${HULK}" "${INJECT}" "${PLAN}" "${HOSTDIR}/"
  # stage the reader onto the switch for counter reads
  sw "mkdir -p ${SW_RD}"
  scp_to "${SW}" "${READER}" "${SETUP}" "${SW_RD}/"
  local PLAN_R="${HOSTDIR}/$(basename "${PLAN}")"

  # ---- protected: ensure the guard interval G is set on chip ---------------
  if [[ "${kind}" == "protected" ]]; then
    log "  ensuring guard G=${G_MS:-25}ms is configured (idempotent)"
    run_local python3 "${SCRIPTS_DIR}/03_configure_tm.py" --set-g --g-ms "${G_MS:-25}" \
      $( [[ "${DRYRUN}" == "1" ]] && echo --dry-run ) >>"${LOGFILE}" 2>&1 \
      || die "guard G configuration failed — see ${LOGFILE}"
  fi

  # ---- per-trial counter/register reset -----------------------------------
  sw "python3 ${SW_RD}/ibspg_paired_setup.py --prog ${PROG} --reset --regs ${TF_REGS} --counters ${TF_RESET_CTRS}" >/dev/null 2>&1 || true

  # ---- read counters (before) ---------------------------------------------
  if [[ "${DRYRUN}" != "1" ]]; then
    sw "python3 ${SW_RD}/p13_read.py --prog ${PROG} --g-ns ${G_NS} --regs ${TF_REGS} --counters ${TF_CTRS} --tag before 2>&1 | grep P13READ" > "${BJSON}" || true
  else
    logcmd "sw: p13_read.py --tag before > ${BJSON}"
  fi

  # ---- start capture on Vision (data-plane iface) -------------------------
  "${SCRIPTS_DIR}/04_start_capture.sh" --host vision --mode replay --out "${PCAP}" --runid "${TRIAL_RUNID}" \
      $( [[ "${DRYRUN}" == "1" ]] && echo --dry-run ) >>"${LOGFILE}" 2>&1
  add_cleanup "\"${SCRIPTS_DIR}/07_stop_capture.sh\" --runid \"${TRIAL_RUNID}\" $( [[ \"${DRYRUN}\" == \"1\" ]] && echo --dry-run ) >/dev/null 2>&1 || true"

  # ---- fire BOTH injectors against ONE shared absolute start epoch ---------
  local START
  START="$(python3 -c "import time;print(repr(time.time() + ${START_LEAD_S:-4}))")"
  if [[ "${DRYRUN}" == "1" ]]; then
    logcmd "vis-sudo: p13_inject.py --side vision --plan ${PLAN_R} --iface ${VIS_DATA_IFACE} --start-epoch \$START [parallel]"
    logcmd "hulk-sudo: p13_inject.py --side hulk --plan ${PLAN_R} --iface ${HULK_DATA_IFACE} --start-epoch \$START [parallel]"
    log "  DRYRUN: would wait out the schedule, then stop capture + read counters (after)."
  else
    ( vis_sudo  "python3 ${HOSTDIR}/p13_inject.py --side vision --plan ${PLAN_R} --iface ${VIS_DATA_IFACE} --start-epoch ${START}" > "${INJV}" 2>&1 ) & local VPID=$!
    ( hulk_sudo "python3 ${HOSTDIR}/p13_inject.py --side hulk   --plan ${PLAN_R} --iface ${HULK_DATA_IFACE} --start-epoch ${START}" > "${INJH}" 2>&1 ) & local HPID=$!
    local VRC HRC; wait ${VPID}; VRC=$?; wait ${HPID}; HRC=$?
    # W2: an injector that exited non-zero means "injected nothing" -> FAIL the trial
    if [[ "${VRC}" != "0" || "${HRC}" != "0" ]]; then
      run_cleanup
      die "injector return codes non-zero (vision=${VRC} hulk=${HRC}) — trial invalid (W2). See ${INJV} / ${INJH}."
    fi
    # wait out the last hold before stopping capture
    python3 -c "import time; time.sleep((${DUR_MS:-8000} + ${G_MS:-25} + ${TAIL_MS:-1500})/1000.0)" 2>/dev/null || sleep 3
  fi

  # ---- stop + fetch the capture (writes manifest w/ G + txn count) ---------
  "${SCRIPTS_DIR}/07_stop_capture.sh" --runid "${TRIAL_RUNID}" --g-ms "${G_MS:-25}" --txn "${NTXN}" \
      $( [[ "${DRYRUN}" == "1" ]] && echo --dry-run ) >>"${LOGFILE}" 2>&1 || die "capture stop/fetch failed (W1)"

  # ---- read counters (after) ----------------------------------------------
  if [[ "${DRYRUN}" != "1" ]]; then
    sw "python3 ${SW_RD}/p13_read.py --prog ${PROG} --g-ns ${G_NS} --regs ${TF_REGS} --counters ${TF_CTRS} --tag after 2>&1 | grep P13READ" > "${AJSON}" || true
  else
    logcmd "sw: p13_read.py --tag after > ${AJSON}"
  fi

  log "[trial ${kind}] done: pcap=${PCAP} before=${BJSON} after=${AJSON}"
}
