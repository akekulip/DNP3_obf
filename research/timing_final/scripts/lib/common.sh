#!/usr/bin/env bash
# common.sh — shared helpers for the DNP3 timing-normalizer lab interface.
#
# Sourced by every scripts/NN_*.sh.  Provides: strict mode, config loading,
# timestamped logging, DRYRUN-aware SSH/SCP helpers, and the Vision relay
# interface auto-detect (directive §18).  It runs no remote command on its own.
#
# Contract for callers:
#   - source this file FIRST, before parsing your own args;
#   - set DRYRUN=1 in the environment (or pass --dry-run, which sets it) to make
#     every remote helper print the command instead of running it;
#   - use log/run_local/sw/vis_sudo/hulk_sudo/host_plain rather than calling ssh
#     directly, so DRYRUN and logging apply uniformly.

# ---- strict error handling (Prime Directive: no silent error) --------------
set -o errexit
set -o nounset
set -o pipefail

# ---- locate the repo + this tree -------------------------------------------
# common.sh lives at research/timing_final/scripts/lib/common.sh
COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPTS_DIR="$(cd "${COMMON_DIR}/.." && pwd)"
TF_DIR="$(cd "${SCRIPTS_DIR}/.." && pwd)"                 # research/timing_final
REPO_ROOT="$(cd "${TF_DIR}/../.." && pwd)"                # repository root

# ---- load configuration ----------------------------------------------------
# Prefer config/lab.env; fall back to the committed example with a warning.
CONFIG_FILE="${LAB_CONFIG:-${TF_DIR}/config/lab.env}"
if [[ ! -f "${CONFIG_FILE}" ]]; then
  CONFIG_FILE="${TF_DIR}/config/lab.env.example"
  _CONFIG_IS_EXAMPLE=1
else
  _CONFIG_IS_EXAMPLE=0
fi
# shellcheck disable=SC1090
set -o allexport; source "${CONFIG_FILE}"; set +o allexport

# ---- credentials (never in the repo) ---------------------------------------
# ~/.lab_env exports SSHPASS.  We source it if present; sshpass -e reads $SSHPASS.
if [[ -f "${LAB_ENV_FILE:-$HOME/.lab_env}" ]]; then
  # shellcheck disable=SC1090
  source "${LAB_ENV_FILE:-$HOME/.lab_env}" 2>/dev/null || true
fi

# ---- runtime knobs ---------------------------------------------------------
DRYRUN="${DRYRUN:-0}"
SSHO="-o ConnectTimeout=15 -o StrictHostKeyChecking=no -o LogLevel=ERROR"

# ---- logging ---------------------------------------------------------------
# Every script writes a timestamped log under LOG_DIR.  log_init NAME sets it up.
_TS() { date +%Y%m%d-%H%M%S; }
LOGFILE=""
log_init() {
  local name="$1"
  mkdir -p "${REPO_ROOT}/${LOG_DIR:-research/timing_final/logs}"
  LOGFILE="${REPO_ROOT}/${LOG_DIR:-research/timing_final/logs}/${name}.$(_TS).log"
  : > "${LOGFILE}"
  log "=== ${name} started $(date -Is) (DRYRUN=${DRYRUN}, config=${CONFIG_FILE##*/}) ==="
  if [[ "${_CONFIG_IS_EXAMPLE}" == "1" ]]; then
    log "WARN: config/lab.env not found; using lab.env.example defaults."
  fi
}
log() {   # stdout + logfile
  local line="[$(date +%H:%M:%S)] $*"
  echo "${line}"
  [[ -n "${LOGFILE}" ]] && echo "${line}" >> "${LOGFILE}" || true
}
logcmd() { # announce a command about to run (directive §18: print the command)
  # to STDERR (+ logfile), never stdout: these announcements must not pollute the output of
  # commands captured via $(sw ...) / $(sw_sudo ...). They still show on the terminal and in
  # the log; only command-substitution capture is protected.
  local line="[$(date +%H:%M:%S)] RUN: $*"
  echo "${line}" >&2
  [[ -n "${LOGFILE}" ]] && echo "${line}" >> "${LOGFILE}" || true
}
die() {   # print at top, nonzero exit (directive §18 + Prime Directive 15)
  log "FATAL: $*"
  exit "${2:-1}"
}

# ---- cleanup registry (directive §18: record cleanup actions) --------------
# Register shell snippets; run_cleanup runs them LIFO on EXIT.  Registered even
# under DRYRUN (they log what they would clean).
_CLEANUP_ACTIONS=()
add_cleanup() { _CLEANUP_ACTIONS+=("$1"); log "CLEANUP-REGISTERED: $1"; }
run_cleanup() {
  local i
  for (( i=${#_CLEANUP_ACTIONS[@]}-1 ; i>=0 ; i-- )); do
    log "CLEANUP-RUN: ${_CLEANUP_ACTIONS[$i]}"
    if [[ "${DRYRUN}" != "1" ]]; then
      eval "${_CLEANUP_ACTIONS[$i]}" || log "CLEANUP-WARN: action failed (continuing)"
    fi
  done
}

# ---- DRYRUN-aware remote helpers -------------------------------------------
# Switch env preamble (SDE) for bfrt/switchd commands.
_SW_ENV='export SDE='"${SW_SDE:-/home/decps/Downloads/bf-sde-9.13.2}"'; export SDE_INSTALL=$SDE/install; export PATH=$SDE_INSTALL/bin:$PATH; export LD_LIBRARY_PATH=$SDE_INSTALL/lib:$LD_LIBRARY_PATH; export PYTHONPATH=$(echo $SDE_INSTALL/lib/python*/site-packages):$(echo $SDE_INSTALL/lib/python*/site-packages/tofino):$PYTHONPATH'

sw() {            # run on the switch under the SDE environment
  local cmd="$*"
  logcmd "sw: ${cmd}"
  if [[ "${DRYRUN}" == "1" ]]; then return 0; fi
  # base64-transport the command so single quotes / heredocs in ${cmd} (e.g. the bfrt python
  # readbacks) survive intact — a plain `bash -lc '${cmd}'` breaks on any inner single quote.
  local enc; enc="$(printf '%s' "${_SW_ENV}; ${cmd}" | base64 | tr -d '\n')"
  sshpass -e ssh ${SSHO} "${SW}" "echo ${enc} | base64 -d | bash -l"
}
# sudo helpers. Two problems the naive form has, both fixed here:
#  (a) the password: piped from the LOCAL $SSHPASS via the ssh session's stdin (here-string),
#      which `sudo -S` reads as its first line. `echo "\$SSHPASS"` expanded on the REMOTE host,
#      where it is unset — the switch masked this via passwordless sudo; Vision/Hulk need it.
#  (b) the quoting: the command is base64-transported and decoded remotely into `bash -c`, so
#      single quotes / parens in ${cmd} (e.g. the tcpdump BPF filter '(tcp port 20000) or …')
#      survive intact — a plain `bash -c '${cmd}'` breaks on the first inner single quote.
_sudo_on() {      # $1=user@host, rest=cmd
  local host="$1"; shift; local cmd="$*"
  local enc; enc="$(printf '%s' "${cmd}" | base64 | tr -d '\n')"
  sshpass -e ssh ${SSHO} "${host}" "sudo -S -p '' bash -c \"\$(echo ${enc} | base64 -d)\"" <<< "${SSHPASS}"
}
sw_sudo() {       # run on the switch as root (bf_switchd start/stop)
  logcmd "sw-sudo: $*"; if [[ "${DRYRUN}" == "1" ]]; then return 0; fi
  _sudo_on "${SW}" "$@"
}
vis_sudo() {      # run on Vision as root (AF_PACKET inject / tcpdump)
  logcmd "vis-sudo: $*"; if [[ "${DRYRUN}" == "1" ]]; then return 0; fi
  _sudo_on "${VIS}" "$@"
}
hulk_sudo() {     # run on Hulk as root
  logcmd "hulk-sudo: $*"; if [[ "${DRYRUN}" == "1" ]]; then return 0; fi
  _sudo_on "${HULK}" "$@"
}
host_plain() {    # unprivileged remote read: host_plain <user@host> <cmd...>
  local who="$1"; shift
  local cmd="$*"
  logcmd "${who}: ${cmd}"
  if [[ "${DRYRUN}" == "1" ]]; then return 0; fi
  sshpass -e ssh ${SSHO} "${who}" "${cmd}"
}
scp_to() {        # scp_to <user@host> <local...> <remote-dir>  (aborts on failure)
  local dst="${!#}"                 # last arg
  local who="$1"; shift
  local files=("${@:1:$#-1}")
  logcmd "scp -> ${who}:${dst}: ${files[*]}"
  if [[ "${DRYRUN}" == "1" ]]; then return 0; fi
  sshpass -e scp ${SSHO} "${files[@]}" "${who}:${dst}"
}
scp_dir_to() {    # scp_dir_to <user@host> <local-dir> <remote-dir>  (recursive; aborts on failure)
  local who="$1" src="$2" dst="$3"
  logcmd "scp -r -> ${who}:${dst}: ${src}"
  if [[ "${DRYRUN}" == "1" ]]; then return 0; fi
  sshpass -e scp ${SSHO} -r "${src}" "${who}:${dst}"
}
scp_from() {      # scp_from <user@host> <remote> <local>  (aborts on failure; W1)
  local who="$1" remote="$2" local_dst="$3"
  logcmd "scp <- ${who}:${remote} -> ${local_dst}"
  if [[ "${DRYRUN}" == "1" ]]; then return 0; fi
  sshpass -e scp ${SSHO} "${who}:${remote}" "${local_dst}"
}
run_local() {     # run a local command, logged, DRYRUN-aware
  logcmd "local: $*"
  if [[ "${DRYRUN}" == "1" ]]; then return 0; fi
  "$@"
}

# ---- reachability ----------------------------------------------------------
ping1() {         # ping1 <ip> -> 0 if reachable
  if [[ "${DRYRUN}" == "1" ]]; then log "DRYRUN ping ${1}"; return 0; fi
  ping -c1 -W2 "$1" >/dev/null 2>&1
}

# ---- Vision relay interface auto-detect (directive §18) --------------------
# Detects the Vision interface holding VIS_RELAY_ADDR (192.168.10.1).  Prints
# the interface name on stdout.  Honors VIS_RELAY_IFACE override.  Fails when
# detection is ambiguous (>1 match) or empty (0 matches) unless overridden.
detect_vis_relay_iface() {
  # IMPORTANT: only the interface name goes to stdout (callers capture it with $());
  # all diagnostics go to stderr via >&2 so the captured value is never polluted.
  if [[ -n "${VIS_RELAY_IFACE:-}" ]]; then
    log "relay iface: using override VIS_RELAY_IFACE=${VIS_RELAY_IFACE}" >&2
    echo "${VIS_RELAY_IFACE}"
    return 0
  fi
  if [[ "${DRYRUN}" == "1" ]]; then
    logcmd "vis: ip -o -4 addr show | awk '\$4 ~ /^${VIS_RELAY_ADDR}\\// {print \$2}'" >&2
    log "relay iface: (dry-run) would auto-detect the iface holding ${VIS_RELAY_ADDR}" >&2
    echo "DRYRUN-AUTODETECT"
    return 0
  fi
  local matches
  matches="$(sshpass -e ssh ${SSHO} "${VIS}" \
    "ip -o -4 addr show | awk -v a='${VIS_RELAY_ADDR}' '\$4 ~ (\"^\" a \"/\") {print \$2}'" \
    2>/dev/null | tr -d '\r' | sort -u || true)"
  local n
  n="$(printf '%s\n' "${matches}" | grep -c . || true)"
  if [[ "${n}" -eq 0 ]]; then
    die "Vision has no interface holding ${VIS_RELAY_ADDR} — add it or set VIS_RELAY_IFACE. (troubleshooting: 'Vision missing 192.168.10.1')"
  elif [[ "${n}" -gt 1 ]]; then
    die "ambiguous: ${n} Vision interfaces hold ${VIS_RELAY_ADDR} [${matches//$'\n'/ }] — set VIS_RELAY_IFACE explicitly."
  fi
  log "relay iface: auto-detected ${matches} (holds ${VIS_RELAY_ADDR})" >&2
  echo "${matches}"
}

# ---- register/counter name lists for dnp3_timing_normalizer ----------------
# Verified against research/timing_final/p4/dnp3_timing_normalizer.p4 (§17).
TF_REGS="reg_tag,reg_deadline,reg_t_ack,reg_native_clrt,reg_protection,reg_ts_first_block,reg_ts_ack_arm,reg_ts_block_term,reg_ts_first_resp_release"
# read list includes ctr_bypass split into :0 (transparent) and :1 (bad-port drop)
TF_CTRS="ctr_arm,ctr_block_enq,ctr_block_loop,ctr_block_term_deadline,ctr_block_term_timeout,ctr_block_term_stale,ctr_ack_arm,ctr_ack_bypass,ctr_resp_enq,ctr_resp_release,ctr_bypass:0,ctr_bypass:1,ctr_response_before_deadline,ctr_response_at_or_after_deadline,ctr_response_actually_held,ctr_response_zero_hold,ctr_release_deadline,ctr_release_fail_open"
# reset list uses bare counter names (index-0 clear only, per the frozen setup script)
TF_RESET_CTRS="ctr_arm,ctr_block_enq,ctr_block_loop,ctr_block_term_deadline,ctr_block_term_timeout,ctr_block_term_stale,ctr_ack_arm,ctr_ack_bypass,ctr_resp_enq,ctr_resp_release,ctr_bypass,ctr_response_before_deadline,ctr_response_at_or_after_deadline,ctr_response_actually_held,ctr_response_zero_hold,ctr_release_deadline,ctr_release_fail_open"

# ---- generic --help / --dry-run preparse -----------------------------------
# Scripts call common_preparse "$@" to handle a leading --dry-run globally.
# (Per-script --help text is printed by the script's own usage function.)
common_flag_dryrun() {
  for a in "$@"; do
    [[ "$a" == "--dry-run" ]] && DRYRUN=1
  done
  export DRYRUN
}
