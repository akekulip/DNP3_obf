#!/usr/bin/env bash
# 00_preflight.sh — check the lab is ready and show the detected topology.
# Read-only: touches nothing on the switch, Vision or Hulk beyond ping/ssh reads.
# Directive §18 (preflight + show topology), §25 (troubleshooting symptoms), §26.
set -o errexit -o nounset -o pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

usage() {
  cat <<EOF
Usage: 00_preflight.sh [--dry-run] [--help]

Verifies, read-only:
  - switch/Vision/Hulk reachable (10.10.54.81 / .19 / .158);
  - Vision retains ${VIS_RELAY_ADDR} and auto-detects the relay-facing interface;
  - exactly one bf_switchd on the switch, and which P4 program is bound;
  - local build toolchain (bf-p4c) and required tools (sshpass, tshark) present.
Prints the topology and a PASS/FAIL summary. Nonzero exit if any hard check fails.
EOF
}
for a in "$@"; do case "$a" in -h|--help) usage; exit 0;; esac; done
common_flag_dryrun "$@"
log_init preflight

FAIL=0
mark() { if [[ "$1" == "0" ]]; then log "  [PASS] $2"; else log "  [FAIL] $2"; FAIL=1; fi; }
# chk "desc" cmd... — run cmd without tripping errexit, then record PASS/FAIL.
chk() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then mark 0 "$d"; else mark 1 "$d"; fi; }

log "---- reachability ----"
chk "switch reachable at ${SW_IP}"  ping1 "${SW_IP}"
chk "Vision reachable at ${VIS_IP}" ping1 "${VIS_IP}"
chk "Hulk reachable at ${HULK_IP}"  ping1 "${HULK_IP}"

log "---- Vision relay address + interface auto-detect ----"
# Presence of the relay address is a hard requirement (§25: 'Vision missing 192.168.10.1').
if [[ "${DRYRUN}" == "1" ]]; then
  RELAY_IFACE="$(detect_vis_relay_iface || true)"
else
  if host_plain "${VIS}" "ip -o -4 addr show | grep -q ' ${VIS_RELAY_ADDR}/'"; then
    mark 0 "Vision holds ${VIS_RELAY_ADDR}"
    if RELAY_IFACE="$(detect_vis_relay_iface)"; then mark 0 "relay-facing interface detected: ${RELAY_IFACE}"
    else mark 1 "relay-facing interface auto-detect (ambiguous?)"; RELAY_IFACE="(ambiguous)"; fi
  else
    mark 1 "Vision holds ${VIS_RELAY_ADDR}"
    RELAY_IFACE="(not detected)"
  fi
fi

log "---- switch program binding ----"
if [[ "${DRYRUN}" == "1" ]]; then
  logcmd "sw-sudo: pgrep -xc bf_switchd ; sw: bfrt p4_name readback"
  BFCOUNT="?"; BOUND="?"
else
  BFCOUNT="$(sw_sudo 'pgrep -xc bf_switchd' 2>/dev/null | tr -d '\r' || echo 0)"
  if [[ "${BFCOUNT}" == "1" ]]; then mark 0 "exactly one bf_switchd running"
  else mark 1 "exactly one bf_switchd running (found: ${BFCOUNT}) [§25: 'more than one bf_switchd']"; fi
  # which program is bound (informational; load/restore change it deliberately)
  BOUND="$(sw "python3 - <<'PY' 2>/dev/null | tr -d '\r' || true
try:
    import bfrt_grpc.client as gc
    i = gc.ClientInterface('${SW_GRPC}', client_id=99, device_id=0, notifications=None)
    print(','.join(i.bfrt_info_get().p4_name_get() if hasattr(i.bfrt_info_get(),'p4_name_get') else []))
except Exception as e:
    print('unknown:%s' % str(e)[:40])
PY" 2>/dev/null || echo unknown)"
  log "  bound P4 program: ${BOUND:-unknown}  (expect '${PROG}' after load, '${SW_RESTORE_PROG}' at rest)"
fi

log "---- local toolchain ----"
chk "local bf-p4c present (${LOCAL_BFP4C_BIN}/bf-p4c)" test -x "${LOCAL_BFP4C_BIN}/bf-p4c"
chk "sshpass present" command -v sshpass
if command -v tshark >/dev/null 2>&1; then log "  [PASS] tshark present (W3 cross-check available)"
else log "  [WARN] tshark not on this host — analyze --require-tshark will fail (W3)"; fi
chk "replay spec present (${REPLAY_SPEC})"     test -f "${REPO_ROOT}/${REPLAY_SPEC}"
chk "replay frames present (${REPLAY_FRAMES})" test -f "${REPO_ROOT}/${REPLAY_FRAMES}"
chk "token/DNP3 injector present (p13_inject.py)" test -f "${REPO_ROOT}/${HARNESS_DIR}/p13_inject.py"

log "======================================================================"
log "TOPOLOGY"
log "  Vision/master  ${VIS_IP}  relay ${VIS_RELAY_ADDR} on ${RELAY_IFACE:-?}  data ${VIS_DATA_IFACE} -> dp${DP_VISION} (dir0)"
log "        |"
log "     Tofino-1 ${SW_IP}   Q_BLOCK qid${QB} HIGH  >  Q_RESP qid${QH} LOW   loopback dp${DP_LOOP} (pg ${PG_L})"
log "        |"
log "  Hulk/outstation ${HULK_IP}  data ${HULK_DATA_IFACE} -> dp${DP_HULK} (dir1)"
log "  physical SEL-751 ${SEL_IP} (link ${SEL_LINK_ADDR}) — MODE B live only, Tofino NOT inline"
log "  program under test: ${PROG} (sha ${P4_SRC_SHA256:0:12})"
log "======================================================================"

if [[ "${FAIL}" == "0" ]]; then log "PREFLIGHT: PASS"; else die "PREFLIGHT: FAIL — resolve the [FAIL] items above before loading."; fi
