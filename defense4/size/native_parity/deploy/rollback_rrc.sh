#!/usr/bin/env bash
# ============================================================================
# rollback_rrc.sh — restore the PROVEN RRC program to a FORWARDING state.
# RUN ON THE SWITCH (decps@10.10.54.81).
#
# ►► NOT-YET-EXECUTED / NOT-YET-VERIFIED-LIVE. This script was AUTHORED and
#    STATICALLY REVIEWED only; it has never been run on the switch. Do NOT treat
#    it as a validated restore path until it has been executed once, deliberately,
#    under explicit authorization, and its two layers observed to pass.
#
# WHY THIS EXISTS. The pre-existing /home/decps/d4_build/rollback_defense3.sh restores
# the WRONG program (case_a_defense3 / d3_final.conf). The program actually loaded and
# serving on this switch is `defense4_rrc_kernel`, cold-loaded from
#   /home/decps/rrc_build/defense4_rrc.conf
# (verified 2026-08-13: `bf_switchd --conf-file /home/decps/rrc_build/defense4_rrc.conf`).
# This script restores THAT program, not Defense 3.
#
# TWO layers, because reloading the program is NOT enough to forward:
#   1. PROGRAM: /home/decps/d3/swap_generic.sh reloads defense4_rrc_kernel COLD from
#      defense4_rrc.conf. It carries the two load-bearing details (sudo; the
#      `tail -f /dev/null |` stdin hold that stops bf_switchd dying on SSH EOF) and
#      stops ANY running bf_switchd (RRC, Defense 4, Defense 3 or otherwise) first.
#   2. OPERATIONAL: a cold bf_switchd load brings the P4 up with NO ports configured —
#      dp8 (loopback), dp9 (Vision/master), dp64 (relay) and dp68 (pktgen) stay DOWN and
#      nothing forwards. RRC's ports/queues/mirror/pktgen AND its size PRE group are
#      established by /home/decps/rrc_build/defense4_rrc_setup.py. Its `configure-all` op
#      runs the timing bring-up (delegated to the frozen caseA setup: config_ports +
#      four-queue ladder + session + mirror + value_set + pktgen reservoir) and THEN
#      installs shape_enable + the RRC_MGID_49_28 PRE group. That returns RRC to the exact
#      forwarding+size state it is serving now.
#
# Idempotent: a cold reload is the canonical clean start; re-running `configure-all` on an
# already-operational RRC is a harmless re-write (it clears+re-writes state, ports, queues,
# pktgen and re-installs the PRE group). Safe to call any number of times.
#
# Mode: defaults to D4 (D_A=D_R=0x8000, the proven RRC bring-up values, and the setup's own
# defaults). Override with ROLLBACK_MODE / ROLLBACK_DA / ROLLBACK_DR if a different proven
# policy must be restored.
# ============================================================================
set -u

# ---- program layer inputs ----
SWAP=/home/decps/d3/swap_generic.sh
RRC_CONF=/home/decps/rrc_build/defense4_rrc.conf
RRC_PROG=defense4_rrc_kernel

# ---- operational layer inputs ----
RRC_SETUP=/home/decps/rrc_build/defense4_rrc_setup.py
# The RRC setup delegates the timing/port bring-up to this frozen caseA setup. It is resolved
# through the D4_CASEA_SETUP env var (first candidate in defense4_rrc_setup.py::_CASEA_CANDS);
# without it the relative fallback path does not exist on this box and run_timing aborts
# "caseA setup not found".
CASEA_SETUP=/home/decps/d4_build/control/defense4_caseA_setup.py
GRPC=localhost:50052
MODE=${ROLLBACK_MODE:-D4}
DA=${ROLLBACK_DA:-0x8000}
DR=${ROLLBACK_DR:-0x8000}

# ---- SDE environment (matches the proven Defense 3 rollback + swap_generic.sh) ----
export SDE=/home/decps/Downloads/bf-sde-9.13.2
export SDE_INSTALL=$SDE/install
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}
export PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$SDE_INSTALL/lib/python3.8/site-packages:${PYTHONPATH:-}
# run_timing runs the caseA subprocess with DEFENSE4_HW_AUTHORIZED=1 itself, but configure-all's
# OWN hardware ops (shape_enable + PRE) also require it in THIS process's environment.
export DEFENSE4_HW_AUTHORIZED=1
export D4_CASEA_SETUP=$CASEA_SETUP

log(){ echo "[rollback-rrc $(date -u +%H:%M:%S)] $*" >&2; }

loaded_prog(){
  local pid conf
  pid=$(pgrep -ox bf_switchd || true); [ -n "$pid" ] || { echo ""; return; }
  conf=$(tr '\0' '\n' < /proc/$pid/cmdline 2>/dev/null | awk '/^--conf-file$/{getline;print;exit}')
  [ -n "$conf" ] && [ -r "$conf" ] || { echo ""; return; }
  python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['p4_devices'][0]['p4_programs'][0]['program-name'])" "$conf" 2>/dev/null || echo ""
}

# ---- preflight: the files this rollback depends on must exist ----
for f in "$SWAP" "$RRC_CONF" "$RRC_SETUP" "$CASEA_SETUP"; do
  [ -r "$f" ] || { log "ERROR: required file missing/unreadable: $f"; exit 1; }
done

# 1. PROGRAM: ALWAYS cold-reload the RRC. A cold bf_switchd load is the canonical clean start,
# and configure-all's timing bring-up expects a clean state (its clean-state guard / pktgen
# arm assumes an un-armed switch). Skipping the reload when RRC looks loaded would break the
# operational restore on an already-armed switch. A safety rollback prioritises a correct,
# forwarding restore over avoiding a ~40 s reload; the transient blip is acceptable.
n=$(pgrep -cx bf_switchd || echo 0)
prog=$(loaded_prog)
log "cold-reloading RRC via swap_generic.sh (found n=$n prog='${prog:-none}') ..."
bash "$SWAP" "$RRC_CONF" "rrc_rollback_$(date -u +%Y%m%dT%H%M%SZ).log" >&2 || true
n=$(pgrep -cx bf_switchd || echo 0); prog=$(loaded_prog)
if [ "$n" != "1" ] || [ "$prog" != "$RRC_PROG" ]; then
  log "ERROR: RRC program NOT loaded (n=$n prog='${prog:-none}', expected $RRC_PROG)"; exit 1
fi
log "RRC program loaded (n=$n prog='$prog')"

# 2. OPERATIONAL: (re)establish ports/queues/mirror/pktgen (timing) AND shape+PRE (size) so
# RRC FORWARDS and normalizes size again. configure-all STOPS on a timing failure, so a
# non-zero exit or any [FAIL] line means forwarding may be down.
log "restoring RRC operational config (configure-all --mode $MODE) ..."
cfg_out=$(cd /home/decps/rrc_build && python3 "$RRC_SETUP" configure-all \
            --mode "$MODE" --d-a "$DA" --d-r "$DR" --grpc "$GRPC" 2>&1)
rc=$?
printf '%s\n' "$cfg_out" >&2
nfail=$(printf '%s\n' "$cfg_out" | grep -cE '^[[:space:]]*\[FAIL\]' || true)
if [ "$rc" != "0" ] || [ "${nfail:-1}" != "0" ]; then
  log "ERROR: RRC operational config failed (rc=$rc, [FAIL] lines=$nfail) — forwarding may be down"
  printf '%s\n' "$cfg_out" | grep -E '^[[:space:]]*\[FAIL\]' | head -5 >&2
  exit 1
fi
log "RRC restored + operational (program loaded, ports/queues/mirror/pktgen up, shape+PRE installed)"
exit 0
