#!/usr/bin/env bash
# ============================================================================
# rollback_rrc.sh — restore the PROVEN RRC (defense4_rrc_kernel) to the EXACT
# forwarding + size-normalizing state captured in a LIVE snapshot. RUN ON THE
# SWITCH (decps@10.10.54.81).
#
# ►► SAFETY-CRITICAL. This is the campaign's rollback / watchdog restore target.
#    It restores the TESTED millisecond hold read off hardware (D4, D_A~2 ms,
#    D_R=20 ms, budget 18000), NEVER a guessed sub-millisecond 0x8000 default
#    (0.033 ms). The timing hold, PRE group, and every port/queue/session field
#    are driven from live_rrc_snapshot.json. It FAILS CLOSED if the snapshot or
#    any load-bearing recipe field cannot be read — it never substitutes a default.
#
# TWO layers, because reloading the program is NOT enough to forward:
#   1. PROGRAM: swap_generic.sh cold-reloads defense4_rrc_kernel from
#      defense4_rrc.conf (sudo; the `tail -f /dev/null |` stdin hold; stops any
#      running bf_switchd first).
#   2. OPERATIONAL: defense4_rrc_setup.py configure-all runs the timing bring-up
#      (delegated to the frozen caseA setup: ports + four-queue ladder + session +
#      mirror + value_set + pktgen reservoir) with the SNAPSHOTTED mode/D_A/D_R/
#      budget/master-ip/relay-ip, then installs+verifies the RRC PRE group and
#      enables shape (SAFE ORDER — shape only after the PRE is verified).
#
# Idempotent: a cold reload is the canonical clean start; re-running configure-all
# is a harmless clear+re-write. Safe to call any number of times.
# ============================================================================
set -u

SNAPSHOT="${ROLLBACK_SNAPSHOT:-/home/decps/rrc_build/live_rrc_snapshot.json}"

# ---- program layer inputs ----
SWAP=/home/decps/d3/swap_generic.sh
RRC_CONF=/home/decps/rrc_build/defense4_rrc.conf
RRC_PROG=defense4_rrc_kernel

# ---- operational layer inputs ----
RRC_SETUP=/home/decps/rrc_build/defense4_rrc_setup.py
CASEA_SETUP=/home/decps/d4_build/control/defense4_caseA_setup.py
GRPC=localhost:50052

# ---- SDE environment (matches swap_generic.sh + the proven bring-up) ----
export SDE=/home/decps/Downloads/bf-sde-9.13.2
export SDE_INSTALL=$SDE/install
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}
export PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$SDE_INSTALL/lib/python3.8/site-packages:${PYTHONPATH:-}
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

# ---- preflight: every file this rollback depends on must exist ----
for f in "$SNAPSHOT" "$SWAP" "$RRC_CONF" "$RRC_SETUP" "$CASEA_SETUP"; do
  [ -r "$f" ] || { log "FAIL-CLOSED: required file missing/unreadable: $f"; exit 1; }
done

# ---- parse the rollback recipe from the LIVE snapshot (FAIL CLOSED) ----
# Emits: MODE D_A_hex D_R_hex BUDGET MASTER_IP RELAY_IP  (or nothing on any bad field).
RECIPE=$(python3 - "$SNAPSHOT" <<'PY'
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    r = d["rollback_recipe"]
    mode = r["mode"]; da = r["d_a_hex"]; dr = r["d_r_hex"]
    b = int(r["budget"]); mip = r["master_ip"]; rip = r["relay_ip"]
    assert mode in ("OFF", "D1", "D2", "D3", "D4", "FAIL_OPEN"), "bad mode"
    assert int(da, 0) >= 0 and int(dr, 0) >= 0, "bad D words"
    assert b > 0, "bad budget"
    assert mip and rip, "bad ips"
    # mode-specific sanity (mirrors caseA / the RRC setup _resolve_timing)
    if mode in ("D1", "D4"): assert int(da, 0) > 0 and int(dr, 0) > 0
    if mode == "D2":         assert int(da, 0) == 0 and int(dr, 0) > 0
    if mode == "D3":         assert int(dr, 0) == 0 and int(da, 0) > 0
    print(mode, da, dr, b, mip, rip)
except Exception as e:
    sys.stderr.write("recipe parse error: %s\n" % e)
    sys.exit(1)
PY
)
if [ -z "$RECIPE" ]; then
  log "FAIL-CLOSED: could not parse a valid rollback_recipe from $SNAPSHOT"; exit 1
fi
read -r MODE DA DR BUDGET MIP RIP <<<"$RECIPE"
log "recipe from snapshot: mode=$MODE D_A=$DA D_R=$DR budget=$BUDGET master=$MIP relay=$RIP"

# build the mode-appropriate deadline args (D2 omits D_A, D3 omits D_R, OFF/FAIL_OPEN none)
CFG_DL=""
case "$MODE" in
  D1|D4) CFG_DL="--d-a $DA --d-r $DR" ;;
  D2)    CFG_DL="--d-r $DR" ;;
  D3)    CFG_DL="--d-a $DA" ;;
  OFF|FAIL_OPEN) CFG_DL="" ;;
  *) log "FAIL-CLOSED: unhandled mode $MODE"; exit 1 ;;
esac

# 1. PROGRAM: ALWAYS cold-reload the RRC (canonical clean start; configure-all's
# bring-up assumes an un-armed switch).
n=$(pgrep -cx bf_switchd || echo 0); prog=$(loaded_prog)
log "cold-reloading RRC via swap_generic.sh (found n=$n prog='${prog:-none}') ..."
bash "$SWAP" "$RRC_CONF" "rrc_rollback_$(date -u +%Y%m%dT%H%M%SZ).log" >&2 || true
n=$(pgrep -cx bf_switchd || echo 0); prog=$(loaded_prog)
if [ "$n" != "1" ] || [ "$prog" != "$RRC_PROG" ]; then
  log "FAIL: RRC program NOT loaded (n=$n prog='${prog:-none}', expected $RRC_PROG)"; exit 1
fi
log "RRC program loaded (n=$n prog='$prog')"

# 2. OPERATIONAL: restore ports/queues/mirror/pktgen (timing) + PRE + shape from the snapshot.
log "restoring RRC operational config (configure-all --mode $MODE $CFG_DL --budget $BUDGET) ..."
cfg_out=$(cd /home/decps/rrc_build && python3 "$RRC_SETUP" configure-all \
            --mode "$MODE" $CFG_DL --budget "$BUDGET" \
            --master-ip "$MIP" --relay-ip "$RIP" --grpc "$GRPC" 2>&1)
rc=$?
printf '%s\n' "$cfg_out" >&2
nfail=$(printf '%s\n' "$cfg_out" | grep -cE '^[[:space:]]*\[FAIL\]' || true)
haspass=$(printf '%s\n' "$cfg_out" | grep -cE '^RESULT: PASS' || true)
if [ "$rc" != "0" ] || [ "${nfail:-1}" != "0" ] || [ "${haspass:-0}" = "0" ]; then
  log "FAIL: RRC operational config failed (rc=$rc, [FAIL] lines=$nfail, RESULT:PASS=$haspass) — forwarding may be down"
  printf '%s\n' "$cfg_out" | grep -E '^[[:space:]]*\[FAIL\]' | head -5 >&2
  exit 1
fi
log "RRC restored + operational (program loaded, ports/queues/mirror/pktgen up, PRE verified, shape ON)"
exit 0
