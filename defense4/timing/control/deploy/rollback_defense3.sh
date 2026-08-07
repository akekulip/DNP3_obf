#!/usr/bin/env bash
# Idempotent Defense 3 restore, RUN ON THE SWITCH (decps@10.10.54.81).
#
# TWO layers, because reloading the program is NOT enough to forward:
#   1. PROGRAM: /home/decps/d3/swap_generic.sh d3_final.conf reloads case_a_defense3 cold.
#      It carries the two load-bearing details (sudo; the `tail -f /dev/null |` stdin hold
#      that stops bf_switchd dying on SSH EOF) and stops any running bf_switchd (Defense 4
#      or otherwise) before relaunching Defense 3.
#   2. OPERATIONAL: a cold bf_switchd load brings the P4 up with NO ports configured — dp9
#      (Vision) and dp64 (relay) stay DOWN and nothing forwards. Defense 3's ports/queues/
#      mirror/pktgen are established by its OWN setup, so this then runs
#      case_a_defense3_fixed_ack_delay_setup.py --config --arm-blockers, exactly as the
#      proven live_r1 restore does, to bring Defense 3 back to a FORWARDING state.
#
# Idempotent: re-running --config on an already-operational Defense 3 is a harmless
# re-write. Safe to call any number of times, from a trap or from the watchdog.
set -u
SWAP=/home/decps/d3/swap_generic.sh
D3_DIR=/home/decps/d3
D3_CONF=$D3_DIR/d3_final.conf
D3_SETUP=$D3_DIR/case_a_defense3_fixed_ack_delay_setup.py
D3_PROG=case_a_defense3
export SDE=/home/decps/Downloads/bf-sde-9.13.2
export SDE_INSTALL=$SDE/install
export LD_LIBRARY_PATH=$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}
export PYTHONPATH=$SDE_INSTALL/lib/python3.8/site-packages/tofino:$SDE_INSTALL/lib/python3.8/site-packages:${PYTHONPATH:-}
log(){ echo "[rollback $(date -u +%H:%M:%S)] $*" >&2; }

loaded_prog(){
  local pid conf
  pid=$(pgrep -ox bf_switchd || true); [ -n "$pid" ] || { echo ""; return; }
  conf=$(tr '\0' '\n' < /proc/$pid/cmdline 2>/dev/null | awk '/^--conf-file$/{getline;print;exit}')
  [ -n "$conf" ] && [ -r "$conf" ] || { echo ""; return; }
  python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['p4_devices'][0]['p4_programs'][0]['program-name'])" "$conf" 2>/dev/null || echo ""
}

# 1. PROGRAM: ensure Defense 3 is the loaded program with exactly one daemon
n=$(pgrep -cx bf_switchd || echo 0)
prog=$(loaded_prog)
if [ "$n" = "1" ] && [ "$prog" = "$D3_PROG" ]; then
  log "Defense 3 program already loaded (1 daemon) — skipping reload"
else
  log "reloading Defense 3 program via swap_generic.sh (found n=$n prog='${prog:-none}') ..."
  bash "$SWAP" "$D3_CONF" "d3_rollback_$(date -u +%Y%m%dT%H%M%SZ).log" >&2 || true
  n=$(pgrep -cx bf_switchd || echo 0); prog=$(loaded_prog)
  if [ "$n" != "1" ] || [ "$prog" != "$D3_PROG" ]; then
    log "ERROR: Defense 3 program NOT loaded (n=$n prog='${prog:-none}')"; exit 1
  fi
fi

# 2. OPERATIONAL: (re)establish Defense 3's ports/queues/mirror/pktgen so it FORWARDS
log "restoring Defense 3 operational config (--config --arm-blockers) ..."
cfg_out=$(cd "$D3_DIR" && python3 "$D3_SETUP" --prog "$D3_PROG" --config --arm-blockers --d-ms 2 2>&1)
nfail=$(printf '%s\n' "$cfg_out" | grep -c '^\[FAIL\]' || true)
if [ "${nfail:-1}" != "0" ]; then
  log "ERROR: Defense 3 operational config reported FAILs ($nfail) — forwarding may be down"
  printf '%s\n' "$cfg_out" | grep '^\[FAIL\]' | head -5 >&2
  exit 1
fi
log "Defense 3 restored + operational (program loaded, ports/queues/mirror configured, blockers armed)"
exit 0
