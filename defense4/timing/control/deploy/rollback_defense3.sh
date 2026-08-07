#!/usr/bin/env bash
# Idempotent Defense 3 restore, RUN ON THE SWITCH (decps@10.10.54.81).
#
# Reuses the PROVEN load mechanism /home/decps/d3/swap_generic.sh verbatim rather than
# re-deriving it: that script carries the two load-bearing details (sudo, and the
# `tail -f /dev/null |` stdin hold that stops bf_switchd dying on SSH EOF) that have each
# broken a swap before. swap_generic.sh d3_final.conf ALSO stops any running bf_switchd
# (Defense 4 or otherwise) before relaunching Defense 3 — which satisfies "stop any
# Defense 4 bf_switchd before relaunching Defense 3".
#
# Idempotent: if Defense 3 is already the loaded program AND exactly one daemon is up,
# it does nothing. Safe to call any number of times, from a trap or from the watchdog.
set -u
SWAP=/home/decps/d3/swap_generic.sh
D3_CONF=/home/decps/d3/d3_final.conf
D3_PROG=case_a_defense3
log(){ echo "[rollback $(date -u +%H:%M:%S)] $*" >&2; }

loaded_prog(){
  local pid conf
  pid=$(pgrep -ox bf_switchd || true); [ -n "$pid" ] || { echo ""; return; }
  conf=$(tr '\0' '\n' < /proc/$pid/cmdline 2>/dev/null | awk '/^--conf-file$/{getline;print;exit}')
  [ -n "$conf" ] && [ -r "$conf" ] || { echo ""; return; }
  python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['p4_devices'][0]['p4_programs'][0]['program-name'])" "$conf" 2>/dev/null || echo ""
}

n=$(pgrep -cx bf_switchd || echo 0)
prog=$(loaded_prog)
if [ "$n" = "1" ] && [ "$prog" = "$D3_PROG" ]; then
  log "Defense 3 ($D3_PROG) already loaded, 1 daemon — nothing to do"; exit 0
fi

log "restoring Defense 3 via swap_generic.sh (found n=$n prog='${prog:-none}') ..."
bash "$SWAP" "$D3_CONF" "d3_rollback_$(date -u +%Y%m%dT%H%M%SZ).log" >&2 || true

n=$(pgrep -cx bf_switchd || echo 0)
prog=$(loaded_prog)
if [ "$n" = "1" ] && [ "$prog" = "$D3_PROG" ]; then
  log "Defense 3 restored OK (1 daemon, prog=$prog)"; exit 0
fi
log "ERROR: Defense 3 NOT restored (n=$n prog='${prog:-none}')"; exit 1
