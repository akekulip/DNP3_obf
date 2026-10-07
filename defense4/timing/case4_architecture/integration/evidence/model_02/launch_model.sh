#!/bin/bash
# Local Tofino-1 ASIC model + bf_switchd in a private user+net+pid namespace. No root, no hardware.
# usage: launch_model.sh <compiled-out-dir-with-conf> <new-output-dir> [driver.py args...]
#   env: WAIT (s to wait for switchd, default 15)  HOLD (s to stay up after the driver)  POST (override driver cmd)
# Three workarounds were needed (see RESULT.md): (1) strip "agent0" (real-board platform manager) from a COPY of the conf,
# (2) LD_PRELOAD shim for /proc/self/pagemap PFNs, (3) tofino-model started without --no-port-monitor.
set -euo pipefail
HERE=$(dirname "$(readlink -f "$0")")
OUTC=$(readlink -f "$1"); OUT=$2; shift 2
mkdir "$OUT"; OUT=$(readlink -f "$OUT")
CONFSRC=$(ls "$OUTC"/*.conf | head -1)
[ -f "$HERE/shim/pagemap_shim.so" ] || gcc -shared -fPIC -O1 -o "$HERE/shim/pagemap_shim.so" "$HERE/shim/pagemap_shim.c" -ldl
python3 - "$CONFSRC" "$OUT/noagent.conf" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
for d in c['p4_devices']: d.pop('agent0',None)
json.dump(c,open(sys.argv[2],'w'),indent=2)
PY
PROG=$(python3 -c "import json;print(json.load(open('$OUT/noagent.conf'))['p4_devices'][0]['p4_programs'][0]['program-name'])")
export PROG
: "${POST:=python3 $HERE/drive.py $*}"; export POST
unshare -Urn --pid --fork --kill-child --mount-proc "$HERE/inner.sh" "$OUT/noagent.conf" "$OUT" 2>&1 | tee "$OUT/session.log"
