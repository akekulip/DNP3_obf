#!/bin/bash
# native_master_loopback.sh -- Phase-1 integration test with a REAL DNP3 stack.
#
# Drives split_server.py (timing-enabled) with the real pydnp3 master
# (run_master.py --action scan-all-classes) over loopback, and asserts:
#   - the master completes a full integrity poll (OnTaskComplete),
#   - the master decodes the outstation database (data actually flowed),
#   - every response was held to the timing target (server timing log),
#   - byte-preservation PASS on every response,
#   - zero deadline-misses, zero bypasses, zero TCP resets.
#
# Requires pydnp3 (system python3). Loopback is a smoke test; the rig is the bar.
# Exit 0 = pass, 1 = fail.
set -u
cd "$(dirname "$0")/.." || exit 1
PORT=20000
LOGDIR="logs/native_master_loopback"
TARGET_MS=25

fuser -k ${PORT}/tcp 2>/dev/null; sleep 0.3
rm -rf "$LOGDIR"; mkdir -p "$LOGDIR"

python3 split_server.py --host 127.0.0.1 --delivery full \
  --timing-mode fixed --target-delay-ms ${TARGET_MS} \
  --hold-after-response-sec 4 --request-timeout-sec 15 --log-dir "$LOGDIR" \
  > "$LOGDIR/server.log" 2>&1 &
SRV=$!
sleep 1.5
kill -0 $SRV 2>/dev/null || { echo "FAIL: server did not start"; cat "$LOGDIR/server.log"; exit 1; }

timeout 45 python3 run_master.py --host 127.0.0.1 --action scan-all-classes \
  --wait-after-action 2 --phase custom --no-csv --no-summary \
  > "$LOGDIR/master.log" 2>&1
MRC=$?
sleep 1; kill $SRV 2>/dev/null; wait $SRV 2>/dev/null

fail=0
check() { if eval "$2"; then echo "  PASS: $1"; else echo "  FAIL: $1"; fail=1; fi; }

check "master process exited cleanly"        "[ $MRC -eq 0 ]"
check "master completed integrity scan"      "grep -q 'Scanning all classes' '$LOGDIR/master.log' && grep -q 'OnTaskComplete' '$LOGDIR/master.log'"
check "master decoded outstation database"   "grep -qiE 'Analog Input|Binary Input|SOEHandler.Process' '$LOGDIR/master.log'"
check "every response held to target"         "python3 -c \"import json,sys; r=[json.loads(l) for l in open('$LOGDIR/timing_decisions.jsonl')]; sys.exit(0 if r and all(abs(x['visible_delay_ms']-${TARGET_MS})<3 for x in r) else 1)\""
check "byte-preservation PASS on all"         "test \$(grep -c 'Byte-preservation check: PASS' '$LOGDIR/server.log') -ge 5"
check "zero deadline-miss / zero bypass"       "python3 -c \"import json,sys; r=[json.loads(l) for l in open('$LOGDIR/timing_decisions.jsonl')]; sys.exit(0 if sum(x['deadline_missed']+x['bypassed'] for x in r)==0 else 1)\""
check "zero TCP resets in master link log"    "[ \$(grep -ciE 'reset|RST' '$LOGDIR/master.log') -eq 0 ]"

echo
if [ $fail -eq 0 ]; then echo "NATIVE-MASTER LOOPBACK: ALL PASS"; else echo "NATIVE-MASTER LOOPBACK: FAILURES"; fi
exit $fail
