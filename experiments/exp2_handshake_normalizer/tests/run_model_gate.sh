#!/usr/bin/env bash
# Experiment 2B model gate: bring up tofino-model + bf_switchd, run the PTF matrix, tear down.
# Must run with root (CAP_NET_RAW + veth creation).  Usage:  sudo bash tests/run_model_gate.sh
set -u
SDE=/home/philip/bf-sde-9.13.1
export SDE SDE_INSTALL="$SDE/install"
export PATH="$SDE_INSTALL/bin:$PATH" LD_LIBRARY_PATH="$SDE_INSTALL/lib:${LD_LIBRARY_PATH:-}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CONF="$HERE/build/handshake_normalizer.conf"
LOG="$HERE/evidence/model"; mkdir -p "$LOG"
PROG=handshake_normalizer

echo "== [1/6] veth setup =="
"$SDE_INSTALL/bin/veth_setup.sh" >"$LOG/veth.log" 2>&1 || { echo "veth_setup FAILED"; exit 10; }

echo "== [2/6] launch tofino-model =="
"$SDE/run_tofino_model.sh" -c "$CONF" -p "$PROG" >"$LOG/model.log" 2>&1 &
MODEL_PID=$!
sleep 6

echo "== [3/6] launch bf_switchd (loads the program) =="
"$SDE/run_switchd.sh" -c "$CONF" -p "$PROG" </dev/null >"$LOG/switchd.log" 2>&1 &
SWITCHD_PID=$!

echo "== [4/6] wait for switchd ready =="
for i in $(seq 1 60); do
  if grep -qiE "bf_switchd: server started|WARM_INIT.*(done|complete)|dev_id 0 initialized|bfruntime" "$LOG/switchd.log" 2>/dev/null; then
    echo "  switchd ready after ${i}s"; break; fi
  sleep 1
done

echo "== [5/6] run PTF matrix =="
"$SDE/run_p4_tests.sh" -p "$PROG" -t "$HERE/tests/ptf" \
    --target asic-model >"$LOG/ptf.log" 2>&1
PTF_RC=$?
echo "  PTF exit: $PTF_RC"
grep -iE "cases pass|FAIL:|Ran [0-9]+ test|OK|FAILED" "$LOG/ptf.log" | tail -20

echo "== [6/6] teardown =="
kill "$SWITCHD_PID" "$MODEL_PID" 2>/dev/null
"$SDE_INSTALL/bin/veth_teardown.sh" >>"$LOG/veth.log" 2>&1 || true
echo "logs in $LOG/  (model.log switchd.log ptf.log)"
exit $PTF_RC
