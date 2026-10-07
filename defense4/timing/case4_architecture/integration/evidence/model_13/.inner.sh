#!/bin/bash
SDE=/home/philip/bf-sde-9.13.1
export SDE SDE_INSTALL=$SDE/install PATH=$SDE/install/bin:$PATH LD_LIBRARY_PATH=$SDE/install/lib:/usr/local/lib
sysctl -qw net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 2>/dev/null || true
ip link set lo up
for n in $DEV_PORTS; do
  ip link add veth$((2*n)) type veth peer name veth$((2*n+1))
  ip link set veth$((2*n)) up; ip link set veth$((2*n+1)) up
done
cd "$OUT"
tofino-model --no-cli -d 1 -k 1 -f "${MODEL_NO_PORTMAP:+None}${MODEL_NO_PORTMAP:-$OUT/ports.json}" --p4-target-config "$OUT/noagent.conf" --install-dir $SDE_INSTALL \
  --chip-type 2 --log-dir . --pkt-log-len 256 ${MODEL_INT_PORT_LOOP:+--int-port-loop $MODEL_INT_PORT_LOOP} ${MODEL_EXTRA:-} > model.out 2>&1 &
sleep 3
LD_PRELOAD="$HERE/model_shim/pagemap_shim.so" bf_switchd --install-dir $SDE_INSTALL --conf-file "$OUT/noagent.conf" \
  --init-mode=cold --status-port 7777 --background > switchd.out 2>&1 &
for i in $(seq 1 ${WAIT:-15}); do ss -lnt | grep -q ':50052 ' && break; sleep 1; done
ss -lnt | grep -q ':50052 ' || { echo "FAIL: bf_switchd gRPC (50052) never came up"; tail -5 switchd.out; exit 3; }
sleep 1
if [ -n "$POST_DRIVER" ]; then python3 "$POST_DRIVER" $DRIVER_ARGS; rc=$?; else sleep ${HOLD:-0}; rc=0; fi
echo "driver exit code $rc"
exit $rc
