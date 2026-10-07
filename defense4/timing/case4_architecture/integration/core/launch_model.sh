#!/bin/bash
# Generic local Tofino-1 model launcher: tofino-model + bf_switchd in a private user/net/pid namespace.
# No root, no hardware, no traffic outside the namespace. Everything dies when the driver exits.
#
#   launch_model.sh -p <compiled out/ dir> -o <NEW output dir> [-P "ports"] [-d driver.py] [-- driver args]
#
#   -p  directory holding the compiler output (the *.conf, bfrt.json, pipe/)
#   -o  new directory (must not exist) for model.out, switchd.out, bf_drivers.log, session.log, noagent.conf
#   -P  space separated device ports to give a veth pair (default "0 1 2 3 9 64 68"); dev port N is veth(2N),
#       the test side is its peer veth(2N+1). Port 64 and 68 are the pipe-local ports of interest.
#   -d  driver run inside the namespace with env PROG OUT DEV_PORTS MODEL_GRPC (default: just hold for HOLD s)
# env: WAIT=seconds to let switchd come up (15), HOLD=seconds to stay up with no driver (0),
#      MODEL_NO_PORTMAP=1 to use the model's default port list (0-16,64) instead of ports.json,
#      MODEL_INT_PORT_LOOP=pipe bitmap for tofino-model --int-port-loop (e.g. 0xf), MODEL_EXTRA=extra model args
# Workarounds (evidence/model_02/RESULT.md): agent0 stripped from a COPY of the conf; LD_PRELOAD pagemap shim.
set -euo pipefail
HERE=$(dirname "$(readlink -f "$0")")
PORTS="0 1 2 3 9 64 68"; DRIVER=""
while getopts "p:o:P:d:" o; do case $o in p) OUTC=$OPTARG;; o) OUT=$OPTARG;; P) PORTS=$OPTARG;; d) DRIVER=$OPTARG;; *) exit 2;; esac; done
shift $((OPTIND-1))
[ -n "${OUTC:-}" ] && [ -n "${OUT:-}" ] || { sed -n 2,14p "$0"; exit 2; }
OUTC=$(readlink -f "$OUTC"); mkdir "$OUT"; OUT=$(readlink -f "$OUT")
CONFSRC=$(ls "$OUTC"/*.conf | head -1)
[ -f "$HERE/model_shim/pagemap_shim.so" ] || gcc -shared -fPIC -O1 -o "$HERE/model_shim/pagemap_shim.so" "$HERE/model_shim/pagemap_shim.c" -ldl
python3 - "$CONFSRC" "$OUT/noagent.conf" <<'PY'
import json,sys
c=json.load(open(sys.argv[1]))
for d in c['p4_devices']: d.pop('agent0',None)
json.dump(c,open(sys.argv[2],'w'),indent=2)
PY
python3 - "$OUT/ports.json" $PORTS <<'PY'
import json,sys
json.dump({"PortToVeth":[{"device_port":int(p),"veth1":2*int(p),"veth2":2*int(p)+1} for p in sys.argv[2:]]},open(sys.argv[1],'w'),indent=1)
PY
export PROG=$(python3 -c "import json;print(json.load(open('$OUT/noagent.conf'))['p4_devices'][0]['p4_programs'][0]['program-name'])")
export DEV_PORTS="$PORTS" OUT HERE MODEL_GRPC=127.0.0.1:50052
export POST_DRIVER="${DRIVER:+$(readlink -f "$DRIVER")}" DRIVER_ARGS="$*"
cat > "$OUT/.inner.sh" <<'INNER'
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
INNER
chmod +x "$OUT/.inner.sh"
set +e
unshare -Urn --pid --fork --kill-child --mount-proc "$OUT/.inner.sh" 2>&1 | tee "$OUT/session.log"
rc=${PIPESTATUS[0]}
echo "hugepages free after run: $(grep HugePages_Free /proc/meminfo | tr -s ' ')" | tee -a "$OUT/session.log"
exit $rc
