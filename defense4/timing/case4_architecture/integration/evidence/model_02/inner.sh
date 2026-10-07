#!/bin/bash
# runs as pid 1 inside `unshare -Urn --pid --fork --kill-child --mount-proc`
# args: CONF OUTDIR ; env: HOLD (seconds to stay up), POST (command run after switchd is up)
CONF=$1; OUT=$2
HERE=$(dirname "$(readlink -f "$0")")
SDE=/home/philip/bf-sde-9.13.1
export SDE SDE_INSTALL=$SDE/install PATH=$SDE/install/bin:$PATH LD_LIBRARY_PATH=$SDE/install/lib:/usr/local/lib
export OUT HERE
ip link set lo up
for i in 0 1 2 3 4 5 6 7 8 9; do ip link add veth$((2*i)) type veth peer name veth$((2*i+1)); ip link set veth$((2*i)) up; ip link set veth$((2*i+1)) up; done
cd $OUT
tofino-model --no-cli -d 1 -k 1 -f None --p4-target-config $CONF --install-dir $SDE_INSTALL --chip-type 2 --log-dir . --pkt-log-len 256 > model.out 2>&1 &
sleep 3
LD_PRELOAD=$HERE/shim/pagemap_shim.so bf_switchd --install-dir $SDE_INSTALL --conf-file $CONF --init-mode=cold --status-port 7777 --background > switchd.out 2>&1 &
sleep ${WAIT:-15}
echo "--- listeners"; ss -lntup | cut -c1-120
if [ -n "$POST" ]; then bash -c "$POST"; fi
sleep ${HOLD:-0}
