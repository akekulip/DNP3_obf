#!/bin/bash
# S6/H1-H2 master boundary on Vision.
# master ns (m_ep 10.44.0.1) <-> veth <-> vision l2_shim (inner=v_in, outer=enp59s0f0np0)
# The shim's outer (enp59s0f0np0) carries fixed cells to dp9.
# sudo on Vision is password-based: this script is invoked under `sudo -S` with the password on stdin,
# so it runs AS ROOT already -- no inner sudo needed.
set -u
DUR=${1:-40}; EXCH=${2:-20}
export PYTHONPATH=/tmp/rsn
SH="python3 -m defense4.size.real_size_normalization.software.l2_shim"
EP="python3 -m defense4.size.real_size_normalization.software.dnp3_endpoint"
OUT=/tmp/bridge_vi; mkdir -p "$OUT"; rm -f "$OUT"/* 2>/dev/null || true

ip netns del masterns 2>/dev/null || true
ip link del v_in 2>/dev/null || true
ip netns add masterns
ip link add v_in type veth peer name m_ep
ip link set m_ep netns masterns
ip netns exec masterns ip link set m_ep address 02:44:00:00:00:01
ip netns exec masterns ip addr add 10.44.0.1/24 dev m_ep
ip netns exec masterns ip link set m_ep up
ip netns exec masterns ip link set lo up
ip link set v_in up
# The reverse cells carry outer dst MAC 02:00:00:00:00:01 (not Vision's real MAC),
# so the i40e NIC would filter them out non-promiscuously. Put it in promisc.
ip link set enp59s0f0np0 promisc on
for i in v_in enp59s0f0np0; do ethtool -K "$i" tso off gso off gro off tx off rx off >/dev/null 2>&1 || true; done

START=$(python3 -c 'import time;print(time.monotonic_ns()+3000000000)')
PYTHONPATH=/tmp/rsn nohup $SH --role vision --inner-iface v_in --outer-iface enp59s0f0np0 \
  --key-file /tmp/bridge.key --start-monotonic-ns $START --duration $DUR \
  --metrics-json $OUT/vision.metrics.json --pcap-prefix $OUT/vision >$OUT/vision.log 2>&1 &
sleep 3
# master runs to completion (foreground), then report
PYTHONPATH=/tmp/rsn timeout $((DUR-2)) ip netns exec masterns $EP --role master --host 10.44.0.2 \
  --exchanges $EXCH --log $OUT/master.jsonl >$OUT/master.json 2>$OUT/master.err
echo "master_rc=$?"
cat $OUT/master.json 2>/dev/null
