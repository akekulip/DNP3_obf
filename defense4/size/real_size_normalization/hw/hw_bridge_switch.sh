#!/bin/bash
# S6/H1-H2 relay-edge boundary on the UFISpace switch CPU.
# relay ns (r_ep 10.44.0.2) <-> veth <-> ufispace l2_shim (inner=u_in, outer=ens1)
# The shim's outer (ens1) is the bf_kpkt CPU port; h1_cellgate bridges it to dp9.
set -u
DUR=${1:-40}; EXCH=${2:-20}
export PYTHONPATH=/tmp/rsn
SH="python3 -m defense4.size.real_size_normalization.software.l2_shim"
EP="python3 -m defense4.size.real_size_normalization.software.dnp3_endpoint"
OUT=/tmp/bridge_sw; mkdir -p "$OUT"; rm -f "$OUT"/* 2>/dev/null || true

sudo -n ip netns del relayns 2>/dev/null || true
sudo -n ip link del u_in 2>/dev/null || true
sudo -n ip netns add relayns
sudo -n ip link add u_in type veth peer name r_ep
sudo -n ip link set r_ep netns relayns
sudo -n ip netns exec relayns ip link set r_ep address 02:44:00:00:00:02
sudo -n ip netns exec relayns ip addr add 10.44.0.2/24 dev r_ep
sudo -n ip netns exec relayns ip link set r_ep up
sudo -n ip netns exec relayns ip link set lo up
sudo -n ip link set u_in up
for i in u_in ens1; do sudo -n ethtool -K "$i" tso off gso off gro off tx off rx off >/dev/null 2>&1 || true; done

START=$(python3 -c 'import time;print(time.monotonic_ns()+3000000000)')
sudo -n bash -c "PYTHONPATH=/tmp/rsn nohup $SH --role ufispace --inner-iface u_in --outer-iface ens1 \
  --key-file /tmp/bridge.key --start-monotonic-ns $START --duration $DUR \
  --metrics-json $OUT/ufispace.metrics.json --pcap-prefix $OUT/ufispace >$OUT/ufispace.log 2>&1 &"
sleep 2
sudo -n bash -c "PYTHONPATH=/tmp/rsn nohup ip netns exec relayns $EP --role relay --host 10.44.0.2 \
  --exchanges $EXCH --connections 1 --log $OUT/relay.jsonl >$OUT/relay.json 2>&1 &"
echo "switch_bridge_up start=$START"
