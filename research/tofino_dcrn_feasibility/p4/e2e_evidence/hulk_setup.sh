#!/bin/bash
# Single-host DCRN test: 2 VEPA-macvlan namespaces on the data NIC + connectivity gate.
set +e
IF=enp59s0f0np0
echo "=== carrier check ==="
ip link set $IF up
sleep 2
ethtool $IF 2>/dev/null | grep -E "Speed|Link detected"
echo "=== teardown any prior ==="
ip netns del ns_master 2>/dev/null; ip netns del ns_out 2>/dev/null
ip link del mv_master 2>/dev/null; ip link del mv_out 2>/dev/null
echo "=== NIC hygiene: promisc + offloads off ==="
ip link set $IF promisc on
ethtool -K $IF gro off gso off tso off lro off 2>/dev/null
echo "=== 2 VEPA macvlans + netns ==="
ip link add link $IF name mv_master type macvlan mode vepa
ip link add link $IF name mv_out    type macvlan mode vepa
ip netns add ns_master; ip netns add ns_out
ip link set mv_master netns ns_master
ip link set mv_out    netns ns_out
ip netns exec ns_master ip addr add 10.0.1.10/16 dev mv_master
ip netns exec ns_master ip link set mv_master up
ip netns exec ns_master ip link set lo up
ip netns exec ns_out    ip addr add 10.0.2.10/16 dev mv_out
ip netns exec ns_out    ip link set mv_out up
ip netns exec ns_out    ip link set lo up
MAC_OUT=$(ip netns exec ns_out    cat /sys/class/net/mv_out/address)
MAC_MAS=$(ip netns exec ns_master cat /sys/class/net/mv_master/address)
echo "mv_master MAC=$MAC_MAS  mv_out MAC=$MAC_OUT"
ip netns exec ns_master ip neigh replace 10.0.2.10 lladdr $MAC_OUT dev mv_master
ip netns exec ns_out    ip neigh replace 10.0.1.10 lladdr $MAC_MAS dev mv_out
echo "=== CONNECTIVITY GATE: arping master->outstation (through switch hairpin) ==="
ip netns exec ns_master arping -c 4 -w 5 -I mv_master 10.0.2.10 2>&1 | tail -6
echo "=== ping (L3 through DCRN passthrough) ==="
ip netns exec ns_master ping -c 3 -W 2 10.0.2.10 2>&1 | tail -4
echo "=== DONE hulk_setup ==="
