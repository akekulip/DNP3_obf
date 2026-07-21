#!/usr/bin/env bash
# c3_hulk_rig_setup.sh — single-host Hulk loopback rig for the Case-A C3 microbenchmark.
# Run ON Hulk AS ROOT. 2 VEPA-macvlan netns on the data NIC talking through the switch dp8 hairpin.
# Supersedes e2e_evidence/hulk_setup.sh: adds the two LOAD-BEARING host fixes that script omitted
# (proven necessary on 2026-07-20 — without them the connectivity gate fails 100%):
#   * i40e `disable-source-pruning on` — else the NIC drops returning hairpinned frames whose source
#     MAC is a LOCAL macvlan (anti-spoof pruning), so nothing comes back through the switch.
#   * strip any stale 10.0.x IP off the root NIC — else the kernel routes 10.0.2.10 locally, bypassing
#     the switch entirely.
# Prereq on the switch: dcrn_defense1 loaded, defense1_setup done, dp8 -> BF_LPBK_MAC_NEAR.
set +e
IF="${C3_WIRE_IFACE:-enp59s0f0np0}"

echo "=== carrier ==="; ip link set "$IF" up; sleep 2
ethtool "$IF" 2>/dev/null | grep -E "Speed|Link detected"

echo "=== teardown any prior ==="
ip netns del ns_master 2>/dev/null; ip netns del ns_out 2>/dev/null
ip link del mv_master 2>/dev/null; ip link del mv_out 2>/dev/null

echo "=== NIC hygiene: promisc + offloads off ==="
ip link set "$IF" promisc on
ethtool -K "$IF" gro off gso off tso off lro off 2>/dev/null

echo "=== HAIRPIN-CRITICAL: i40e source-pruning off ==="
ethtool --set-priv-flags "$IF" disable-source-pruning on 2>/dev/null \
    && echo "  disable-source-pruning on" || echo "  WARN: priv-flag unavailable (non-i40e?) — hairpin may fail"

echo "=== strip stale 10.0.x off root NIC (else routed locally, bypassing switch) ==="
for a in $(ip -4 -o addr show "$IF" | grep -oE "10[.]0[.][0-9]+[.][0-9]+/[0-9]+"); do
    ip addr del "$a" dev "$IF" && echo "  stripped $a"
done

echo "=== 2 VEPA macvlans + netns ==="
ip link add link "$IF" name mv_master type macvlan mode vepa
ip link add link "$IF" name mv_out    type macvlan mode vepa
ip netns add ns_master; ip netns add ns_out
ip link set mv_master netns ns_master
ip link set mv_out    netns ns_out
ip netns exec ns_master ip addr add 10.0.1.10/16 dev mv_master
ip netns exec ns_master ip link set mv_master up; ip netns exec ns_master ip link set lo up
ip netns exec ns_out    ip addr add 10.0.2.10/16 dev mv_out
ip netns exec ns_out    ip link set mv_out up;     ip netns exec ns_out ip link set lo up
# rp_filter off (hairpin path is asymmetric to the kernel's reverse-path view)
for ns in ns_master ns_out; do ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0; done

MAC_OUT=$(ip netns exec ns_out    cat /sys/class/net/mv_out/address)
MAC_MAS=$(ip netns exec ns_master cat /sys/class/net/mv_master/address)
echo "mv_master MAC=$MAC_MAS  mv_out MAC=$MAC_OUT"
ip netns exec ns_master ip neigh replace 10.0.2.10 lladdr "$MAC_OUT" dev mv_master
ip netns exec ns_out    ip neigh replace 10.0.1.10 lladdr "$MAC_MAS" dev mv_out

echo "=== CONNECTIVITY GATE: ping master -> outstation through the switch hairpin ==="
ip netns exec ns_master ping -c 3 -W 1 10.0.2.10 2>&1 | tail -4
echo "=== DONE c3_hulk_rig_setup ==="
