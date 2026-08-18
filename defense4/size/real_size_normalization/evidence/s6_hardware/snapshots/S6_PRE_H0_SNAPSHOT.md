# S6 read-only hardware snapshot (pre-H0)
captured by a decps SSH read-only reconnaissance session; NO mutations.

## Access verified
- Vision  decps@10.10.54.19  (hostname vision), DNP3 NIC enp59s0f0np0 = 192.168.10.1/24
- Switch  decps@10.10.54.81  (hostname ufispace, UFISpace S9180-32X Tofino-1, SDE 9.13.2)
- SEL-751 192.168.10.7 / ION 192.168.10.8 reachable only through Vision (dp64 leg); NOT contacted

## Switch: currently loaded program (the sibling that a swap would displace)
conf-file /home/decps/rrc_build/defense4_rrc.conf
program: defense4_rrc_kernel (RRC baseline)

## Switch: CPU-port netdev + deploy/rollback mechanism
- ens1 (MAC 00:02:00:00:03:00) = bf_kpkt CPU-port netdev  [second trusted boundary hook]
- program swap: /home/decps/d3/swap_generic.sh <conf> <log>
- rollback to D3: /home/decps/d3/swap_to_d3.sh
- port setup: defense4_caseA_setup.py configure --mode <MODE>  (needs DEFENSE4_HW_AUTHORIZED=1)
- ports: dp8=loopback, dp9=Vision master, dp64=relay leg (1G), dp68=pktgen

## Vision: offloads (must normalize before size evidence, runbook R3)
tcp-segmentation-offload: on
generic-segmentation-offload: on
generic-receive-offload: on
