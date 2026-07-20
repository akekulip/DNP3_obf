#!/bin/bash
LABEL=$1
cd /home/decps/Projects/DNP3/dnp3_split_harness
RUN="sudo -u decps -H python3"
ip netns exec ns_out $RUN run_outstation.py --host 10.0.2.10 --port 20000 > /tmp/out_$LABEL.log 2>&1 &
sleep 7
ip netns exec ns_out ss -tlnp 2>/dev/null | grep -q ':20000' && echo OUTSTATION_LISTENING || { echo NOT_LISTENING; tail -6 /tmp/out_$LABEL.log; }
# capture on the physical wire (root ns) — sees the hairpinned traffic
tcpdump -i enp59s0f0np0 -w /tmp/dcrn_${LABEL}_wire.pcap -U 'tcp port 20000' >/dev/null 2>&1 &
TD=$!
sleep 1
ip netns exec ns_master $RUN run_master.py --host 10.0.2.10 --local 10.0.1.10 --port 20000 \
    --phase custom --action scan-class0 --repeat 20 --delay-between 0.3 --no-csv --no-summary > /tmp/mas_$LABEL.log 2>&1
echo "MASTER_EXIT=$?"
sleep 1; kill $TD 2>/dev/null; pkill -u decps -f run_outstation 2>/dev/null; sleep 1
echo "=== master received data? (grep SOE/received/values) ==="
grep -icE "received|OnReceiveHeader|Indexed|value=|SOE" /tmp/mas_$LABEL.log | sed 's/^/data_lines=/'
grep -iE "channel state change: (OPEN|SHUTDOWN)" /tmp/mas_$LABEL.log | sort | uniq -c
echo "=== wire pcap frame count ==="
tcpdump -r /tmp/dcrn_${LABEL}_wire.pcap 2>/dev/null | wc -l
echo "=== per-frame: time, ethsrc, ipsrc->ipdst, srcport>dstport, len (first 30) ==="
tshark -r /tmp/dcrn_${LABEL}_wire.pcap -Y 'tcp.len>0' -T fields -e frame.time_relative -e eth.src -e ip.src -e tcp.srcport -e tcp.dstport -e tcp.len 2>/dev/null | head -30
