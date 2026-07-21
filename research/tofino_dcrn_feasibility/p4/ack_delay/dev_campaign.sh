#!/usr/bin/env bash
# dev_campaign.sh <label> <readiness_list_csv> <n>  — run ONE device campaign on Hulk AS ROOT.
# Captures /tmp/c3caps/<label>.pcap over N continuous txns on one connection with the given readiness
# distribution (a synthetic "device" native latency profile). The switch mode (forward/case-a) is set
# by the caller. Used to build the Formby-eval anonymity set (SEL-751 + synthetic separate-ACK devices).
set -u
LABEL="${1:?label}"; RLIST="${2:?readiness_csv}"; N="${3:-99}"
P=/home/decps/Projects/DNP3/dnp3_split_harness/payloads/sel751
D=/tmp/c3caps; mkdir -p "$D"
pkill -9 -f minimal_c3 2>/dev/null; sleep 1
rm -f "$D/$LABEL.pcap" "$D/${LABEL}_srv.log" "$D/${LABEL}_cli.log"
tcpdump -i enp59s0f0np0 -w "$D/$LABEL.pcap" -U -s 128 'tcp port 20000' >/dev/null 2>&1 &
TD=$!
sleep 0.8
ip netns exec ns_out sudo -u decps -H python3 /tmp/minimal_c3_continuous_server.py \
    --host 10.0.2.10 --port 20000 --n "$N" --readiness-list "$RLIST" --seed 3 \
    --request-file "$P/orig_0001.bin" --response-file "$P/resp_0001.bin" >"$D/${LABEL}_srv.log" 2>&1 &
sleep 0.5
ip netns exec ns_master sudo -u decps -H python3 /tmp/minimal_c3_continuous_client.py \
    --host 10.0.2.10 --local 10.0.1.10 --port 20000 --n "$N" --gap-ms 30 \
    --request-file "$P/orig_0001.bin" --response-file "$P/resp_0001.bin" >"$D/${LABEL}_cli.log" 2>&1 &
for _ in $(seq 1 80); do grep -q "C3-CCLIENT done" "$D/${LABEL}_cli.log" 2>/dev/null && break; sleep 0.5; done
sleep 0.5
kill "$TD" 2>/dev/null
echo "[$LABEL] $(grep -hoE '[0-9]+/[0-9]+ byte-identical' "$D/${LABEL}_cli.log" 2>/dev/null) frames=$(tcpdump -r "$D/$LABEL.pcap" 2>/dev/null | wc -l)"
