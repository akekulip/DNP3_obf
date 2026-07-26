# Wireshark guide (corrected)

Field names below were checked against the installed build with `tshark -G fields`. Nothing here
depends on a DNP3 dissector being present, because this tshark build does not expose `dnp3.*`
fields on port 20000 by default.

## Capture

Capture on the master leg. The `wireshark` group permits this, so no sudo:

```bash
wireshark -k -i enp59s0f0np0 -f "(host 192.168.10.7 and tcp port 20000) or ether proto 0x88c1"
```

The filter **must** include `ether proto 0x88c1`. The v1 captures used
`host 192.168.10.7 and tcp port 20000` and were then searched for blocker frames, which that filter
excludes by construction — a test that could not fail. Use snap length 0 so nothing is truncated.

Headless equivalent:

```bash
sg wireshark -c "dumpcap -i enp59s0f0np0 \
  -f '(host 192.168.10.7 and tcp port 20000) or ether proto 0x88c1' \
  -s 0 -a duration:30 -w capture.pcap"
```

## Reading the CLRT off the screen

CLRT is the Cross-Layer Response Time: the interval between the relay's pure TCP ACK and its DNP3
RESPONSE.

1. Display filter: `ip.src == 192.168.10.7`. You now see only the relay's own packets, alternating
   between a pure ACK (Length 0) and the DNP3 response (Length 54 TCP payload, 120-byte frame).
2. View → Time Display Format → **Seconds Since Previous Displayed Packet**.
3. The Time value on each response row is the CLRT.

Native runs jitter roughly between 0.001 and 0.009 s. Protected runs sit near 0.025 s.

**Caveat you will hit:** the relay emits a TCP keepalive every ~10 s when idle, carrying
`seq = SND.NXT - 1` and zero payload. It looks like a pure ACK. If your poll interval exceeds ~10 s
the alternation above is broken by keepalives, and the row-to-row delta is no longer the CLRT.

## Filters that matter

| filter | shows | expected |
|:--|:--|:--|
| `ip.src==192.168.10.7 && tcp.len==0` | the relay's pure ACKs (and keepalives) | one per poll, plus ~1 per 10 s idle |
| `ip.src==192.168.10.7 && tcp.len>0` | DNP3 responses | one per poll, TCP payload 54 B |
| `tcp.analysis.retransmission` | hold exceeded the relay's retransmit timer | empty in all shipped captures |
| `tcp.analysis.flags` | any transport anomaly | empty in all shipped captures |
| `eth.type==0x88c1` | blocker frames on a host leg | see below |
| `_ws.malformed` | corruption | empty in all shipped captures |

On `eth.type==0x88c1`: the shipped campaign captures were taken with the narrow v1 filter, so they
cannot answer this question either way. Treat blocker visibility as **untested in the shipped
captures**, not as proven absent. Any new capture should use the wide filter above.

## Command line

```bash
# CLRT by hand
tshark -r protected.pcap -Y "ip.src==192.168.10.7" \
       -T fields -e frame.time_delta_displayed -e tcp.len

# transport integrity
tshark -r protected.pcap -Y "tcp.analysis.retransmission" | wc -l   # want 0
tshark -r protected.pcap -Y "_ws.malformed"               | wc -l   # want 0

# layer-specific lengths (54 is the TCP payload, not the frame)
tshark -r protected.pcap -Y "ip.src==192.168.10.7 && tcp.len>0" \
       -T fields -e frame.len -e ip.len -e tcp.len | sort -u

# DNP3 link addresses, decoded from the payload bytes (no dissector needed)
# link header: 05 64 | len | ctrl | dst(2, LE) | src(2, LE) | crc(2)
tshark -r protected.pcap -Y "ip.src==192.168.10.7 && tcp.len>0" \
       -T fields -e tcp.payload | head -1
```

The authoritative recomputation is `evidence/corrected_v2/scripts/analyze_live_clrt.py`, which pairs
on the expected acknowledgement number rather than on adjacency, and is cross-checked by an
independent tshark-only pipeline.
