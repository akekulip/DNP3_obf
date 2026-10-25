#!/usr/bin/env python3
"""OPERATE J, switch residence and the latency split from correlated, bounded anchors (c52 timing diagnosis).

  relay_anchor_check.py OUT.pcap IN.pcap TAP.pcap CLOCKS.json --master-port P --op-j-ns N --expected-operates K
                        [--max-bound-ns B] [--json OUT]

OUT/IN = the master NIC's TX/RX captures; TAP = an independent capture of the relay leg (both directions).
CLOCKS = {"master": {...}, "tap": {...}}, each {"iface", "mode", "before", "after"}: mode is the capture's tcpdump
timestamp type and before/after are phc_offset.py records (offset_ns = PHC - CLOCK_REALTIME, bound_ns) taken around
the block. Hardware timestamps (`adapter_unsynced`) are mapped to CLOCK_REALTIME with the mean of the two offsets;
each capture's uncertainty is max(bound_before, bound_after) + |offset_after - offset_before| / 2 (the drift is not
assumed linear). A cross-capture interval carries the sum of both captures' uncertainties.

Nothing is reported as measured unless every expected item is correlated and the uncertainty is within the declared
maximum; otherwise the result is "unproven" with the specific reason (Philip, 2026-10-25: no blanket exception).
Relay turnaround uses the tap alone (one clock). Capture timestamps are NIC receive times, not wire departure.
"""
import argparse
import json
import struct
import sys

OUTSTATION_PORT = 20000
OPERATE = 4
HARDWARE_MODES = ('adapter_unsynced', 'adapter')
MAGIC = {b'\xd4\xc3\xb2\xa1': 1000, b'\x4d\x3c\xb2\xa1': 1}   # little-endian microsecond / nanosecond pcap


def tcp_records(path):
    """Integer-nanosecond IPv4/TCP records of a classic little-endian Ethernet pcap (micro- or nanosecond)."""
    with open(path, 'rb') as f:
        data = f.read()
    scale = MAGIC.get(data[:4])
    if scale is None or struct.unpack('<I', data[20:24])[0] != 1:
        raise ValueError('%s: not a little-endian Ethernet pcap' % path)
    p = 24
    while p + 16 <= len(data):
        sec, sub, incl, _ = struct.unpack('<IIII', data[p:p + 16])
        f = data[p + 16:p + 16 + incl]
        p += 16 + incl
        if len(f) < 34 or f[12:14] != b'\x08\x00' or f[23] != 6:
            continue
        ihl = (f[14] & 0x0F) * 4
        tcp = f[14 + ihl:14 + struct.unpack('!H', f[16:18])[0]]
        sport, dport, seq, ack = struct.unpack('!HHII', tcp[:12])
        yield dict(time_ns=sec * 10**9 + sub * scale, sport=sport, dport=dport, seq=seq, ack=ack, flags=tcp[13],
                   payload=tcp[(tcp[12] >> 4) * 4:])


def requests(path, master_port):
    """{(seq, function): (first time, attempts, payload length)} of DNP3 master requests, first-seen order."""
    out = {}
    for r in tcp_records(path):
        p = r['payload']
        if r['sport'] == master_port and r['dport'] == OUTSTATION_PORT and len(p) >= 13 and p[:2] == b'\x05\x64':
            t, n, length = out.get((r['seq'], p[12]), (r['time_ns'], 0, len(p)))
            out[(r['seq'], p[12])] = (min(t, r['time_ns']), n + 1, length)
    return out


def responses(path, master_port):
    """{seq: (first time, ack)} of relay data segments toward the master."""
    out = {}
    for r in tcp_records(path):
        if r['sport'] == OUTSTATION_PORT and r['dport'] == master_port and r['payload']:
            if r['seq'] not in out or r['time_ns'] < out[r['seq']][0]:
                out[r['seq']] = (r['time_ns'], r['ack'])
    return out


def clock(record):
    """(offset_ns, uncertainty_ns) of one capture, or raises ValueError with the reason."""
    if not isinstance(record, dict) or not all(isinstance(record.get(k), dict) for k in ('before', 'after')):
        raise ValueError('clock relation missing or malformed')
    if record.get('mode') not in HARDWARE_MODES:
        raise ValueError('host timestamps (mode %r): no clock-relation bound' % record.get('mode'))
    b, a = record['before'], record['after']
    for s in (b, a):
        if not all(isinstance(s.get(k), (int, float)) for k in ('offset_ns', 'bound_ns')):
            raise ValueError('clock relation missing or malformed')
    return (b['offset_ns'] + a['offset_ns']) / 2.0, max(b['bound_ns'], a['bound_ns']) + abs(a['offset_ns'] - b['offset_ns']) / 2.0


def unproven(reason):
    return dict(status='unproven', reason=reason)


def interval(values, bound):
    return dict(status='measured', n=len(values), min_ns=min(values), max_ns=max(values), bound_ns=bound)


def evaluate(out_pcap, in_pcap, tap_pcap, clocks, master_port, op_j_ns, expected_operates, max_bound_ns):
    sent, tapped = requests(out_pcap, master_port), requests(tap_pcap, master_port)
    tap_rsp, master_rsp = responses(tap_pcap, master_port), responses(in_pcap, master_port)
    result = {}
    # relay turnaround: one capture, one clock
    turn = []
    for (seq, _), (t, _, length) in tapped.items():
        match = [rt for rt, ack in tap_rsp.values() if ack == (seq + length) % 2**32 and rt >= t]
        if match:
            turn.append(min(match) - t)
    result['relay_turnaround'] = (interval(turn, 0) if turn and len(turn) == len(tapped)
                                  else unproven('%d of %d relay-leg requests have a relay-leg response'
                                                % (len(turn), len(tapped))))
    try:
        (m_off, m_u), (t_off, t_u) = clock((clocks or {}).get('master')), clock((clocks or {}).get('tap'))
    except ValueError as error:
        for key in ('operate_j', 'request_forwarding', 'switch_residence'):
            result[key] = unproven(str(error))
        return result
    bound = m_u + t_u
    if bound > max_bound_ns:
        reason = 'combined clock bound %.0f ns exceeds the declared maximum %d ns' % (bound, max_bound_ns)
        for key in ('operate_j', 'request_forwarding', 'switch_residence'):
            result[key] = unproven(reason)
        return result

    def cross(t_tap, t_master):     # tap-clock instant minus master-clock instant, in CLOCK_REALTIME
        # the epoch-scale integers are subtracted first: a float at ~1.8e18 ns has ~256 ns resolution
        return (t_tap - t_master) - (t_off - m_off)

    missing = [k for k in sent if k not in tapped]
    forward = [cross(tapped[k][0], sent[k][0]) for k in sent if k in tapped]
    result['request_forwarding'] = (interval(forward, bound) if sent and not missing
                                    else unproven('%d master requests not observed on the relay leg' % len(missing)))
    ops = {k: v for k, v in sent.items() if k[1] == OPERATE}
    if len(ops) < expected_operates:
        result['operate_j'] = unproven('%d OPERATEs sent on the master capture, expected %d'
                                       % (len(ops), expected_operates))
    elif any(k not in tapped for k in ops):
        result['operate_j'] = unproven('%d OPERATEs not observed on the relay leg'
                                       % sum(k not in tapped for k in ops))
    else:
        j = [cross(tapped[k][0], v[0]) for k, v in ops.items()]
        r = dict(interval(j, bound), op_j_ns=op_j_ns, retransmitted=sum(v[1] > 1 for v in ops.values()))
        if min(j) - bound >= op_j_ns:
            r['pass'] = True
        elif min(j) + bound < op_j_ns:
            r['pass'] = False
        else:
            r = unproven('minimum J %.0f ns is within the uncertainty (+-%.0f ns) of op_j %d ns'
                         % (min(j), bound, op_j_ns))
        result['operate_j'] = r
    # switch residence: master RX (master clock) minus the relay-leg response (tap clock)
    paired = [-cross(tap_rsp[s][0], master_rsp[s][0]) for s in tap_rsp if s in master_rsp]
    lost = [s for s in tap_rsp if s not in master_rsp]
    result['switch_residence'] = (interval(paired, bound) if paired and not lost
                                  else unproven('%d relay-leg responses not observed at the master' % len(lost)))
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('out_pcap')
    ap.add_argument('in_pcap')
    ap.add_argument('tap_pcap')
    ap.add_argument('clocks')
    ap.add_argument('--master-port', type=int, required=True)
    ap.add_argument('--op-j-ns', type=int, required=True)
    ap.add_argument('--expected-operates', type=int, required=True)
    ap.add_argument('--max-bound-ns', type=int, default=10_000)
    ap.add_argument('--json')
    a = ap.parse_args(argv)
    with open(a.clocks) as f:
        clocks = json.load(f)
    r = evaluate(a.out_pcap, a.in_pcap, a.tap_pcap, clocks, a.master_port, a.op_j_ns, a.expected_operates,
                 a.max_bound_ns)
    text = json.dumps(r, indent=1)
    if a.json:
        with open(a.json, 'w') as f:
            f.write(text + '\n')
    print(text)
    return 0


if __name__ == '__main__':
    sys.exit(main())
