#!/usr/bin/env python3
"""Per-exchange timing at the master's capture point, from a run's two captures (scapy).

  clrt_check.py OUT.pcap IN.pcap [--json FILE]

OUT.pcap is `tcpdump -Q out` on the parent NIC (frames as the endpoints sent them), IN.pcap is `-Q in`
(frames as the switch returned them); both carry the same NIC clock. The master's view is its own
requests in OUT and the outstation's frames in IN.

For each master request (a DNP3-bearing segment from the master):
  t_req   time the request left the master (OUT)
  t_ack   arrival (IN) of the first outstation frame whose ACK covers the end of the request
  t_resp  arrival (IN) of the first outstation DNP3 segment after the request
  clrt    = t_resp - t_ack   (the measured m_R - m_A of NOTATION_MAPPING.md; never D_R)
  rt      = t_resp - t_req   (complete request-to-response latency)
  ack_lat = t_ack - t_req
`piggyback` marks exchanges whose covering ACK is the response segment itself, where clrt is 0 by
construction and carries no information. Requests are classed by DNP3 function code."""
import argparse
import json
import statistics
import sys

from scapy.all import rdpcap, IP, TCP

MASTER = '192.168.10.61'
FUNC = {1: 'READ', 3: 'SELECT', 4: 'OPERATE'}


def segments(path, from_master):
    out = []
    for pkt in rdpcap(path):
        if IP not in pkt or TCP not in pkt or (pkt[IP].src == MASTER) != from_master:
            continue
        ip, t = pkt[IP], pkt[TCP]
        payload = bytes(t)[t.dataofs * 4: ip.len - ip.ihl * 4]
        out.append({'t': float(pkt.time), 'seq': t.seq, 'ack': t.ack, 'len': len(payload), 'payload': payload,
                    'flags': int(t.flags)})
    return out


def after(a, b):
    """a >= b in 32-bit sequence space."""
    return ((a - b) & 0xffffffff) < 0x80000000


def stats(values):
    if not values:
        return None
    v = sorted(values)
    q = lambda p: v[min(len(v) - 1, int(round(p * (len(v) - 1))))]
    return {'n': len(v), 'min': v[0], 'median': statistics.median(v), 'iqr': q(0.75) - q(0.25), 'p95': q(0.95),
            'p99': q(0.99), 'max': v[-1], 'sd': statistics.pstdev(v) if len(v) > 1 else 0.0}


def exchanges(out_path, in_path):
    reqs = [s for s in segments(out_path, True) if s['len'] >= 13 and s['payload'][:2] == b'\x05\x64']
    back = segments(in_path, False)
    rows, j = [], 0
    for i, r in enumerate(reqs):
        end = (r['seq'] + r['len']) & 0xffffffff
        nxt = reqs[i + 1]['t'] if i + 1 < len(reqs) else float('inf')
        t_ack = t_resp = None
        piggy = False
        while j < len(back) and back[j]['t'] < r['t']:
            j += 1
        k = j
        while k < len(back) and back[k]['t'] < nxt:
            b = back[k]
            covers = (b['flags'] & 0x10) and after(b['ack'], end)
            if t_ack is None and covers:
                t_ack, piggy = b['t'], b['len'] > 0
            if b['len'] and b['payload'][:2] == b'\x05\x64' and covers:
                t_resp = b['t']
                break
            k += 1
        row = {'i': i, 'kind': FUNC.get(r['payload'][12], 'F%d' % r['payload'][12]), 't_req': r['t'],
               'complete': t_ack is not None and t_resp is not None, 'piggyback': piggy}
        if row['complete']:
            row.update(ack_lat_us=(t_ack - r['t']) * 1e6, clrt_us=(t_resp - t_ack) * 1e6, rt_us=(t_resp - r['t']) * 1e6,
                       resp_len=back[k]['len'])
        rows.append(row)
    return rows


def summarize(rows):
    out = {}
    for kind in sorted(set(r['kind'] for r in rows)):
        sel = [r for r in rows if r['kind'] == kind]
        done = [r for r in sel if r['complete']]
        out[kind] = {'requests': len(sel), 'complete': len(done), 'piggyback': sum(r['piggyback'] for r in done),
                     'resp_len': sorted(set(r['resp_len'] for r in done)),
                     'clrt_us': stats([r['clrt_us'] for r in done if not r['piggyback']]),
                     'rt_us': stats([r['rt_us'] for r in done]), 'ack_lat_us': stats([r['ack_lat_us'] for r in done])}
    return out


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('out_pcap')
    ap.add_argument('in_pcap')
    ap.add_argument('--json')
    a = ap.parse_args()
    rows = exchanges(a.out_pcap, a.in_pcap)
    summary = summarize(rows)
    if a.json:
        json.dump({'summary': summary, 'exchanges': rows}, open(a.json, 'w'), indent=1)
    json.dump(summary, sys.stdout, indent=1)
    print()
