#!/usr/bin/env python3
"""OPERATE command hold J from a trial's two captures: master TX to outstation RX of every DNP3 request.

  hold_check.py OUT.pcap IN.pcap --master-port P [--outstation-port 20000] [--json FILE]

OUT = `tcpdump -Q out` on Vision's switch-facing parent NIC: the request as the master sent it (master-side tap).
IN  = `-Q in` on the same NIC: the request as the switch delivered it toward the outstation (outstation-side tap).
A request is keyed by (TCP sequence, DNP3 function), so a retransmission is the same request; its transit is the
first arrival minus the first transmission. The interval includes path and capture delay and is not an ASIC
residency timestamp. Timestamps are the pcap's microsecond records read as float seconds and rounded to 0.1 us
(the convention seg61_02/analysis/repeat_sbo_report.py has always reported, which imports this helper).

operate_hold() is the verdict: every OPERATE sent is observed at the outstation side, at least as many as the
complete OPERATE exchanges and the configured SBO count. The transit (and how many fall below op_j) is reported as
data, never a pass/fail criterion.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ARCH = os.path.abspath(os.path.join(HERE, '..', '..'))
READ_REENCODE = os.path.join(ARCH, 'integration', 'core', 'response_only_rearm', 'stage_experiments',
                             'read_reencode_01')
if READ_REENCODE not in sys.path:
    sys.path.insert(0, READ_REENCODE)
import capture  # noqa: E402

OUTSTATION_PORT = 20000
OPERATE = 4
NAMES = (('read', 1), ('select', 3), ('operate', 4))
OBSERVATION = {'tx': 'out.pcap master-side tap', 'rx': 'in.pcap outstation-side tap',
               'includes': 'path and capture delay; not an ASIC residency timestamp'}


def _requests(path, master_port, outstation_port=OUTSTATION_PORT):
    """{(seq, function): [capture times]} of every DNP3-bearing master request, in first-seen order."""
    out, app = {}, {}
    for r in capture.tcp_records(path):
        p = r['payload']
        if r['src'][1] == master_port and r['dst'][1] == outstation_port and len(p) >= 13 and p[:2] == b'\x05\x64':
            out.setdefault((r['seq'], p[12]), []).append(r['time'])
            app.setdefault((r['seq'], p[12]), p[11] & 0x0F)
    return out, app


def request_transit_us(out_pcap, in_pcap, master_port, outstation_port=OUTSTATION_PORT):
    """Per function code, master TX (out.pcap) to outstation RX (in.pcap) of each request that arrived, in
    microseconds: the OPERATE command hold J (independent of CLRT) and the unheld READ/SELECT transit."""
    sent, _ = _requests(out_pcap, master_port, outstation_port)
    arrived, _ = _requests(in_pcap, master_port, outstation_port)
    transit = {}
    for key, times in sent.items():
        if key in arrived:
            transit.setdefault(key[1], []).append(round((min(arrived[key]) - min(times)) * 1e6, 1))
    return transit


def analyze(out_pcap, in_pcap, master_port, outstation_port=OUTSTATION_PORT):
    """Per-OPERATE rows (every OPERATE the master sent, observed or not) and the per-function transit lists."""
    sent, app = _requests(out_pcap, master_port, outstation_port)
    arrived, _ = _requests(in_pcap, master_port, outstation_port)
    operates = []
    for key, times in sent.items():
        if key[1] != OPERATE:
            continue
        seen = key in arrived
        operates.append({'seq': key[0], 'app_seq': app[key], 'tx_attempts': len(times),
                         'observed': seen,
                         'transit_us': round((min(arrived[key]) - min(times)) * 1e6, 1) if seen else None})
    transit = request_transit_us(out_pcap, in_pcap, master_port, outstation_port)
    return {'observation': OBSERVATION, 'master_port': master_port, 'outstation_port': outstation_port,
            'operates': operates,
            'transit_us': {name: transit.get(fc, []) for name, fc in NAMES}}


def _number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def operate_hold(hold, op_j_ns, complete_operates, expected_operates):
    """Delivery verdict over analyze() output: every OPERATE sent was observed at the outstation side, as many as
    completed and as configured. The minimum transit and the rows below op_j are reported, never gated."""
    op_j_us = op_j_ns / 1000.0
    rows = (hold or {}).get('operates') if isinstance(hold, dict) else None
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        return {'op_j_us': op_j_us, 'observation': OBSERVATION, 'sent': None, 'observed': None,
                'min_transit_us': None, 'below_op_j': [], 'sufficient': False,
                'reasons': ['OPERATE hold evidence missing or malformed'], 'pass': False}
    observed = [r for r in rows if r.get('observed') is True and _number(r.get('transit_us'))]
    missing = [r for r in rows if not (r.get('observed') is True and _number(r.get('transit_us')))]
    below = [dict(seq=r.get('seq'), app_seq=r.get('app_seq'), transit_us=r['transit_us'])
             for r in observed if r['transit_us'] < op_j_us]
    reasons = []
    if expected_operates and len(rows) < expected_operates:
        reasons.append('%d OPERATEs sent on the master-side capture, expected %d' % (len(rows), expected_operates))
    if missing:
        reasons.append('%d OPERATEs sent but not observed at the outstation-side capture (app_seq %s)'
                       % (len(missing), [r.get('app_seq') for r in missing][:8]))
    if isinstance(complete_operates, int) and len(observed) < complete_operates:
        reasons.append('%d OPERATE transits observed for %d complete OPERATE exchanges'
                       % (len(observed), complete_operates))
    sufficient = not reasons
    minimum = min((r['transit_us'] for r in observed), default=None)
    return {'op_j_us': op_j_us, 'observation': (hold or {}).get('observation') or OBSERVATION, 'sent': len(rows),
            'observed': len(observed), 'complete_operates': complete_operates, 'expected_operates': expected_operates,
            'min_transit_us': minimum, 'below_op_j': below, 'sufficient': sufficient, 'reasons': reasons,
            'pass': not reasons}


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('out_pcap')
    ap.add_argument('in_pcap')
    ap.add_argument('--master-port', type=int, required=True)
    ap.add_argument('--outstation-port', type=int, default=OUTSTATION_PORT)
    ap.add_argument('--json')
    a = ap.parse_args()
    report = analyze(a.out_pcap, a.in_pcap, a.master_port, a.outstation_port)
    if a.json:
        json.dump(report, open(a.json, 'w'), indent=1, default=str)
    print(json.dumps({'operates': len(report['operates']),
                      'observed': sum(r['observed'] for r in report['operates']),
                      'min_operate_transit_us': min((r['transit_us'] for r in report['operates'] if r['observed']),
                                                    default=None)}))
