#!/usr/bin/env python3
"""Per-exchange timing at the master's capture point, from a run's two captures.

  clrt_check.py OUT.pcap IN.pcap [--json FILE]

OUT = `tcpdump -Q out` on the parent NIC (frames as the master/outstation sent them); IN = `-Q in`
(frames as the switch returned them). Both carry the same parent-NIC clock, so every interval below is a
host-capture-point interval, not an isolated ASIC forwarding time, and timestamps are integer
microseconds at the capture resolution (not epoch floats, which could not justify sub-microsecond
precision).

A logical request is one application exchange: a DNP3-bearing master segment, keyed by (four-tuple,
connection incarnation, TCP sequence start, DNP3 function). A TCP retransmission resends the same bytes
at the same sequence, so it is retained as another ATTEMPT of the same logical request, never a new one.
Each logical request is associated with:

  t_ack   first returned frame whose ACK covers the end of the request (master sequence space)
  t_resp  first returned DNP3 response (same four-tuple and incarnation) whose application sequence
          echoes the request and whose ACK covers the request end -- the application-sequence match is
          what stops an unrelated covering response from being misattributed.

  clrt    = t_resp - t_ack    (the measured m_R - m_A of NOTATION_MAPPING.md; never D_R)
  rt      = t_resp - t_req    (complete request-to-response latency, from the first attempt)
  ack_lat = t_ack - t_req

`piggyback` marks an exchange whose covering ACK is the response segment itself; clrt is 0 by
construction there and carries no information. An exchange with no covering response is `incomplete`
(a failed exchange) and is reported in the completion counts, though latency statistics are taken only
from the declared eligible subset: complete, non-piggyback, single-attempt exchanges.

Standard deviation is reported under two explicit keys, `sd_population` (divide by n) and `sd_sample`
(divide by n-1); there is no bare `sd`. The convention is also written into every report as `sd_convention`.

DNP3 CRCs are verified on requests and responses. A checksum-offloaded master segment carries only a
TCP pseudo-header placeholder, which is not corruption and does not affect the DNP3 CRC; returned frames
are checksum-validated.
"""
import argparse
import json
import os
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wire_check as wc  # noqa: E402

MASTER_IP = wc.MASTER_IP
FUNC = {0: 'CONFIRM', 1: 'READ', 2: 'WRITE', 3: 'SELECT', 4: 'OPERATE', 5: 'DIRECT_OPERATE',
        0x81: 'RESPONSE', 0x82: 'UNSOLICITED'}
RESPONSE_FUNCS = (0x81, 0x82)
SD_CONVENTION = ('sd_population divides by n (statistics.pstdev); sd_sample divides by n-1 (statistics.stdev). '
                 'Both are in the units of the statistic (microseconds); a single value reports 0.0 for both.')


def after(a, b):
    """a >= b in 32-bit sequence space."""
    return ((a - b) & 0xffffffff) < 0x80000000


def func_of(payload):
    return payload[12] if len(payload) > 12 else None


def app_seq(payload):
    return payload[11] & 0x0f if len(payload) > 11 else None


def stats(values):
    if not values:
        return None
    v = sorted(values)
    q = lambda p: v[min(len(v) - 1, int(round(p * (len(v) - 1))))]
    return {'n': len(v), 'min': v[0], 'median': int(statistics.median(v)), 'iqr': q(0.75) - q(0.25),
            'p95': q(0.95), 'p99': q(0.99), 'max': v[-1],
            'sd_population': round(statistics.pstdev(v), 1) if len(v) > 1 else 0.0,
            'sd_sample': round(statistics.stdev(v), 1) if len(v) > 1 else 0.0}


def _master_requests(out_segs):
    reqs = [s for s in out_segs if s['src'] == MASTER_IP and s['len'] >= 13 and s['payload'][:2] == b'\x05\x64']
    logical = []
    by_key = {}
    for r in sorted(reqs, key=lambda s: (s['t_us'], s['index'])):
        key = (r['flow'], r['inc'], r['seq'], func_of(r['payload']))
        if key in by_key:
            by_key[key]['attempts'].append(r)
            continue
        crc_ok, _ = wc.dnp3_ok(r['payload'])
        lr = {'flow': r['flow'], 'inc': r['inc'], 'seq': r['seq'], 'func': func_of(r['payload']),
              'app_seq': app_seq(r['payload']), 'end': (r['seq'] + r['len']) & 0xffffffff,
              't_req': r['t_us'], 'dnp3_crc_ok': crc_ok, 'attempts': [r],
              'kind': FUNC.get(func_of(r['payload']), 'F%d' % func_of(r['payload']))}
        by_key[key] = lr
        logical.append(lr)
    return logical


def exchanges(out_path, in_path):
    out_segs = wc.assign_incarnations(wc.parse(out_path)[0])
    in_segs = wc.assign_incarnations(wc.parse(in_path)[0])
    back = sorted([s for s in in_segs if s['src'] != MASTER_IP], key=lambda s: (s['t_us'], s['index']))
    rows = []
    for lr in _master_requests(out_segs):
        t_ack = t_resp = resp_len = None
        piggy = False
        resp_crc_ok = None
        for b in back:
            if b['flow'] != lr['flow'] or b['inc'] != lr['inc'] or b['t_us'] < lr['t_req']:
                continue
            covers = (b['flags'] & wc.ACK) and after(b['ack'], lr['end'])
            if t_ack is None and covers:
                t_ack, piggy = b['t_us'], b['len'] > 0
            is_resp = (b['len'] and b['payload'][:2] == b'\x05\x64' and
                       func_of(b['payload']) in RESPONSE_FUNCS and app_seq(b['payload']) == lr['app_seq'])
            if is_resp and covers:
                t_resp, resp_len = b['t_us'], b['len']
                resp_crc_ok = wc.dnp3_ok(b['payload'])[0]
                break
        row = {'kind': lr['kind'], 'app_seq': lr['app_seq'], 't_req': lr['t_req'],
               'attempts': len(lr['attempts']), 'retransmitted': len(lr['attempts']) > 1,
               'req_crc_ok': lr['dnp3_crc_ok'], 'complete': t_resp is not None, 'piggyback': piggy,
               'resp_crc_ok': resp_crc_ok, 'resp_len': resp_len}
        if t_ack is not None:
            row['ack_lat_us'] = t_ack - lr['t_req']
        if t_resp is not None:
            row['clrt_us'] = t_resp - t_ack if t_ack is not None else None
            row['rt_us'] = t_resp - lr['t_req']
        rows.append(row)
    return rows


def summarize(rows):
    out = {}
    for kind in sorted(set(r['kind'] for r in rows)):
        sel = [r for r in rows if r['kind'] == kind]
        done = [r for r in sel if r['complete']]
        eligible = [r for r in done if not r['piggyback'] and not r['retransmitted']]
        out[kind] = {
            'logical_requests': len(sel), 'attempts': sum(r['attempts'] for r in sel),
            'retransmitted': sum(r['retransmitted'] for r in sel),
            'complete': len(done), 'incomplete': len(sel) - len(done),
            'piggyback': sum(r['piggyback'] for r in done),
            'req_crc_bad': sum(not r['req_crc_ok'] for r in sel),
            'resp_crc_bad': sum(r['resp_crc_ok'] is False for r in done),
            'resp_len': sorted(set(r['resp_len'] for r in done if r['resp_len'] is not None)),
            'eligible_for_latency': len(eligible),
            'clrt_us': stats([r['clrt_us'] for r in eligible if r.get('clrt_us') is not None]),
            'rt_us': stats([r['rt_us'] for r in eligible]),
            'ack_lat_us': stats([r['ack_lat_us'] for r in eligible if r.get('ack_lat_us') is not None])}
    return out


def analyze(out_path, in_path):
    rows = exchanges(out_path, in_path)
    return {'sd_convention': SD_CONVENTION,
            'note': 'intervals are host-capture-point (same parent-NIC clock), not ASIC forwarding time; '
                    'timestamps are integer microseconds at the capture resolution',
            'summary': summarize(rows), 'exchanges': rows}


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('out_pcap')
    ap.add_argument('in_pcap')
    ap.add_argument('--json')
    a = ap.parse_args()
    report = analyze(a.out_pcap, a.in_pcap)
    if a.json:
        json.dump(report, open(a.json, 'w'), indent=1, default=str)
    json.dump(report['summary'], sys.stdout, indent=1, default=str)
    print()
    # a run whose requests or responses fail their DNP3 CRC is a corrupt extraction
    bad = any(k['req_crc_bad'] or k['resp_crc_bad'] for k in report['summary'].values())
    sys.exit(1 if bad else 0)
