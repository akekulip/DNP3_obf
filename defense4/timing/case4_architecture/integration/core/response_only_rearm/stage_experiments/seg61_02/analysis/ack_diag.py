#!/usr/bin/env python3
"""ACK-delay localization (ctl_timing_01/evidence/m9d_01/ACK_DIAG_PLAN_20261017.md), per exchange, from retained evidence.

  python3 ack_diag.py RUN_DIR [RUN_DIR ...] -o out.json [--md out.md]

Captures, both on Vision's interface: out.pcap is what Vision transmits, before the switch (the master's request;
the outstation's ACK and response as emitted); in.pcap is what Vision receives from the switch (the master's ACK
and response). timing.json's exchanges come from them (clrt_check.py): clrt_us is in.pcap's response time minus
its ACK time.

For each timed exchange the master-received ACK frame is found in in.pcap at t_req + ack_lat_us, and its TCP ack value
names the switch's register entry: the m9d after-snapshot's egress_diag entries[ack & 0x3fff] = [lo, hi], the
egress parser timestamps (ns) of that ACK and response. switch_clrt = (hi - lo) mod 2^32.

Per plan: tail = |clrt - 950| > 100 us; signature = ACK latency > 500 us above the kind's median and round trip within
300 us of its median. An m9d tail is localized downstream of the egress parser when |switch_clrt - 950| <= 100 us,
at or before it when that also exceeds 100 us, and unmatched when no entry exists.
"""
import argparse
import json
import statistics
import subprocess
from pathlib import Path

GAP_US, TOL_US = 950.0, 100.0


def frames(pcap):
    """(t_us, src, dst, ack, payload_len) of TCP frames, absolute sequence numbers."""
    out = []
    text = subprocess.run(['tcpdump', '-tt', '-nn', '-S', '-r', str(pcap), 'tcp'], capture_output=True,
                          text=True).stdout
    for line in text.splitlines():
        p = line.split()
        try:
            sec, frac = p[0].split('.')
            t = int(sec) * 1_000_000 + int(frac)
            src, dst = p[2], p[4].rstrip(':')
            ack = int(p[p.index('ack') + 1].rstrip(',')) if 'ack' in p else None
            length = int(p[-1]) if p[-2] == 'length' else 0
        except (ValueError, IndexError):
            continue
        out.append((t, src, dst, ack, length))
    return out


def nearest(fr, t, want_payload, tol_us=3):
    best = None
    for f in fr:
        if (f[4] > 0) == want_payload and f[1].endswith('.20000') and abs(f[0] - t) <= tol_us:
            if best is None or abs(f[0] - t) < abs(best[0] - t):
                best = f
    return best


def trial_rows(trial):
    ex = json.loads((trial / 'timing.json').read_text())['exchanges']
    snaps = sorted((trial / 'snapshots').glob('*_after.json'))
    diag = json.loads(snaps[0].read_text()).get('egress_diag') if snaps else None
    entries = {int(k): v for k, v in ((diag or {}).get('entries') or {}).items()}
    rx = frames(trial / 'in.pcap')
    rows = []
    for i, e in enumerate(ex):
        if e.get('clrt_us') is None or e.get('ack_lat_us') is None:
            continue
        ack_frame = nearest(rx, e['t_req'] + e['ack_lat_us'], False)
        rsp_frame = nearest(rx, e['t_req'] + e['rt_us'], True) if e.get('rt_us') is not None else None
        ackv = ack_frame[3] if ack_frame else None
        entry = entries.get(ackv & 0x3fff) if ackv is not None and diag is not None else None
        switch_clrt = ((entry[1] - entry[0]) & 0xffffffff) / 1000.0 if entry and entry[0] and entry[1] else None
        rows.append(dict(index=i, kind=e['kind'], clrt_us=e['clrt_us'], ack_lat_us=e['ack_lat_us'], rt_us=e.get('rt_us'),
                         ack=ackv, response_ack=rsp_frame[3] if rsp_frame else None, diag_present=diag is not None,
                         switch_clrt_us=switch_clrt))
    return rows


def classify(rows):
    med = {}
    for kind in {r['kind'] for r in rows}:
        rs = [r for r in rows if r['kind'] == kind]
        med[kind] = dict(ack=statistics.median(r['ack_lat_us'] for r in rs), rt=statistics.median(r['rt_us'] for r in rs
                                                                                                  if r['rt_us']))
    tails = []
    for r in rows:
        if abs(r['clrt_us'] - GAP_US) <= TOL_US:
            continue
        m = med[r['kind']]
        sig = r['ack_lat_us'] - m['ack'] > 500 and r['rt_us'] is not None and abs(r['rt_us'] - m['rt']) <= 300
        if not r['diag_present']:
            where = 'no instrument (control)'
        elif r['switch_clrt_us'] is None:
            where = 'unmatched'
        elif abs(r['switch_clrt_us'] - GAP_US) <= TOL_US:
            where = 'downstream of the egress parser'
        else:
            where = 'at or before the egress parser'
        tails.append(dict(r, signature=sig, kind_median_ack_us=m['ack'], kind_median_rt_us=m['rt'], localized=where))
    return med, tails


def p99(values):
    v = sorted(values)
    return v[max(0, -(-len(v) * 99 // 100) - 1)] if v else None


def analyse(run):
    run = Path(run)
    out = dict(run=run.name, trials=[])
    for trial in sorted(run.glob('*/*/*_t*')):
        if not (trial / 'timing.json').is_file():
            continue
        rows = trial_rows(trial)
        arm = trial.parent.name
        med, tails = classify(rows)
        if arm not in ('timing_only', 'combined'):          # untimed arms have no 950 us target: no tails
            tails = []
        per_kind = {}
        for kind in sorted({r['kind'] for r in rows}):
            rs = [r for r in rows if r['kind'] == kind]
            per_kind[kind] = dict(n=len(rs), median_clrt_us=statistics.median(r['clrt_us'] for r in rs),
                                  p99_abs_error_us=p99([abs(r['clrt_us'] - GAP_US) for r in rs]),
                                  tails=sum(1 for t in tails if t['kind'] == kind))
        matched = [r for r in rows if r['switch_clrt_us'] is not None]
        corr = [r['clrt_us'] - r['switch_clrt_us'] for r in matched]
        out['trials'].append(dict(
            trial=trial.name, arm=arm, timed=arm in ('timing_only', 'combined'), per_kind=per_kind, tails=tails,
            instrumented=any(r['diag_present'] for r in rows), matched=len(matched), exchanges=len(rows),
            host_minus_switch_clrt_us=dict(median=statistics.median(corr), p99=p99([abs(c) for c in corr]),
                                           max=max(corr, key=abs)) if corr else None))
    return out


def markdown(results):
    lines = ['| run | arm | kind | n | median CLRT us | p99 abs error us | tails | matched | host-switch CLRT median/p99 us |',
             '|---|---|---|---:|---:|---:|---:|---:|---|']
    for r in results:
        for t in r['trials']:
            if not t['timed']:
                continue
            c = t['host_minus_switch_clrt_us']
            for kind, k in t['per_kind'].items():
                lines.append('| %s | %s | %s | %d | %.0f | %s | %d | %s | %s |' % (
                    r['run'], t['arm'], kind, k['n'], k['median_clrt_us'], k['p99_abs_error_us'], k['tails'],
                    '%d/%d' % (t['matched'], t['exchanges']) if t['instrumented'] else '-',
                    '%.1f / %.1f' % (c['median'], c['p99']) if c else '-'))
    lines += ['', '| run | arm | exchange | kind | CLRT us | ACK lat us | RT us | signature | switch CLRT us | localized |',
              '|---|---|---:|---|---:|---:|---:|---|---:|---|']
    for r in results:
        for t in r['trials']:
            for x in t['tails']:
                lines.append('| %s | %s | %d | %s | %.0f | %d | %s | %s | %s | %s |' % (
                    r['run'], t['arm'], x['index'], x['kind'], x['clrt_us'], x['ack_lat_us'], x['rt_us'], x['signature'],
                    '%.1f' % x['switch_clrt_us'] if x['switch_clrt_us'] is not None else '-', x['localized']))
    return '\n'.join(lines) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('runs', nargs='+')
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--md')
    a = ap.parse_args(argv)
    results = [analyse(r) for r in a.runs]
    Path(a.output).write_text(json.dumps(results, indent=1) + '\n')
    if a.md:
        Path(a.md).write_text(markdown(results))
    for r in results:
        for t in r['trials']:
            if t['timed']:
                print(r['run'], t['arm'], {k: (round(v['median_clrt_us']), v['p99_abs_error_us'], v['tails'])
                                          for k, v in t['per_kind'].items()}, 'matched', t['matched'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
