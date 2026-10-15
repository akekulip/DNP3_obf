#!/usr/bin/env python3
"""Per-cycle records and control timing for repeated-SBO silicon blocks (Gate 2).

  python3 repeat_sbo_report.py RUN_DIR [RUN_DIR ...] -o repeat_sbo_summary.json

For every trial (one connection: READ, then N x (SELECT, OPERATE, READ)) it joins, cycle by cycle:
  wire        timing.json exchanges in request order: application sequence, attempts (a wire-level duplicate shows
              as attempts > 1), ACK latency, CLRT, request-to-response; and from in.pcap every control response's
              reassembled application fragment, whose CROB on-time must be 100 + cycle and status 0
  master      the endpoint's per-cycle record (on-time, callbacks, issued/completed, status, following READ)
  outstation  the append-only callback events (one SELECT then one OPERATE per cycle, on-time, ns)
and fails a trial on any mismatch: order, sequence continuity mod 16, duplicates, echo, callback count, status,
timestamps out of order. Timing is pooled per arm with nearest-rank percentiles (eval_summary conventions).
Retained captures are read only.
"""
import argparse
import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[5]
sys.path.insert(0, str(ARCH / 'integration/evidence/rearm_01'))
sys.path.insert(0, str(ARCH / 'protocol/hw_vepa'))
sys.path.insert(0, str(HERE.parents[1] / 'read_reencode_01'))
import capture  # noqa: E402
import dnp3_std as std  # noqa: E402
import eval_summary as es  # noqa: E402

OUTSTATION_PORT = 20000


def last_json(path):
    lines = [line for line in Path(path).read_text().splitlines() if line.startswith('{')]
    return json.loads(lines[-1]) if lines else {}


def dist(values):
    values = [v for v in values if isinstance(v, (int, float))]
    if not values:
        return None
    return {'n': len(values), 'min': min(values), 'p50': statistics.median(values), 'p95': es.pct(values, 0.95),
            'p99': es.pct(values, 0.99), 'max': max(values), 'mean': round(statistics.mean(values), 2),
            'sd': es.sd_sample(values)}


def wire_controls(in_pcap, master_port):
    """CROB (on_time_ms, status) of every control response the master received, in stream order."""
    streams = capture.streams(in_pcap, include_incarnation=True, require_handshake=True)
    rsp = [v for k, v in streams.items() if k[0][1] == OUTSTATION_PORT and k[1][1] == master_port]
    if len(rsp) != 1:
        raise ValueError('expected one response stream, found %d' % len(rsp))
    out = []
    for app, _lens, _seq in std.reassemble(capture.frames(rsp[0]))[0]:
        # app: application control, function, IIN(2), then G12V1 q0x28 count(2) index(2) and the 11-octet CROB
        if app[1] == 0x81 and app[4:7] == b'\x0c\x01\x28':
            obj = app[11:22]
            out.append({'app_seq': app[0] & 0x0F, 'on_time_ms': int.from_bytes(obj[2:6], 'little'),
                        'off_time_ms': int.from_bytes(obj[6:10], 'little'), 'status': obj[10]})
    return out


def request_transit_us(d, master_port):
    """Per function code, master TX (out.pcap) to outstation RX (in.pcap) of each request, in microseconds. Both taps
    are Vision's switch-facing port, so this is the switch's hold of the request: the OPERATE command hold J
    (independent of CLRT) and the unheld READ/SELECT transit."""
    def requests(path):
        out = {}
        for r in capture.tcp_records(path):
            p = r['payload']
            if r['src'][1] == master_port and r['dst'][1] == OUTSTATION_PORT and len(p) >= 13 and p[:2] == b'\x05\x64':
                out.setdefault((r['seq'], p[12]), []).append(r['time'])
        return out
    sent, arrived = requests(d / 'out.pcap'), requests(d / 'in.pcap')
    transit = {}
    for key, times in sent.items():
        if key in arrived:
            transit.setdefault(key[1], []).append(round((min(arrived[key]) - min(times)) * 1e6, 1))
    return transit


def trial_cycles(d, gap_us):
    master = last_json(d / 'master.json')
    outstation = last_json(d / 'outstation.json')
    result = json.load(open(d / 'result.json'))
    ex = sorted(json.load(open(d / 'timing.json'))['exchanges'], key=lambda e: e['t_req'])
    cycles_n = master.get('sbo_cycles') or 0
    failures, rows = [], []
    kinds = [e['kind'] for e in ex]
    want = ['READ'] * (len(ex) - 3 * cycles_n) + ['SELECT', 'OPERATE', 'READ'] * cycles_n
    if kinds != want:
        failures.append('exchange order differs from READ.. then (SELECT, OPERATE, READ) x %d' % cycles_n)
    seqs = [e['app_seq'] for e in ex]
    if any((b - a) % 16 != 1 for a, b in zip(seqs, seqs[1:])):
        failures.append('application sequence not continuous mod 16')
    try:
        echoes = wire_controls(d / 'in.pcap', result['master_port'])
    except (OSError, ValueError, KeyError) as error:
        echoes, failures = [], failures + ['wire echo unreadable: %s' % error]
    events = outstation.get('events') or []
    lead = len(ex) - 3 * cycles_n
    for c in range(cycles_n):
        sel, op, rd = (ex[lead + 3 * c + i] if lead + 3 * c + i < len(ex) else {} for i in range(3))
        mc = (master.get('cycles') or [{}] * cycles_n)[c] if c < len(master.get('cycles') or []) else {}
        es_, eo = (events[2 * c] if 2 * c < len(events) else {}), (events[2 * c + 1] if 2 * c + 1 < len(events) else {})
        we = echoes[2 * c:2 * c + 2]
        row = {'cycle': c, 'on_time_ms': 100 + c,
               'select': {k: sel.get(k) for k in ('app_seq', 'attempts', 'ack_lat_us', 'clrt_us', 'rt_us', 'resp_len', 'piggyback')},
               'operate': {k: op.get(k) for k in ('app_seq', 'attempts', 'ack_lat_us', 'clrt_us', 'rt_us', 'resp_len', 'piggyback')},
               'read': {k: rd.get(k) for k in ('app_seq', 'attempts', 'clrt_us', 'resp_len')},
               'wire_echo': we, 'master': mc, 'outstation': [es_, eo],
               'sbo_completion_us': (op['t_req'] + op['rt_us'] - sel['t_req'])
               if isinstance(op.get('rt_us'), (int, float)) and sel.get('t_req') is not None else None}
        problems = []
        for name, e in (('SELECT', sel), ('OPERATE', op), ('READ', rd)):
            if e.get('attempts') != 1 or not e.get('complete'):
                problems.append('%s attempts=%r complete=%r' % (name, e.get('attempts'), e.get('complete')))
        if [w.get('on_time_ms') for w in we] != [100 + c, 100 + c] or any(w.get('status') != 0 for w in we):
            problems.append('wire echo %r' % we)
        if [w.get('app_seq') for w in we] != [sel.get('app_seq'), op.get('app_seq')]:
            problems.append('wire echo sequence %r vs requests %r' % ([w.get('app_seq') for w in we],
                                                                      [sel.get('app_seq'), op.get('app_seq')]))
        if (mc.get('on_time_ms'), mc.get('callbacks'), mc.get('ok'), mc.get('status'), mc.get('read_matches_seed')) != \
                (100 + c, 1, True, 0, True):
            problems.append('master record %r' % {k: mc.get(k) for k in ('on_time_ms', 'callbacks', 'ok', 'status')})
        if not (isinstance(mc.get('issued_ns'), int) and isinstance(mc.get('completed_ns'), int)
                and mc['issued_ns'] < mc['completed_ns']):
            problems.append('master timestamps out of order')
        if (es_.get('kind'), eo.get('kind'), es_.get('on_time_ms'), eo.get('on_time_ms'), es_.get('status'),
                eo.get('status'), es_.get('index'), eo.get('index')) != ('SELECT', 'OPERATE', 100 + c, 100 + c, 0, 0, 1, 1):
            problems.append('outstation callbacks %r %r' % (es_, eo))
        elif not es_.get('ns', 0) < eo.get('ns', 0):
            problems.append('outstation OPERATE callback not after its SELECT')
        if c and isinstance(mc.get('issued_ns'), int) and rows and \
                isinstance(rows[-1]['master'].get('completed_ns'), int) and mc['issued_ns'] < rows[-1]['master']['completed_ns']:
            problems.append('cycle issued before the previous cycle completed')
        row['ok'] = not problems
        row['problems'] = problems
        failures += ['cycle %d: %s' % (c, p) for p in problems]
        rows.append(row)
    if len(events) != 2 * cycles_n:
        failures.append('outstation reported %d callbacks for %d cycles' % (len(events), cycles_n))
    if len(echoes) != 2 * cycles_n:
        failures.append('wire carried %d control responses for %d cycles' % (len(echoes), cycles_n))
    reads = [e for e in ex if e['kind'] == 'READ' and e.get('complete') and e.get('attempts') == 1 and not e.get('piggyback')]
    try:
        transit = request_transit_us(d, result['master_port'])
    except (OSError, ValueError, KeyError) as error:
        transit, failures = {}, failures + ['request transit unreadable: %s' % error]
    return {'cycles': cycles_n, 'rows': rows, 'failures': failures, 'ok': not failures,
            'read_error_us': [e['clrt_us'] - gap_us for e in reads if isinstance(e.get('clrt_us'), (int, float))],
            'read_rt_us': [e['rt_us'] for e in ex if e['kind'] == 'READ' and e.get('complete') and e.get('attempts') == 1
                           and isinstance(e.get('rt_us'), (int, float))],
            'transit_us': {name: transit.get(fc, []) for name, fc in (('read', 1), ('select', 3), ('operate', 4))},
            'resp_lens': sorted({(e['kind'], e['resp_len']) for e in ex if e.get('resp_len')})}


def report(roots):
    out = {'runs': [], 'arms': {}}
    for root in roots:
        rec = json.load(open(Path(root) / 'campaign_run.json'))
        gap_us = rec['effective']['timing_params_ns']['gap'] / 1000.0
        for arm in rec['arms']:
            for tr in arm['trials']:
                d = Path(root) / arm['fixture'] / arm['arm'] / tr['label']
                t = trial_cycles(d, gap_us if arm.get('T') else 0.0)
                out['runs'].append({'run': Path(root).name, 'arm': arm['arm'], 'label': tr['label'], 'trial_ok': tr.get('ok'),
                                    'cycles': t['cycles'], 'cycles_ok': sum(r['ok'] for r in t['rows']),
                                    'failures': t['failures'][:6], 'resp_lens': t['resp_lens'], 'rows': t['rows']})
                agg = out['arms'].setdefault(arm['arm'], {'blocks': 0, 'cycles': 0, 'cycles_ok': 0, 'timed': bool(arm.get('T')),
                                                          'values': {}})
                agg['blocks'] += 1
                agg['cycles'] += t['cycles']
                agg['cycles_ok'] += sum(r['ok'] for r in t['rows'])
                v = agg['values']
                for r in t['rows']:
                    for kind in ('select', 'operate'):
                        for metric in ('ack_lat_us', 'clrt_us', 'rt_us'):
                            v.setdefault('%s_%s' % (kind, metric), []).append(r[kind].get(metric))
                    v.setdefault('sbo_completion_us', []).append(r['sbo_completion_us'])
                v.setdefault('read_error_us' if arm.get('T') else 'read_clrt_us', []).extend(t['read_error_us'])
                v.setdefault('read_rt_us', []).extend(t['read_rt_us'])
                for name, values in t['transit_us'].items():
                    v.setdefault('%s_request_transit_us' % name, []).extend(values)
                gap = gap_us if arm.get('T') else 0.0
                for r in t['rows']:                                   # CLRT minus the configured gap, timed arms
                    for kind in ('select', 'operate'):
                        if isinstance(r[kind].get('clrt_us'), (int, float)) and arm.get('T') and not r[kind].get('piggyback'):
                            v.setdefault('%s_clrt_error_us' % kind, []).append(r[kind]['clrt_us'] - gap)
                            v.setdefault('%s_abs_clrt_error_us' % kind, []).append(abs(r[kind]['clrt_us'] - gap))
    for agg in out['arms'].values():
        agg['timing'] = {k: dist(vals) for k, vals in agg.pop('values').items()}
    out['ok'] = all(r['failures'] == [] for r in out['runs'])
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('runs', nargs='+')
    ap.add_argument('-o', '--output', required=True)
    a = ap.parse_args(argv)
    out = report([Path(r) for r in a.runs])
    Path(a.output).write_text(json.dumps(out, indent=1, default=str) + '\n')
    for arm, agg in out['arms'].items():
        t = agg['timing']
        print('%-12s blocks=%d cycles=%d ok=%d  SELECT clrt p50=%s  OPERATE clrt p50=%s  OPERATE req->ack p50=%s  '
              'OPERATE hold min=%s' % (
            arm, agg['blocks'], agg['cycles'], agg['cycles_ok'], (t.get('select_clrt_us') or {}).get('p50'),
            (t.get('operate_clrt_us') or {}).get('p50'), (t.get('operate_ack_lat_us') or {}).get('p50'),
            (t.get('operate_request_transit_us') or {}).get('min')))
    print('all cycles ok:', out['ok'])
    return 0 if out['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
