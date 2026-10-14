#!/usr/bin/env python3
"""Tables from a campaign run directory.

  report.py RUN_DIR            (also: campaign.py report --run-dir RUN_DIR)

RUN_DIR holds campaign_run.json and <fixture>/<arm>/<label>/ with snapshots/<label>_before.json and _after.json,
timing.json (clrt_check) and wire.json (wire_check). One table per (fixture, arm, preset), one column per trial.
Every delta is after minus before, the convention of evidence/mirror_fix_silicon_01 (sna minus snb):

  loop packets / bytes   sum over the four loop ports (48/180/181/182) of the $FramesTransmittedAll and
                         $OctetsTransmittedTotal deltas, plus each port's own
  orig re-waits          OUT_HELD_REWAIT delta;  blocker laps: the diag blocker_laps deltas, if the build has them
  CLRT / req->ACK / req->resp   READ exchanges, microseconds at the host capture point; SD both population and sample
  gap error              CLRT minus the intended gap (timing_params_ns.gap of the run, in microseconds)
  bad octets             delta of ($OctetsReceived - $OctetsReceivedinGoodFrames) summed over the four loop ports
Anything a trial's files do not contain is shown as '-'. Paired blocks add A-B per condition (A = the first preset
of the first pair). Stdlib only.
"""
import json
import os
import sys

import checks

LOOP_ROLES = ('n_ack_return', 't_in', 'hb_return', 'held_return')
PORT_OF = {'n_ack_return': 48, 't_in': 180, 'hb_return': 181, 'held_return': 182}


def _json(path):
    try:
        return json.load(open(path))
    except (OSError, ValueError):
        return None


def _delta(a, b, getter):
    try:
        return getter(a) - getter(b)
    except (KeyError, TypeError):
        return None


def trial_metrics(root, fixture, arm, trial, gap_ns):
    label = trial['label']
    d = os.path.join(root, fixture, arm, label)
    b = _json(os.path.join(d, 'snapshots', '%s_before.json' % label))
    a = _json(os.path.join(d, 'snapshots', '%s_after.json' % label))
    t = _json(os.path.join(d, 'timing.json'))
    w = _json(os.path.join(d, 'wire.json'))
    m = {'label': label, 'fixture': fixture, 'arm': arm, 'preset': trial.get('preset')}
    m['per_port'] = {}
    pk = by = bad = 0
    ok_loop = bool(a and b)
    for role in LOOP_ROLES:
        f = _delta(a, b, lambda s: s['loop_ports'][role]['$FramesTransmittedAll']) if ok_loop else None
        o = _delta(a, b, lambda s: s['loop_ports'][role]['$OctetsTransmittedTotal']) if ok_loop else None
        g = _delta(a, b, lambda s: s['loop_ports'][role]['$OctetsReceived'] - s['loop_ports'][role]['$OctetsReceivedinGoodFrames']) if ok_loop else None
        m['per_port'][role] = {'pkts': f, 'bytes': o}
        if f is None or o is None:
            ok_loop = False
        else:
            pk, by = pk + f, by + o
        bad = bad + g if (g is not None and bad is not None) else None
    m['loop_pkts'], m['loop_bytes'] = (pk, by) if ok_loop else (None, None)
    m['bad_octets'] = bad if ok_loop else None
    m['rewaits'] = _delta(a, b, lambda s: s['outcomes']['OUT_HELD_REWAIT']) if a and b else None
    try:
        m['stale'], m['stale_sources'] = checks.stale_delta(b, a, trial.get('diagnostic', False)) if a and b else (None, None)
    except ValueError:
        m['stale'], m['stale_sources'] = None, None
    blk = None
    if a and b and a.get('diag', {}).get('present') and b.get('diag', {}).get('present'):
        blk = sum(a['diag']['blocker_laps'][r] - b['diag']['blocker_laps'][r] for r in a['diag']['blocker_laps'])
    m['blocker_laps'] = blk
    m['read_triggers'] = _delta(a, b, lambda s: s['pktgen']['READ']['trigger_counter']) if a and b else None
    m['read_pkts'] = _delta(a, b, lambda s: s['pktgen']['READ']['pkt_counter']) if a and b else None
    rd = (t or {}).get('summary', {}).get('READ')
    m['clrt'] = rd and rd.get('clrt_us')
    m['ack'] = rd and rd.get('ack_lat_us')
    m['rt'] = rd and rd.get('rt_us')
    m['read_precision'] = checks.read_precision(t, gap_ns) if t and gap_ns is not None else None
    if m['read_precision']:
        m['read_precision']['gated'] = trial.get('observed', {}).get('read_precision', {}).get('gated')
    m['gap_us'] = gap_ns / 1000.0 if gap_ns else None
    m['gap_us'] = int(m['gap_us']) if m['gap_us'] is not None and m['gap_us'] == int(m['gap_us']) else m['gap_us']
    for key, stat in (('gap_error_median_us', 'median'), ('gap_error_p95_us', 'p95')):
        m[key] = (m['clrt'][stat] - m['gap_us']) if m['clrt'] and m['gap_us'] is not None else None
    for k, src in (('logical', 'logical_requests'), ('complete', 'complete'), ('incomplete', 'incomplete'),
                   ('retransmitted', 'retransmitted'), ('piggyback', 'piggyback')):
        m[k] = rd[src] if rd else None
    m['duplicate_returned'] = len(w['duplicate_returned']) if w and 'duplicate_returned' in w else None
    m['unmatched_returned'] = len(w['unmatched_returned']) if w and 'unmatched_returned' in w else None
    exs = [e for e in (t or {}).get('exchanges', []) if e.get('resp_len')]
    reads = [e for e in exs if e.get('kind') == 'READ']
    native = {'READ': 49, 'SELECT': 37, 'OPERATE': 37}
    padded = [e for e in exs if e['resp_len'] > native.get(e['kind'], e['resp_len'])]
    m['padding_coverage'] = round(len([e for e in reads if e['resp_len'] > 49]) / len(reads), 4) if reads else None
    m['growth_bytes'] = ((trial.get('observed') or {}).get('growth_bytes'))
    if m['growth_bytes'] is None and exs:
        native = {'READ': 49, 'SELECT': 37, 'OPERATE': 37}
        m['growth_bytes'] = sum(e['resp_len'] - native.get(e['kind'], e['resp_len']) for e in exs)
    m['padded_responses'] = len(padded) if exs else None
    return m


def load(root):
    """[metrics dict] for every trial of campaign_run.json, in run order."""
    rec = _json(os.path.join(root, 'campaign_run.json'))
    if rec is None:
        raise SystemExit('%s has no readable campaign_run.json' % root)
    gap = (rec.get('effective') or {}).get('timing_params_ns', {}).get('gap')
    out = []
    for arm in rec['arms']:
        for tr in arm['trials']:
            if tr.get('loss') or tr.get('scenario'):          # reported in their own tables, not mixed into the metrics
                continue
            out.append(trial_metrics(root, arm['fixture'], arm['arm'], tr, gap))
    return out


def _f(v, nd=1):
    if v is None:
        return '-'
    if isinstance(v, float) and v != int(v):
        return ('%.' + str(nd) + 'f') % v
    return '{:,}'.format(int(v))


def _stat(m, key, stat):
    return m[key][stat] if m.get(key) else None


def _precision(metric, *keys):
    value = metric.get('read_precision')
    for key in keys:
        value = value.get(key) if isinstance(value, dict) else None
    return value


ROWS = [
    ('eligible READs', lambda m: _precision(m, 'eligible')),
    ('excluded incomplete', lambda m: _precision(m, 'excluded', 'incomplete')),
    ('excluded piggyback', lambda m: _precision(m, 'excluded', 'piggyback')),
    ('excluded multiple attempts', lambda m: _precision(m, 'excluded', 'multiple_attempts')),
    ('excluded missing CLRT', lambda m: _precision(m, 'excluded', 'missing_clrt')),
    ('p99 absolute error (us)', lambda m: _precision(m, 'absolute_error_us', 'p99')),
    ('loop packets', lambda m: m['loop_pkts']), ('loop bytes', lambda m: m['loop_bytes']),
    ] + [('port %d pkts/bytes' % PORT_OF[r], (lambda r: lambda m: '%s/%s' % (_f(m['per_port'][r]['pkts']),
                                                                          _f(m['per_port'][r]['bytes'])))(r))
         for r in LOOP_ROLES] + [
    ('orig re-waits', lambda m: m['rewaits']), ('blocker laps', lambda m: m['blocker_laps']),
    ('CLRT median (us)', lambda m: _stat(m, 'clrt', 'median')), ('CLRT IQR', lambda m: _stat(m, 'clrt', 'iqr')),
    ('CLRT p95', lambda m: _stat(m, 'clrt', 'p95')), ('CLRT p99', lambda m: _stat(m, 'clrt', 'p99')),
    ('CLRT SD (population)', lambda m: _stat(m, 'clrt', 'sd_population')),
    ('CLRT SD (sample)', lambda m: _stat(m, 'clrt', 'sd_sample')),
    ('req->ACK median', lambda m: _stat(m, 'ack', 'median')), ('req->ACK p95', lambda m: _stat(m, 'ack', 'p95')),
    ('req->resp median', lambda m: _stat(m, 'rt', 'median')), ('req->resp p95', lambda m: _stat(m, 'rt', 'p95')),
    ('intended gap (us)', lambda m: m['gap_us']),
    ('gap error median', lambda m: m['gap_error_median_us']), ('gap error p95', lambda m: m['gap_error_p95_us']),
    ('READs complete', lambda m: '%s/%s' % (_f(m['complete']), _f(m['logical']))),
    ('incomplete', lambda m: m['incomplete']), ('retransmitted', lambda m: m['retransmitted']),
    ('piggybacked', lambda m: m['piggyback']), ('duplicate returned', lambda m: m['duplicate_returned']),
    ('unmatched returned', lambda m: m['unmatched_returned']),
    ('padding coverage', lambda m: m['padding_coverage']), ('growth bytes', lambda m: m['growth_bytes']),
    ('READ triggers', lambda m: m['read_triggers']), ('READ gen pkts', lambda m: m['read_pkts']),
    ('stale tokens', lambda m: m['stale']), ('bad octets', lambda m: m['bad_octets']),
]
DIFFS = [('loop packets', lambda m: m['loop_pkts']), ('loop bytes', lambda m: m['loop_bytes']),
         ('orig re-waits', lambda m: m['rewaits']), ('blocker laps', lambda m: m['blocker_laps']),
         ('CLRT median', lambda m: _stat(m, 'clrt', 'median')),
         ('CLRT SD (population)', lambda m: _stat(m, 'clrt', 'sd_population')),
         ('req->resp median', lambda m: _stat(m, 'rt', 'median')),
         ('gap error median', lambda m: m['gap_error_median_us'])]


def _table(title, ms):
    cols = ['t%d' % i for i in range(len(ms))]
    lines = ['== %s ==' % title]
    w0 = max(len(r[0]) for r in ROWS)
    cells = {r[0]: [_f(r[1](m)) if not isinstance(r[1](m), str) else r[1](m) for m in ms] for r in ROWS}
    wc = [max([len(cols[i])] + [len(cells[k][i]) for k in cells]) for i in range(len(ms))]
    lines.append('%-*s  %s' % (w0, '', '  '.join('%*s' % (wc[i], cols[i]) for i in range(len(ms)))))
    for name, _ in ROWS:
        lines.append('%-*s  %s' % (w0, name, '  '.join('%*s' % (wc[i], cells[name][i]) for i in range(len(ms)))))
    lines.append('trials: ' + ', '.join('%s=%s' % (c, m['label']) for c, m in zip(cols, ms)))
    return lines


def _g(v, fmt='%s'):
    return '-' if v is None else fmt % v


def _table_rows(title, header, rows):
    w = [max(len(str(x)) for x in col) for col in zip(header, *rows)] if rows else [len(h) for h in header]
    line = lambda r: '  '.join('%-*s' % (w[i], r[i]) for i in range(len(header)))
    return ['== %s ==' % title, line(header)] + [line(r) for r in rows]


def loss_rows(rec):
    rows = []
    for arm in rec['arms']:
        for tr in arm['trials']:
            l = tr.get('loss')
            if not l:
                continue
            p = l.get('packet') or {}
            rows.append((tr['label'], '%s:%s' % (l['class'], l['n']),
                         '%s/%s' % (_g(p.get('seq')), _g(p.get('len'))) if p else '-',
                         'yes' if l.get('completed') else 'NO', _g(l.get('recovery_s')), _g(l.get('first_retx_delay_ms')),
                         _g(l.get('retransmissions')), 'yes' if l.get('exactly_once') else 'NO',
                         '%s/%s' % (_g(l.get('growth_bytes')), _g(l.get('expected_growth_bytes'))),
                         _g(l.get('completion_delta_s')), 'ok' if tr.get('ok') else 'FAIL'))
    return rows


def reconnect_rows(rec):
    rows = []
    for arm in rec['arms']:
        for tr in arm['trials']:
            sc = tr.get('scenario')
            if not sc:
                continue
            for cn in ('c1', 'c2', 'c3'):
                c = sc['connections'].get(cn)
                if not c:
                    rows.append((cn, tr['label'], '-', '-', 'not run', '-', '-', '-', '-', '-'))
                    continue
                rows.append((cn, tr['label'], '%s/%s' % (_g(c.get('role')), _g(c.get('master_port'))),
                             'ok' if c.get('connect_ok') else 'FAILED', 'yes' if c.get('completed') else 'NO',
                             ','.join(str(x) for x in c.get('resp_lens', [])) or '-',
                             'yes' if c.get('padded') else 'no', _g(c.get('retransmitted')),
                             'yes' if c.get('master_timeout') else 'no', ''))
    return rows


def render(root):
    metrics = load(root)
    rec = json.load(open(os.path.join(root, 'campaign_run.json')))
    groups = []
    for m in metrics:
        key = (m['fixture'], m['arm'], m['preset'])
        for g in groups:
            if g[0] == key:
                g[1].append(m)
                break
        else:
            groups.append((key, [m]))
    effective = rec.get('effective', {})
    out = ['config sha256: %s; file sha256: %s' % (rec.get('config_sha256', '-'), rec.get('config_file_sha256', '-')),
           'policy: reconnect=%s; max_token_stale=%s; evaluation=%s' %
           (effective.get('reconnect_policy', 'unrecorded'), effective.get('max_token_stale', 'unrecorded'), effective.get('evaluation', 'unrecorded'))]
    for (fx, arm, preset), ms in groups:
        out += _table('fixture %s | arm %s | preset %s' % (fx, arm, preset or '(config default)'), ms) + ['']
        for metric in ms:
            precision = metric['read_precision']
            if precision:
                out.append('%s READ precision: eligible%d/%d, exclusions%s, gated=%s, qualifies=%s; worst tails%s' %
                           (metric['label'], precision['eligible'], precision['read_rows'], precision['excluded'],
                            precision.get('gated'), precision['pass'], precision['tails']))
            if metric['stale_sources'] is not None:
                out.append('%s stale-source deltas19..24: %s (sum%s)' %
                           (metric['label'], metric['stale_sources'], metric['stale']))
    pairs = rec.get('pairs') or []
    if pairs:
        by_label = {m['label']: m for m in metrics}
        a_name = pairs[0]['order'][0]
        out.append('== paired blocks: A=%s, B=%s (differences A-B) ==' % (a_name, pairs[0]['order'][1]))
        for p in pairs:
            ms = [by_label.get(l) for l in p['labels']]
            if any(m is None for m in ms):
                out.append('pair %d: missing trials' % p['pair'])
                continue
            A = next(m for m in ms if m['preset'] == a_name)
            B = next(m for m in ms if m['preset'] != a_name)
            c = p['condition']
            out.append('pair %d  delay_ms=%s gap_ms=%s start_delay_ms=%s seed=%s  order=%s  ok=%s' % (
                p['pair'], c['delay_ms'], c['gap_ms'], c['start_delay_ms'], c['seed'], '>'.join(p['order']), p['ok']))
            for name, fn in DIFFS:
                va, vb = fn(A), fn(B)
                diff = None if va is None or vb is None else va - vb
                if isinstance(diff, float):
                    diff = round(diff, 1)
                out.append('  A-B %-22s %s   (A %s, B %s)' % (name, _f(diff) if diff is not None else '-',
                                                              _f(va), _f(vb)))
        out.append('')
    lr = loss_rows(rec)
    if lr:
        out += _table_rows('loss trials', ('trial', 'class:n', 'packet seq/len', 'completed', 'recovery s', 'first retx ms',
                                           'retransmissions', 'exactly-once', 'growth/expected', 'completion delta s',
                                           'ok'), lr) + ['']
    rr = reconnect_rows(rec)
    if rr:
        out += _table_rows('reconnect scenarios', ('connection', 'trial', 'role/port', 'connect', 'completed', 'resp lens',
                                                   'padded', 'retransmitted', 'timeout', ''), rr) + [
            'legend: c1 = installed port; c2 = new port with no switch rows (expected native); c3 = installed tuple again '
            '(effective reconnect policy above determines whether c3 is gated).', '']
    return '\n'.join(out).rstrip() + '\n'


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        sys.exit('usage: report.py RUN_DIR')
    print(render(argv[0]), end='')
    return 0


if __name__ == '__main__':
    sys.exit(main())
