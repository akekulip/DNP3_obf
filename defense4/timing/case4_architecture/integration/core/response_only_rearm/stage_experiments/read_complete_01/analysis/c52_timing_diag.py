"""Offline master-NIC diagnosis of physical SEL-751 timing failures (Python >= 3.10). Fail-closed on missing input.

  c52_timing_diag.py BLOCK_DIR [BLOCK_DIR ...] --out OUT_DIR

Input per block: campaign_run.json (effective.timing_params_ns) and physical_relay/<arm>/<trial>/, where a trial is
either one connection (in.pcap, out.pcap, master.json, result.json, trial.json) or c1/c2/... connection subdirs
with the trial.json one level up. in.pcap is what the master NIC received, out.pcap what it sent.

The TCP spans, the first master-visible ACK of each request and the complete CLRT come from
the recorded a4ebbecbe relay checker, so this historical diagnosis keeps the campaign's original calculations.
Checksums are not validated (TX captures carry partial checksums under offload).

Everything is observed at ONE point: the master NIC. A delay seen there can sit in the relay, the switch or the
path, and this tool never apportions it. T's t0 (where readiness and da are measured from) is not observed either;
the request->ACK interval it reports is master-observed and includes the unknown forward delay.

Outputs OUT_DIR/diagnosis.json and OUT_DIR/DIAGNOSIS.md; every number in the Markdown is computed here.
Exit 0 on success, 2 when an input is missing or malformed (nothing is written then).
"""
import argparse
import json
import math
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
STAGE = ROOT.parent
sys.path.insert(0, str(HERE))
from historical_checker import load_checker  # noqa: E402

relay_check = load_checker('a4ebbecbe')
wc = relay_check.wc

T_ON = {'off': False, 'size_only': False, 'timing_only': True, 'combined': True}
FUNCTIONS = {1: 'READ', 3: 'SELECT', 4: 'OPERATE'}
OPS = ('READ', 'SELECT', 'OPERATE')
T_LABEL = 'master-observed; T t0 unobserved (forward delay unknown)'
CLRT_BINS_US = (0, 100, 500, 900, 1000, 1500, 2500, 5000, 30000)
CONNECTION_FILES = ('in.pcap', 'out.pcap', 'master.json', 'result.json')
MASK = 0xffffffff


class DiagError(Exception):
    """Missing or malformed input; the CLI reports it and exits nonzero."""


def _load_json(path):
    if not path.is_file():
        raise DiagError('missing %s' % path)
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise DiagError('malformed JSON %s: %s' % (path, error)) from error


def nearest_rank(values, q):
    values = sorted(values)
    return values[max(0, math.ceil(q * len(values)) - 1)] if values else None


def describe(values):
    values = [v for v in values if v is not None]
    if not values:
        return dict(n=0, p50=None, p90=None, p99=None, max=None)
    return dict(n=len(values), p50=nearest_rank(values, .5), p90=nearest_rank(values, .9),
                p99=nearest_rank(values, .99), max=max(values))


def precision_like_relay_check(rows, gap_ns):
    """relay_check.precision on this tool's rows (same eligibility, nearest-rank p99)."""
    pseudo = dict(exchanges=[dict(operation=r['operation'], piggyback=r['piggyback'],
                                  complete_clrt_us=r['clrt_complete_us']) for r in rows])
    return {op: dict(p99_us=v['p99_nearest_rank_abs_error_us'], max_us=v['max_abs_error_us'],
                     eligible=v['eligible'], planned=v['planned'])
            for op, v in relay_check.precision(pseudo, gap_ns).items()}


# --- discovery ---

def block_params(block):
    run = _load_json(block / 'campaign_run.json')
    params = (run.get('effective') or {}).get('timing_params_ns')
    if not params or not all(k in params for k in ('da', 'gap', 'readiness')):
        raise DiagError('%s: campaign_run.json lacks effective.timing_params_ns {da,gap,readiness}' % block)
    return params


def discover(block):
    """[(arm, trial_dir, [(connection_name, connection_dir)])], validated before any analysis."""
    fixture = block / 'physical_relay'
    if not fixture.is_dir():
        raise DiagError('%s: no physical_relay directory' % block)
    trials = []
    for arm_dir in sorted(p for p in fixture.iterdir() if p.is_dir()):
        if arm_dir.name not in T_ON:
            raise DiagError('%s: unknown arm %r (T state unknown)' % (block, arm_dir.name))
        for trial in sorted(p for p in arm_dir.iterdir() if p.is_dir()):
            subs = sorted((p for p in trial.iterdir() if p.is_dir() and re.fullmatch(r'c\d+', p.name)),
                          key=lambda p: int(p.name[1:]))
            connections = [(p.name, p) for p in subs] or [('single', trial)]
            for _, cdir in connections:
                missing = [name for name in CONNECTION_FILES if not (cdir / name).is_file()]
                if missing:
                    raise DiagError('%s: missing %s' % (cdir, ', '.join(missing)))
            if not (trial / 'trial.json').is_file():
                raise DiagError('%s: missing trial.json' % trial)
            trials.append((arm_dir.name, trial, connections))
    if not trials:
        raise DiagError('%s: no trials under physical_relay' % block)
    return trials


# --- per connection ---

def _isn(packets):
    syns = [p for p in packets if p['flags'] & wc.SYN]
    return min(syns, key=lambda p: p['timestamp_ns']) if syns else None


def retransmissions(packets):
    """Data segments that start below the already-sent frontier, in capture-time order: (packet, offset, dup_seq)."""
    syn = _isn(packets)
    if syn is None:
        return []
    isn, frontier, seen, out = syn['seq'], 0, set(), []
    for p in sorted(packets, key=lambda p: (p['timestamp_ns'], p['index'])):
        if not p['payload_len']:
            continue
        offset = (p['seq'] - isn) & MASK
        if offset < frontier:
            out.append((p, offset, p['seq'] in seen))
        seen.add(p['seq'])
        frontier = max(frontier, offset + p['payload_len'])
    return out


def duplicate_acks(packets):
    """Pure ACKs repeating the previous pure ACK's ack number with no new data between them."""
    count, last = 0, None
    for p in sorted(packets, key=lambda p: (p['timestamp_ns'], p['index'])):
        if p['payload_len'] or p['flags'] & (wc.SYN | wc.FIN | wc.RST):
            last = None
            continue
        if p['flags'] & wc.ACK:
            count += p['ack'] == last
            last = p['ack']
    return count


def packet_timeline(report, origin_ns, start_ns, end_ns, isns):
    rows = []
    for direction in ('out', 'in'):
        for p in report['packets'][direction]:
            if start_ns <= p['timestamp_ns'] <= end_ns:
                rows.append(dict(direction='master TX' if direction == 'out' else 'master RX',
                                 t_after_request_us=(p['timestamp_ns'] - origin_ns) / 1000,
                                 flags=p['flags'], payload_len=p['payload_len'],
                                 rel_seq=(p['seq'] - isns[direction]) & MASK if isns[direction] is not None else None,
                                 rel_ack=(p['ack'] - isns['in' if direction == 'out' else 'out']) & MASK
                                 if isns['in' if direction == 'out' else 'out'] is not None else None))
    return sorted(rows, key=lambda r: r['t_after_request_us'])


def analyze_connection(cdir, context, params):
    master = _load_json(cdir / 'master.json')
    records = master.get('records') or []
    if not records or not records[0].get('local_address'):
        raise DiagError('%s: master.json has no records with local_address' % cdir)
    port = records[0]['local_address'][1]
    report = relay_check.analyze(cdir, port)
    exchanges = report.get('exchanges') or []
    if len(exchanges) != len(records):
        raise DiagError('%s: relay_check exchanges (%d) != master records (%d)' % (cdir, len(exchanges), len(records)))
    syn_out, syn_in = _isn(report['packets']['out']), _isn(report['packets']['in'])
    isns = dict(out=syn_out['seq'] if syn_out else None, **{'in': syn_in['seq'] if syn_in else None})
    retx = dict(out=retransmissions(report['packets']['out']), **{'in': retransmissions(report['packets']['in'])})
    gap_us, da_us, ready_us = params['gap'] / 1000, params['da'] / 1000, params['readiness'] / 1000
    rows, attributed, previous = [], dict(out=0, **{'in': 0}), None
    for index, (record, ex) in enumerate(zip(records, exchanges)):
        req, resp = ex['request'], ex['response']
        try:
            fc = bytes.fromhex(record['request_app_hex'])[1]
        except (KeyError, ValueError, IndexError) as error:
            raise DiagError('%s: record %d has no request application bytes' % (cdir, index)) from error
        operation = FUNCTIONS.get(fc, 'FC%d' % fc)
        if operation != record.get('operation'):
            raise DiagError('%s: record %d function code %d disagrees with %r' % (cdir, index, fc,
                                                                                  record.get('operation')))
        row = dict(context, connection_position=index, first_on_connection=index == 0,
                   operation=operation, function_code=fc, workload=record.get('workload'),
                   previous_operation=previous['operation'] if previous else None,
                   span_complete=bool(req and resp), piggyback=ex['piggyback'],
                   clrt_complete_us=ex['complete_clrt_us'], clrt_first_us=ex['first_clrt_us'])
        if req and resp:
            t0 = req['first_timestamp_ns']
            ack = ex['ack_timestamp_ns']
            row.update(request_tx_ns=t0, request_sequence_start=req['sequence_start'],
                       request_tx_after_syn_us=(t0 - syn_out['timestamp_ns']) / 1000 if syn_out else None,
                       idle_before_request_us=((t0 - previous['response_complete_ns']) / 1000
                                               if previous and previous.get('response_complete_ns') else None),
                       ack_rx_after_request_us=(ack - t0) / 1000 if ack else None,
                       response_first_after_request_us=(resp['first_timestamp_ns'] - t0) / 1000,
                       response_complete_after_request_us=(resp['complete_timestamp_ns'] - t0) / 1000,
                       response_complete_ns=resp['complete_timestamp_ns'])
            for direction, span, key in (('out', req, 'request'), ('in', resp, 'response')):
                hits = [(p, off, dup) for p, off, dup in retx[direction]
                        if span['start_offset'] <= off < span['end_offset']]
                attributed[direction] += len(hits)
                row[key + '_retransmissions'] = len(hits)
                row[key + '_duplicate_seq'] = sum(dup for _, _, dup in hits)
                row[key + '_retransmit_after_first_tx_us'] = [(p['timestamp_ns'] - t0) / 1000 for p, _, _ in hits]
        else:
            row.update(request_retransmissions=None, response_retransmissions=None)
        row['clrt_error_us'] = row['clrt_complete_us'] - gap_us if row['clrt_complete_us'] is not None else None
        rta = row.get('ack_rx_after_request_us')
        row['t_interval'] = (dict(request_to_ack_us=rta, minus_da_us=rta - da_us if rta is not None else None,
                                  minus_readiness_us=rta - ready_us if rta is not None else None,
                                  at_or_beyond_readiness=rta is not None and rta >= ready_us, label=T_LABEL)
                             if context['t_on'] else None)
        row['fallback_trial_first_transaction'] = context['trial_fallback'] and index == 0
        row['fallback_signature'] = bool(context['t_on'] and rta is not None and rta >= ready_us)
        retransmitted = bool(row.get('request_retransmissions') or row.get('response_retransmissions'))
        if row['fallback_signature'] or retransmitted:
            end = row['response_complete_ns'] if row.get('response_complete_ns') else t0
            for key in ('request', 'response'):
                end = max([end] + [t0 + int(us * 1000) for us in row.get(key + '_retransmit_after_first_tx_us') or []])
            row['packet_timeline'] = packet_timeline(report, t0, t0, end, isns)
        rows.append(row)
        previous = row
    for row in rows:
        row.pop('response_complete_ns', None)
    summary = dict(connection=context['connection'], transactions=len(rows),
                   relay_check_failures=[f for f in report['failures'] if 'checksum' not in f
                                         and 'denominators not supplied' not in f],
                   retransmissions=dict(master_tx=len(retx['out']), master_rx=len(retx['in']),
                                        unattributed_tx=len(retx['out']) - attributed['out'],
                                        unattributed_rx=len(retx['in']) - attributed['in']),
                   duplicate_acks=dict(master_tx=duplicate_acks(report['packets']['out']),
                                       master_rx=duplicate_acks(report['packets']['in'])))
    return rows, summary


def candidate_of(block_name):
    match = re.search(r'_(c\d+)_', block_name)
    return match.group(1) if match else block_name


def analyze_block(block):
    block = Path(block)
    params = block_params(block)
    trials = discover(block)
    out = dict(block=block.name, candidate=candidate_of(block.name), timing_params_ns=params,
               trials=[], transactions=[])
    for arm, trial_dir, connections in trials:
        trial = _load_json(trial_dir / 'trial.json')
        outcomes = ((trial.get('observed') or {}).get('switch') or {}).get('outcomes') or {}
        ack_fb, resp_fb = outcomes.get('OUT_ACK_FALLBACK', 0), outcomes.get('OUT_RESP_FALLBACK', 0)
        tinfo = dict(arm=arm, trial=trial_dir.name, t_on=T_ON[arm], out_ack_fallback=ack_fb,
                     out_resp_fallback=resp_fb, switch_outcomes_present=bool(outcomes),
                     retained_ok=trial.get('ok'), connections=[])
        for name, cdir in connections:
            context = dict(block=block.name, candidate=out['candidate'], arm=arm, trial=trial_dir.name,
                           connection=name, t_on=T_ON[arm], trial_ack_fallback=ack_fb, trial_resp_fallback=resp_fb,
                           trial_fallback=bool(ack_fb or resp_fb))
            rows, summary = analyze_connection(cdir, context, params)
            tinfo['connections'].append(summary)
            out['transactions'].extend(rows)
        trows = [r for r in out['transactions'] if r['trial'] == trial_dir.name]
        tinfo['fallback_signature_transactions'] = sum(r['fallback_signature'] for r in trows)
        tinfo['precision'] = {c['connection']: precision_like_relay_check(
            [r for r in trows if r['connection'] == c['connection']], params['gap']) for c in tinfo['connections']}
        out['trials'].append(tinfo)
    return out


# --- summaries ---

def params_key(params):
    return 'gap%dus_ready%dms' % (params['gap'] // 1000, params['readiness'] // 1000000)


def clean(rows):
    """Rows eligible for the zero-fallback distributions: complete span, CLRT present, no piggyback, no
    retransmission either way, in a trial whose switch counters show no fallback."""
    return [r for r in rows if r['span_complete'] and r['clrt_complete_us'] is not None and not r['piggyback']
            and not r['request_retransmissions'] and not r['response_retransmissions'] and not r['trial_fallback']]


def clrt_bins(values):
    edges = list(CLRT_BINS_US) + [math.inf]
    return {('[%g,%g)' % (lo, hi)): sum(lo <= v < hi for v in values) for lo, hi in zip(edges, edges[1:])}


def group_stats(rows, keys):
    groups = {}
    for r in rows:
        groups.setdefault(tuple(r[k] if not callable(k) else k(r) for k in keys), []).append(r)
    out = []
    for key in sorted(groups, key=lambda k: tuple(str(x) for x in k)):
        g = groups[key]
        errs = [abs(r['clrt_error_us']) for r in g]
        out.append(dict(key=list(key), abs_error_us=describe(errs),
                        request_to_ack_us=describe([r['ack_rx_after_request_us'] for r in g]),
                        clrt_us=describe([r['clrt_complete_us'] for r in g]),
                        within_100us=sum(e <= 100 for e in errs)))
    return out


def summarize(blocks):
    rows = [r for b in blocks for r in b['transactions']]
    pkey = {b['block']: params_key(b['timing_params_ns']) for b in blocks}
    for r in rows:
        r['params_key'] = pkey[r['block']]
    fallback = []
    for b in blocks:
        for t in b['trials']:
            if not (t['out_ack_fallback'] or t['out_resp_fallback']):
                continue
            trows = [r for r in b['transactions'] if r['trial'] == t['trial']]
            fallback.append(dict(block=b['block'], arm=t['arm'], trial=t['trial'],
                                 out_ack_fallback=t['out_ack_fallback'], out_resp_fallback=t['out_resp_fallback'],
                                 signature_count=sum(r['fallback_signature'] for r in trows),
                                 signature_transactions=[r for r in trows if r['fallback_signature']],
                                 first_transactions=[r for r in trows if r['first_on_connection']]))
    unexplained = [dict(block=r['block'], arm=r['arm'], trial=r['trial'], connection=r['connection'],
                        connection_position=r['connection_position'], operation=r['operation'],
                        request_to_ack_us=r['ack_rx_after_request_us'],
                        request_retransmissions=r.get('request_retransmissions'))
                   for r in rows if r['fallback_signature'] and not r['trial_fallback']]
    zero = clean(rows)
    excluded = dict(fallback_trial=sum(r['trial_fallback'] for r in rows),
                    retransmitted=sum(bool(r.get('request_retransmissions') or r.get('response_retransmissions'))
                                      and not r['trial_fallback'] for r in rows),
                    incomplete_or_piggyback=sum((not r['span_complete'] or r['piggyback']) and not r['trial_fallback']
                                                for r in rows))
    by_arm_op = group_stats(zero, ('candidate', 'params_key', 'arm', 'operation'))
    for g in by_arm_op:
        cand, pk, arm, op = g['key']
        g['clrt_bins_us'] = clrt_bins([r['clrt_complete_us'] for r in zero if (r['candidate'], r['params_key'],
                                                                                r['arm'], r['operation']) ==
                                       (cand, pk, arm, op)])
    retx = [r for r in rows if r.get('request_retransmissions') or r.get('response_retransmissions')]
    return dict(
        fallback_cases=fallback,
        signature_without_fallback_counter=unexplained,
        zero_fallback=dict(
            eligibility='complete span, CLRT present, not piggybacked, no retransmission, trial switch counters show '
                        'no OUT_ACK_FALLBACK/OUT_RESP_FALLBACK',
            eligible=len(zero), excluded=excluded, by_arm_operation=by_arm_op,
            by_position=group_stats(zero, ('candidate', 'params_key', 'arm', 'first_on_connection')),
            by_previous_operation=group_stats(zero, ('candidate', 'params_key', 'arm', 'operation',
                                                     'previous_operation')),
            by_block=group_stats(zero, ('block', 'arm', 'operation'))),
        retransmitted_transactions=retx)


# --- Markdown ---

def fmt(v, digits=0):
    if v is None:
        return '-'
    if isinstance(v, bool):
        return 'yes' if v else 'no'
    if isinstance(v, float):
        return ('%.' + str(digits) + 'f') % v
    return str(v)


def table(header, rows):
    lines = ['| ' + ' | '.join(header) + ' |', '|' + '---|' * len(header)]
    lines += ['| ' + ' | '.join(fmt(c) if not isinstance(c, str) else c for c in row) + ' |' for row in rows]
    return '\n'.join(lines)


def ms(us):
    return fmt(us / 1000, 3) if us is not None else '-'


def stat_cells(d, scale=1.0):
    return [fmt(d[k] / scale if d[k] is not None else None, 0 if scale == 1 else 3) for k in ('p50', 'p90', 'p99', 'max')]


def timeline_md(r):
    lines = [table(['when (ms after request TX)', 'direction', 'flags', 'payload', 'rel seq', 'rel ack'],
                   [[ms(p['t_after_request_us']), p['direction'], '0x%02x' % p['flags'], fmt(p['payload_len']),
                     fmt(p['rel_seq']), fmt(p['rel_ack'])] for p in r.get('packet_timeline', [])])]
    return '\n'.join(lines)


def cluster_lines(groups):
    """Generated prose for the CLRT histogram: per candidate and parameter set, over the T-on arms, the shares of
    complete CLRT below 100 us, in [1500,2500) us, and in the [900,1000) us bin that contains a 950 us gap."""
    totals = {}
    for g in groups:
        cand, params, arm, _ = g['key']
        if arm not in ('timing_only', 'combined'):
            continue
        t = totals.setdefault((cand, params), dict.fromkeys(('n', 'low', 'high', 'gap'), 0))
        b = g['clrt_bins_us']
        t['n'] += sum(b.values())
        t['low'] += b.get('[0,100)', 0)
        t['high'] += b.get('[1500,2500)', 0)
        t['gap'] += b.get('[900,1000)', 0)
    lines = []
    for (cand, params), t in sorted(totals.items()):
        if t['n']:
            lines.append('- %s %s, T-on arms (n=%d): %.1f%% of complete CLRT below 100 us, %.1f%% in [1500,2500) us, '
                         '%.1f%% in [900,1000) us (the bin of a 950 us gap).' % (cand, params, t['n'], 100.0 * t['low'] / t['n'],
                                                        100.0 * t['high'] / t['n'], 100.0 * t['gap'] / t['n']))
    return lines


def render(diag):
    s = diag['summary']
    params = {b['block']: b['timing_params_ns'] for b in diag['blocks']}
    std = diag['blocks'][0]['timing_params_ns']
    L = ['# Master-NIC timing diagnosis of the physical SEL-751 blocks', '',
         'Generated by `analysis/c52_timing_diag.py` from the retained captures; every number below is computed by '
         'the tool. Observation point: the master NIC only (Vision `in.pcap` received, `out.pcap` sent). CLRT is '
         "relay_check's complete CLRT: response complete minus the first master-visible ACK of the request; the "
         'error is CLRT minus the configured gap.', '',
         'Blocks: ' + ', '.join('`%s`' % b['block'] for b in diag['blocks']) + '.', '',
         '## Timing parameters and what they are measured from', '',
         table(['block', 'da (ms)', 'gap (us)', 'op_j (ms)', 'pb (ms)', 'readiness (ms)', 'cap (ms)'],
               [[b, fmt(p['da'] / 1e6, 3), fmt(p['gap'] / 1e3, 0), fmt(p.get('op_j', 0) / 1e6, 3),
                 fmt(p.get('pb', 0) / 1e6, 3), fmt(p['readiness'] / 1e6, 3), fmt(p.get('cap', 0) / 1e6, 3)]
                for b, p in params.items()]), '',
         "readiness (%s ms in the standard blocks) and da are measured by T from its internal t0, which is not "
         "observed here: T's t0 is when the request reached the switch, after the unobserved master->switch "
         'forward delay. Every request->ACK interval below is therefore labelled "%s"; it is an upper bound on '
         "the interval from T's t0, never the interval itself." % (fmt(std['readiness'] / 1e6, 3), T_LABEL), '']

    L += ['## (a) Trials whose switch counters show a fallback', '',
          'The counters (trial.json observed.switch.outcomes) are per trial, not per transaction or per connection. '
          'The tool marks a transaction as carrying the fallback signature when T is on and its master-observed '
          'request->ACK interval is at least readiness. That is a master-side consistency check, not proof that '
          'this transaction is the one the counter recorded.', '',
          table(['block', 'arm', 'trial', 'ACK_FALLBACK', 'RESP_FALLBACK', 'signature transactions'],
                [[f['block'], f['arm'], f['trial'].rsplit('_', 1)[-1], fmt(f['out_ack_fallback']),
                  fmt(f['out_resp_fallback']), fmt(f['signature_count'])] for f in s['fallback_cases']]), '']
    for f in s['fallback_cases']:
        L += ['### %s %s %s' % (f['block'], f['arm'], f['trial'].rsplit('_', 1)[-1]), '',
              'First transaction of every connection in the trial:', '',
              table(['conn', 'op', 'TX after SYN (ms)', 'req->ACK (ms)', 'req->resp first (ms)',
                     'req->resp complete (ms)', 'CLRT (us)', 'signature'],
                    [[r['connection'], r['operation'], ms(r.get('request_tx_after_syn_us')),
                      ms(r.get('ack_rx_after_request_us')), ms(r.get('response_first_after_request_us')),
                      ms(r.get('response_complete_after_request_us')), fmt(r['clrt_complete_us']),
                      fmt(r['fallback_signature'])] for r in f['first_transactions']]), '']
        for r in f['signature_transactions']:
            L += ['Signature transaction: connection %s, position %d, %s. Packets between its request TX and '
                  'response completion:' % (r['connection'], r['connection_position'], r['operation']), '',
                  timeline_md(r), '']
    L += ['Transactions with the signature (T on, master-observed request->ACK at or beyond readiness) in trials '
          'whose counters show NO fallback: %d.' % len(s['signature_without_fallback_counter']), '']
    if s['signature_without_fallback_counter']:
        L += [table(['block', 'arm', 'trial', 'conn', 'position', 'op', 'req->ACK (ms)', 'request retransmissions'],
                    [[u['block'], u['arm'], u['trial'].rsplit('_', 1)[-1], u['connection'],
                      fmt(u['connection_position']), u['operation'], ms(u['request_to_ack_us']),
                      fmt(u['request_retransmissions'])] for u in s['signature_without_fallback_counter']]), '']

    z = s['zero_fallback']
    L += ['## (b) Timing failures in trials with no fallback', '',
          'Eligible transactions: %d (%s). Excluded: %d in fallback trials, %d retransmitted, %d incomplete or '
          'piggybacked.' % (z['eligible'], z['eligibility'], z['excluded']['fallback_trial'],
                            z['excluded']['retransmitted'], z['excluded']['incomplete_or_piggyback']), '',
          '### |CLRT - gap| and request->ACK by candidate, arm and operation', '',
          table(['cand', 'params', 'arm', 'op', 'n', '|err| p50', 'p90', 'p99', 'max (us)', '<=100 us',
                 'req->ACK p50', 'p90', 'p99', 'max (ms)'],
                [g['key'] + [fmt(g['abs_error_us']['n'])] + stat_cells(g['abs_error_us']) +
                 [fmt(g['within_100us'])] + stat_cells(g['request_to_ack_us'], 1000) for g in z['by_arm_operation']]),
          '', '### CLRT histogram (us)', '']
    bins = list(z['by_arm_operation'][0]['clrt_bins_us']) if z['by_arm_operation'] else []
    L += [table(['cand', 'params', 'arm', 'op'] + bins,
                [g['key'] + [fmt(g['clrt_bins_us'][b]) for b in bins] for g in z['by_arm_operation']]), '',
          'With T on, complete CLRT clusters away from the configured gap rather than at it (counts from the '
          'table above):', ''] + cluster_lines(z['by_arm_operation']) + ['',
          '### By connection position (first transaction on the connection vs the rest)', '',
          table(['cand', 'params', 'arm', 'first', 'n', '|err| p50', 'p90', 'p99', 'max (us)',
                 'req->ACK p50', 'p90', 'p99', 'max (ms)'],
                [g['key'] + [fmt(g['abs_error_us']['n'])] + stat_cells(g['abs_error_us']) +
                 stat_cells(g['request_to_ack_us'], 1000) for g in z['by_position']]), '',
          '### By operation and previous operation', '',
          table(['cand', 'params', 'arm', 'op', 'prev op', 'n', '|err| p50', 'p90', 'p99', 'max (us)'],
                [g['key'] + [fmt(g['abs_error_us']['n'])] + stat_cells(g['abs_error_us'])
                 for g in z['by_previous_operation']]), '',
          '### Per block', '',
          table(['block', 'arm', 'op', 'n', '|err| p50', 'p90', 'p99', 'max (us)', '<=100 us'],
                [g['key'] + [fmt(g['abs_error_us']['n'])] + stat_cells(g['abs_error_us']) + [fmt(g['within_100us'])]
                 for g in z['by_block']]), '']

    L += ['## (c) Retransmitted transactions', '',
          'A retransmission is a data segment that starts below the already-sent sequence frontier of its '
          'direction, in capture order. The implied master RTO is the first retransmission minus the original TX.',
          '']
    if not s['retransmitted_transactions']:
        L += ['None found.', '']
    req_retx = [r for r in s['retransmitted_transactions'] if r.get('request_retransmissions')]
    if req_retx:
        rtos = [r['request_retransmit_after_first_tx_us'][0] for r in req_retx]
        L += ['Request retransmissions (master TX): %d transactions; the first retransmission fired %s to %s ms after '
              'the original request. A request whose first ACK has not reached the master by then is retransmitted, '
              'so any ACK hold that, seen from the master, exceeds this interval produces a duplicate request at the '
              'switch.' % (len(req_retx), ms(min(rtos)), ms(max(rtos))), '',
              table(['block', 'arm', 'trial', 'conn', 'pos', 'op', 'request SEQ', 'implied RTO (ms)',
                     'first ACK (ms)', 'ACK minus retransmission (ms)', 'response complete (ms)'],
                    [[r['block'], r['arm'], r['trial'].rsplit('_', 1)[-1], r['connection'],
                      fmt(r['connection_position']), r['operation'], fmt(r.get('request_sequence_start')),
                      ms(r['request_retransmit_after_first_tx_us'][0]), ms(r.get('ack_rx_after_request_us')),
                      ms(r['ack_rx_after_request_us'] - r['request_retransmit_after_first_tx_us'][0]
                         if r.get('ack_rx_after_request_us') is not None else None),
                      ms(r.get('response_complete_after_request_us'))] for r in req_retx]), '']
    for r in s['retransmitted_transactions']:
        first_retx = (r['request_retransmit_after_first_tx_us'] or [None])[0]
        ack = r.get('ack_rx_after_request_us')
        L += ['### %s %s %s conn %s position %d (%s, request SEQ %s)' % (
                  r['block'], r['arm'], r['trial'].rsplit('_', 1)[-1], r['connection'], r['connection_position'],
                  r['operation'], r.get('request_sequence_start')), '',
              table(['request retransmissions', 'implied RTO (ms)', 'response retransmissions',
                     'response retransmitted at (ms)', 'first ACK (ms)', 'ACK after the retransmission', 'response complete (ms)', 'CLRT (us)'],
                    [[fmt(r['request_retransmissions']), ms(first_retx), fmt(r['response_retransmissions']),
                      ', '.join(ms(v) for v in r['response_retransmit_after_first_tx_us']) or '-',
                      ms(ack), fmt(first_retx is not None and ack is not None and ack > first_retx),
                      ms(r.get('response_complete_after_request_us')), fmt(r['clrt_complete_us'])]]), '',
              timeline_md(r), '']

    L += ['## Undecidable from master-only data', '',
          'The master NIC sees one end of a path that runs master -> switch (T) -> relay -> switch -> master. The '
          'following hypotheses each fit the tables above and cannot be separated without a second observation '
          'point:', '',
          "1. **Relay first-response turnaround versus switch hold.** A slow first transaction on a connection "
          "can be the relay answering its first request late (cold application state), or T holding the ACK until "
          "readiness (%s ms from T's t0) and the response until its fallback. Decided by a passive tap on the "
          "relay leg (relay-side RX/TX timestamps of the same request, ACK and response), which shows when the "
          "relay itself produced the ACK and response." % fmt(std['readiness'] / 1e6, 3),
          "2. **Where the CLRT error is added.** A CLRT that differs from the gap (%s us) can come from the relay "
          "releasing the ACK and response at its own spacing that T then does not reshape, from T's release "
          "scheduling, or from queueing on the return path. Decided by switch-side ingress/egress timestamps for "
          "the ACK and response (and the relay-leg tap for their arrival at the switch)." % fmt(std['gap'] / 1e3),
          "3. **Forward delay to T's t0.** The request->ACK interval includes the master->switch forward delay and "
          "any switch ingress delay before t0; neither readiness nor da can be checked against it. Decided by "
          "switch timestamps of request ingress (t0) or a tap on the master leg at the switch.",
          '4. **Which transaction a fallback counter recorded.** The counters are per trial; the signature here is '
          'a master-side match only. Decided by per-transaction switch records (fallback events keyed by '
          'connection and generation).',
          '5. **Cause of a request retransmission.** A missing ACK at the master before its RTO can be a request '
          'lost before the relay, a request the relay received but answered late, or an ACK held or dropped in the '
          'switch. Decided by the relay-leg tap (did the original request reach the relay, and when did the relay '
          'ACK it) together with switch drop/hold counters per packet.', '']
    return '\n'.join(L) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('blocks', nargs='+', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        blocks = [analyze_block(b) for b in args.blocks]
    except DiagError as error:
        print('c52_timing_diag: ' + str(error), file=sys.stderr)
        return 2
    summary = summarize(blocks)
    transactions = [r for b in blocks for r in b.pop('transactions')]
    diag = dict(schema='c52-timing-diag-v1',
                observation_scope='master NIC only; no relay-side or switch-side timestamps; T t0 unobserved',
                checksums_validated=False, blocks=blocks, summary=summary, transactions=transactions)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'diagnosis.json').write_text(json.dumps(diag, indent=1) + '\n')
    (args.out / 'DIAGNOSIS.md').write_text(render(diag))
    print('wrote %s and %s (%d transactions)' % (args.out / 'diagnosis.json', args.out / 'DIAGNOSIS.md',
                                                  len(transactions)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
