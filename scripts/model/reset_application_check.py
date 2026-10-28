"""Revised reset contract, checked from a contention run's model log (Philip, 2026-10-17).

  python3 reset_application_check.py RUN_DIR [TAG ...]    (default: every restart point the run recorded, i.e. the
                                                           meta points whose tag starts 'restart' and that carry
                                                           'restarts': the ordinary and the targeted ones)

The contract this checks (it does not replace the original check, which keeps its recorded results):
  A reset takes effect for T's held traffic at T's reset-application pass: the T ingress pass that runs close_epoch
  (seals cur_epoch_reg, bit 31) and live_reset_gen (bumps gen_alloc_reg) on the reset hand-off. After it, a held
  packet of the old incarnation fails match_epoch or the lane-generation check and is dropped or flushed, never
  released. Required for each point:
  1. every response copy that reached the master was released by a T pass BEFORE the application pass;
  2. no T pass releases a response of the connection at or after the application pass;
  3. the release passes attributed to the connection equal T's own release count for the point (RESP_RELEASE +
     RESP_FALLBACK delta, recorded by the driver), so no release was lost to attribution.
Any other outcome is a non-PASS verdict: FAIL (2 broken), 'unattributed' (1 or 3 unprovable), 'no reset applied'.

Attribution (code review: trace_model_log keys records by packet id, but every model-log line carries the ids of both
the ingress and the egress packet active in the pipe, so its actions can land on the wrong record). Here an ingress
record begins at an 'Ingress Pkt from port' header and takes that header's packet dump as its frame. Every
'Execute ... Action: t_Ingress.*' (pipe 1) or 'n_Ingress.*' (pipe 0) line belongs to the current ingress record of
its pipe. A connection's records are those whose frame carries its first response's server sequence; the master RST
and its hand-off acknowledge that sequence.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

LINE = re.compile(r'^:\d\d-\d\d (\d\d:\d\d:\d\d\.\d+):\s+:(?:0x[0-9a-f]+|-):(?:0x[0-9a-f]+|-):<\d+,(\d+),[-\d]+>:(.*)$')
HEX = re.compile(r'^(?:[0-9a-f]{2} )*[0-9a-f]{2} ?$')
ACTION = re.compile(r'Execute (?:Default )?Action: ([nt]_Ingress\.\w+)')


def load_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key %s' % key)
            result[key] = value
        return result
    return json.loads(Path(path).read_text(), object_pairs_hook=unique)


def ingress_records(lines):
    """Ingress records {wall, pipe, frame, actions} from model-log lines, attributed per pipe as described above."""
    records, current, dumping = [], {}, {}
    for raw in lines:
        m = LINE.match(raw.rstrip('\n'))
        if not m:
            continue
        wall, pipe, text = m.group(1), int(m.group(2)), m.group(3).strip()
        if text.startswith('==========') and 'Ingress Pkt from port' in text:
            port = re.search(r'Ingress Pkt from port (\d+)', text)
            rec = dict(wall=wall, pipe=pipe, frame='', actions=[], t_units=None, port=int(port.group(1)))
            records.append(rec)
            current[pipe] = rec
            dumping[pipe] = 'header'
            continue
        if text.startswith('=========='):
            dumping[pipe] = None                      # another hop's header: the ingress dump (if any) has ended
            continue
        if text == 'Packet :':
            if dumping.get(pipe) == 'header':
                dumping[pipe] = 'ingress'
            continue
        if dumping.get(pipe) == 'ingress' and HEX.match(text):
            current[pipe]['frame'] += text.replace(' ', '')
            continue
        dumping[pipe] = None if dumping.get(pipe) == 'ingress' else dumping.get(pipe)
        if 'global_tstamp[39:8]' in text and 'to value' in text and pipe in current \
                and current[pipe].get('t_units') is None:
            # T's clock (md.now = global_tstamp[39:8] & ~1, 256 ns units), taken by this ingress pass's parser
            current[pipe]['t_units'] = int(re.search(r'to value\s+(0x[0-9a-f]+)', text).group(1), 16)
            continue
        a = ACTION.search(text)
        if a:
            owner_pipe = 1 if a.group(1).startswith('t_') else 0
            if owner_pipe in current:
                current[owner_pipe]['actions'].append(a.group(1))
    return records


def classify(records, t_release_count=None, copies_to_master=None):
    """records: the connection's T (pipe-1) ingress records in log order. Pure; unit-tested."""
    acts = lambda r: ' '.join(r['actions'])
    order = list(enumerate(records))
    applied = [i for i, r in order if 'close_epoch' in acts(r) and 'live_reset_gen' in acts(r)]
    releases = [i for i, r in order if 'release_response' in acts(r)]
    if not applied:
        return dict(verdict='no reset applied', releases=len(releases))
    first = applied[0]
    before = [records[i]['wall'] for i in releases if i < first]
    after = [records[i]['wall'] for i in releases if i >= first]          # a tie counts as after
    out = dict(applied_at=records[first]['wall'], released_before=before, released_after=after,
               t_release_count=t_release_count, copies_to_master=copies_to_master)
    if after:
        out['verdict'] = 'FAIL'
    elif t_release_count is None or copies_to_master is None:
        out['verdict'] = 'unattributed'
        out['reason'] = "the point's T release count or master copy count was not recorded"
    elif len(before) != t_release_count:
        out['verdict'] = 'unattributed'
        out['reason'] = 'release passes found (%d) differ from T release count (%d)' % (len(before), t_release_count)
    elif len(before) < copies_to_master:
        out['verdict'] = 'unattributed'
        out['reason'] = 'copies at the master (%d) exceed releases found before the reset (%d)' % (
            copies_to_master, len(before))
    else:
        out['verdict'] = 'PASS'
    return out


def server_seq_pattern(results, tag):
    case = next(c for c in results['cases'] if c['name'] == '%s_SYNACK' % tag)
    received = case['received']
    if not isinstance(received, dict) or not all(isinstance(v, list) for v in received.values()):
        raise ValueError('malformed SYNACK capture')
    frames = [f for values in received.values() for f in values]
    if len(frames) != 1:
        raise ValueError('SYNACK capture must contain exactly one frame')
    frame = bytes.fromhex(frames[0])
    if (len(frame) < 54 or frame[12:14] != bytes.fromhex('0800') or frame[14] != 0x45 or
            frame[23] != 6 or frame[47] & 0x12 != 0x12):
        raise ValueError('malformed IPv4 TCP SYNACK')
    return '%08x' % ((int.from_bytes(frame[38:42], 'big') + 1) & 0xffffffff)


def restart_tags(results):
    return tuple(p['tag'] for p in results['meta'].get('points', [])
                 if str(p.get('tag', '')).startswith('restart') and 'restarts' in p)


def coverage_problems(results, reports):
    """Require the complete ordinary/targeted reset experiment, with report fields attributed to actual cases.

    Target attempts are 1..3 per kind, contiguous and ending at the first positive restart/stage-0 witness.
    This validates retained evidence; it never manufactures coverage from a PASS label.
    """
    problems = []
    if not isinstance(results, dict) or not isinstance(reports, dict):
        return ['malformed reset results/report']
    meta = results.get('meta') or {}
    if not isinstance(meta, dict):
        return ['malformed contention metadata']
    cases, points = results.get('cases'), meta.get('points')
    if meta.get('sections') != 'all':
        problems.append('reset qualification requires all contention sections')
    if not isinstance(cases, list) or not cases or not isinstance(points, list):
        return problems + ['missing contention cases/points']
    by_case, by_point = {}, {}
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get('name'), str):
            problems.append('malformed case')
            continue
        name = case['name']
        if name in by_case:
            problems.append('duplicate case %s' % name)
        by_case[name] = case
        if (case.get('ok') is not True or case.get('skip') or case.get('skipped') or
                case.get('status') in ('skip', 'skipped')):
            problems.append('case did not pass: %s' % name)
    summary = results.get('summary') or {}
    if not isinstance(summary, dict):
        return problems + ['malformed contention summary']
    if (type(summary.get('total')) is not int or type(summary.get('passed')) is not int or
            summary.get('total') != len(cases) or summary.get('passed') != len(cases) or summary.get('failed') != []):
        problems.append('contention summary does not reconcile with passing cases')
    for point in points:
        if not isinstance(point, dict) or not isinstance(point.get('tag'), str):
            problems.append('malformed point')
            continue
        tag = point['tag']
        if tag in by_point:
            problems.append('duplicate point %s' % tag)
        by_point[tag] = point
    ordinary = ('restart_READ', 'restart_SELECT')
    pattern = re.compile(r'^restart_targeted_(READ|SELECT)_([1-3])$')
    tags = [tag for tag in by_point if tag in ordinary or pattern.fullmatch(tag)]
    for tag, point in by_point.items():
        if tag.startswith('restart') and ('restarts' in point or not tag.endswith('_new_READ')) and tag not in tags:
            problems.append('unexpected reset point %s' % tag)
    for tag in ordinary:
        if tag not in by_point:
            problems.append('missing reset point %s' % tag)
    for kind in ('READ', 'SELECT'):
        tries = sorted((int(pattern.fullmatch(t).group(2)), by_point[t]) for t in tags
                       if pattern.fullmatch(t) and pattern.fullmatch(t).group(1) == kind)
        if not tries or [n for n, _ in tries] != list(range(1, len(tries) + 1)):
            problems.append('missing/noncontiguous targeted %s attempts' % kind)
        positive = [i for i, (_, point) in enumerate(tries)
                    if type(point.get('restarts')) is int and point['restarts'] >= 1 and
                    point.get('stage0_seen') is True]
        if positive != [len(tries) - 1]:
            problems.append('targeted %s needs a final positive restart witness' % kind)
        case = by_case.get('restart_targeted_%s_path_exercised' % kind, {})
        if (case.get('ok') is not True or case.get('observed') is not True or type(case.get('tries')) is not int or case.get('tries') != len(tries) or
                case.get('restarts') != [p.get('restarts') for _, p in tries] or
                case.get('stage0_seen') != [p.get('stage0_seen') for _, p in tries]):
            problems.append('targeted %s aggregate is missing/inconsistent' % kind)
    if set(reports) != set(tags):
        problems.append('reset reports do not exactly cover executed reset points')
    required = ('SYN', 'SYNACK', 'final_ACK', 'first_RST_relayed_once', 'response_at_most_once',
                'new_SYN', 'new_SYNACK', 'new_final_ACK', 'new_READ_request_relayed',
                'new_READ_delivered_once_committed', 'new_RST_relayed')
    # The timestamp-bearing relay profile adds an option-order check to each restart's new READ; it is required.
    if (meta.get('endpoint_profile') or {}).get('tcp_profile') == 'sel751_ts':
        required += ('new_READ_timestamp_options_delivery_order',)
    expected_cases = {'restart_targeted_%s_path_exercised' % k for k in ('READ', 'SELECT')}
    for tag in tags:
        point = by_point[tag]
        kind = 'SELECT' if 'SELECT' in tag else 'READ'
        if (point.get('kind') != kind or type(point.get('restarts')) is not int or point['restarts'] < 0 or
                type(point.get('relayed_resets')) is not int or point.get('relayed_resets') != 1 or
                type(point.get('response_copies_to_master')) is not int or
                point['response_copies_to_master'] not in (0, 1)):
            problems.append('malformed reset point %s' % tag)
        suffixes = required + (('work_cell_idle_at_start', 'request_relayed') if pattern.fullmatch(tag) else ())
        expected_cases.update('%s_%s' % (tag, suffix) for suffix in suffixes)
        if pattern.fullmatch(tag) and type(point.get('stage0_seen')) is not bool:
            problems.append('malformed targeted stage-0 witness %s' % tag)
        busy = point.get('count_busy_delta')
        if (not isinstance(busy, list) or len(busy) <= 5 or
                any(type(n) is not int or n < 0 for n in busy) or busy[5] != point.get('restarts')):
            problems.append('restart counter delta is inconsistent: %s' % tag)
        for suffix in suffixes:
            name = '%s_%s' % (tag, suffix)
            if by_case.get(name, {}).get('ok') is not True:
                problems.append('missing/nonpassing reset case %s' % name)
        for suffix, key, field in (('first_RST_relayed_once', 'relayed', 'relayed_resets'),
                                    ('response_at_most_once', 'copies', 'response_copies_to_master')):
            if by_case.get('%s_%s' % (tag, suffix), {}).get(key) != point.get(field):
                problems.append('reset case/point disagree: %s_%s' % (tag, suffix))
        report = reports.get(tag)
        if not isinstance(report, dict):
            problems.append('missing/malformed reset report %s' % tag)
            continue
        deltas = point.get('t_deltas')
        count = None
        if isinstance(deltas, dict) and all(type(v) is int and v >= 0 for v in deltas.values()):
            count = deltas.get('RESP_RELEASE', 0) + deltas.get('RESP_FALLBACK', 0)
        before = report.get('released_before')
        if (report.get('verdict') != 'PASS' or not isinstance(report.get('applied_at'), str) or
                not report['applied_at'] or report.get('released_after') != [] or not isinstance(before, list) or
                any(not isinstance(x, str) or not x for x in before) or count is None or
                type(report.get('t_release_count')) is not int or report.get('t_release_count') != count or
                len(before) != count or report.get('copies_to_master') != point.get('response_copies_to_master') or
                type(report.get('copies_to_master')) is not int or report['copies_to_master'] > count or
                type(report.get('restarts')) is not int or report.get('restarts') != point.get('restarts')):
            problems.append('reset report is incomplete/inconsistent: %s' % tag)
        try:
            if report.get('server_seq') != server_seq_pattern(results, tag):
                problems.append('reset report sequence differs from SYNACK: %s' % tag)
        except (KeyError, StopIteration, ValueError, TypeError, IndexError):
            problems.append('reset SYNACK attribution is malformed: %s' % tag)
    if meta.get('ordinary_restart_by_kind') != {k: by_point.get('restart_' + k, {}).get('restarts')
                                               for k in ('READ', 'SELECT')}:
        problems.append('ordinary restart aggregate is inconsistent')
    for name in by_case:
        if name.startswith('restart') and name not in expected_cases:
            problems.append('unexpected reset case %s' % name)
    return problems


def check(run_dir, tags=None):
    run_dir = Path(run_dir)
    result_files = list(run_dir.glob('*_results.json'))
    logs = list(run_dir.glob('model_*.log'))
    if len(result_files) != 1 or len(logs) != 1:
        raise ValueError('reset checker requires exactly one results file and model log')
    results = load_json(result_files[0])
    tags = tags or restart_tags(results)
    with open(logs[0], errors='replace') as log:
        records = ingress_records(log)
    out = {}
    for tag in tags:
        pattern = server_seq_pattern(results, tag)
        conn = [r for r in records if r['pipe'] == 1 and pattern in r['frame']]
        point = next((p for p in results['meta'].get('points', []) if p.get('tag') == tag), {})
        t_deltas = point.get('t_deltas')
        count = (t_deltas.get('RESP_RELEASE', 0) + t_deltas.get('RESP_FALLBACK', 0)) if t_deltas is not None else None
        out[tag] = dict(classify(conn, count, point.get('response_copies_to_master')), server_seq=pattern,
                        restarts=point.get('restarts'))
    return out


def main(argv):
    try:
        result = check(argv[1], tuple(argv[2:]) or None)
        files = list(Path(argv[1]).glob('*_results.json'))
        problems = ([] if argv[2:] else coverage_problems(load_json(files[0]), result))
        if problems:
            result['_coverage_problems'] = problems
        print(json.dumps(result, indent=1))
        return 0 if result and not problems and all(isinstance(v, dict) and v.get('verdict') == 'PASS'
                                                   for v in result.values()) else 1
    except (OSError, ValueError, TypeError, KeyError, StopIteration, IndexError) as error:
        print(json.dumps(dict(error=str(error)), indent=1))
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
