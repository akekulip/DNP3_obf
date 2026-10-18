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

LINE = re.compile(r'^:\d\d-\d\d (\d\d:\d\d:\d\d\.\d+):\s+:(?:0x[0-9a-f]+|-):(?:0x[0-9a-f]+|-):<\d+,(\d+),[-\d]+>:(.*)$')
HEX = re.compile(r'^(?:[0-9a-f]{2} )*[0-9a-f]{2} ?$')
ACTION = re.compile(r'Execute (?:Default )?Action: ([nt]_Ingress\.\w+)')


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
    frame = bytes.fromhex(next(iter(case['received'].values()))[0])
    return '%08x' % ((int.from_bytes(frame[38:42], 'big') + 1) & 0xffffffff)


def restart_tags(results):
    return tuple(p['tag'] for p in results['meta'].get('points', [])
                 if str(p.get('tag', '')).startswith('restart') and 'restarts' in p)


def check(run_dir, tags=None):
    run_dir = Path(run_dir)
    results = json.loads(next(run_dir.glob('*_results.json')).read_text())
    tags = tags or restart_tags(results)
    with open(next(run_dir.glob('model_*.log')), errors='replace') as log:
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
    result = check(argv[1], tuple(argv[2:]) or None)
    print(json.dumps(result, indent=1))
    return 0 if result and all(v['verdict'] == 'PASS' for v in result.values()) else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))
