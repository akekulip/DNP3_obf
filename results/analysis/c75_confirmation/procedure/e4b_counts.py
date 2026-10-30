#!/usr/bin/env python3
"""E4b (SELECT without OPERATE) counts per block, from the same per-trial fields confirmation_summary.strict_trial
reads: trial/standards/wire ok, SELECT CROB SUCCESS on points 1 and 3, OPERATE count, the READ right after each
SELECT answered OK, READ responses equal to the class image, TCP retransmissions, and the CLRT of the READs right
after a SELECT (complete_clrt_us, piggybacked exchanges excluded).

    $RESEARCH_PYTHON e4b_counts.py TRIAL... --out OUT.json
"""
import argparse, json, statistics, sys
from pathlib import Path


def trial(path):
    path = Path(path)
    t, v, w = (json.loads((path / n).read_text()) for n in ('trial.json', 'standards_verdict.json', 'relay_wire.json'))
    ex = w['exchanges']
    image = v['expected']['read_classes']
    sel = [e for e in ex if e['operation'] == 'SELECT']
    after = [ex[i + 1] for i, e in enumerate(ex[:-1]) if e['operation'] == 'SELECT' and ex[i + 1]['operation'] == 'READ']
    reads = [e for e in ex if e['operation'] == 'READ']
    size = lambda e: e['response']['end_offset'] - e['response']['start_offset']
    return dict(trial=path.name, ok=bool(t['ok'] and v['ok'] and w['ok']),
                select_success=sum(e['application']['ok'] and sorted(map(tuple, e['application']['points']))
                                   == [(1, 'SUCCESS'), (3, 'SUCCESS')] for e in sel), selects=len(sel),
                operates=sum(e['operation'] == 'OPERATE' for e in ex),
                read_after_select_ok=sum(e['application']['ok'] and e['response']['complete'] for e in after),
                reads_after_select=len(after), reads_ok=sum(e['application']['ok'] for e in reads), reads=len(reads),
                reads_image=sum(size(e) == image[e.get('workload') or 'integrity']['image'] for e in reads),
                retransmissions=w['retransmissions'],
                clrt_after_select_us=[e['complete_clrt_us'] for e in after
                                      if not e['piggyback'] and e.get('complete_clrt_us') is not None])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('trials', nargs='+')
    ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args()
    rows = [trial(p) for p in a.trials]
    total = lambda k: sum(r[k] for r in rows)
    clrt = sorted(c for r in rows for c in r['clrt_after_select_us'])
    out = dict(trials=dict(n=total('ok'), of=len(rows)),
               select_crob_success=dict(n=total('select_success'), of=total('selects')),
               operate_requests=total('operates'),
               read_after_select_ok=dict(n=total('read_after_select_ok'), of=total('reads_after_select')),
               reads_ok=dict(n=total('reads_ok'), of=total('reads')),
               reads_equal_image=dict(n=total('reads_image'), of=total('reads')),
               retransmissions={d: sum(r['retransmissions'][d] for r in rows) for d in ('out', 'in')},
               clrt_after_select_us=dict(n=len(clrt), median=statistics.median(clrt) if clrt else None,
                                         min=clrt[0] if clrt else None, max=clrt[-1] if clrt else None),
               per_trial=[{k: v for k, v in r.items() if k != 'clrt_after_select_us'} for r in rows])
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=1) + '\n')
    print(json.dumps({k: v for k, v in out.items() if k != 'per_trial'}))


if __name__ == '__main__':
    sys.exit(main())
