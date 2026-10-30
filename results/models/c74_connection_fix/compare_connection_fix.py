#!/usr/bin/env python3
"""Compare the c74 connection-fix regression run with the same driver's run on c72, case by case.

  python3 compare_connection_fix.py C72_RUN_DIR C74_RUN_DIR OUT_JSON

Per case: both verdicts, the failed check names, and a build-independent outcome digest (port-64 labels of every
observation, the request/ACK summaries' busy and first_event lists, probe outcomes). 'as_before' cases must have an
identical digest on both builds; 'fix' cases must pass on c74 (their c72 result is the RED baseline); 'residual'
cases record what each build accepted.
"""
import hashlib
import json
import sys
from pathlib import Path

SUMMARY_KEYS = ('read_summary', 'ack_summary', 'operate_summary', 'syn_summary', 'B_read_summary', 'command_summary',
                'mismatched_summary', 'matching_summary')


def digest(record):
    out = dict(port64=[o.get('port64') for o in record.get('observations') or []])
    for key in SUMMARY_KEYS:
        value = record.get(key)
        if isinstance(value, dict) and 'busy' in value:
            out[key] = dict(busy=value['busy'], first_event=value['first_event'], t_ingress=value['t_ingress'])
        elif isinstance(value, dict):
            out[key] = {k: dict(busy=v['busy'], first_event=v['first_event']) for k, v in value.items()}
    for key in ('probes', 'probe', 'old_incarnation_probe', 'recovery'):
        value = record.get(key)
        if isinstance(value, dict):
            if key == 'probes':
                out[key] = {k: dict(port64=v['port64'], first_event=v['summary']['first_event']) for k, v in value.items()}
            else:
                out[key] = dict(port64=value.get('port64'),
                                first_event=(value.get('summary') or {}).get('first_event'))
    for key in ('port64_READ_copies', 't_ingress', 'residual_accepted', 'image_len'):
        if key in record:
            out[key] = record[key]
    return out


def load(run):
    return {path.name[5:-5]: json.loads(path.read_text()) for path in sorted(Path(run).glob('case_*.json'))}


def main():
    base, cand, out = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
    a, b = load(base), load(cand)
    cases, problems = {}, []
    for name in sorted(set(a) | set(b)):
        x, y = a.get(name), b.get(name)
        if x is None or y is None:
            problems.append('%s missing on %s' % (name, 'c72' if x is None else 'c74'))
            continue
        expectation = y['expectation']
        dx, dy = digest(x), digest(y)
        row = dict(scenario=y['scenario'], read_class=y['read_class'], evidence_kind=y['evidence_kind'],
                   expectation=expectation, c72_verdict=x['verdict'], c74_verdict=y['verdict'],
                   c72_failed=[c['name'] for c in x['checks'] if not c['ok']],
                   c74_failed=[c['name'] for c in y['checks'] if not c['ok']],
                   digest_identical=dx == dy, c72=dx, c74=dy)
        if expectation == 'as_before':
            row['acceptable'] = dx == dy and x['verdict'] == y['verdict'] == 'pass'
        elif expectation == 'fix':
            row['acceptable'] = y['verdict'] == 'pass'
        else:
            row['acceptable'] = y['verdict'] == 'pass'
        if not row['acceptable']:
            problems.append(name)
        cases[name] = row
    report = dict(schema='c74-connection-fix-vs-c72-v1', c72_run=str(base.name), c74_run=str(cand.name),
                  observation='SDK tofino-model functional output; not hardware, not timing',
                  rule="as_before: identical outcome digest and pass on both; fix: pass on c74 (c72 = RED baseline); "
                       "residual: recorded, pass = case completed",
                  cases=cases, problems=problems, all_acceptable=not problems,
                  counts={k: sum(1 for r in cases.values() if r['expectation'] == k) for k in ('fix', 'as_before', 'residual')},
                  comparator=dict(sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                  source=Path(__file__).read_text()))
    out.write_text(json.dumps(report, indent=1, default=str) + '\n')
    print(json.dumps(dict(all_acceptable=report['all_acceptable'], problems=problems,
                          verdicts={k: (v['c72_verdict'], v['c74_verdict'], v['digest_identical']) for k, v in cases.items()}),
                     indent=0))
    return 0 if not problems else 1


if __name__ == '__main__':
    raise SystemExit(main())
