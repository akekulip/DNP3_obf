#!/usr/bin/env python3
"""Three-way comparison of the 40-case connection-fix driver on c72, c74 and c75, case by case.

  python3 compare_connection_fix_3way.py C72_RUN C74_RUN C75_RUN OUT_JSON

The outcome digest is results/models/c74_connection_fix/compare_connection_fix.py digest() (imported, not copied).
'normalized' removes busy_retry_rst_next from every busy list: that entry is a retry pass that found the cell still
held, and how many occur follows model timing. c74's own attempts 02 and 03 differ in it (stale_retry_mixed 9 and 0,
collision_causal_integrity 1 and 2, dup_during_retry_mixed 22 and 24; results/builds/c74/README.md). Raw digests are
kept in the output, and raw-digest equality is reported beside the normalized one. (The first version of this script
only collapsed consecutive repeats, which still separated 0 from 10 such passes in stale_retry_mixed; it was changed
after the preliminary comparison against c72_02 showed that, before the final comparison was written.)

Expectations (plan Step 2):
  as_c74  the retry cases: c75 passes and its normalized digest equals c74's. The plan names H1, H1_sbo, collision,
          exhaust, dup and stale_retry; collision_causal, H1prime and operate_retry_before_select_response exercise the
          same retry rows and are expected the same way.
  as_c72  the late-ACK cases H2, H2r, stale_ack, residual_* and reconnect: c75's normalized digest and verdict equal
          c72's. Prediction recorded before the c75 run: reconnect will NOT meet this, because connection B's final
          ACK and READ are sent back to back, which is the H1 path (the READ retries on c74 and c75, busy_drop on c72);
          only the A-ACK refusal is the late-ACK part, and it is refused on all three builds.
  as_before  the eight unchanged cases: identical normalized digest on all three builds and pass on all three.
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = HERE.parent / 'c74_connection_fix' / 'compare_connection_fix.py'
spec = importlib.util.spec_from_file_location('compare_c72_c74', BASE)
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

AS_C74 = ('H1', 'H1_sbo', 'collision', 'exhaust', 'dup_during_retry', 'stale_retry', 'collision_causal', 'H1prime',
          'operate_retry_before_select_response')
AS_C72 = ('H2', 'H2r', 'stale_ack', 'residual_class_mismatch', 'residual_later_read', 'reconnect')
PLAN_NAMED = {'H1', 'H1_sbo', 'collision', 'exhaust', 'dup_during_retry', 'dup_after_admit', 'stale_retry'} | set(AS_C72)


def drop_failed_retries(items):
    return [item for item in items if item != 'busy_retry_rst_next']


def normalize(value):
    if isinstance(value, dict):
        return {k: (drop_failed_retries(v) if k == 'busy' and isinstance(v, list) else normalize(v))
                for k, v in value.items()}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def expectation(record):
    scenario = record['scenario']
    if scenario in AS_C74:
        return 'as_c74'
    if scenario in AS_C72:
        return 'as_c72'
    return 'as_before'


def main():
    runs = dict(zip(('c72', 'c74', 'c75'), (Path(p) for p in sys.argv[1:4])))
    out = Path(sys.argv[4])
    loaded = {k: base.load(v) for k, v in runs.items()}
    names = sorted(set().union(*[set(v) for v in loaded.values()]))
    cases, problems = {}, []
    for name in names:
        rec = {k: v.get(name) for k, v in loaded.items()}
        if any(r is None for r in rec.values()):
            problems.append('%s missing on %s' % (name, [k for k, r in rec.items() if r is None]))
            continue
        raw = {k: base.digest(r) for k, r in rec.items()}
        norm = {k: normalize(v) for k, v in raw.items()}
        verdict = {k: r['verdict'] for k, r in rec.items()}
        want = expectation(rec['c75'])
        if want == 'as_c74':
            ok = verdict['c75'] == verdict['c74'] == 'pass' and norm['c75'] == norm['c74']
        elif want == 'as_c72':
            ok = verdict['c75'] == verdict['c72'] and norm['c75'] == norm['c72']
        else:
            ok = set(verdict.values()) == {'pass'} and norm['c72'] == norm['c74'] == norm['c75']
        row = dict(scenario=rec['c75']['scenario'], read_class=rec['c75']['read_class'],
                   evidence_kind=rec['c75']['evidence_kind'], plan_named=rec['c75']['scenario'] in PLAN_NAMED,
                   expectation=want, meets_expectation=ok, verdicts=verdict,
                   failed_checks={k: [c['name'] for c in r['checks'] if not c['ok']] for k, r in rec.items()},
                   c75_normalized_digest_equals=dict(c72=norm['c75'] == norm['c72'], c74=norm['c75'] == norm['c74']),
                   c75_raw_digest_equals=dict(c72=raw['c75'] == raw['c72'], c74=raw['c75'] == raw['c74']),
                   digests=raw)
        if not ok:
            problems.append(name)
        cases[name] = row
    report = dict(schema='c75-connection-fix-3way-v1', runs={k: v.name for k, v in runs.items()},
                  driver_sha256={k: json.loads((v / 'launch_command.json').read_text()).get('driver_sha256')
                                 for k, v in runs.items()},
                  exit_codes={k: json.loads((v / 'launch_command.json').read_text()).get('exit_code')
                              for k, v in runs.items()},
                  observation='SDK tofino-model functional output; not hardware, not timing',
                  rule=__doc__.split('Expectations (plan Step 2):')[1].strip(),
                  cases=cases, problems=problems, all_meet_expectation=not problems,
                  counts={k: sum(1 for r in cases.values() if r['expectation'] == k) for k in ('as_c74', 'as_c72', 'as_before')},
                  comparator=dict(sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                  source=Path(__file__).read_text(),
                                  digest_from=str(BASE.relative_to(HERE.parents[2])),
                                  digest_from_sha256=hashlib.sha256(BASE.read_bytes()).hexdigest()))
    out.write_text(json.dumps(report, indent=1, default=str) + '\n')
    print(json.dumps(dict(all_meet_expectation=report['all_meet_expectation'], problems=problems,
                          table={k: (v['expectation'], v['verdicts']['c72'], v['verdicts']['c74'], v['verdicts']['c75'],
                                     v['c75_normalized_digest_equals']) for k, v in cases.items()}), indent=0))
    return 0 if not problems else 1


if __name__ == '__main__':
    raise SystemExit(main())
