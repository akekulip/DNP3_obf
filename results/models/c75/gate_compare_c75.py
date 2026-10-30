#!/usr/bin/env python3
"""Compare the 17 model drivers run on c75 with c72's gate runs, case by case and leaf by leaf (gate_compare_c74.py with
the build name changed, and c74's runs added to the identical-T-binary cross table).

  python3 gate_compare_c75.py REPO OUT_JSON

For each run_model.REQUIRED driver: the latest results/models/c75 attempt against c72's model_summary_v3.json
latest_by_driver run. Cases come from scripts/model/diag_gate_compare.cases() (name, ok, observed). Case names and
verdicts must be identical. Every differing observed leaf is listed and classified:
  t_timestamp  - a T register whose value is a model timestamp (t_Ingress.*_at_reg)
  t_rewait     - a T hold re-wait count: cell 1 (rewait_ack/rewait_response) of the T outcome counts
  t_old_epoch  - cell 14 (drop_old_epoch) of the T outcome counts: held packets still looping when the epoch moves.
                 Not in the stated allowed list; the report shows it varying between c72 and c72_diag_mirror runs of
                 the identical T binary, i.e. run-to-run hold-loop timing.
  other        - anything else (not allowed)
T outcome counts are the action-execution counts telemetry_from_log.py derives from the model log
(action_observations.json: cell 1 rewait_*, cell 14 drop_old_epoch); the list is compared element by element.
"""
import hashlib, json, re, sys
from pathlib import Path

repo, out = Path(sys.argv[1]).resolve(), Path(sys.argv[2])
sys.path.insert(0, str(repo / 'scripts/model'))
import diag_gate_compare as dgc
import run_model

TS = re.compile(r't_Ingress\.\w*_at_reg\b|/\w*_at_reg/')
REWAIT = re.compile(r'rewait|re_wait|re-wait', re.I)


def leaves(v, p=''):
    if isinstance(v, dict):
        for k, x in v.items():
            yield from leaves(x, p + '/' + str(k))
    elif isinstance(v, list) and any(isinstance(x, (dict, list)) for x in v):
        for i, x in enumerate(v):
            yield from leaves(x, p + '/' + str(i))
    else:
        yield p, v


def classify(path, case):
    if TS.search(path):
        return 't_timestamp'
    if REWAIT.search(path):
        return 't_rewait'
    return 'other'


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


models = repo / 'results/models'
base_runs = json.loads((repo / 'results/builds/c72/model_summary_v3.json').read_text())['latest_by_driver']
drivers, allowed, strict = {}, True, True
for name in run_model.REQUIRED:
    runs = sorted(models.glob('c75/model_%s_c75_[0-9][0-9]' % name))
    if not runs:
        drivers[name] = dict(error='no c75 run'); allowed = strict = False
        continue
    new, base = runs[-1], models / 'c72' / base_runs[name]
    if not (new / 'launch_command.json').is_file():
        drivers[name] = dict(error='latest c75 attempt has no launch record (incomplete)', c75_run=new.name); allowed = strict = False
        continue
    a, b = dgc.cases(base), dgc.cases(new)
    launch = json.loads((new / 'launch_command.json').read_text())
    same_files = sorted(a) == sorted(b)
    verdicts = same_files and all([c[:2] for c in a[f]['cases']] == [c[:2] for c in b[f]['cases']] for f in a)
    diffs = []
    for f in sorted(set(a) & set(b)):
        for x, y in zip(a[f]['cases'], b[f]['cases']):
            if x[:2] != y[:2] or x[2] == y[2]:
                continue
            ox, oy = json.loads(x[2]), json.loads(y[2])
            lx, ly = dict(leaves(ox)), dict(leaves(oy))
            for path in sorted(set(lx) | set(ly)):
                vx, vy = lx.get(path, '<absent>'), ly.get(path, '<absent>')
                if vx == vy:
                    continue
                if path.endswith('/T/outcomes') and isinstance(vx, list) and isinstance(vy, list) and len(vx) == len(vy):
                    for i, (p, q) in enumerate(zip(vx, vy)):
                        if p != q:
                            diffs.append(dict(file=f, case=x[0], leaf='%s[%d]' % (path, i), c72=p, c75=q,
                                              kind={1: 't_rewait', 14: 't_old_epoch'}.get(i, 'other')))
                    continue
                diffs.append(dict(file=f, case=x[0], leaf=path, c72=vx, c75=vy, kind=classify(path, x[0])))
    other = [d for d in diffs if d['kind'] == 'other']
    stated = [d for d in diffs if d['kind'] not in ('t_timestamp', 't_rewait')]
    ok = launch.get('exit_code') == 0 and verdicts and not other
    strict &= launch.get('exit_code') == 0 and verdicts and not stated
    allowed &= ok
    drivers[name] = dict(c72_run=base.name, c75_run=new.name, c75_attempts=[r.name for r in runs],
                         c75_exit_code=launch.get('exit_code'),
                         c72_summary={f: a[f]['summary'] for f in a}, c75_summary={f: b[f]['summary'] for f in b},
                         case_count=sum(len(a[f]['cases']) for f in a),
                         case_names_and_verdicts_identical=verdicts,
                         observed_leaf_differences=diffs[:60], observed_leaf_difference_count=len(diffs),
                         kinds={k: sum(1 for d in diffs if d['kind'] == k) for k in ('t_timestamp', 't_rewait', 't_old_epoch', 'other')},
                         acceptable=ok)
def t_cells(run):
    out = {}
    for f in sorted(run.glob('*_results.json')):
        for c in json.loads(f.read_text()).get('cases', []):
            o = c.get('observed')
            if isinstance(o, dict) and isinstance(o.get('T'), dict) and isinstance(o['T'].get('outcomes'), list):
                out[c['name']] = [o['T']['outcomes'][1], o['T']['outcomes'][14]]
    return out


cross = {}
for name in ('control_timing', 'response_ready', 'rearm'):
    runs = {'c72': models / 'c72' / base_runs[name]}
    diag = sorted(models.glob('c72_diag_mirror/model_%s_c72_diag_mirror_[0-9][0-9]' % name))
    if diag:
        runs['c72_diag_mirror'] = diag[-1]
    c74 = sorted(models.glob('c74/model_%s_c74_[0-9][0-9]' % name))
    if c74:
        runs['c74'] = c74[-1]
    if 'c75_run' in drivers.get(name, {}):
        runs['c75'] = models / 'c75' / drivers[name]['c75_run']
    cells = {k: t_cells(v) for k, v in runs.items()}
    names = sorted(set.intersection(*[set(c) for c in cells.values()])) if cells else []
    cross[name] = dict(runs={k: v.name for k, v in runs.items()},
                       distinct_cell1_cell14_per_run={k: sorted({tuple(c[n]) for n in names}) for k, c in cells.items()})
report = dict(schema='c75-gate-vs-c72-v1', build='c75', baseline='c72',
              observation='SDK tofino-model functional output; not hardware, not timing',
              rule='case names and verdicts identical; differing observed leaves only T timestamp registers or T hold '
                   're-wait counts (results/builds/c72_diag_mirror/README.md: run-to-run variation)',
              drivers=drivers, all_c75_runs_exit_0=all(d.get('c75_exit_code') == 0 for d in drivers.values()),
              all_verdicts_identical=all(d.get('case_names_and_verdicts_identical') for d in drivers.values()),
              only_stated_allowed_differences=strict,
              only_run_to_run_variation=allowed,
              t_outcome_cells_across_identical_t_binary_runs=cross,
              t_binary_note='pipe 1 (T and x) of c75 equals c72 byte for byte in response_only.bfa except the compiler run_id line; '
                            'c72_diag_mirror pipe 1 equals c72 after generated-name normalisation (scripts/diag_mirror_checks.py pipe1_equivalence)',
              comparator=dict(path='this script (source embedded)', sha256=sha(__file__), source=Path(__file__).read_text(),
                              reuses='scripts/model/diag_gate_compare.py cases()', reused_sha256=sha(repo / 'scripts/model/diag_gate_compare.py')))
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps(report, indent=1, default=str) + '\n')
print(json.dumps(dict(all_c75_runs_exit_0=report['all_c75_runs_exit_0'], all_verdicts_identical=report['all_verdicts_identical'],
                      only_stated_allowed_differences=strict,
              only_run_to_run_variation=allowed,
              t_outcome_cells_across_identical_t_binary_runs=cross,
              t_binary_note='pipe 1 (T and x) of c75 equals c72 byte for byte in response_only.bfa except the compiler run_id line; '
                            'c72_diag_mirror pipe 1 equals c72 after generated-name normalisation (scripts/diag_mirror_checks.py pipe1_equivalence)',
                      per_driver={k: (v.get('c75_exit_code'), v.get('case_count'), v.get('kinds')) for k, v in drivers.items()}), indent=0))
sys.exit(0 if allowed else 1)
