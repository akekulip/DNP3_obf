"""Compare the model drivers run on a diagnostic build BASE_diag_mirror (sessions absent) with BASE's own runs.

  python3 scripts/model/diag_gate_compare.py --repo REPO [--build BASE_diag_mirror] [--overlay OVERLAY]
      --out results/models/BASE_diag_mirror/gate_vs_BASE_NN.json

--build defaults to the canonical candidate's diagnostic build (results/analysis/stage_cut/current_build.json) and
the baseline is always the base the build name derives from (c72_diag_mirror -> c72, c74_diag_mirror -> c74).
For each of run_model.REQUIRED: the latest diag attempt and BASE's model_summary_v3.json latest_by_driver run; every
*_results.json case is compared by (name, ok, observed). Observed values that carry model wall-clock measurements can
differ between any two runs, so differences are listed, not hidden. With --overlay, the report also records how the
tree the runs used differs from the commit it was archived from (--base-commit, git show), file by file.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent


def sha(data):
    return hashlib.sha256(data).hexdigest()


def cases(run):
    out = {}
    for path in sorted(run.glob('*_results.json')):
        record = json.loads(path.read_text())
        out[path.name] = dict(summary=record.get('summary'), cases=[
            [c.get('name'), c.get('ok'), json.dumps(c.get('observed'), sort_keys=True)] for c in record.get('cases', [])])
    return out


def overlay_manifest(repo, overlay, base='HEAD'):
    differ, added = {}, {}
    for folder in ('scripts', 'tests/fixtures'):
        for path in sorted((overlay / folder).rglob('*')):
            if not path.is_file() or '__pycache__' in path.parts:
                continue
            rel = str(path.relative_to(overlay))
            head = subprocess.run(['git', '-C', str(repo), 'show', '%s:%s' % (base, rel)], capture_output=True)
            if head.returncode:
                added[rel] = sha(path.read_bytes())
            elif head.stdout != path.read_bytes():
                differ[rel] = dict(head=sha(head.stdout), overlay=sha(path.read_bytes()))
    commit = subprocess.run(['git', '-C', str(repo), 'rev-parse', base], capture_output=True, text=True).stdout.strip()
    return dict(base_commit=commit, overlay=str(overlay), differs_from_base=differ, added=added)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--overlay', type=Path)
    parser.add_argument('--base-commit', default='HEAD', help='commit the overlay was archived from')
    parser.add_argument('--build', help='BASE_diag_mirror (default: the canonical candidate\'s diagnostic build)')
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    repo = args.repo.resolve()
    if args.build is None:
        current = json.loads((repo / 'results/analysis/stage_cut/current_build.json').read_text())
        args.build = current['candidate'] + '_diag_mirror'
    if not args.build.endswith('_diag_mirror') or not args.build[:-len('_diag_mirror')]:
        parser.error('--build must be BASE_diag_mirror')
    args.baseline = args.build[:-len('_diag_mirror')]
    import sys
    sys.path.insert(0, str(HERE))
    import run_model
    models = repo / 'results/models'
    base_runs = json.loads((repo / 'results/builds' / args.baseline / 'model_summary_v3.json').read_text())['latest_by_driver']
    drivers = {}
    for name in run_model.REQUIRED:
        runs = sorted(models.glob('%s/model_%s_%s_[0-9][0-9]' % (args.build, name, args.build)))
        if not runs:
            drivers[name] = dict(error='no diag run')
            continue
        diag, base = runs[-1], models / args.baseline / base_runs[name]
        a, b = cases(base), cases(diag)
        launch = json.loads((diag / 'launch_command.json').read_text())
        diffs = []
        for rname in sorted(set(a) | set(b)):
            x, y = (a.get(rname) or {}).get('cases', []), (b.get(rname) or {}).get('cases', [])
            if [c[:2] for c in x] != [c[:2] for c in y]:
                diffs.append(dict(file=rname, kind='case names or verdicts differ'))
            diffs += [dict(file=rname, case=cx[0], base=cx[2][:200], diag=cy[2][:200])
                      for cx, cy in zip(x, y) if cx[:2] == cy[:2] and cx[2] != cy[2]]
        summaries = {r: (b.get(r) or {}).get('summary') for r in b}
        drivers[name] = dict(base_run=base.name, diag_run=diag.name, diag_exit_code=launch.get('exit_code'),
                             diag_summary=summaries, base_summary={r: (a.get(r) or {}).get('summary') for r in a},
                             verdicts_identical=not any(d.get('kind') for d in diffs),
                             observed_differences=[d for d in diffs if not d.get('kind')][:30],
                             observed_difference_count=sum(1 for d in diffs if not d.get('kind')))
    report = dict(schema='diag-mirror-gate-vs-base-v1', build=args.build, baseline=args.baseline,
                  sessions='absent (the gate drivers do not configure the diagnostic sessions)',
                  observation='SDK tofino-model functional output; not hardware, not timing', drivers=drivers,
                  all_diag_runs_exit_0=all(d.get('diag_exit_code') == 0 for d in drivers.values()),
                  all_verdicts_identical=all(d.get('verdicts_identical') for d in drivers.values()),
                  comparator_sha256=sha(Path(__file__).read_bytes()))
    if args.overlay:
        report['tree'] = overlay_manifest(repo, args.overlay.resolve(), args.base_commit)
    args.out.write_text(json.dumps(report, indent=1) + '\n')
    print(json.dumps(dict(all_diag_runs_exit_0=report['all_diag_runs_exit_0'], all_verdicts_identical=report['all_verdicts_identical'],
                          observed_difference_counts={k: v.get('observed_difference_count') for k, v in drivers.items()})))
    return 0 if report['all_diag_runs_exit_0'] and report['all_verdicts_identical'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
