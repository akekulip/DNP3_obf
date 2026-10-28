#!/usr/bin/env python3
"""Replay a retained c72 hardware matrix with the exact checker code its freeze bound (audit 2026-10-28).

Editing anything in scripts/checks/ changes the checker hash that every recorded standards verdict binds, so the
current tree cannot replay historical evidence once the checkers are repaired. This tool rebuilds the bound tree:
every scripts/ file listed in the campaign's freeze.json is taken from a git commit and written only if its bytes
match the freeze's SHA-256. The index's evidence files are hardlinked (copied if linking fails) into the same tree,
so code root and evidence root coincide and the frozen code runs unpatched. The replay copies each trial before it
writes any verdict, and it re-checks every indexed hash first. Every repository module the replay loads must be a
verified file of the frozen tree: a module from the live repository, or a tree file whose bytes did not match the
freeze, is reported as unverified, and the run refuses to start if a frozen module name is already loaded.
Standard-library and site-packages modules are listed as the environment. Exit codes: 0 replay reproduced, 1 replay
did not complete, 2 audit failure (unverified module or preloaded name).

Modes, reported separately:
  original          the frozen replay, unadapted (three-connection trials stop at the missing result.json);
  scenario_adapter  the same tree plus replay_scenario_adapter.py (hash recorded), which reads scenario.json for
                    those trials.
A reproduced replay means the recorded verdicts were reproduced, including recorded failures; it does not mean the
trials passed.

  python3 scripts/analysis/replay_frozen.py --campaign CAMPAIGN_DIR --index INDEX_JSON --mode MODE --output OUT.json
"""
import argparse
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[2]
SCHEMA = 'c72-replay-frozen-v1'
DEFAULT_COMMIT = 'b2634701d'      # first commit of the current layout; the checker closure is unchanged there


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git_blob(commit):
    def read(path):
        result = subprocess.run(['git', '-C', str(REPO), 'show', '%s:%s' % (commit, path)], capture_output=True)
        return result.stdout if result.returncode == 0 else None
    return read


def materialize(freeze_files, read_blob, dest):
    """Write each freeze-listed scripts/ file whose bytes match the freeze; report the rest."""
    report = dict(verified=[], mismatched=[], missing=[])
    for path in sorted(p for p in freeze_files if p.startswith('scripts/')):
        data = read_blob(path)
        if data is None:
            report['missing'].append(path)
        elif sha(data) != freeze_files[path]['sha256']:
            report['mismatched'].append(path)
        else:
            target = Path(dest) / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            report['verified'].append(path)
    return report


def inside(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def audit_loaded(module_files, tree, verified, repo=REPO):
    """Sort loaded modules: verified frozen-tree files, unverified repository files, and the environment."""
    tree, repo = Path(tree).resolve(), Path(repo).resolve()
    seen = dict(verified=[], unverified=[], environment=[])
    for name in sorted(module_files):
        if not module_files[name]:
            continue                                         # built-in module without a file
        path = Path(module_files[name]).resolve()
        if inside(path, tree):
            rel = str(path.relative_to(tree))
            seen['verified' if rel in verified else 'unverified'].append(rel)
        elif inside(path, repo):
            seen['unverified'].append('%s (live repository)' % path.relative_to(repo))
        else:
            seen['environment'].append(name)
    return {key: sorted(values) for key, values in seen.items()}


def preloaded(frozen_names, modules):
    """Frozen module names already present in the process would be reused instead of the frozen files."""
    return sorted(name for name in frozen_names if name in modules)


def link_evidence(index_path, tree):
    """Hardlink (or copy) the index and every file it binds into the tree at the same relative path."""
    index_rel = Path(index_path).resolve().relative_to(REPO)
    paths = [index_rel] + [Path(p) for p in json.loads(Path(index_path).read_text())['files']]
    for rel in paths:
        target = Path(tree) / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.link(REPO / rel, target)
        except OSError:
            shutil.copy2(REPO / rel, target)
    return Path(tree) / index_rel, len(paths)


def recorded_outcomes(manifest):
    """Per block, the trials and the verdicts the live campaign recorded in trial.json."""
    outcomes = {}
    for step in json.loads(Path(manifest).read_text())['steps']:
        root = REPO / Path(step['run_root']).relative_to(Path(step['run_root']).parents[3])
        trials = sorted(root.glob('*/*/*/trial.json'))
        failed = [json.loads(t.read_text())['label'] for t in trials if json.loads(t.read_text()).get('ok') is not True]
        outcomes[step['id']] = dict(trials=len(trials), recorded_ok=len(trials) - len(failed), recorded_fail=failed)
    return outcomes


def run(campaign, index, mode, commit):
    freeze = json.loads((Path(campaign) / 'freeze.json').read_text())
    with tempfile.TemporaryDirectory(prefix='dnp3_frozen_tree_') as tree:
        report = materialize(freeze['files'], git_blob(commit), tree)
        tree_index, linked = link_evidence(index, tree)
        frozen_names = {p.stem for d in ('scripts/hardware', 'scripts/checks') for p in (Path(tree) / d).glob('*.py')}
        collisions = preloaded(frozen_names, sys.modules)
        if collisions:
            raise SystemExit('refusing: frozen module names already loaded: %s' % ', '.join(collisions))
        sys.path[:0] = [str(Path(tree) / 'scripts/hardware'), str(Path(tree) / 'scripts/checks')]
        before = set(sys.modules)
        replay = importlib.import_module('replay')
        adapter = None
        if mode == 'scenario_adapter':
            sys.path.insert(0, str(REPO / 'scripts/analysis'))
            import replay_scenario_adapter
            replay_scenario_adapter.install(replay)
            path = Path(replay_scenario_adapter.__file__)
            adapter = dict(path=str(path.relative_to(REPO)), sha256=sha(path.read_bytes()))
        result = replay.replay_index(tree_index)
        loaded = {name: getattr(sys.modules[name], '__file__', '') or '' for name in set(sys.modules) - before}
        loaded.pop('replay_scenario_adapter', None)          # the declared addition; its SHA-256 is under 'adapter'
        audit = audit_loaded(loaded, tree, set(report['verified']))
    manifest = REPO / json.loads(Path(index).read_text())['matrix_manifest']
    outcomes = recorded_outcomes(manifest)
    failed = sorted(b for b, o in outcomes.items() if o['recorded_fail'])
    statement = ('%d exchanges accounted for in replay (%s); recorded verdicts reproduced; blocks with a recorded '
                 'FAIL: %s' % (result['exchanges'], mode, ', '.join(failed) or 'none'))
    if result['failures']:
        statement = 'replay did not complete (%s): %d exchanges reached; first failure: %s' % (
            mode, result['exchanges'], result['failures'][0])
    return dict(schema=SCHEMA, mode=mode, campaign=str(Path(campaign).resolve().relative_to(REPO)),
                index=str(Path(index).resolve().relative_to(REPO)), commit=commit,
                freeze_version=freeze.get('freeze_version'), materialized=report, evidence_files_linked=linked,
                loaded_modules=audit,
                adapter=adapter, replay=result, recorded_block_outcomes=outcomes, statement=statement)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--campaign', type=Path, required=True)
    parser.add_argument('--index', type=Path, required=True)
    parser.add_argument('--mode', choices=('original', 'scenario_adapter'), required=True)
    parser.add_argument('--commit', default=DEFAULT_COMMIT)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    report = run(args.campaign, args.index, args.mode, args.commit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=1, sort_keys=True) + '\n')
    print(report['statement'])
    if report['loaded_modules']['unverified']:
        return 2
    return 1 if report['replay']['failures'] else 0


if __name__ == '__main__':
    raise SystemExit(main())
