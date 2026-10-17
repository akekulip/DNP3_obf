#!/usr/bin/env python3
"""Freeze record (version 2) for one build and its silicon blocks, and the check that gates every block.

  python3 freeze_gate.py write BUILD_DIR -o FREEZE.json --configs CONFIG [CONFIG ...] [--regen PATH=COMMAND ...]
                                [--diagnostic-exception REASON]
  python3 freeze_gate.py check FREEZE.json [--config CONFIG] [--record OUT.json]   # exit 1 on any failure

Review of 7637390c1 (freeze and reproducibility): the m9_01 freeze pinned the build and the caller scripts, but not
the acceptance modules that make the judgment (protocol/hw_vepa campaign.py, standards.py, clrt_check.py,
hold_check.py and others). Version 2 pins:
- the build's P4 source, inputs and generator copy;
- both compiles' manifests, bfrt.json, p4pp and tofino.bin;
- every non-test Python file of the harness, acceptance and installer directories (HARNESS_DIRS);
- run_block.sh;
- the verdict analysis scripts (ANALYSIS);
- the named block configs.
A pinned file that git does not track (compiler outputs; a config matching an ignore pattern) is listed with
`tracked: false`. A missing one fails the check with its regeneration command when one was recorded, so a fresh
clone fails clearly instead of passing silently. The check result can be retained beside the block's evidence
(--record); run_block_frozen.sh does that before calling run_block.sh.

Version 3 (review of af7bd434; Philip 2026-10-17: bind the runner to the actual candidate) adds one `candidate`
record: the source sha256, each compile's artifacts, the build's model_summary_v3.json (its hash, recomputed
verdict and summary version), the frozen config set, and an optional diagnostic_exception. It also pins every file
in the model runs' dependency closures. `check --config CONFIG` then requires the supplied config to belong to that
one candidate. The checks are listed in candidate_binding(). Matching several files to hashes one by one is not
enough.
"""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HW = Path(__file__).resolve().parent
REPO = HW.parents[6]
A = 'defense4/timing/case4_architecture/'
HARNESS_DIRS = (A + 'protocol/hw_vepa', A + 'integration/evidence/rearm_01/hw',
                A + 'integration/core/response_only_rearm/hw', A + 'integration/core/response_only/hw')
HARNESS_FILES = (A + 'integration/evidence/rearm_01/hw/run_block.sh', A + 'integration/core/response_only_rearm/cp.py',
                 # row builders and the switch-side scripts that install and restore (review of round 2)
                 A + 'integration/core/response_only/cp.py', A + 'integration/core/response_only/port_map.py',
                 A + 'protocol/response_path_cp.py')
HARNESS_GLOBS = ('*.py', '*.sh')                 # in every HARNESS_DIRS directory
BASELINE_DIRS = (A + 'integration/evidence/rearm_01/hw/restore_baseline',)
ANALYSIS = (A + 'integration/core/response_only_rearm/stage_experiments/seg61_02/analysis/m5_summary.py',
            A + 'integration/core/response_only_rearm/stage_experiments/seg61_02/analysis/isolation_v3.py',
            A + 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/model_summary.py',
            A + 'integration/core/response_only_rearm/stage_experiments/seg61_02/analysis/ack_diag.py')
BUILD_FILES = ('response_only.p4', 'response_only.inputs.json', 'generate.py', 'resource_review.json')
COMPILE_FILES = ('manifest.json', 'out/bfrt.json', 'out/response_only.p4pp', 'out/p0/tofino.bin', 'out/p1/tofino.bin')
COMPILES = ('compile_local', 'compile_switch_9132')
LOADED_COMPILE = 'compile_switch_9132'           # the compile the switch loads (SDK 9.13.2)
FREEZE_V3 = 'freeze-v3-20261017'
CASE4 = A                                       # configs give paths relative to case4_architecture/


def sha(path):
    return hashlib.sha256((REPO / path).read_bytes()).hexdigest()


def tracked(path):
    return subprocess.run(['git', '-C', str(REPO), 'ls-files', '--error-unmatch', path],
                          capture_output=True).returncode == 0


def rel(path):
    return str(Path(path).resolve().relative_to(REPO))


def collect(build, configs):
    files = [rel(build / f) for f in BUILD_FILES if (build / f).is_file()]
    files += [rel(build / c / f) for c in ('compile_local', 'compile_switch_9132') for f in COMPILE_FILES]
    files += [rel(build / c / 'out' / f) for c in COMPILES for f in manifest_artifacts(build, c)]
    for d in HARNESS_DIRS:
        for g in HARNESS_GLOBS:
            files += [rel(p) for p in sorted((REPO / d).glob(g))]
    for d in BASELINE_DIRS:
        files += [rel(p) for p in sorted((REPO / d).rglob('*')) if p.is_file()]
    files += list(HARNESS_FILES) + list(ANALYSIS) + [rel(c) for c in configs]
    files += closure_files(build)
    return sorted(set(files))


def model_summary_module():
    import importlib.util
    path = HW.parents[2] / 'core/response_only_rearm/stage_experiments/ctl_timing_01/model_summary.py'
    spec = importlib.util.spec_from_file_location('model_summary', path)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    spec.loader.exec_module(module)
    return module


def latest_attempts(build):
    """{driver: run directory name} of the build's latest model attempts (model_summary's own matching)."""
    latest = {}
    for r in model_summary_module().attempts(Path(build).resolve()):
        if r['driver'] not in latest or r['attempt'] > latest[r['driver']]['attempt']:
            latest[r['driver']] = r
    return {d: r['run'] for d, r in sorted(latest.items())}


def closure_files(build):
    """Every repository file in the dependency closures of the build's latest model attempts."""
    out = []
    for run in latest_attempts(build).values():
        closure = build.parent / run / 'dependency_closure.json'
        if closure.is_file():
            out += list(json.loads(closure.read_text()).get('files', {}))
    return out


def manifest_artifacts(build, compile_dir):
    """Every artifact a compile's manifest lists (review finding 2: context.json, .conf and .bfa are loaded too)."""
    path = build / compile_dir / 'manifest.json'
    if not path.is_file():
        return []
    return sorted(k for k in json.loads(path.read_text()).get('artifact_sha256', {}) if k != 'manifest.json')


def compile_problems(build, source):
    """Why a compile does not belong to this source (review finding 1): its manifest must name the source, exit 0,
    and every artifact it lists must be on disk at the recorded sha256."""
    problems = []
    for c in COMPILES:
        path = build / c / 'manifest.json'
        if not path.is_file():
            problems.append('%s: no manifest' % c)
            continue
        m = json.loads(path.read_text())
        if m.get('source_sha256') != source:
            problems.append('%s: manifest source %s is not the build source %s' % (c, m.get('source_sha256'), source))
        if m.get('exit_code') != 0:
            problems.append('%s: compile exit %s' % (c, m.get('exit_code')))
        for f in manifest_artifacts(build, c):
            target = build / c / 'out' / f
            if not target.is_file():
                problems.append('%s: %s missing' % (c, f))
            elif sha(rel(target)) != m['artifact_sha256'][f]:
                problems.append('%s: %s on disk differs from its manifest' % (c, f))
    return problems


def write(a):
    build = Path(a.build).resolve()
    files = collect(build, a.configs)
    missing = [f for f in files if not (REPO / f).is_file()]
    if missing:
        raise SystemExit('cannot freeze, missing: ' + ' '.join(missing))
    regen = dict(item.split('=', 1) for item in a.regen or [])
    source = sha(rel(build / 'response_only.p4'))
    bad = compile_problems(build, source)
    if bad:
        raise SystemExit('cannot freeze, compiles not bound to the source: ' + '; '.join(bad))
    candidate = candidate_record(build, source, a.configs, a.diagnostic_exception)
    if candidate['model']['qualification'] != 'model_gate_passed' and not a.diagnostic_exception:
        raise SystemExit('cannot freeze a qualifying candidate: model gate %s (%s); a diagnostic block needs '
                         '--diagnostic-exception REASON' % (candidate['model']['qualification'],
                                                             '; '.join(candidate['model']['blocked_reasons'][:3])))
    summary = build / 'model_summary_v3.json'
    if summary.is_file():
        files = sorted(set(files + [rel(summary)]))
    record = dict(freeze_version=FREEZE_V3, build=rel(build), source_sha256=source, candidate=candidate,
                  files={f: dict(sha256=sha(f), tracked=tracked(f), regenerate=regen.get(f)) for f in files},
                  note='checked before every block by run_block_frozen.sh (freeze_gate.py check --config --record)')
    Path(a.output).write_text(json.dumps(record, indent=1) + '\n')
    print('wrote', a.output, len(files), 'files,', sum(not v['tracked'] for v in record['files'].values()), 'untracked')
    return 0


def candidate_record(build, source, configs, exception):
    """The one identity a block's config must match (version 3)."""
    ms = model_summary_module()
    summary = build / 'model_summary_v3.json'
    live = ms.summarize_v3(build)
    stored = json.loads(summary.read_text()) if summary.is_file() else None
    if stored is None:
        qualification, reasons = 'blocked', ['no model_summary_v3.json for this build']
    elif (stored.get('summary_version') != ms.SUMMARY_V3 or stored.get('source_sha256') != source
          or stored.get('qualification') != live['qualification']
          or stored.get('blocked_reasons') != live['blocked_reasons']):
        qualification, reasons = 'blocked', ['model_summary_v3.json is stale or not this source; rerun '
                                             'model_summary.py --v3 --write']
    else:
        qualification, reasons = live['qualification'], live['blocked_reasons']
    artifacts = {c: dict({f: sha(rel(build / c / f)) for f in COMPILE_FILES},
                         **{'out/' + f: sha(rel(build / c / 'out' / f)) for f in manifest_artifacts(build, c)})
                 for c in COMPILES}
    return dict(source_sha256=source, build=rel(build),
                loaded_compile=dict(out_dir=rel(build / LOADED_COMPILE / 'out'),
                                    manifest=rel(build / LOADED_COMPILE / 'manifest.json')),
                artifacts=artifacts,
                model=dict(summary=rel(summary) if stored is not None else None,
                           summary_sha256=sha(rel(summary)) if stored is not None else None,
                           summary_version=ms.SUMMARY_V3, qualification=qualification, blocked_reasons=reasons,
                           latest_by_driver=live['latest_by_driver']),
                configs={rel(c): sha(rel(c)) for c in configs},
                diagnostic_exception=(dict(reason=exception, qualifies=False) if exception else None))


def _case4(path):
    """A config path (relative to case4_architecture/) as a repository path."""
    return str(Path(CASE4) / path) if path else None


def candidate_binding(frozen, config):
    """Problems binding CONFIG to the frozen candidate ([] = bound). Required:
    - the freeze is version 3 and carries a candidate record;
    - the config file is one of the candidate's frozen configs, at its frozen sha256;
    - every build the config can load (cfg['builds']) names the candidate's source sha256, its loaded compile's
      out_dir and manifest, and any pinned artifact hash equals the candidate's;
    - ctl_timing_identity names the same source and the same loaded compile;
    - the model verdict is model_gate_passed, or a diagnostic exception is recorded (its blocks do not qualify)."""
    cand = frozen.get('candidate')
    if frozen.get('freeze_version') != FREEZE_V3 or not cand:
        return ['freeze %s has no candidate record (version 3 required)' % frozen.get('freeze_version')]
    problems = []
    path = rel(config)
    if cand['configs'].get(path) is None:
        problems.append('config %s is not one of the candidate\'s frozen configs' % path)
    elif sha(path) != cand['configs'][path]:
        problems.append('config %s changed since the freeze' % path)
    cfg = json.loads(Path(config).read_text())
    loaded = cand['loaded_compile']
    out_hashes = {f[len('out/'):]: h for f, h in cand['artifacts'][LOADED_COMPILE].items() if f.startswith('out/')}
    builds = cfg.get('builds') or {}
    if not builds:
        problems.append('config names no build')
    for name, b in sorted(builds.items()):
        if b.get('source_sha256') != cand['source_sha256']:
            problems.append('build %s: source %s is not the candidate %s' % (name, b.get('source_sha256'),
                                                                             cand['source_sha256']))
        if _case4(b.get('out_dir')) != loaded['out_dir']:
            problems.append('build %s: out_dir %s is not the candidate\'s %s' % (name, b.get('out_dir'),
                                                                                  loaded['out_dir']))
        if _case4(b.get('manifest')) != loaded['manifest']:
            problems.append('build %s: manifest %s is not the candidate\'s' % (name, b.get('manifest')))
        for f, h in sorted((b.get('hashes') or {}).items()):
            if h is not None and f in out_hashes and h != out_hashes[f]:
                problems.append('build %s: hashes[%s] is not the candidate\'s artifact' % (name, f))
    ident = cfg.get('ctl_timing_identity') or {}
    if ident.get('source_sha256') != cand['source_sha256']:
        problems.append('ctl_timing_identity.source_sha256 %s is not the candidate' % ident.get('source_sha256'))
    if _case4((ident.get('switch_compile') or {}).get('out_dir')) != loaded['out_dir']:
        problems.append('ctl_timing_identity.switch_compile.out_dir is not the candidate\'s loaded compile')
    if cand['model']['qualification'] != 'model_gate_passed' and not cand.get('diagnostic_exception'):
        problems.append('model gate %s and no diagnostic exception' % cand['model']['qualification'])
    # review finding 4: an exception admits only a config that declares itself diagnostic (fail closed)
    if cand.get('diagnostic_exception') and cfg.get('purpose') != 'diagnostic':
        problems.append('diagnostic exception recorded, but config purpose is %r, not "diagnostic"' % cfg.get('purpose'))
    build = REPO / cand['build']
    problems += ['compile: ' + p for p in compile_problems(build, cand['source_sha256'])]
    # review finding 3: the model verdict is recomputed before every block; a later attempt or failure note blocks
    live = model_summary_module().summarize_v3(build)
    if (live['qualification'] != cand['model']['qualification']
            or live.get('latest_by_driver') != cand['model'].get('latest_by_driver')):
        problems.append('model evidence changed since the freeze: now %s, latest %s'
                        % (live['qualification'], live.get('latest_by_driver')))
    return problems


def check(a):
    frozen = json.loads(Path(a.freeze).read_text())
    changed, missing = [], []
    for f, v in frozen['files'].items():
        if not (REPO / f).is_file():
            missing.append(dict(path=f, regenerate=v.get('regenerate')))
        elif sha(f) != v['sha256']:
            changed.append(f)
    where = Path(a.freeze).resolve()
    result = dict(freeze=str(where.relative_to(REPO)) if REPO in where.parents else str(where), freeze_version=frozen.get('freeze_version'), source_sha256=frozen['source_sha256'],
                  files=len(frozen['files']), changed=changed, missing=missing, ok=not changed and not missing)
    if a.config:
        binding = candidate_binding(frozen, a.config)
        cand = frozen.get('candidate') or {}
        result.update(config=rel(a.config), config_sha256=sha(rel(a.config)), candidate_binding=binding,
                      model_qualification=(cand.get('model') or {}).get('qualification'),
                      diagnostic_exception=cand.get('diagnostic_exception'),
                      qualifies=not binding and (cand.get('model') or {}).get('qualification') == 'model_gate_passed'
                      and not cand.get('diagnostic_exception'))
        result['ok'] = result['ok'] and not binding
    if a.record:
        Path(a.record).parent.mkdir(parents=True, exist_ok=True)
        Path(a.record).write_text(json.dumps(result, indent=1) + '\n')
    print('freeze check:', 'OK' if result['ok'] else 'FAILED', len(changed), 'changed,', len(missing), 'missing')
    for m in missing:
        print('  missing', m['path'], ('regenerate: ' + m['regenerate']) if m['regenerate'] else '')
    for c in changed:
        print('  changed', c)
    for b in result.get('candidate_binding', []):
        print('  not bound:', b)
    if result.get('diagnostic_exception'):
        print('  DIAGNOSTIC EXCEPTION (does not qualify):', result['diagnostic_exception']['reason'])
    return 0 if result['ok'] else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    w = sub.add_parser('write')
    w.add_argument('build')
    w.add_argument('-o', '--output', required=True)
    w.add_argument('--configs', nargs='+', default=[])
    w.add_argument('--regen', nargs='*', help='PATH=COMMAND for a file git does not track')
    w.add_argument('--diagnostic-exception', help='freeze a build whose model gate is not passed, for diagnostic '
                   'blocks only; recorded, and those blocks do not qualify the candidate')
    c = sub.add_parser('check')
    c.add_argument('freeze')
    c.add_argument('--config', help='the block config; it must belong to the frozen candidate')
    c.add_argument('--record')
    a = ap.parse_args(argv)
    return write(a) if a.cmd == 'write' else check(a)


if __name__ == '__main__':
    sys.exit(main())
