"""Freeze the current source, compile, 17-model verdict, checker closure and exact hardware configs."""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
HW=Path(__file__).resolve().parent
REPO=HW.parents[1]
FREEZE_V3='freeze-v3-20261017'
COMPILE_FILES=('manifest.json','compile.log','compiler_evidence.json','compiler_evidence.tar.xz',
               'out/bfrt.json','out/response_only.p4pp','out/p0/tofino.bin','out/p1/tofino.bin')
BUILD_FILES=('response_only.p4','response_only.inputs.json','supported_profile.json','resource_review.json')
CANONICAL_P4='p4/response_only.p4'
# A declared diagnostic build (scripts/build_diag_mirror.py) carries DIAG_IDENTITY; its model evidence lives in
# DIAG_MODELS/<build name>/ and replaces the model gate for its own, never-qualifying, diagnostic blocks.
DIAG_IDENTITY='diag_mirror.json'
DIAG_GENERATOR='scripts/build_diag_mirror.py'
DIAG_MODELS='results/models'
DIAG_EVIDENCE=('diag_mirror_fidelity_01.json','gate_vs_c72_01.json')
DIAG_QUALIFICATION='diagnostic_model_evidence'

def sha(path):
    return hashlib.sha256((REPO / path).read_bytes()).hexdigest()


def tracked(path):
    return subprocess.run(['git', '-C', str(REPO), 'ls-files', '--error-unmatch', path],
                          capture_output=True).returncode == 0


def rel(path):
    return str(Path(path).resolve().relative_to(REPO))


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
        closure = model_summary_module().model_root(build) / run / 'dependency_closure.json'
        if closure.is_file():
            out += list(json.loads(closure.read_text()).get('files', {}))
    return out


def manifest_artifacts(build, compile_dir):
    """Every artifact a compile's manifest lists (context.json, .conf and .bfa are loaded too)."""
    path = build / compile_dir / 'manifest.json'
    if not path.is_file():
        return []
    return sorted(k for k in json.loads(path.read_text()).get('artifact_sha256', {}) if k != 'manifest.json')


def write(a):
    build = Path(a.build).resolve()
    files = collect(build, a.configs)
    if declared_diagnostic(build):
        files = sorted(set(files + [str(Path(rel(build)) / DIAG_IDENTITY)] + diagnostic_evidence_paths(build)))
    missing = [f for f in files if not (REPO / f).is_file()]
    if missing:
        raise SystemExit('cannot freeze, missing: ' + ' '.join(missing))
    regen = dict(item.split('=', 1) for item in a.regen or [])
    source = sha(rel(build / 'response_only.p4'))
    bad = compile_problems(build, source)
    if bad:
        raise SystemExit('cannot freeze, compiles not bound to the source: ' + '; '.join(bad))
    candidate = candidate_record(build, source, a.configs, a.diagnostic_exception)
    if candidate.get('diagnostic'):
        bad = diagnostic_evidence_problems(build)
        if bad:
            raise SystemExit('cannot freeze a diagnostic candidate: ' + '; '.join(bad))
    elif candidate['model']['qualification'] != 'model_gate_passed':
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
    """The one identity a block's config must match (version 3). A declared diagnostic build records its two model
    evidence hashes instead of the model gate (summarize_v3 is not consulted), diagnostic=True and qualifies=False."""
    diagnostic = declared_diagnostic(build)
    if diagnostic:
        model = dict(qualification=DIAG_QUALIFICATION, evidence=diagnostic_evidence(build))
    else:
        model = canonical_model_record(build, source)
    artifacts = {c: dict({f: sha(rel(build / c / f)) for f in COMPILE_FILES},
                         **{'out/' + f: sha(rel(build / c / 'out' / f)) for f in manifest_artifacts(build, c)})
                 for c in build_compiles(build)}
    record = dict(source_sha256=source, build=rel(build),
                  loaded_compile=dict(out_dir=rel(build / loaded_compile(build) / 'out'),
                                      manifest=rel(build / loaded_compile(build) / 'manifest.json')),
                  artifacts=artifacts, model=model,
                  configs={rel(c): sha(rel(c)) for c in configs},
                  diagnostic_exception=(dict(reason=exception, qualifies=False) if exception else None))
    if diagnostic:
        record.update(diagnostic=True, qualifies=False)
    return record


def canonical_model_record(build, source):
    """The model-gate verdict of a canonical build, from the stored and the live model_summary_v3."""
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
                                             'model_summary.py --write']
    else:
        qualification, reasons = live['qualification'], live['blocked_reasons']
    return dict(summary=rel(summary) if stored is not None else None,
                summary_sha256=sha(rel(summary)) if stored is not None else None,
                summary_version=ms.SUMMARY_V3, qualification=qualification, blocked_reasons=reasons,
                latest_by_driver=live['latest_by_driver'])


def candidate_binding(frozen, config):
    """Problems binding CONFIG to the frozen candidate ([] = bound). Required:
    - the freeze is version 3 and carries a candidate record;
    - the config file is one of the candidate's frozen configs, at its frozen sha256;
    - every build the config can load (cfg['builds']) names the candidate's source sha256, its loaded compile's
      out_dir and manifest, and any pinned artifact hash equals the candidate's;
    - ctl_timing_identity names the same source and the same loaded compile;
    - canonical candidate: the model verdict is model_gate_passed and the live summarize_v3 still agrees;
    - diagnostic candidate (diagnostic=True, and the build still declares diag_mirror.json): the config purpose is
      'diagnostic', cfg['diag_mirror']['source_sha256'] is the candidate source, compile_problems re-admits the
      build (diagnostic_problems) and both model evidence files still have their frozen sha256."""
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
    loaded_name = Path(loaded['manifest']).parent.name    # compile_switch_9132, or compile_local on a one-SDK build
    out_hashes = {f[len('out/'):]: h for f, h in cand['artifacts'][loaded_name].items() if f.startswith('out/')}
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
    build = REPO / cand['build']
    declared = declared_diagnostic(build)
    diagnostic = cand.get('diagnostic') is True or declared
    if (cand.get('diagnostic') is True) != declared:
        problems.append('candidate diagnostic flag %r disagrees with the build (%s %s)'
                        % (cand.get('diagnostic'), DIAG_IDENTITY, 'present' if declared else 'absent'))
    if diagnostic:
        problems += diagnostic_binding_problems(cand, cfg, build)
    elif cand['model']['qualification'] != 'model_gate_passed':
        problems.append('model gate %s and no diagnostic exception' % cand['model']['qualification'])
    # an exception admits only a config that declares itself diagnostic (fail closed)
    if cand.get('diagnostic_exception') and cfg.get('purpose') != 'diagnostic':
        problems.append('diagnostic exception recorded, but config purpose is %r, not "diagnostic"' % cfg.get('purpose'))
    problems += ['compile: ' + p for p in compile_problems(build, cand['source_sha256'])]
    if diagnostic:
        return problems
    # the model verdict is recomputed before every block; a later attempt or failure note blocks
    live = model_summary_module().summarize_v3(build)
    if (live['qualification'] != cand['model']['qualification']
            or live.get('latest_by_driver') != cand['model'].get('latest_by_driver')):
        problems.append('model evidence changed since the freeze: now %s, latest %s'
                        % (live['qualification'], live.get('latest_by_driver')))
    return problems


def diagnostic_binding_problems(cand, cfg, build):
    """The diagnostic part of candidate_binding (the build's admission is rechecked by compile_problems)."""
    problems = []
    if cfg.get('purpose') != 'diagnostic':
        problems.append('diagnostic candidate, but config purpose is %r, not "diagnostic"' % cfg.get('purpose'))
    mirror = cfg.get('diag_mirror') if isinstance(cfg.get('diag_mirror'), dict) else {}
    if mirror.get('source_sha256') != cand['source_sha256']:
        problems.append('diag_mirror.source_sha256 %s is not the candidate build source %s'
                        % (mirror.get('source_sha256'), cand['source_sha256']))
    if cand['model'].get('qualification') != DIAG_QUALIFICATION:
        problems.append('diagnostic candidate model qualification %r is not %s'
                        % (cand['model'].get('qualification'), DIAG_QUALIFICATION))
    now = diagnostic_evidence(build)
    if not cand['model'].get('evidence') or now != cand['model'].get('evidence'):
        problems.append('diagnostic model evidence changed since the freeze: now %s' % now)
    return problems


def check(a):
    frozen = json.loads(Path(a.freeze).read_text())
    build = REPO / frozen['build']
    compile_dir = build / 'compile_local'
    prefix = rel(compile_dir) + '/'
    missing_compile = any(name.startswith(prefix) and not (REPO/name).is_file()
                          for name in frozen['files'])
    if missing_compile:
        retained = [compile_dir/name for name in ('compiler_evidence.json','compiler_evidence.tar.xz')]
        if all(path.is_file() and (frozen['files'].get(rel(path)) or {}).get('sha256') == sha(rel(path))
               for path in retained):
            compiler_module().restore_evidence(compile_dir, source_root=build)
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
                      and not cand.get('diagnostic_exception') and not cand.get('diagnostic'))
        if cand.get('diagnostic'):
            result['diagnostic'] = True
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
    if result.get('diagnostic'):
        print('  DIAGNOSTIC BUILD (blocks do not qualify):', frozen['build'])
    return 0 if result['ok'] else 1


def model_summary_module():
    import importlib.util
    path=REPO/'scripts/model/model_summary.py'
    sys.path.insert(0,str(path.parent))
    spec=importlib.util.spec_from_file_location('current_model_summary',path)
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build_compiles(build):
    return ('compile_local',)


def loaded_compile(build):
    return 'compile_local'


def _case4(path):
    if not path:return None
    value=Path(path)
    return str(value.resolve().relative_to(REPO)) if value.is_absolute() else str(value)


def config_closure(configs):
    sys.path[:0]=[str(HW),str(HW.parent/'checks')]
    import endpoint_profiles
    import campaign_base
    files=[]
    for path in configs:
        cfg=campaign_base.load_config(path)
        files += [rel(p)for p in endpoint_profiles.native_observation_files(cfg)]
    return files


def collect(build,configs):
    files=[rel(build/name)for name in BUILD_FILES if (build/name).is_file()]
    files += [rel(build/c/name)for c in build_compiles(build)for name in COMPILE_FILES]
    files += [rel(build/c/'out'/name)for c in build_compiles(build)for name in manifest_artifacts(build,c)]
    files += [rel(path) for c in build_compiles(build) for path in (build/c/'source').rglob('*') if path.is_file()]
    files += [rel(p)for folder in ('scripts','p4')for p in (REPO/folder).rglob('*')
              if p.is_file()and p.suffix in ('.py','.sh','.json','.p4','.c','.txt') and '__pycache__'not in p.parts]
    sys.path.insert(0,str(REPO/'scripts/model'))
    import retained_logs
    files += [rel(p)for p in retained_logs.retained_files(build)]
    files += [rel(c)for c in configs]+closure_files(build)+config_closure(configs)
    return sorted(set(files))


def declared_diagnostic(build):
    """A build declares itself diagnostic by carrying diag_mirror.json (anything at that path, even a dangling link)."""
    path = Path(build) / DIAG_IDENTITY
    return path.exists() or path.is_symlink()


def diagnostic_problems(build, source):
    """Problems admitting BUILD as a declared diagnostic build ([] = admitted). All must hold:
    - build/diag_mirror.json is a readable JSON object;
    - its canonical_sha256 is the sha256 of p4/response_only.p4 now;
    - its generator_sha256 is the sha256 of scripts/build_diag_mirror.py now;
    - the generator's own derive(), run in-process on the canonical file, reproduces build/response_only.p4 byte for
      byte (a generator that is not the hashed one is refused and never executed);
    - its source_sha256 is the sha256 of build/response_only.p4, and so is the candidate SOURCE."""
    build = Path(build)
    try:
        meta = json.loads((build / DIAG_IDENTITY).read_text())
    except (OSError, ValueError) as error:
        return ['%s unreadable: %s' % (DIAG_IDENTITY, error)]
    if not isinstance(meta, dict):
        return ['%s is not a JSON object' % DIAG_IDENTITY]
    try:
        canonical, generator = sha(CANONICAL_P4), sha(DIAG_GENERATOR)
        derived = (build / 'response_only.p4').read_bytes()
    except OSError as error:
        return ['diagnostic admission inputs unreadable: ' + str(error)]
    problems = []
    if meta.get('canonical_sha256') != canonical:
        problems.append('%s canonical_sha256 %s is not the current %s %s'
                        % (DIAG_IDENTITY, meta.get('canonical_sha256'), CANONICAL_P4, canonical))
    if meta.get('generator_sha256') != generator:
        problems.append('%s generator_sha256 %s is not the current %s %s'
                        % (DIAG_IDENTITY, meta.get('generator_sha256'), DIAG_GENERATOR, generator))
        problems.append('derived source not regenerated: the generator is not the one %s names' % DIAG_IDENTITY)
    else:
        try:
            regenerated = diag_generator().derive((REPO / CANONICAL_P4).read_text())[0].encode()
            if regenerated != derived:
                problems.append("regenerating %s with the generator's derive() does not reproduce %s"
                                % (CANONICAL_P4, build / 'response_only.p4'))
        except (OSError, ValueError, TypeError, AttributeError, ImportError, SyntaxError) as error:
            problems.append('derived source cannot be regenerated: %s' % error)
    digest = hashlib.sha256(derived).hexdigest()
    if meta.get('source_sha256') != digest:
        problems.append('%s source_sha256 %s is not the build source %s' % (DIAG_IDENTITY, meta.get('source_sha256'),
                                                                             digest))
    if source != digest:
        problems.append("candidate source %s is not the build's derived source %s" % (source, digest))
    return problems


def diag_generator():
    import importlib.util
    spec=importlib.util.spec_from_file_location('current_diag_generator',REPO/DIAG_GENERATOR)
    generator=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    return generator


def diagnostic_evidence_paths(build):
    return [str(Path(DIAG_MODELS) / Path(build).name / name) for name in DIAG_EVIDENCE]


def diagnostic_evidence(build):
    """{path: sha256 or None if unreadable} of the build's two diagnostic model evidence files."""
    return {path: sha(path) if (REPO / path).is_file() else None for path in diagnostic_evidence_paths(build)}


def diagnostic_evidence_problems(build):
    """Problems with the diagnostic model evidence a freeze binds ([] = usable): the fidelity record passed (true)
    for this build's source; gate_vs_c72 names this build and lists every required model driver, each with
    verdicts_identical true and diag_exit_code 0."""
    build = Path(build)
    values, problems = {}, []
    for name, path in zip(DIAG_EVIDENCE, diagnostic_evidence_paths(build)):
        try:
            values[name] = json.loads((REPO / path).read_text())
        except (OSError, ValueError) as error:
            problems.append('diagnostic evidence %s unreadable: %s' % (path, error))
    if problems:
        return problems
    fidelity, gate = values[DIAG_EVIDENCE[0]], values[DIAG_EVIDENCE[1]]
    if not isinstance(fidelity, dict) or not isinstance(gate, dict):
        return ['diagnostic evidence is not a JSON object']
    try:
        source = hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest()
        required = set(model_summary_module().required_drivers(build))
    except (OSError, ValueError, KeyError, TypeError) as error:
        return ['diagnostic evidence cannot be checked: %s' % error]
    if fidelity.get('passed') is not True:
        problems.append('%s: fidelity passed is %r, not true' % (DIAG_EVIDENCE[0], fidelity.get('passed')))
    if fidelity.get('source_sha256') != source:
        problems.append('%s: source_sha256 %s is not the build source %s'
                        % (DIAG_EVIDENCE[0], fidelity.get('source_sha256'), source))
    if gate.get('build') != build.name:
        problems.append('%s: build %r is not %s' % (DIAG_EVIDENCE[1], gate.get('build'), build.name))
    drivers = gate.get('drivers') if isinstance(gate.get('drivers'), dict) else {}
    if required - set(drivers):
        problems.append('%s: required drivers missing: %s' % (DIAG_EVIDENCE[1], sorted(required - set(drivers))))
    for driver, verdict in sorted(drivers.items()):
        verdict = verdict if isinstance(verdict, dict) else {}
        code = verdict.get('diag_exit_code')
        if verdict.get('verdicts_identical') is not True or type(code) is not int or code != 0:
            problems.append('%s: driver %s verdicts_identical %r, diag_exit_code %r (need true, 0)'
                            % (DIAG_EVIDENCE[1], driver, verdict.get('verdicts_identical'), code))
    return problems


def compile_problems(build,source):
    """Problems binding BUILD's compile to SOURCE ([] = bound). A build without diag_mirror.json must be the canonical
    source; a declared diagnostic build must pass diagnostic_problems instead. Every other check is shared."""
    compiler=compiler_module()
    problems=[]
    if declared_diagnostic(build):
        problems += diagnostic_problems(build,source)
    elif sha(CANONICAL_P4)!=source:
        problems.append('candidate is not the canonical current P4 source')
    try:
        result=compiler.verify_evidence(build/'compile_local',source_root=build)
        if result.get('compiled_artifacts_verified') is not True:
            problems.append('current compiler/source/artifact evidence does not verify')
        manifest=json.loads((build/'compile_local/manifest.json').read_text())
        if manifest.get('source_sha256')!=source:problems.append('compile source differs from candidate')
        if re.match(r'^p4c\s+9\.13\.2(?:\s|$)',manifest.get('compiler',''))is None:
            problems.append('current hardware requires SDK9.13.2')
        pipes=manifest['resources']['pipes']
        for pipe,gress,limit in (('p0','ingress',10),('p0','egress',10),('p1','ingress',8),('p1','egress',4)):
            value=pipes[pipe]['stages'][gress]
            if type(value)is not int or value>limit:
                problems.append('%s %s stages %r exceeds current limit%d'%(pipe,gress,value,limit))
    except (OSError,ValueError,KeyError,TypeError)as error:
        problems.append('compile evidence unreadable: '+str(error))
    return problems


def compiler_module():
    import importlib.util
    spec=importlib.util.spec_from_file_location('current_compile_evidence',REPO/'scripts/build.py')
    compiler=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(compiler)
    return compiler


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    sub=parser.add_subparsers(dest='cmd',required=True)
    write_parser=sub.add_parser('write')
    write_parser.add_argument('build')
    write_parser.add_argument('-o','--output',required=True)
    write_parser.add_argument('--configs',nargs='+',required=True)
    write_parser.set_defaults(regen=None,diagnostic_exception=None)
    check_parser=sub.add_parser('check')
    check_parser.add_argument('freeze')
    check_parser.add_argument('--config',required=True)
    check_parser.add_argument('--record')
    args=parser.parse_args(argv)
    return write(args)if args.cmd=='write'else check(args)


if __name__=='__main__':
    raise SystemExit(main())
