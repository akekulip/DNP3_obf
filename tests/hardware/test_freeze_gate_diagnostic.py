"""Freeze-gate admission of the declared c72_diag_mirror diagnostic build (offline; committed evidence is only read).

A build with diag_mirror.json is admitted only when that identity binds the current canonical P4, the current generator
and the generator's own in-process derivation of the build's source. Its blocks are bound to the diagnostic model
evidence by hash and never qualify. A build without diag_mirror.json keeps the canonical model-gate rules."""
import contextlib
import copy
import hashlib
import io
import json
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/hardware'), str(ROOT / 'scripts/checks')]
import freeze_gate

DIAG = ROOT / 'results/builds/c72_diag_mirror'
C72 = ROOT / 'results/builds/c72'
DIAG_MODELS = ROOT / 'results/models/c72_diag_mirror'
C72_CONFIG = ROOT / 'results/hardware/campaigns/rc01_hw_c72_20261027_02/configs/02_d5_reference.json'
EVIDENCE = ('diag_mirror_fidelity_01.json', 'gate_vs_c72_01.json')
COMPILED = 'compile_local/out/response_only.p4pp'
needs_diag = pytest.mark.skipif(not (DIAG / COMPILED).is_file(), reason='compiled c72_diag_mirror outputs not restored')
needs_c72 = pytest.mark.skipif(not (C72 / COMPILED).is_file(), reason='compiled c72 outputs not restored')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


DIAG_SOURCE = sha(DIAG / 'response_only.p4')
C72_SOURCE = sha(C72 / 'response_only.p4')


def one_byte(path):
    """Change the case of one ASCII letter in the second half of a file (the file stays valid UTF-8)."""
    data = bytearray(path.read_bytes())
    index = next(i for i in range(len(data) // 2, len(data)) if 0x61 <= data[i] <= 0x7a)
    data[index] ^= 0x20
    path.write_bytes(bytes(data))


def edit_identity(build, **changes):
    meta = json.loads((build / 'diag_mirror.json').read_text())
    meta.update(changes)
    (build / 'diag_mirror.json').write_text(json.dumps(meta, indent=2) + '\n')


def refuse(*_args, **_kwargs):
    raise AssertionError('this path must not be consulted')


def write(build, configs, output):
    with contextlib.redirect_stdout(io.StringIO()):
        return freeze_gate.write(SimpleNamespace(build=str(build), output=str(output), regen=None,
                                                 configs=[str(c) for c in configs], diagnostic_exception=None))


def check(freeze, config, record):
    with contextlib.redirect_stdout(io.StringIO()):
        code = freeze_gate.check(SimpleNamespace(freeze=str(freeze), config=str(config), record=str(record)))
    return code, json.loads(Path(record).read_text())


def controlled_files(mp):
    """write() over a fixed file set: the build source, its compile manifest and the configs (write() itself adds the
    model summary or the diagnostic identity and evidence). collect()'s repository-wide set is unchanged behaviour,
    and other work edits files in it concurrently, which would race a write() followed by a check()."""
    def collect(build, configs):
        return sorted({freeze_gate.rel(Path(build) / 'response_only.p4'),
                       freeze_gate.rel(Path(build) / 'compile_local/manifest.json')}
                      | {freeze_gate.rel(c) for c in configs})
    mp.setattr(freeze_gate, 'collect', collect)


def patch_outside_paths(mp):
    """Let the gate name temporary configs and evidence by absolute path; repository paths keep their names."""
    original = freeze_gate.rel

    def rel(path):
        try:
            return original(path)
        except ValueError:
            return str(Path(path).resolve())
    mp.setattr(freeze_gate, 'rel', rel)


def copy_models(root, mp):
    """Temporary copies of the two diagnostic model evidence files, bound into the gate."""
    models = root / 'models' / DIAG.name
    models.mkdir(parents=True)
    for name in EVIDENCE:
        shutil.copyfile(DIAG_MODELS / name, models / name)
    mp.setattr(freeze_gate, 'DIAG_MODELS', str(models.parent))
    return models


def diag_config(root, name, change=None):
    """A c72 block config rebound to the diagnostic build, with the diagnostic contract fields."""
    cfg = json.loads(C72_CONFIG.read_text())
    manifest = json.loads((DIAG / 'compile_local/manifest.json').read_text())
    out_dir = 'results/builds/c72_diag_mirror/compile_local/out'
    for build in cfg['builds'].values():
        build.update(source_sha256=DIAG_SOURCE, manifest='results/builds/c72_diag_mirror/compile_local/manifest.json',
                     out_dir=out_dir, hashes={f: manifest['artifact_sha256'][f] for f in build['hashes']})
    cfg['ctl_timing_identity'] = dict(source_sha256=DIAG_SOURCE, switch_compile=dict(out_dir=out_dir))
    cfg['purpose'] = 'diagnostic'
    cfg['diag_mirror'] = dict(state='on', copy_port=10, capture_interface='enp59s0f1np1',
                              build_label='c72_diag_mirror', source_sha256=DIAG_SOURCE)
    cfg['ports_map']['stat_ports'] = '9,64,10'
    if change:
        change(cfg)
    path = root / 'configs' / (name + '.json')
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(cfg, indent=2) + '\n')
    return path


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    """Temporary copies of the canonical P4 and the generator, bound into the gate in place of the committed files."""
    canonical = tmp_path / 'p4/response_only.p4'
    generator = tmp_path / 'scripts/build_diag_mirror.py'
    for target, origin in ((canonical, ROOT / 'p4/response_only.p4'),
                           (generator, ROOT / 'scripts/build_diag_mirror.py')):
        target.parent.mkdir(parents=True)
        shutil.copyfile(origin, target)
    monkeypatch.setattr(freeze_gate, 'CANONICAL_P4', str(canonical))
    monkeypatch.setattr(freeze_gate, 'DIAG_GENERATOR', str(generator))
    return SimpleNamespace(canonical=canonical, generator=generator)


@pytest.fixture
def small_build(tmp_path):
    """A temporary build: copies of the identity and the derived source; compile_local links the committed compile."""
    build = tmp_path / 'builds/c72_diag_mirror'
    build.mkdir(parents=True)
    for name in ('response_only.p4', 'diag_mirror.json'):
        shutil.copyfile(DIAG / name, build / name)
    (build / 'compile_local').symlink_to(DIAG / 'compile_local')
    return build


@pytest.fixture
def models(tmp_path, monkeypatch):
    return copy_models(tmp_path, monkeypatch)


# --- item 1/2: admission and compile_problems -------------------------------------------------------------------

@needs_c72
def test_canonical_c72_compile_check_never_consults_the_diagnostic_rules(monkeypatch):
    monkeypatch.setattr(freeze_gate, 'diagnostic_problems', refuse)
    assert not freeze_gate.declared_diagnostic(C72)
    assert freeze_gate.compile_problems(C72, C72_SOURCE) == []


def test_undeclared_build_keeps_exactly_the_canonical_source_problem(tmp_path, monkeypatch):
    (tmp_path / 'p4').mkdir()
    (tmp_path / 'p4/response_only.p4').write_text('current source')
    build = tmp_path / 'build'
    (build / 'compile_local').mkdir(parents=True)
    digest = hashlib.sha256(b'another source').hexdigest()
    pipes = {'p0': {'stages': dict(ingress=10, egress=10)}, 'p1': {'stages': dict(ingress=8, egress=4)}}
    (build / 'compile_local/manifest.json').write_text(json.dumps(dict(source_sha256=digest, compiler='p4c 9.13.2',
                                                                       resources={'pipes': pipes})))
    monkeypatch.setattr(freeze_gate, 'REPO', tmp_path)
    monkeypatch.setattr(freeze_gate, 'compiler_module', lambda: SimpleNamespace(
        verify_evidence=lambda *args, **kwargs: {'compiled_artifacts_verified': True}))
    monkeypatch.setattr(freeze_gate, 'diagnostic_problems', refuse)
    assert freeze_gate.compile_problems(build, digest) == ['candidate is not the canonical current P4 source']


def test_declared_diagnostic_build_is_admitted_when_every_identity_matches():
    assert freeze_gate.declared_diagnostic(DIAG)
    assert freeze_gate.diagnostic_problems(DIAG, DIAG_SOURCE) == []


@needs_diag
def test_admitted_diagnostic_build_passes_every_other_compile_check_unchanged():
    assert freeze_gate.compile_problems(DIAG, DIAG_SOURCE) == []


TAMPERS = {
    'derived_source_one_byte': (lambda b, i: one_byte(b / 'response_only.p4'), ('does not reproduce', 'source_sha256')),
    # identity re-hashed to the tampered file: only the in-process regeneration can catch it
    'derived_source_one_byte_identity_rehashed': (
        lambda b, i: (one_byte(b / 'response_only.p4'), edit_identity(b, source_sha256=sha(b / 'response_only.p4'))),
        ('does not reproduce',)),
    'generator_changed': (lambda b, i: i.generator.write_text(i.generator.read_text() + '# changed\n'),
                          ('generator_sha256',)),
    'canonical_changed': (lambda b, i: one_byte(i.canonical), ('canonical_sha256',)),
    'identity_canonical_sha': (lambda b, i: edit_identity(b, canonical_sha256='0' * 64), ('canonical_sha256',)),
    'identity_generator_sha': (lambda b, i: edit_identity(b, generator_sha256='0' * 64), ('generator_sha256',)),
    'identity_source_sha': (lambda b, i: edit_identity(b, source_sha256='0' * 64), ('source_sha256',)),
    'identity_hashes_absent': (lambda b, i: (b / 'diag_mirror.json').write_text('{}\n'),
                               ('canonical_sha256', 'generator_sha256', 'source_sha256')),
    'identity_unreadable': (lambda b, i: (b / 'diag_mirror.json').write_text('{not json'), ('diag_mirror.json',)),
    'identity_not_an_object': (lambda b, i: (b / 'diag_mirror.json').write_text('[]\n'), ('diag_mirror.json',)),
    'identity_dangling_link': (lambda b, i: ((b / 'diag_mirror.json').unlink(),
                                             (b / 'diag_mirror.json').symlink_to(b / 'absent.json')),
                               ('diag_mirror.json',)),
}


@pytest.mark.parametrize('case', sorted(TAMPERS))
def test_declared_diagnostic_build_is_refused_on_any_identity_mismatch(case, inputs, small_build):
    assert freeze_gate.diagnostic_problems(small_build, DIAG_SOURCE) == []      # the untouched copy is admitted
    tamper, expected = TAMPERS[case]
    tamper(small_build, inputs)
    source = sha(small_build / 'response_only.p4') if (small_build / 'response_only.p4').is_file() else DIAG_SOURCE
    assert freeze_gate.declared_diagnostic(small_build)
    problems = freeze_gate.diagnostic_problems(small_build, source)
    compiled = freeze_gate.compile_problems(small_build, source)
    for text in expected:
        assert any(text in problem for problem in problems), problems
        assert any(text in problem for problem in compiled), compiled
    assert 'candidate is not the canonical current P4 source' not in compiled


def test_changed_generator_is_never_executed(inputs, small_build):
    inputs.generator.write_text('raise SystemExit("an unverified generator was executed")\n')
    problems = freeze_gate.diagnostic_problems(small_build, DIAG_SOURCE)
    assert any('generator_sha256' in problem for problem in problems)
    assert any('not regenerated' in problem for problem in problems)


def test_candidate_source_must_be_the_regenerated_derived_source():
    problems = freeze_gate.diagnostic_problems(DIAG, C72_SOURCE)
    assert len(problems) == 1 and 'candidate source' in problems[0], problems


def test_build_without_identity_is_not_diagnostic_and_fails_the_canonical_check(small_build):
    (small_build / 'diag_mirror.json').unlink()
    assert not freeze_gate.declared_diagnostic(small_build)
    assert 'candidate is not the canonical current P4 source' in freeze_gate.compile_problems(small_build, DIAG_SOURCE)
    assert any('diag_mirror.json' in p for p in freeze_gate.diagnostic_problems(small_build, DIAG_SOURCE))


# --- item 3: model evidence, write, binding, check ----------------------------------------------------------------

def test_committed_diagnostic_model_evidence_passes():
    assert freeze_gate.diagnostic_evidence_problems(DIAG) == []
    assert freeze_gate.diagnostic_evidence(DIAG) == {
        'results/models/c72_diag_mirror/' + name: sha(DIAG_MODELS / name) for name in EVIDENCE}


def drop_driver(value, name):
    value['drivers'].pop(name)


EVIDENCE_DEFECTS = {
    'fidelity_not_passed': ('diag_mirror_fidelity_01.json', lambda v: v.update(passed=False)),
    'fidelity_passed_absent': ('diag_mirror_fidelity_01.json', lambda v: v.pop('passed')),
    'fidelity_passed_not_boolean': ('diag_mirror_fidelity_01.json', lambda v: v.update(passed='true')),
    'fidelity_other_source': ('diag_mirror_fidelity_01.json', lambda v: v.update(source_sha256=C72_SOURCE)),
    'driver_verdicts_differ': ('gate_vs_c72_01.json',
                               lambda v: v['drivers']['abandon'].update(verdicts_identical=False)),
    'driver_verdicts_absent': ('gate_vs_c72_01.json', lambda v: v['drivers']['smoke'].pop('verdicts_identical')),
    'driver_exit_nonzero': ('gate_vs_c72_01.json', lambda v: v['drivers']['relay_sbo'].update(diag_exit_code=1)),
    'driver_exit_false': ('gate_vs_c72_01.json', lambda v: v['drivers']['relay_sbo'].update(diag_exit_code=False)),
    'driver_exit_absent': ('gate_vs_c72_01.json', lambda v: v['drivers']['policy'].pop('diag_exit_code')),
    'required_driver_missing': ('gate_vs_c72_01.json', lambda v: drop_driver(v, 'response_ready')),
    'no_drivers': ('gate_vs_c72_01.json', lambda v: v.update(drivers={})),
    'gate_other_build': ('gate_vs_c72_01.json', lambda v: v.update(build='c72')),
}


@pytest.mark.parametrize('case', sorted(EVIDENCE_DEFECTS))
def test_diagnostic_evidence_that_did_not_pass_is_refused(case, models):
    name, change = EVIDENCE_DEFECTS[case]
    value = json.loads((models / name).read_text())
    change(value)
    (models / name).write_text(json.dumps(value, indent=1) + '\n')
    assert freeze_gate.diagnostic_evidence_problems(DIAG)


@pytest.mark.parametrize('name', EVIDENCE)
def test_missing_or_unreadable_diagnostic_evidence_is_refused(name, models):
    (models / name).write_text('{truncated')
    assert any(name in p for p in freeze_gate.diagnostic_evidence_problems(DIAG))
    (models / name).unlink()
    assert any(name in p for p in freeze_gate.diagnostic_evidence_problems(DIAG))


@needs_diag
def test_diagnostic_candidate_records_hashed_model_evidence_and_never_qualifies(monkeypatch):
    real = freeze_gate.model_summary_module

    def no_live_gate():
        module = real()
        module.summarize_v3 = refuse
        return module
    monkeypatch.setattr(freeze_gate, 'model_summary_module', no_live_gate)
    record = freeze_gate.candidate_record(DIAG, DIAG_SOURCE, [], None)
    assert record['diagnostic'] is True and record['qualifies'] is False
    assert record['model']['qualification'] == 'diagnostic_model_evidence'
    assert record['model']['evidence'] == {'results/models/c72_diag_mirror/' + name: sha(DIAG_MODELS / name)
                                           for name in EVIDENCE}
    assert record['source_sha256'] == DIAG_SOURCE and record['build'] == 'results/builds/c72_diag_mirror'


@needs_diag
def test_freeze_write_refuses_a_diagnostic_candidate_whose_fidelity_did_not_pass(models, tmp_path, monkeypatch):
    controlled_files(monkeypatch)
    value = json.loads((models / EVIDENCE[0]).read_text())
    value['passed'] = False
    (models / EVIDENCE[0]).write_text(json.dumps(value, indent=1) + '\n')
    with pytest.raises(SystemExit) as refused:
        write(DIAG, [C72_CONFIG], tmp_path / 'freeze.json')
    assert 'diagnostic' in str(refused.value) and 'passed' in str(refused.value)
    assert not (tmp_path / 'freeze.json').exists()


CONFIG_VARIANTS = {
    'bound': None,
    'purpose_absent': lambda c: c.pop('purpose'),
    'purpose_qualification': lambda c: c.update(purpose='qualification'),
    'mirror_absent': lambda c: c.pop('diag_mirror'),
    'mirror_not_an_object': lambda c: c.update(diag_mirror='on'),
    'mirror_source_c72': lambda c: c['diag_mirror'].update(source_sha256=C72_SOURCE),
}


@pytest.fixture(scope='module')
def frozen_diag(tmp_path_factory):
    """One freeze of the diagnostic build over every config variant (patches undone before the tests run)."""
    root = tmp_path_factory.mktemp('diag_freeze')
    with pytest.MonkeyPatch.context() as mp:
        patch_outside_paths(mp)
        controlled_files(mp)
        models = copy_models(root, mp)
        configs = {name: diag_config(root, name, change) for name, change in CONFIG_VARIANTS.items()}
        write(DIAG, configs.values(), root / 'freeze.json')
    return SimpleNamespace(root=root, models=models, configs=configs, path=root / 'freeze.json',
                           frozen=json.loads((root / 'freeze.json').read_text()))


@pytest.fixture
def bound(frozen_diag, monkeypatch):
    patch_outside_paths(monkeypatch)
    monkeypatch.setattr(freeze_gate, 'DIAG_MODELS', str(frozen_diag.models.parent))
    return frozen_diag


@needs_diag
def test_freeze_of_an_admitted_diagnostic_build_records_a_non_qualifying_candidate(bound):
    cand = bound.frozen['candidate']
    assert cand['diagnostic'] is True and cand['qualifies'] is False
    assert cand['source_sha256'] == DIAG_SOURCE == bound.frozen['source_sha256']
    assert cand['model']['qualification'] == 'diagnostic_model_evidence'
    evidence = {str(bound.models / name): sha(bound.models / name) for name in EVIDENCE}
    assert cand['model']['evidence'] == evidence
    assert set(evidence) | {'results/builds/c72_diag_mirror/diag_mirror.json'} <= set(bound.frozen['files'])


@needs_diag
def test_bound_diagnostic_block_is_admitted_but_never_qualifies(bound):
    assert freeze_gate.candidate_binding(bound.frozen, bound.configs['bound']) == []
    code, record = check(bound.path, bound.configs['bound'], bound.root / 'check_bound.json')
    assert code == 0 and record['ok'] is True and record['candidate_binding'] == []
    assert record['changed'] == [] and record['missing'] == []
    assert record['qualifies'] is False and record['diagnostic'] is True


@needs_diag
@pytest.mark.parametrize('variant,text', [('purpose_absent', 'purpose'), ('purpose_qualification', 'purpose'),
                                          ('mirror_absent', 'diag_mirror.source_sha256'),
                                          ('mirror_not_an_object', 'diag_mirror.source_sha256'),
                                          ('mirror_source_c72', 'diag_mirror.source_sha256')])
def test_diagnostic_binding_requires_the_diagnostic_config_contract(bound, variant, text):
    problems = freeze_gate.candidate_binding(bound.frozen, bound.configs[variant])
    assert len(problems) == 1 and text in problems[0], problems
    code, record = check(bound.path, bound.configs[variant], bound.root / ('check_%s.json' % variant))
    assert code == 1 and record['qualifies'] is False


@needs_diag
@pytest.mark.parametrize('name', EVIDENCE)
def test_diagnostic_binding_refuses_model_evidence_changed_since_the_freeze(bound, name):
    path = bound.models / name
    original = path.read_bytes()
    try:
        one_byte(path)
        problems = freeze_gate.candidate_binding(bound.frozen, bound.configs['bound'])
    finally:
        path.write_bytes(original)
    assert any('evidence changed' in p for p in problems), problems


@needs_diag
@pytest.mark.parametrize('which,text', [('generator', 'generator_sha256'), ('canonical', 'canonical_sha256')])
def test_diagnostic_binding_rechecks_admission(bound, inputs, which, text):
    path = getattr(inputs, which)
    path.write_text(path.read_text() + '\n// changed\n' if which == 'canonical' else path.read_text() + '# changed\n')
    problems = freeze_gate.candidate_binding(bound.frozen, bound.configs['bound'])
    assert any(p.startswith('compile: ') and text in p for p in problems), problems


@needs_diag
@pytest.mark.parametrize('forge', ['flag_removed', 'qualification_model_gate_passed', 'evidence_hash',
                                   'evidence_absent'])
def test_diagnostic_binding_refuses_a_forged_candidate_record(bound, forge):
    frozen = copy.deepcopy(bound.frozen)
    cand = frozen['candidate']
    if forge == 'flag_removed':
        cand.pop('diagnostic')
        cand.pop('qualifies')
    elif forge == 'qualification_model_gate_passed':
        cand['model']['qualification'] = 'model_gate_passed'
    elif forge == 'evidence_hash':
        first = sorted(cand['model']['evidence'])[0]
        cand['model']['evidence'][first] = '0' * 64
    else:
        cand['model'].pop('evidence')
    assert freeze_gate.candidate_binding(frozen, bound.configs['bound'])


def test_check_never_reports_a_diagnostic_candidate_as_qualifying(tmp_path, monkeypatch):
    monkeypatch.setattr(freeze_gate, 'candidate_binding', lambda frozen, config: [])
    results = {}
    for name, extra in (('canonical', {}), ('diagnostic', dict(diagnostic=True, qualifies=False))):
        frozen = dict(freeze_version=freeze_gate.FREEZE_V3, build='results/builds/c72', source_sha256=C72_SOURCE,
                      files={}, candidate=dict(model=dict(qualification='model_gate_passed'), diagnostic_exception=None,
                                               **extra))
        (tmp_path / (name + '.json')).write_text(json.dumps(frozen))
        results[name] = check(tmp_path / (name + '.json'), C72_CONFIG, tmp_path / ('check_%s.json' % name))[1]
    assert results['canonical']['qualifies'] is True and 'diagnostic' not in results['canonical']
    assert results['diagnostic']['qualifies'] is False and results['diagnostic']['diagnostic'] is True


@needs_c72
def test_canonical_c72_freeze_keeps_the_model_gate_rules_and_qualifies(tmp_path, monkeypatch):
    stored = json.loads((C72 / 'model_summary_v3.json').read_text())
    real = freeze_gate.model_summary_module

    def stored_gate():
        module = real()
        module.summarize_v3 = lambda build: {key: stored[key] for key in
                                             ('qualification', 'blocked_reasons', 'latest_by_driver')}
        return module
    monkeypatch.setattr(freeze_gate, 'model_summary_module', stored_gate)
    controlled_files(monkeypatch)
    for name in ('diagnostic_problems', 'diagnostic_evidence', 'diagnostic_evidence_problems'):
        monkeypatch.setattr(freeze_gate, name, refuse)
    write(C72, [C72_CONFIG], tmp_path / 'freeze.json')
    frozen = json.loads((tmp_path / 'freeze.json').read_text())
    cand = frozen['candidate']
    assert sorted(cand) == ['artifacts', 'build', 'configs', 'diagnostic_exception', 'loaded_compile', 'model',
                            'source_sha256']
    assert cand['model']['qualification'] == 'model_gate_passed' and cand['model']['summary'] is not None
    assert freeze_gate.candidate_binding(frozen, C72_CONFIG) == []
    code, record = check(tmp_path / 'freeze.json', C72_CONFIG, tmp_path / 'check.json')
    assert code == 0 and record['qualifies'] is True and 'diagnostic' not in record
    assert record['candidate_binding'] == [] and record['changed'] == [] and record['missing'] == []
    assert set(frozen['files']) == {'results/builds/c72/response_only.p4', str(C72_CONFIG.relative_to(ROOT)),
                                    'results/builds/c72/compile_local/manifest.json',
                                    'results/builds/c72/model_summary_v3.json'}
    # the canonical rules still recheck the live model verdict before every block
    module = stored_gate()
    monkeypatch.setattr(freeze_gate, 'model_summary_module', lambda: SimpleNamespace(
        summarize_v3=lambda build: dict(module.summarize_v3(build), qualification='blocked')))
    moved = freeze_gate.candidate_binding(frozen, C72_CONFIG)
    assert any('model evidence changed since the freeze' in p for p in moved), moved
