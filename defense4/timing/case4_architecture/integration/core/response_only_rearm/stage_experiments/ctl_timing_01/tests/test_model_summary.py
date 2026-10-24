"""model_summary.py: every attempt listed, a driver judged by its latest attempt, unresolved failures block."""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('model_summary', HERE.parent / 'model_summary.py')
ms = importlib.util.module_from_spec(spec)
sys.modules['model_summary'] = ms
spec.loader.exec_module(ms)


def make_build(root, name='m9_01'):
    build = root / name
    build.mkdir()
    (build / 'response_only.p4').write_text('source\n')
    return build, hashlib.sha256(b'source\n').hexdigest()


def attempt(root, build, driver, n, sha, passed, total, exit_code=0, note=None):
    d = root / ('model_%s_%s_%02d' % (driver, build.name, n))
    d.mkdir()
    (d / 'launch_command.json').write_text(json.dumps(dict(source_sha256=sha, exit_code=exit_code, MILESTONE='m9')))
    failed = [] if passed == total else ['case_%d' % i for i in range(total - passed)]
    (d / ('%s_results.json' % driver)).write_text(json.dumps(dict(summary=dict(passed=passed, total=total,
                                                                              failed=failed))))
    if note is not None:
        (d / 'FAILURE_20261016.md').write_text(note)
    return d


def all_pass(root, build, sha):
    for driver in ms.REQUIRED:
        attempt(root, build, driver, 1, sha, 10, 10)


def test_all_required_latest_pass_is_not_blocked(tmp_path):
    build, sha = make_build(tmp_path)
    all_pass(tmp_path, build, sha)
    s = ms.summarize(build)
    assert s['qualification'] == 'model_gate_passed' and s['blocked_reasons'] == []
    assert len(s['runs']) == len(ms.REQUIRED)


def test_physical_relay_cannot_pass_with_only_the_nine_historical_drivers(tmp_path):
    build, sha = make_build(tmp_path)
    (build / 'response_only.inputs.json').write_text(json.dumps(
        {'supported_profile': {'endpoint_profile': 'sel751'}}))
    all_pass(tmp_path, build, sha)
    summary = ms.summarize(build)
    assert summary['qualification'] == 'blocked'
    for driver in ('policy', 'policy_boundary', 'two_read_robust', 'smoke_sizeoff',
                   'abandon', 'relay_sbo', 'fin_busy'):
        assert '%s: no attempt' % driver in summary['blocked_reasons']


def test_physical_relay_requires_all_sixteen_gates(tmp_path):
    build, sha = make_build(tmp_path)
    (build / 'response_only.inputs.json').write_text(json.dumps(
        {'supported_profile': {'endpoint_profile': 'sel751'}}))
    drivers = tuple(ms.REQUIRED) + ('policy', 'policy_boundary', 'two_read_robust',
                                  'smoke_sizeoff', 'abandon', 'relay_sbo', 'fin_busy')
    for driver in drivers:
        attempt(tmp_path, build, driver, 1, sha, 10, 10)
    summary = ms.summarize(build)
    assert summary['qualification'] == 'model_gate_passed'
    assert set(summary['required_drivers']) == set(drivers)


def test_malformed_qualification_profile_does_not_fall_back_to_historical_gate(tmp_path):
    build, sha = make_build(tmp_path)
    (build / 'response_only.inputs.json').write_text('{broken')
    all_pass(tmp_path, build, sha)
    summary = ms.summarize(build)
    assert summary['qualification'] == 'blocked'
    assert any('qualification profile' in reason for reason in summary['blocked_reasons'])


@pytest.mark.parametrize('selector', (None, 'software'))
@pytest.mark.parametrize('marker', (
    {'transforms_applied': ['relay_sbo', 'relay_ts']},
    {'supported_profile': {'tcp_profile': 'sel751_ts'}},
    {'supported_profile': {'encoding': {
        'native_input_octets': {'SELECT': 49, 'OPERATE': 49}, 'output_octets': 60}}},
))
def test_relay_semantics_cannot_downgrade_to_historical_gate(tmp_path, selector, marker):
    build, sha = make_build(tmp_path)
    doc = dict(marker)
    if selector is not None:
        doc['endpoint_profile'] = selector
    (build / 'response_only.inputs.json').write_text(json.dumps(doc))
    all_pass(tmp_path, build, sha)
    summary = ms.summarize(build)
    assert summary['qualification'] == 'blocked'
    assert any('qualification profile' in reason for reason in summary['blocked_reasons'])


def test_a_later_failure_blocks_although_an_earlier_attempt_passed(tmp_path):
    build, sha = make_build(tmp_path)
    all_pass(tmp_path, build, sha)
    attempt(tmp_path, build, 'contention', 2, sha, 223, 300, exit_code=1)
    s = ms.summarize(build)
    assert s['qualification'] == 'blocked'
    assert s['latest_by_driver']['contention'].endswith('_02')
    assert {r['run'] for r in s['runs']} >= {'model_contention_m9_01_01', 'model_contention_m9_01_02'}


def test_an_unresolved_failure_note_blocks_even_if_a_later_attempt_passes(tmp_path):
    build, sha = make_build(tmp_path)
    all_pass(tmp_path, build, sha)
    attempt(tmp_path, build, 'abort', 2, sha, 1, 2, exit_code=1, note='cause not determined\n')
    attempt(tmp_path, build, 'abort', 3, sha, 2, 2)
    s = ms.summarize(build)
    assert s['qualification'] == 'blocked'
    assert any('unresolved FAILURE_20261016.md' in r for r in s['blocked_reasons'])


def test_a_resolved_failure_note_does_not_block(tmp_path):
    build, sha = make_build(tmp_path)
    all_pass(tmp_path, build, sha)
    attempt(tmp_path, build, 'abort', 2, sha, 1, 2, exit_code=1, note='RESOLVED: see the fix\n')
    attempt(tmp_path, build, 'abort', 3, sha, 2, 2)
    assert ms.summarize(build)['qualification'] == 'model_gate_passed'


@pytest.mark.parametrize('case', ('missing_driver', 'other_source', 'missing_results'))
def test_missing_or_mismatched_evidence_blocks(tmp_path, case):
    build, sha = make_build(tmp_path)
    for driver in ms.REQUIRED:
        if case == 'missing_driver' and driver == 'dup':
            continue
        d = attempt(tmp_path, build, driver, 1, 'f' * 64 if case == 'other_source' and driver == 'smoke' else sha,
                    10, 10)
        if case == 'missing_results' and driver == 'rearm':
            (d / 'rearm_results.json').unlink()
    assert ms.summarize(build)['qualification'] == 'blocked'


def test_write_keeps_the_hand_written_summary(tmp_path):
    build, sha = make_build(tmp_path)
    all_pass(tmp_path, build, sha)
    (build / 'model_summary.json').write_text(json.dumps({'counted_passes_m9_01': {}}))
    ms.main([str(build), '--write'])
    kept = list(build.glob('model_summary_superseded_*.json'))
    assert len(kept) == 1 and 'counted_passes_m9_01' in kept[0].read_text()
    assert json.loads((build / 'model_summary.json').read_text())['generated_by'] == 'ctl_timing_01/model_summary.py'


# ---- summary v2: verified provenance and coverage (review of 7637390c1, finding 3) ----------------------------------
NEG = [dict(tag='abort_held_%s_plus%d' % (k, o), offset=o, resets_seq=[], e_reset_front_delta=0, responses=1,
            t_deltas={'RESP_RELEASE': 1}) for k in ('READ', 'SELECT') for o in (48, 50)]


def attempt_v2(root, build, driver, n, sha, code, inner=None, sections=None, points=None, launch_sha='auto'):
    d = attempt(root, build, driver, n, sha, 10, 10)
    (d / 'driver_source.py').write_text(code)
    record = json.loads((d / 'launch_command.json').read_text())
    if launch_sha == 'auto':
        record['driver_sha256'] = hashlib.sha256(code.encode()).hexdigest()
    elif launch_sha is not None:
        record['driver_sha256'] = launch_sha
    (d / 'launch_command.json').write_text(json.dumps(record))
    res = json.loads((d / ('%s_results.json' % driver)).read_text())
    res['meta'] = dict(driver_sha256=inner or hashlib.sha256(code.encode()).hexdigest(), sections=sections,
                       points=points or [])
    (d / ('%s_results.json' % driver)).write_text(json.dumps(res))
    return d


CONTENTION = 'contention driver\n'


def all_pass_v2(root, build, sha, **abort):
    for driver in ms.REQUIRED:
        if driver == 'contention':
            attempt_v2(root, build, driver, 1, sha, CONTENTION, sections='all')
        elif driver == 'abort':
            kw = dict(inner=hashlib.sha256(CONTENTION.encode()).hexdigest(), sections=['abort'], points=NEG)
            kw.update(abort)
            attempt_v2(root, build, driver, 1, sha, 'wrapper\n', **kw)
        else:
            attempt_v2(root, build, driver, 1, sha, driver + ' driver\n')


def test_v2_passes_with_verified_provenance(tmp_path):
    build, sha = make_build(tmp_path)
    all_pass_v2(tmp_path, build, sha)
    assert ms.summarize_v2(build)['qualification'] == 'model_gate_passed'


def test_v2_blocks_missing_driver_hashes_where_v1_passed(tmp_path):
    """Review counterexample: every launch record's driver hash removed; v1 still passed."""
    build, sha = make_build(tmp_path)
    all_pass_v2(tmp_path, build, sha)
    for launch in tmp_path.glob('model_*/launch_command.json'):
        record = json.loads(launch.read_text())
        record.pop('driver_sha256')
        launch.write_text(json.dumps(record))
    assert ms.summarize(build)['qualification'] == 'model_gate_passed'
    assert ms.summarize_v2(build)['qualification'] == 'blocked'


@pytest.mark.parametrize('abort', (dict(inner='f' * 64), dict(sections='all'), dict(points=NEG[:1]),
                                   dict(points=[dict(NEG[0], responses=0)] + NEG[1:]), dict(points=[])))
def test_v2_blocks_wrapper_identity_coverage_or_weak_negatives(tmp_path, abort):
    build, sha = make_build(tmp_path)
    all_pass_v2(tmp_path, build, sha, **abort)
    assert ms.summarize_v2(build)['qualification'] == 'blocked'


def test_v2_launch_hash_must_match_the_retained_driver(tmp_path):
    build, sha = make_build(tmp_path)
    all_pass_v2(tmp_path, build, sha)
    launch = next(tmp_path.glob('model_smoke_*/launch_command.json'))
    record = json.loads(launch.read_text())
    record['driver_sha256'] = 'e' * 64
    launch.write_text(json.dumps(record))
    assert ms.summarize_v2(build)['qualification'] == 'blocked'


@pytest.mark.parametrize('line, resolved', (('RESOLVED: corrected', False),
                                            ('RESOLVED: model_abort_m9_01_02', True),
                                            ('RESOLVED: model_abort_m9_01_99', False)))
def test_v2_resolution_must_reference_something_that_exists(tmp_path, line, resolved):
    build, sha = make_build(tmp_path)
    all_pass_v2(tmp_path, build, sha)
    attempt_v2(tmp_path, build, 'abort', 2, sha, 'wrapper\n', inner=hashlib.sha256(CONTENTION.encode()).hexdigest(),
               sections=['abort'], points=NEG)
    (tmp_path / 'model_abort_m9_01_01' / 'FAILURE_20261016.md').write_text(line + '\n')
    # the referenced sibling must exist as a run directory beside the build
    if resolved:
        (tmp_path / 'model_abort_m9_01_02').exists()
    assert (ms.summarize_v2(build)['qualification'] == 'model_gate_passed') == resolved


def test_enforce_exits_nonzero_when_blocked(tmp_path):
    build, sha = make_build(tmp_path)
    all_pass_v2(tmp_path, build, sha, inner='f' * 64)
    assert ms.main([str(build), '--v2']) == 0
    assert ms.main([str(build), '--v2', '--enforce']) == 1


def test_runs_of_another_build_with_a_suffix_name_are_not_attempts(tmp_path):
    """Found 2026-10-17: model_abort_probe_x_m9_01_01 belongs to build probe_x_m9_01, not m9_01."""
    build, sha = make_build(tmp_path)
    all_pass_v2(tmp_path, build, sha)
    other = tmp_path / 'model_contention_probe_x_m9_01_01'
    other.mkdir()
    (other / 'launch_command.json').write_text(json.dumps(dict(source_sha256='f' * 64, exit_code=1)))
    s = ms.summarize_v2(build)
    assert s['qualification'] == 'model_gate_passed' and other.name not in {r['run'] for r in s['runs']}


# ---- summary v3: mandatory dependency evidence (review of af7bd434; Philip 2026-10-17) -----------------------------
sys.path.insert(0, str(HERE.parent))
import record_closure  # noqa: E402
import run_model  # noqa: E402
import model_profile  # noqa: E402


@pytest.fixture
def v3(tmp_path, monkeypatch):
    """A build whose every latest attempt carries a dependency closure over files in a temporary repository."""
    repo = tmp_path / 'repo'
    (repo / 'drivers').mkdir(parents=True)
    (repo / 'lib.py').write_text('shared library\n')
    monkeypatch.setattr(ms, 'REPO', repo)
    drivers = {}
    build, sha = make_build(tmp_path)
    historical = repo / 'profiles'
    monkeypatch.setattr(model_profile, 'HERE', historical)
    for name in ('m9_01', 'm10_03'):
        registered = historical / 'evidence' / name
        registered.mkdir(parents=True)
        (registered / 'response_only.inputs.json').write_text(json.dumps({'source_sha256': sha}))
    all_pass_v2(tmp_path, build, sha)
    for d in sorted(tmp_path.glob('model_*_m9_01_*')):
        driver = d.name[len('model_'):-len('_m9_01_01')]
        path = repo / 'drivers' / (driver + '.py')
        path.write_bytes((d / 'driver_source.py').read_bytes())
        drivers[driver] = path
    monkeypatch.setattr(run_model, 'DRIVERS', drivers)
    for d in sorted(tmp_path.glob('model_*_m9_01_*')):
        driver = d.name[len('model_'):-len('_m9_01_01')]
        files = {'lib.py': hashlib.sha256(b'shared library\n').hexdigest(),
                 'drivers/%s.py' % driver: hashlib.sha256(drivers[driver].read_bytes()).hexdigest()}
        if driver in ms.WRAPPERS:
            inner = drivers[ms.WRAPPERS[driver]]
            files['drivers/%s.py' % ms.WRAPPERS[driver]] = hashlib.sha256(inner.read_bytes()).hexdigest()
        closure = d / 'dependency_closure.json'
        closure.write_text(json.dumps(dict(closure_version=record_closure.CLOSURE_VERSION, files=files)))
        record = json.loads((d / 'launch_command.json').read_text())
        record['dependency_closure_sha256'] = hashlib.sha256(closure.read_bytes()).hexdigest()
        (d / 'launch_command.json').write_text(json.dumps(record))
    return build, repo


def test_v3_passes_with_verified_dependency_evidence(v3):
    build, _ = v3
    s = ms.summarize_v3(build)
    assert s['qualification'] == 'model_gate_passed' and s['provenance_limitations'] == []


@pytest.mark.parametrize('source', ('unknown', 'm10_as_m9'))
def test_missing_inputs_cannot_use_launch_spelling_to_bypass_the_verified_profile(v3, source):
    build, _ = v3
    if source == 'unknown':
        (build / 'response_only.p4').write_text('unknown successor source\n')
        sha = hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest()
        for launch in build.parent.glob('model_*/launch_command.json'):
            record = json.loads(launch.read_text()); record['source_sha256'] = sha
            launch.write_text(json.dumps(record))
    else:
        registered = model_profile.HERE / 'evidence/m9_01/response_only.inputs.json'
        registered.write_text(json.dumps({'source_sha256': '0' * 64}))
    assert not (build / 'response_only.inputs.json').exists()
    assert ms.summarize_v2(build)['qualification'] == 'model_gate_passed'
    summary = ms.summarize_v3(build)
    assert summary['qualification'] == 'blocked'
    assert any('source/profile' in reason for reason in summary['blocked_reasons'])


def test_v3_blocks_a_run_without_dependency_evidence_and_states_the_limitation(v3):
    build, _ = v3
    (build.parent / 'model_dup_m9_01_01' / 'dependency_closure.json').unlink()
    s = ms.summarize_v3(build)
    assert ms.summarize_v2(build)['qualification'] == 'model_gate_passed'          # v2 status unchanged
    assert s['qualification'] == 'blocked' and s['provenance_limitations'] == [
        'dup: model_dup_m9_01_01 predates mandatory dependency evidence']


@pytest.mark.parametrize('case', ('unbound', 'changed_dependency', 'absent_dependency', 'no_inner_driver',
                                  'wrong_version'))
def test_v3_blocks_mismatched_dependency_evidence(v3, case):
    build, repo = v3
    run = build.parent / 'model_abort_m9_01_01'
    closure = run / 'dependency_closure.json'
    data = json.loads(closure.read_text())
    if case == 'unbound':
        closure.write_text(closure.read_text() + ' ')
    elif case == 'changed_dependency':
        (repo / 'lib.py').write_text('changed\n')
    elif case == 'absent_dependency':
        (repo / 'lib.py').unlink()
    elif case in ('no_inner_driver', 'wrong_version'):
        if case == 'no_inner_driver':
            data['files'].pop('drivers/contention.py')
        else:
            data['closure_version'] = 'v0'
        closure.write_text(json.dumps(data))
        record = json.loads((run / 'launch_command.json').read_text())
        record['dependency_closure_sha256'] = hashlib.sha256(closure.read_bytes()).hexdigest()
        (run / 'launch_command.json').write_text(json.dumps(record))
    assert ms.summarize_v3(build)['qualification'] == 'blocked'


def test_enforce_exits_nonzero_unless_v3_passes(v3):
    build, _ = v3
    assert ms.main([str(build), '--v3', '--enforce']) == 0
    (build.parent / 'model_smoke_m9_01_01' / 'dependency_closure.json').unlink()
    assert ms.main([str(build), '--v3', '--enforce']) == 1


@pytest.mark.parametrize('offset', (None, '48'))
def test_v2_judges_a_required_abort_tag_even_without_a_usable_offset(tmp_path, offset):
    """Review finding 5: a required tag whose offset is absent or a string was skipped by the survival check."""
    build, sha = make_build(tmp_path)
    row = dict(NEG[0], resets_seq=[1], responses=0)
    if offset is None:
        row.pop('offset')
    else:
        row['offset'] = offset
    all_pass_v2(tmp_path, build, sha, points=[row] + NEG[1:])
    assert ms.summarize_v2(build)['qualification'] == 'blocked'


def install_complete_reset(run):
    retained = HERE.parent / 'evidence/model_contention_m10_03_07'
    path = run / 'contention_results.json'
    old = json.loads(path.read_text())
    results = json.loads((retained / 'contention_results.json').read_text())
    results['meta']['driver_sha256'] = old['meta']['driver_sha256']
    path.write_text(json.dumps(results))
    (run / 'reset_application.json').write_bytes((retained / 'reset_application.json').read_bytes())


@pytest.mark.parametrize('content, passes', ((None, False), ('{}', False),
                                             ('{"restart_READ": {"verdict": "PASS"}, "restart_SELECT": {"verdict": "FAIL"}}', False),
                                             ('{"restart_READ": {"verdict": "no reset applied"}}', False),
                                             ('{"restart_READ": {"verdict": "PASS"}, "restart_SELECT": {"verdict": "PASS"}}', False)))
def test_v3_requires_the_revised_reset_contract_for_m10_contention(v3, content, passes):
    """Philip, 2026-10-17: the m10 contention attempt passes only with reset_application.json all PASS."""
    build, _ = v3
    run = build.parent / 'model_contention_m9_01_01'
    record = json.loads((run / 'launch_command.json').read_text())
    record['MILESTONE'] = 'm10'
    (run / 'launch_command.json').write_text(json.dumps(record))
    if content is not None:
        (run / 'reset_application.json').write_text(content)
    assert (ms.summarize_v3(build)['qualification'] == 'model_gate_passed') is passes


def test_v3_blocks_an_m10_contention_attempt_with_an_unmeasured_committed_path(v3):
    build, _ = v3
    run = build.parent / 'model_contention_m9_01_01'
    record = json.loads((run / 'launch_command.json').read_text())
    record['MILESTONE'] = 'm10'
    (run / 'launch_command.json').write_text(json.dumps(record))
    install_complete_reset(run)
    assert ms.summarize_v3(build)['qualification'] == 'model_gate_passed'
    results = run / 'contention_results.json'
    data = json.loads(results.read_text())
    data['meta']['committed_path_not_measured'] = ['sweep_OPERATE_030ms']
    results.write_text(json.dumps(data))
    s = ms.summarize_v3(build)
    assert s['qualification'] == 'blocked' and any('not measured' in x for x in s['blocked_reasons'])


@pytest.mark.parametrize('mutate', ('held_unmeasured', 'no_results', 'two_results'))
def test_v3_blocks_unmeasured_held_aborts_and_unreadable_results(v3, mutate):
    build, _ = v3
    run = build.parent / 'model_contention_m9_01_01'
    record = json.loads((run / 'launch_command.json').read_text())
    record['MILESTONE'] = 'm10'
    (run / 'launch_command.json').write_text(json.dumps(record))
    install_complete_reset(run)
    results = run / 'contention_results.json'
    if mutate == 'held_unmeasured':
        data = json.loads(results.read_text())
        data['meta']['abort_released_before_send'] = ['abort_held_READ']
        results.write_text(json.dumps(data))
    elif mutate == 'no_results':
        results.rename(run / 'moved.json')
    else:
        (run / 'extra_results.json').write_text(results.read_text())
    assert ms.summarize_v3(build)['qualification'] == 'blocked'


@pytest.mark.parametrize('case, ok', (('later_pass', True), ('note_on_latest', False), ('no_evidence_path', False),
                                      ('later_fails', False), ('plain_text', False)))
def test_a_disclosed_unresolved_note_stands_only_beside_a_later_complete_pass(tmp_path, case, ok):
    """Philip, 2026-10-17: attempt 04 may be frozen as a disclosed, unresolved interruption only if a later complete
    attempt passes. It is listed, never counted as resolved."""
    build, sha = make_build(tmp_path)
    all_pass_v2(tmp_path, build, sha)
    inner = hashlib.sha256(CONTENTION.encode()).hexdigest()
    run1 = tmp_path / 'model_abort_m9_01_01'
    (run1 / 'trace.txt').write_text('evidence\n')
    if case != 'note_on_latest':
        attempt_v2(tmp_path, build, 'abort', 2, sha, 'wrapper\n', inner=inner, sections=['abort'], points=NEG)
    if case == 'later_fails':
        res = next((tmp_path / 'model_abort_m9_01_02').glob('*_results.json'))
        data = json.loads(res.read_text())
        data['summary'] = dict(passed=1, total=2, failed=['x'])
        res.write_text(json.dumps(data))
    line = {'no_evidence_path': 'DISCLOSED UNRESOLVED: model_abort_m9_01_01/missing.txt',
            'plain_text': 'cause not determined'}.get(case, 'DISCLOSED UNRESOLVED: model_abort_m9_01_01/trace.txt')
    (run1 / 'FAILURE_20261016.md').write_text(line + '\n')
    s = ms.summarize_v2(build)
    assert (s['qualification'] == 'model_gate_passed') == ok, s['blocked_reasons']
    assert bool(s['disclosed_unresolved']) == ok
    if ok:
        assert s['disclosed_unresolved'][0]['passed_later_attempt'] == 'model_abort_m9_01_02'


@pytest.mark.parametrize('driver, key', (('contention', 'abort_released_before_reset'),
                                         ('abort', 'abort_released_before_send'),
                                         ('abort', 'abort_released_before_reset'),
                                         ('contention', 'abort_held_not_established')))
def test_v3_blocks_an_unmeasured_held_abort_decided_by_t_passes_and_in_the_abort_driver(v3, driver, key):
    """Harness fix 2: a held abort whose release T's passes put before the reset application is judged by the
    released-branch contract, and still did not measure the held path; the abort driver runs the same cases."""
    build, _ = v3
    run = next(build.parent.glob('model_%s_m9_01_*' % driver))
    record = json.loads((run / 'launch_command.json').read_text())
    record['MILESTONE'] = 'm10'
    (run / 'launch_command.json').write_text(json.dumps(record))
    contention = build.parent / 'model_contention_m9_01_01'
    if driver == 'abort':
        rec = json.loads((contention / 'launch_command.json').read_text())
        rec['MILESTONE'] = 'm10'
        (contention / 'launch_command.json').write_text(json.dumps(rec))
    install_complete_reset(contention)
    assert ms.summarize_v3(build)['qualification'] == 'model_gate_passed'
    results = next(run.glob('*_results.json'))
    data = json.loads(results.read_text())
    data['meta'][key] = ['abort_held_READ']
    results.write_text(json.dumps(data))
    s = ms.summarize_v3(build)
    assert s['qualification'] == 'blocked' and any('held abort path not measured' in x for x in s['blocked_reasons'])


@pytest.mark.parametrize('tag', ('restart_READ', 'invented'))
def test_reset_application_singleton_pass_does_not_prove_coverage(tmp_path, tag):
    (tmp_path / 'reset_application.json').write_text(json.dumps({tag: {'verdict': 'PASS'}}))
    assert ms._reset_application_problems(tmp_path)


def test_successor_profile_cannot_bypass_reset_gate_using_an_older_launch_milestone(v3):
    build, _ = v3
    sha = hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest()
    (build / 'response_only.inputs.json').write_text(json.dumps(dict(source_sha256=sha, milestone='successor',
        supported_profile=dict(reset_restart_required=True, t_child_count=1, candidate=dict(source_sha256=sha)))))
    summary = ms.summarize_v3(build)
    assert summary['qualification'] == 'blocked'
    assert any('reset application/results evidence' in p for p in summary['blocked_reasons'])
    assert any('bound reset postcheck' in p for p in summary['blocked_reasons'])


@pytest.mark.parametrize('binding', ('missing', 'mismatched', 'current'))
def test_every_successor_driver_must_bind_the_executed_supported_profile(v3, binding):
    build, _ = v3
    sha = hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest()
    inputs = build / 'response_only.inputs.json'
    inputs.write_text(json.dumps(dict(source_sha256=sha, milestone='successor',
        supported_profile=dict(reset_restart_required=True, t_child_count=1, candidate=dict(source_sha256=sha)))))
    digest = hashlib.sha256(inputs.read_bytes()).hexdigest()
    for launch in build.parent.glob('model_*/launch_command.json'):
        record = json.loads(launch.read_text())
        record['supported_profile_sha256'] = digest
        if launch.parent.name.startswith('model_control_timing_'):
            if binding == 'missing': record.pop('supported_profile_sha256')
            elif binding == 'mismatched': record['supported_profile_sha256'] = '0' * 64
        launch.write_text(json.dumps(record))
    summary = ms.summarize_v3(build)
    reasons = [reason for reason in summary['blocked_reasons'] if 'supported_profile_sha256' in reason]
    assert bool(reasons) is (binding != 'current')
    if reasons:
        assert len(reasons) == 1 and reasons[0].startswith('control_timing:')


def test_duplicate_json_reset_report_keys_are_rejected(v3):
    build, _ = v3
    run = build.parent / 'model_contention_m9_01_01'
    install_complete_reset(run)
    path = run / 'reset_application.json'
    report = json.loads(path.read_text())
    duplicate = json.dumps('restart_READ') + ':' + json.dumps(report['restart_READ'])
    path.write_text('{' + duplicate + ',' + path.read_text().lstrip()[1:])
    assert ms._reset_application_problems(run)
