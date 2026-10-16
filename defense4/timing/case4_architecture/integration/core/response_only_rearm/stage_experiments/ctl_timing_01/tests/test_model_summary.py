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
    attempt(tmp_path, build, 'abort', 1, sha, 1, 2, exit_code=1, note='cause not determined\n')
    attempt(tmp_path, build, 'abort', 2, sha, 2, 2)
    s = ms.summarize(build)
    assert s['qualification'] == 'blocked'
    assert any('unresolved FAILURE_20261016.md' in r for r in s['blocked_reasons'])


def test_a_resolved_failure_note_does_not_block(tmp_path):
    build, sha = make_build(tmp_path)
    all_pass(tmp_path, build, sha)
    attempt(tmp_path, build, 'abort', 1, sha, 1, 2, exit_code=1, note='RESOLVED: see the fix\n')
    attempt(tmp_path, build, 'abort', 2, sha, 2, 2)
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
