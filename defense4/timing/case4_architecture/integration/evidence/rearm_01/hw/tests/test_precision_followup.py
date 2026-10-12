import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location('precision_followup', Path(__file__).resolve().parents[1] / 'precision_followup.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def record(failures=(), allowed=True):
    return {'ok': not failures, 'restore': [{'rc': 0, 'ok': True} for _ in range(5)],
            'arms': [{'trials': [{'ok': not failures, 'failures': list(failures),
                                  'continuation': {'allowed': allowed}}]}]}


def test_clean_restored_run_can_advance():
    assert module.admissible(record())


def test_precision_failure_requires_explicit_runner_continuation():
    assert module.admissible(record(['READ precision: p99 exceeds100']))
    assert not module.admissible(record(['READ precision: missing samples'], allowed=False))


def test_app_failure_never_advances():
    assert not module.admissible(record(['READ precision: p99 exceeds100', 'application failure']))


def test_incomplete_restore_never_advances():
    data = record()
    data['restore'].pop()
    assert not module.admissible(data)
    data = record()
    data['restore'][0]['rc'] = 1
    assert not module.admissible(data)
