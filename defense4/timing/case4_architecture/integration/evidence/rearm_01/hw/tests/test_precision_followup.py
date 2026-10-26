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


def test_any_trial_failure_never_advances():
    # no failure kind is excused: a former timing-threshold string blocks like any other failure
    assert not module.admissible(record(['READ precision: legacy failure string']))
    assert not module.admissible(record(['application failure']))


def test_incomplete_restore_never_advances():
    data = record()
    data['restore'].pop()
    assert not module.admissible(data)
    data = record()
    data['restore'][0]['rc'] = 1
    assert not module.admissible(data)
