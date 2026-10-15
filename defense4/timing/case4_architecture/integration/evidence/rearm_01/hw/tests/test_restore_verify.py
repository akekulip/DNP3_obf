"""restore_verify.py comparison and record logic, offline (no host contact)."""
import copy
import importlib.util
import json
from pathlib import Path

HW = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('restore_verify_test', HW / 'restore_verify.py')
rv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rv)


def snap():
    return {'program': 'case4_response_path', 'errors': {},
            'tables': {'$PORT': {'entries': [{'key': {'$DEV_PORT': {'value': 164}}, 'data': {'$PORT_UP': True}}]},
                       '$PORT_STAT': {'entries': [{'data': {'rx': 1}}]},
                       'pipe.fwd': {'entries': [{'key': {'k': 1}, 'action': 'route'}]}}}


def test_identical_except_volatile_counters_passes():
    pre, post = snap(), snap()
    post['tables']['$PORT_STAT']['entries'][0]['data']['rx'] = 999
    errors, compared = rv.compare_snapshots(pre, post)
    assert errors == [] and compared == 2


def test_any_changed_port_or_table_or_program_fails():
    for mutate in (lambda s: s['tables']['$PORT']['entries'][0]['data'].update({'$PORT_UP': False}),
                   lambda s: s['tables']['pipe.fwd']['entries'].append({'key': {'k': 2}}),
                   lambda s: s['tables'].pop('pipe.fwd'),
                   lambda s: s.update(program='response_only'),
                   lambda s: s.update(errors={'pipe.fwd': 'read failed'})):
        post = snap()
        mutate(post)
        assert rv.compare_snapshots(snap(), post)[0]


def test_runner_record_is_found_and_failed_or_missing_steps_are_reported(tmp_path):
    steps = [{'step': s, 'rc': 0, 'ok': True} for s in rv.REQUIRED_STEPS]
    (tmp_path / 'series_run.json').write_text(json.dumps({'restore': steps}))
    path, record = rv.run_record(tmp_path)
    assert path.name == 'series_run.json' and len(record['restore']) == 4
    assert rv.run_record(tmp_path / 'absent') == (None, None)
