"""record_closure.py records every repository file a driver executes, including dynamically loaded ones."""
import json
import os
import subprocess
import sys
from pathlib import Path

RECORDER = Path(__file__).resolve().parents[1] / 'record_closure.py'


def run(tmp_path, exit_code=0):
    repo = tmp_path / 'repo'
    (repo / 'lib').mkdir(parents=True, exist_ok=True)
    (repo / 'lib' / 'by_path.py').write_text('VALUE = 1\n')
    (repo / 'lib' / 'by_spec.py').write_text('VALUE = 2\n')
    (repo / 'drv.py').write_text(
        'import importlib.util, sys\nfrom pathlib import Path\n'
        'sys.path.insert(0, str(Path(__file__).parent / "lib"))\nimport by_path\n'
        'spec = importlib.util.spec_from_file_location("x", Path(__file__).parent / "lib" / "by_spec.py")\n'
        'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n'
        'raise SystemExit(%d)\n' % exit_code)
    out = tmp_path / 'out' / 'dependency_closure.json'
    env = dict(os.environ, CTL_CLOSURE_TARGET=str(repo / 'drv.py'), CTL_CLOSURE_OUT=str(out),
               CTL_CLOSURE_REPO=str(repo))
    env.pop('PYTHONDONTWRITEBYTECODE', None)          # the cached-bytecode case needs the .pyc written
    rc = subprocess.run([sys.executable, str(RECORDER)], env=env).returncode
    return rc, json.loads(out.read_text())


def test_records_dynamic_imports_and_keeps_exit_status(tmp_path):
    rc, record = run(tmp_path, exit_code=3)
    assert rc == 3
    assert set(record['files']) == {'drv.py', 'lib/by_path.py', 'lib/by_spec.py'}
    assert record['target'] == 'drv.py' and record['closure_version'].startswith('dependency-closure-v1')


def test_records_a_module_loaded_from_cached_bytecode(tmp_path):
    run(tmp_path)
    assert list((tmp_path / 'repo' / 'lib' / '__pycache__').glob('by_path*.pyc'))
    rc, record = run(tmp_path)                         # second run imports by_path from its .pyc
    assert rc == 0 and 'lib/by_path.py' in record['files']


def test_reset_postcheck_binds_checker_results_log_and_profile_and_preserves_failure(tmp_path):
    import sys
    sys.path.insert(0, str(RECORDER.parent))
    import run_model
    import model_summary
    run = tmp_path / 'run'
    run.mkdir()
    (run / 'dependency_closure.json').write_text(json.dumps(dict(closure_version='dependency-closure-v1-20261017', files={})))
    (run / 'contention_results.json').write_text(json.dumps(dict(meta=dict(points=[], sections='all'), cases=[], summary={})))
    (run / 'model_test.log').write_text('no reset application\n')
    profile = tmp_path / 'response_only.inputs.json'
    profile.write_text('{}')
    assert run_model.check_reset(run, profile) != 0
    closure = json.loads((run / 'dependency_closure.json').read_text())
    check = closure['postchecks']['reset_application']
    assert check['exit_code'] != 0 and set(check['input_sha256']) == {
        'contention_results.json', 'model_test.log', 'response_only.inputs.json'}
    assert any(name.endswith('/reset_application_check.py') for name in closure['files'])
    assert model_summary._postcheck_problems(run, profile)


def test_complete_reset_postcheck_execution_is_bound_and_tampering_is_rejected(tmp_path):
    import sys
    sys.path.insert(0, str(RECORDER.parent))
    import run_model
    import model_summary
    import reset_application_check as rac
    run = tmp_path / 'run'
    run.mkdir()
    retained = RECORDER.parent / 'evidence/model_contention_m10_03_07/contention_results.json'
    results = json.loads(retained.read_text())
    (run / 'contention_results.json').write_text(json.dumps(results))
    (run / 'dependency_closure.json').write_text(json.dumps(dict(closure_version='dependency-closure-v1-20261017', files={})))
    lines = []
    tick = 0
    for tag in rac.restart_tags(results):
        point = next(p for p in results['meta']['points'] if p['tag'] == tag)
        count = sum(point['t_deltas'].get(k, 0) for k in ('RESP_RELEASE', 'RESP_FALLBACK'))
        pattern = rac.server_seq_pattern(results, tag)
        for actions in [['release_response_counted']] * count + [['close_epoch', 'live_reset_gen']]:
            tick += 1
            prefix = ':10-18 12:00:%02d.000001: :0x1:-:<0,1,0>:' % tick
            lines.extend([prefix + '========== Ingress Pkt from port 180 (4 bytes) ==========\n',
                          prefix + 'Packet :\n', prefix + ' '.join(pattern[i:i+2] for i in range(0, 8, 2)) + '\n'])
            lines.extend(prefix + 'Execute Action: t_Ingress.' + action + '\n' for action in actions)
    (run / 'model_test.log').write_text(''.join(lines))
    profile = tmp_path / 'response_only.inputs.json'
    profile.write_text('{}')
    assert run_model.check_reset(run, profile) == 0
    assert model_summary._postcheck_problems(run, profile) == []
    for path in (profile, run / 'contention_results.json', run / 'model_test.log',
                 run / 'reset_application.json', run / 'reset_application.dependencies.json'):
        old = path.read_text()
        path.write_text(old + ' ')
        assert model_summary._postcheck_problems(run, profile), path
        path.write_text(old)


def test_missing_driver_closure_remains_a_recorded_failure(tmp_path):
    import sys
    sys.path.insert(0, str(RECORDER.parent))
    import run_model
    (tmp_path / 'contention_results.json').write_text('{}')
    (tmp_path / 'model_test.log').write_text('')
    inputs = tmp_path / 'response_only.inputs.json'
    inputs.write_text('{}')
    assert run_model.check_reset(tmp_path, inputs) != 0
    closure = json.loads((tmp_path / 'dependency_closure.json').read_text())
    assert closure.get('closure_version') is None and closure['error']
