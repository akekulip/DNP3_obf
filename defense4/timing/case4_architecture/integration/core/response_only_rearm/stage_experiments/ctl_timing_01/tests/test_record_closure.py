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
