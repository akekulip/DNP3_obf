"""Historical checker code stays isolated from the current campaign checker."""
import importlib.util
import shutil
from pathlib import Path

import pytest

ANALYSIS = Path(__file__).resolve().parents[1]


def load_tool():
    spec = importlib.util.spec_from_file_location('historical_checker_test', ANALYSIS / 'historical_checker.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_recorded_checker_has_historical_contract_without_replacing_live_module():
    tool = load_tool()
    checker = tool.load_checker('a4ebbecbe')
    assert checker.source_revision == 'a4ebbecbe'
    assert callable(checker.precision)
    assert checker.__name__ != 'relay_check'


@pytest.mark.parametrize('changed', ['wire_check.py', 'endpoint_profiles.py'])
def test_changed_import_fails_closed(tmp_path, monkeypatch, changed):
    tool = load_tool()
    for name in ('wire_check.py', 'endpoint_profiles.py'):
        shutil.copy(tool.CHECKER_DIR / name, tmp_path / name)
    (tmp_path / changed).write_text('# changed dependency\n')
    monkeypatch.setattr(tool, 'CHECKER_DIR', tmp_path)
    with pytest.raises(ValueError, match='pinned worktree'):
        tool.load_checker('a4ebbecbe')
