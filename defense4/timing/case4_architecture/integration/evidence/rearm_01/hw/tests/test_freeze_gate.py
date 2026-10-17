"""freeze_gate.py: the version-2 freeze covers the acceptance code and fails clearly on change or absence.

Runs against a small self-contained repository in a temp directory (git-initialised), so it needs neither the
real compiler outputs (untracked) nor a particular checkout.
"""
import json
import subprocess
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import freeze_gate as fg  # noqa: E402


@pytest.fixture
def repo(tmp_path, monkeypatch):
    root = tmp_path / 'repo'
    for d in fg.HARNESS_DIRS:
        (root / d).mkdir(parents=True)
    for name in ('campaign.py', 'standards.py', 'clrt_check.py', 'hold_check.py', 'checks.py'):
        (root / fg.A / 'protocol/hw_vepa' / name).write_text('# ' + name + '\n')
    for name in ('token_window.py', 'candidate_isolation.py', 'freeze_gate.py'):
        (root / fg.A / 'integration/evidence/rearm_01/hw' / name).write_text('# ' + name + '\n')
    for f in list(fg.HARNESS_FILES) + list(fg.ANALYSIS):
        (root / f).parent.mkdir(parents=True, exist_ok=True)
        (root / f).write_text('# ' + f + '\n')
    build = root / fg.A / 'integration/core/response_only_rearm/stage_experiments/ctl_timing_01/evidence/x_01'
    for f in fg.BUILD_FILES:
        (build / f).parent.mkdir(parents=True, exist_ok=True)
        (build / f).write_text(f + '\n')
    for c in ('compile_local', 'compile_switch_9132'):
        for f in fg.COMPILE_FILES:
            (build / c / f).parent.mkdir(parents=True, exist_ok=True)
            (build / c / f).write_text(c + f + '\n')
    for d in fg.BASELINE_DIRS:
        (root / d).mkdir(parents=True, exist_ok=True)
        (root / d / 'state.txt').write_text('baseline\n')
    (root / fg.A / 'protocol/hw_vepa/switch_swap.sh').write_text('# swap\n')
    config = root / 'config.json'
    config.write_text('{}\n')
    subprocess.run(['git', 'init', '-q', str(root)], check=True)
    subprocess.run(['git', '-C', str(root), 'add', '-A', '--', '.', ':!**/compile_*/out/**'], check=True)
    monkeypatch.setattr(fg, 'REPO', root)
    return root, build, config


def freeze(tmp_path, build, config):
    out = tmp_path / 'freeze.json'
    assert fg.main(['write', str(build), '-o', str(out), '--configs', str(config)]) == 0
    return out


def test_freeze_covers_the_acceptance_modules_named_by_the_review(tmp_path, repo):
    root, build, config = repo
    files = json.loads(freeze(tmp_path, build, config).read_text())['files']
    for name in ('campaign.py', 'standards.py', 'clrt_check.py', 'hold_check.py', 'checks.py'):
        assert fg.A + 'protocol/hw_vepa/' + name in files
    for name in ('token_window.py', 'candidate_isolation.py', 'freeze_gate.py'):
        assert fg.A + 'integration/evidence/rearm_01/hw/' + name in files
    assert fg.A + 'integration/evidence/rearm_01/hw/run_block.sh' in files
    assert fg.A + 'protocol/hw_vepa/switch_swap.sh' in files
    assert any('restore_baseline/state.txt' in f for f in files)
    assert fg.A + 'integration/core/response_only/cp.py' in files
    assert any(f.endswith('analysis/isolation_v3.py') for f in files) and 'config.json' in files


def test_check_passes_unchanged_and_records_its_result(tmp_path, repo):
    root, build, config = repo
    out = freeze(tmp_path, build, config)
    record = tmp_path / 'rec' / 'freeze_check.json'
    assert fg.main(['check', str(out), '--record', str(record)]) == 0
    assert json.loads(record.read_text())['ok'] is True


def test_check_fails_when_a_frozen_file_changes(tmp_path, repo):
    root, build, config = repo
    out = freeze(tmp_path, build, config)
    (root / fg.A / 'protocol/hw_vepa/standards.py').write_text('# changed\n')
    assert fg.main(['check', str(out)]) == 1


def test_a_missing_file_fails_with_its_regeneration_command(tmp_path, repo, capsys):
    root, build, config = repo
    out = tmp_path / 'freeze.json'
    assert fg.main(['write', str(build), '-o', str(out), '--configs', str(config),
                    '--regen', 'config.json=python3 build_configs.py']) == 0
    config.unlink()
    assert fg.main(['check', str(out)]) == 1
    assert 'regenerate: python3 build_configs.py' in capsys.readouterr().out


def test_compiler_outputs_are_pinned_and_marked_untracked(tmp_path, repo):
    root, build, config = repo
    files = json.loads(freeze(tmp_path, build, config).read_text())['files']
    outs = {f: v for f, v in files.items() if '/compile_' in f and '/out/' in f}
    assert len(outs) == 8 and all(v['tracked'] is False for v in outs.values())
    assert files['config.json']['tracked'] is True


def test_write_refuses_when_a_required_file_is_absent(tmp_path, repo):
    root, build, config = repo
    (build / 'compile_local/out/bfrt.json').unlink()
    with pytest.raises(SystemExit, match='cannot freeze, missing'):
        fg.main(['write', str(build), '-o', str(tmp_path / 'f.json')])
