"""Fresh endpoint directories work; retained run labels remain exclusive."""
import importlib.util
from pathlib import Path

import pytest

HW = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('name', ['vision_candidate', 'vision_isolation', 'vision_replay'])
def test_scenario_creates_fresh_runs_parent_but_refuses_reuse(tmp_path, monkeypatch, name):
    spec = importlib.util.spec_from_file_location('fresh_' + name, HW / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    vc = module if name == 'vision_candidate' else module.vc
    runs = tmp_path / 'new_endpoint' / 'runs'
    monkeypatch.setattr(vc.vr, 'RUNS', runs)
    monkeypatch.setattr(vc, 'guard', lambda *a, **kw: None)

    def stop_before_traffic(*args):
        raise RuntimeError('test stops before traffic')
    monkeypatch.setattr(vc, 'preflight', stop_before_traffic)
    args = ('fresh_run', 59400, 'rst', 1) if name == 'vision_candidate' else ('fresh_run', 59400, 1)
    result = module.scenario(*args, apply=True)
    assert result['ok'] is False
    assert result['error'] == 'test stops before traffic'
    assert (runs / 'fresh_run' / 'scenario.json').is_file()
    with pytest.raises(FileExistsError):
        module.scenario(*args, apply=True)


# These tests execute the real entrypoints; only the external campaign/freeze/restore
# processes are replaced, so no host or switch is contacted.
import os
import shutil
import subprocess
import sys
import time
import json


@pytest.fixture
def block_rig(tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    repo = tmp_path / 'repo'
    arch = repo / 'defense4/timing/case4_architecture'
    hw = arch / 'integration/evidence/rearm_01/hw'
    hw.mkdir(parents=True)
    subprocess.run(['git', 'init', '-q', str(repo)], check=True)
    for name in ('run_block.sh', 'run_block_frozen.sh', 'guarded_block.py'):
        if (HW / name).exists():
            shutil.copyfile(HW / name, hw / name)
    cfg = repo / 'config.json'
    cfg.write_text(json.dumps({'evidence_dir': 'runs'}))
    (hw / 'candidate_campaign.py').write_text("""
import json, os, pathlib, sys, time
args = sys.argv[1:]
cfg = json.loads(pathlib.Path(args[args.index('--config')+1]).read_text())
root = pathlib.Path(__file__).resolve().parents[4] / cfg['evidence_dir'] / args[args.index('--run-id')+1]
if args[0] == 'plan':
    if os.environ.get('WAIT_FOR'):
        pathlib.Path(os.environ['WAIT_FOR'] + '.ready').touch()
        while not pathlib.Path(os.environ['WAIT_FOR']).exists(): time.sleep(.01)
    if os.environ.get('PLAN_BLOCKED'):
        print('BLOCKED/UNBOUND (a real run refuses): invalid input')
    raise SystemExit(0)
if root.exists(): raise SystemExit(1)
root.mkdir(parents=True)
(root / 'campaign_run.json').write_text('{}')
raise SystemExit(int(os.environ.get('BLOCK_RC', '0')))
""")
    (hw / 'restore_verify.py').write_text("""
import json, os, pathlib, sys
root = pathlib.Path(sys.argv[sys.argv.index('--run-root')+1])
(root / 'restore_verify.json').write_text(json.dumps({'checked': True}))
print('restoration checked')
raise SystemExit(int(os.environ.get('RESTORE_RC', '0')))
""")
    (hw / 'freeze_gate.py').write_text("""
import pathlib, sys
record = pathlib.Path(sys.argv[sys.argv.index('--record')+1])
record.parent.mkdir(parents=True, exist_ok=True)
record.write_text('new freeze check')
""")
    return repo, arch, hw, cfg


def block_cmd(rig, frozen=False, extra=()):
    repo, arch, hw, cfg = rig
    cmd = ['bash', str(hw / ('run_block_frozen.sh' if frozen else 'run_block.sh'))]
    if frozen:
        cmd += [str(repo / 'freeze.json')]
    return cmd + ['candidate_campaign', str(cfg), 'unit'] + list(extra)


@pytest.mark.parametrize('frozen', [False, True])
def test_wrapper_refuses_existing_evidence_without_changing_any_file(block_rig, frozen):
    repo, arch, hw, cfg = block_rig
    root = arch / 'runs/unit'
    root.mkdir(parents=True)
    for name in ('run_block_plan.out', 'run_block_run.out', 'restore_verify.out',
                 'restore_verify.json', 'freeze_check.json'):
        (root / name).write_text('retained ' + name)
    before = {str(p.relative_to(repo)): p.read_bytes() for p in repo.rglob('*') if p.is_file()}
    result = subprocess.run(block_cmd(block_rig, frozen), capture_output=True, text=True)
    assert result.returncode != 0
    after = {str(p.relative_to(repo)): p.read_bytes() for p in repo.rglob('*') if p.is_file()}
    assert after == before


def test_wrapper_dry_run_never_creates_run_or_restoration_evidence(block_rig):
    repo, arch, hw, cfg = block_rig
    result = subprocess.run(block_cmd(block_rig, extra=['--dry-run']), capture_output=True, text=True)
    assert result.returncode == 0
    assert not (arch / 'runs/unit').exists()
    assert not (hw / 'freeze_checks/unit.json').exists()


@pytest.mark.parametrize('frozen', [False, True])
def test_wrapper_refuses_existing_freeze_record_without_overwrite(block_rig, frozen):
    repo, arch, hw, cfg = block_rig
    rec = hw / 'freeze_checks/unit.json'
    rec.parent.mkdir()
    rec.write_text('retained')
    result = subprocess.run(block_cmd(block_rig, frozen), capture_output=True, text=True)
    assert result.returncode != 0
    assert rec.read_text() == 'retained'
    assert not (arch / 'runs/unit').exists()


def test_wrapper_rejects_a_plan_warning_before_hardware_or_restore(block_rig):
    repo, arch, hw, cfg = block_rig
    result = subprocess.run(block_cmd(block_rig), env=dict(os.environ, PLAN_BLOCKED='1'), capture_output=True)
    assert result.returncode == 1
    assert not (arch / 'runs/unit').exists()


@pytest.mark.parametrize('block_rc,restore_rc,want', [(0,0,0), (1,0,1), (2,0,1), (0,1,2), (1,1,2)])
def test_wrapper_always_verifies_restore_after_entered_block(block_rig, block_rc, restore_rc, want):
    repo, arch, hw, cfg = block_rig
    result = subprocess.run(block_cmd(block_rig), env=dict(os.environ, BLOCK_RC=str(block_rc), RESTORE_RC=str(restore_rc)),
                            capture_output=True, text=True)
    assert result.returncode == want
    root = arch / 'runs/unit'
    assert json.loads((root / 'restore_verify.json').read_text()) == {'checked': True}
    assert (root / 'run_block_plan.out').is_file()
    assert (root / 'run_block_run.out').is_file()


def test_wrapper_reservation_excludes_a_concurrent_same_id_before_plan(block_rig, tmp_path):
    repo, arch, hw, cfg = block_rig
    release = tmp_path / 'release'
    first = subprocess.Popen(block_cmd(block_rig), env=dict(os.environ, WAIT_FOR=str(release)),
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not Path(str(release) + '.ready').exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert Path(str(release) + '.ready').exists()
        second = subprocess.run(block_cmd(block_rig), capture_output=True, timeout=10)
        assert second.returncode == 1
        assert not (arch / 'runs/unit').exists()
    finally:
        release.touch()
        first.communicate(timeout=10)
    assert first.returncode == 0


def test_frozen_wrapper_retains_new_check_only_after_an_entered_block(block_rig):
    repo, arch, hw, cfg = block_rig
    result = subprocess.run(block_cmd(block_rig, frozen=True), capture_output=True, text=True)
    assert result.returncode == 0
    assert (arch / 'runs/unit/freeze_check.json').read_text() == 'new freeze check'
    assert (hw / 'freeze_checks/unit.json').read_text() == 'new freeze check'


def test_wrapper_canonicalizes_alias_before_refusing_retained_root(block_rig):
    repo, arch, hw, cfg = block_rig
    cfg.write_text(json.dumps({'evidence_dir': 'runs/../runs'}))
    root = arch / 'runs/unit'
    root.mkdir(parents=True)
    retained = root / 'restore_verify.json'
    retained.write_text('retained')
    result = subprocess.run(block_cmd(block_rig), capture_output=True, text=True)
    assert result.returncode == 1
    assert retained.read_text() == 'retained'
    assert not (hw / 'run_block.log').exists()


def test_wrapper_refuses_dangling_run_root_symlink_before_records(block_rig):
    repo, arch, hw, cfg = block_rig
    (arch / 'runs').mkdir()
    (arch / 'runs/unit').symlink_to(arch / 'missing')
    result = subprocess.run(block_cmd(block_rig), capture_output=True, text=True)
    assert result.returncode == 1
    assert not (hw / 'run_block.log').exists()
    assert not (arch / 'missing').exists()


def test_wrapper_preserves_legacy_run_log_before_new_hardware_entry(block_rig, tmp_path):
    repo, arch, hw, cfg = block_rig
    retained = tmp_path / 'run_block_unit.out'
    retained.write_text('retained run output')
    result = subprocess.run(block_cmd(block_rig), capture_output=True, text=True)
    assert result.returncode == 1
    assert retained.read_text() == 'retained run output'
    assert not (arch / 'runs/unit').exists()


def test_wrapper_campaign_refusal_before_root_does_not_restore(block_rig):
    repo, arch, hw, cfg = block_rig
    tool = hw / 'candidate_campaign.py'
    tool.write_text("import sys\nraise SystemExit(0 if sys.argv[1] == 'plan' else 1)\n")
    result = subprocess.run(block_cmd(block_rig), capture_output=True, text=True)
    assert result.returncode == 1
    assert not (arch / 'runs/unit').exists()


def test_wrapper_verifies_restore_after_termination_during_entered_block(block_rig, tmp_path):
    import signal
    repo, arch, hw, cfg = block_rig
    release = tmp_path / 'release_run'
    tool = hw / 'candidate_campaign.py'
    text = tool.read_text().replace("raise SystemExit(int(os.environ.get('BLOCK_RC', '0')))",
        "while not pathlib.Path(os.environ['RUN_RELEASE']).exists(): time.sleep(.01)\n"
        "raise SystemExit(0)")
    tool.write_text(text)
    proc = subprocess.Popen(block_cmd(block_rig), env=dict(os.environ, RUN_RELEASE=str(release)),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not (arch / 'runs/unit/campaign_run.json').exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert (arch / 'runs/unit/campaign_run.json').exists()
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
    finally:
        release.touch()
        proc.communicate(timeout=10)
    assert proc.returncode == 1
    assert json.loads((arch / 'runs/unit/restore_verify.json').read_text()) == {'checked': True}


@pytest.mark.parametrize('option', ['--conf', '--run-i', '--app'])
def test_wrapper_cannot_forward_abbreviated_identity_or_apply_options(block_rig, option):
    repo, arch, hw, cfg = block_rig
    result = subprocess.run(block_cmd(block_rig, extra=[option, 'other']), capture_output=True, text=True)
    assert result.returncode == 1
    assert not (arch / 'runs/unit').exists()


def test_wrapper_unavailable_restore_checker_stops_the_hardware_sequence(block_rig):
    repo, arch, hw, cfg = block_rig
    # A failed checker process must retain the stop status, even after block success.
    (hw / 'restore_verify.py').unlink()
    result = subprocess.run(block_cmd(block_rig), capture_output=True, text=True)
    assert result.returncode == 2
    assert (arch / 'runs/unit/restore_verify.out').is_file()


@pytest.mark.parametrize('restore_rc,want', [(0, 1), (1, 2)])
def test_post_entry_log_failure_cannot_mask_restoration_status(block_rig, restore_rc, want):
    repo, arch, hw, cfg = block_rig
    tool = hw / 'candidate_campaign.py'
    tool.write_text(tool.read_text().replace("(root / 'campaign_run.json').write_text('{}')",
        "(root / 'campaign_run.json').write_text('{}')\n"
        "log = pathlib.Path(__file__).parent / 'run_block.log'\n"
        "log.unlink()\nlog.mkdir()"))
    result = subprocess.run(block_cmd(block_rig), env=dict(os.environ, RESTORE_RC=str(restore_rc)),
                            capture_output=True, text=True)
    assert result.returncode == want
    assert json.loads((arch / 'runs/unit/restore_verify.json').read_text()) == {'checked': True}
    assert 'nothing entered' not in result.stderr
    assert 'nothing touched' not in result.stderr


@pytest.mark.parametrize('restore_rc,want', [(0, 1), (1, 2)])
def test_post_entry_wait_failure_still_verifies_restore(block_rig, monkeypatch, restore_rc, want):
    repo, arch, hw, cfg = block_rig
    spec = importlib.util.spec_from_file_location('guarded_block_wait_failure', hw / 'guarded_block.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    monkeypatch.setattr(runner.tempfile, 'tempdir', str(repo.parent))
    original = runner.command_output
    def fail_after_entered_command(command, output, env=None):
        result = original(command, output, env)
        if command[2] == 'run':
            raise OSError('wait failed after child entered')
        return result
    monkeypatch.setattr(runner, 'command_output', fail_after_entered_command)
    monkeypatch.setenv('RESTORE_RC', str(restore_rc))
    assert runner.block('candidate_campaign', cfg, 'unit', []) == want
    assert json.loads((arch / 'runs/unit/restore_verify.json').read_text()) == {'checked': True}


@pytest.mark.parametrize('interrupted_phase', ['retention', 'reservation_cleanup'])
def test_post_entry_termination_never_downgrades_unverified_restore(block_rig, monkeypatch, interrupted_phase):
    repo, arch, hw, cfg = block_rig
    spec = importlib.util.spec_from_file_location('guarded_block_post_restore_interrupt', hw / 'guarded_block.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    monkeypatch.setattr(runner.tempfile, 'tempdir', str(repo.parent))
    monkeypatch.setenv('RESTORE_RC', '1')
    if interrupted_phase == 'retention':
        def interrupt_copy(_source, _destination):
            raise KeyboardInterrupt
        monkeypatch.setattr(runner, 'copy_new', interrupt_copy)
    else:
        original = runner.Path.rmdir
        def interrupt_cleanup(path):
            if path.parent.name == 'run_reservations':
                raise KeyboardInterrupt
            return original(path)
        monkeypatch.setattr(runner.Path, 'rmdir', interrupt_cleanup)
    try:
        status = runner.block('candidate_campaign', cfg, 'unit', [])
    except KeyboardInterrupt:
        pytest.fail('post-entry termination escaped the unverified-restore stop status')
    assert status == 2
    assert json.loads((arch / 'runs/unit/restore_verify.json').read_text()) == {'checked': True}
