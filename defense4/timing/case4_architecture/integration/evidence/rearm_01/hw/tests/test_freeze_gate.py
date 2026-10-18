"""freeze_gate.py: the version-2 freeze covers the acceptance code and fails clearly on change or absence.

Runs against a small self-contained repository in a temp directory (git-initialised), so it needs neither the
real compiler outputs (untracked) nor a particular checkout.
"""
import json
import subprocess
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import freeze_gate as fg  # noqa: E402


def write_manifest(compile_dir, source, exit_code=0):
    """A compile manifest as compile scripts write it: source, exit code and every out/ artifact's sha256."""
    out = compile_dir / 'out'
    hashes = {str(f.relative_to(out)): fg.hashlib.sha256(f.read_bytes()).hexdigest()
              for f in sorted(out.rglob('*')) if f.is_file()}
    (compile_dir / 'manifest.json').write_text(json.dumps(dict(source_sha256=source, exit_code=exit_code,
                                                               artifact_sha256=hashes)))


class FakeSummary:
    """Stands in for ctl_timing_01/model_summary.py: summarize_v3 returns a fixed verdict."""
    SUMMARY_V3 = 'model-summary-v3-20261017'

    def __init__(self, verdict):
        self.verdict = verdict

    def summarize_v3(self, build):
        return dict(dict(latest_by_driver={}), **self.verdict)

    def attempts(self, build):
        return []


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
    source = fg.hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest()
    for c in ('compile_local', 'compile_switch_9132'):
        for f in fg.COMPILE_FILES + ('out/p0/context.json',):
            (build / c / f).parent.mkdir(parents=True, exist_ok=True)
            (build / c / f).write_text(c + f + '\n')
        write_manifest(build / c, source)
    for d in fg.BASELINE_DIRS:
        (root / d).mkdir(parents=True, exist_ok=True)
        (root / d / 'state.txt').write_text('baseline\n')
    (root / fg.A / 'protocol/hw_vepa/switch_swap.sh').write_text('# swap\n')
    config = root / 'config.json'
    config.write_text('{}\n')
    verdict = dict(qualification='model_gate_passed', blocked_reasons=[], latest_by_driver={})
    (build / 'model_summary_v3.json').write_text(json.dumps(dict(verdict, summary_version=FakeSummary.SUMMARY_V3,
                                                                 source_sha256=source)))
    monkeypatch.setattr(fg, 'model_summary_module', lambda: FakeSummary(verdict))
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


def test_successor_profile_is_pinned_before_hardware_entry(tmp_path, repo):
    root, build, config = repo
    profile = build / 'supported_profile.json'
    profile.write_text('{"t_child_count": 1}\n')
    out = freeze(tmp_path, build, config)
    profile.write_text('{"t_child_count": 3}\n')
    assert fg.main(['check', str(out)]) == 1


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
    assert len(outs) == 10 and all(v['tracked'] is False for v in outs.values())
    assert files['config.json']['tracked'] is True


def test_write_refuses_when_a_required_file_is_absent(tmp_path, repo):
    root, build, config = repo
    (build / 'compile_local/out/bfrt.json').unlink()
    with pytest.raises(SystemExit, match='cannot freeze, missing'):
        fg.main(['write', str(build), '-o', str(tmp_path / 'f.json')])


# ---- version 3: one candidate identity, bound to the supplied config (review of af7bd434) -------------------------
def block_config(root, build, **change):
    """A config shaped like the block configs: a loaded build and ctl_timing_identity, both naming the build."""
    source = fg.hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest()
    case4 = build.relative_to(root / fg.A)
    loaded = dict(source_sha256=source, out_dir=str(case4 / 'compile_switch_9132/out'),
                  manifest=str(case4 / 'compile_switch_9132/manifest.json'),
                  hashes={'bfrt.json': None, 'p0/tofino.bin': fg.hashlib.sha256(
                      (build / 'compile_switch_9132/out/p0/tofino.bin').read_bytes()).hexdigest()})
    cfg = dict(builds={'ctl_x_01': loaded}, arms=[dict(build='ctl_x_01')],
               ctl_timing_identity=dict(source_sha256=source, switch_compile=dict(out_dir=loaded['out_dir'])))
    for key, value in change.items():
        cfg[key] = value(cfg) if callable(value) else value
    path = root / ('block_%d.json' % len(list(root.glob('block_*.json'))))
    path.write_text(json.dumps(cfg))
    return path


def freeze_v3(tmp_path, build, configs, *extra):
    out = tmp_path / 'freeze.json'
    assert fg.main(['write', str(build), '-o', str(out), '--configs'] + [str(c) for c in configs] + list(extra)) == 0
    return out


def test_v3_records_one_candidate_and_binds_its_own_config(tmp_path, repo):
    root, build, _ = repo
    config = block_config(root, build)
    out = freeze_v3(tmp_path, build, [config])
    cand = json.loads(out.read_text())['candidate']
    assert cand['model']['qualification'] == 'model_gate_passed' and cand['diagnostic_exception'] is None
    record = tmp_path / 'check.json'
    assert fg.main(['check', str(out), '--config', str(config), '--record', str(record)]) == 0
    result = json.loads(record.read_text())
    assert result['candidate_binding'] == [] and result['qualifies'] is True


def _other_source(cfg):
    cfg['builds']['ctl_x_01']['source_sha256'] = 'f' * 64
    return cfg['builds']


def _other_out_dir(cfg):
    cfg['builds']['ctl_x_01']['out_dir'] = cfg['builds']['ctl_x_01']['out_dir'].replace('switch_9132', 'local')
    return cfg['builds']


def _other_artifact(cfg):
    cfg['builds']['ctl_x_01']['hashes']['p0/tofino.bin'] = 'e' * 64
    return cfg['builds']


def _other_identity(cfg):
    return dict(cfg['ctl_timing_identity'], source_sha256='d' * 64)


@pytest.mark.parametrize('change', (dict(builds=_other_source), dict(builds=_other_out_dir),
                                    dict(builds=_other_artifact), dict(ctl_timing_identity=_other_identity),
                                    dict(builds={})))
def test_v3_refuses_a_config_of_another_build(tmp_path, repo, change):
    root, build, _ = repo
    good = block_config(root, build)
    bad = block_config(root, build, **change)
    out = freeze_v3(tmp_path, build, [good, bad])          # frozen, but not this candidate's
    assert fg.main(['check', str(out), '--config', str(good)]) == 0
    assert fg.main(['check', str(out), '--config', str(bad)]) == 1


def test_v3_refuses_a_config_outside_the_frozen_set_or_changed(tmp_path, repo):
    root, build, _ = repo
    frozen = block_config(root, build)
    other = block_config(root, build)
    out = freeze_v3(tmp_path, build, [frozen])
    assert fg.main(['check', str(out), '--config', str(other)]) == 1
    frozen.write_text(frozen.read_text() + ' ')
    assert fg.main(['check', str(out), '--config', str(frozen)]) == 1


def test_v3_refuses_to_freeze_a_blocked_model_gate_without_an_exception(tmp_path, repo, monkeypatch):
    root, build, _ = repo
    blocked = dict(qualification='blocked', blocked_reasons=['contention: 378/379'])
    (build / 'model_summary_v3.json').write_text(json.dumps(dict(
        blocked, summary_version=FakeSummary.SUMMARY_V3,
        source_sha256=fg.hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest())))
    monkeypatch.setattr(fg, 'model_summary_module', lambda: FakeSummary(blocked))
    with pytest.raises(SystemExit, match='cannot freeze a qualifying candidate'):
        freeze_v3(tmp_path, build, [block_config(root, build)])


def test_v3_records_a_diagnostic_exception_and_never_qualifies(tmp_path, repo, monkeypatch):
    root, build, _ = repo
    blocked = dict(qualification='blocked', blocked_reasons=['egress_diag: no attempt'])
    (build / 'model_summary_v3.json').write_text(json.dumps(dict(
        blocked, summary_version=FakeSummary.SUMMARY_V3,
        source_sha256=fg.hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest())))
    monkeypatch.setattr(fg, 'model_summary_module', lambda: FakeSummary(blocked))
    config = block_config(root, build, purpose='diagnostic')
    qualifying = block_config(root, build)                     # no purpose: treated as qualifying, refused
    out = freeze_v3(tmp_path, build, [config, qualifying], '--diagnostic-exception', 'isolation deadline diagnostic')
    record = tmp_path / 'check.json'
    assert fg.main(['check', str(out), '--config', str(config), '--record', str(record)]) == 0
    result = json.loads(record.read_text())
    assert result['qualifies'] is False and result['diagnostic_exception']['reason'] == 'isolation deadline diagnostic'
    assert fg.main(['check', str(out), '--config', str(qualifying)]) == 1


def test_v3_blocks_a_stale_model_summary(tmp_path, repo, monkeypatch):
    root, build, _ = repo
    monkeypatch.setattr(fg, 'model_summary_module', lambda: FakeSummary(dict(qualification='blocked',
                                                                              blocked_reasons=['new failure'])))
    with pytest.raises(SystemExit, match='stale'):
        freeze_v3(tmp_path, build, [block_config(root, build)])


def test_a_version_2_freeze_cannot_bind_a_config(tmp_path, repo):
    root, build, _ = repo
    config = block_config(root, build)
    out = freeze_v3(tmp_path, build, [config])
    data = json.loads(out.read_text())
    data['freeze_version'] = 'freeze-v2-20261017'
    data.pop('candidate')
    out.write_text(json.dumps(data))
    assert fg.main(['check', str(out), '--config', str(config)]) == 1


def test_runner_exits_3_and_never_reaches_run_block_on_a_foreign_config(tmp_path, repo):
    """The real frozen entrypoint checks the candidate before an external run."""
    import shutil
    root, build, _ = repo
    hw = root / fg.A / 'integration/evidence/rearm_01/hw'
    for name in ('run_block.sh', 'run_block_frozen.sh', 'guarded_block.py'):
        shutil.copy(HERE / name, hw / name)
    shutil.copy(HERE / 'freeze_gate.py', hw / 'freeze_gate.py')
    ct = hw.parents[2] / 'core/response_only_rearm/stage_experiments/ctl_timing_01'
    ct.mkdir(parents=True, exist_ok=True)
    (ct / 'model_summary.py').write_text(
        "SUMMARY_V3 = %r\n"
        "def attempts(build):\n    return []\n"
        "def summarize_v3(build):\n    return dict(qualification='model_gate_passed', blocked_reasons=[],"
        " latest_by_driver={})\n" % FakeSummary.SUMMARY_V3)
    marker = tmp_path / 'run_block_called'
    (hw / 'candidate_campaign.py').write_text(
        'import json, pathlib, sys\n'
        'if sys.argv[1] == "plan": raise SystemExit(0)\n'
        'cfg = json.loads(pathlib.Path(sys.argv[sys.argv.index("--config")+1]).read_text())\n'
        'root = pathlib.Path(__file__).resolve().parents[4] / cfg["evidence_dir"] / sys.argv[sys.argv.index("--run-id")+1]\n'
        'root.mkdir(parents=True)\n'
        'pathlib.Path(%r).touch()\n' % str(marker))
    (hw / 'restore_verify.py').write_text('print("restore verified by test fixture")\n')
    good = block_config(root, build, evidence_dir='ev')
    bad = block_config(root, build, evidence_dir='ev', builds=_other_source)
    out = freeze_v3(tmp_path, build, [good, bad])
    run = subprocess.run(['bash', str(hw / 'run_block_frozen.sh'), str(out), 'candidate_campaign', str(bad), 'r1'],
                         stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert run.returncode == 3 and not marker.exists()
    assert 'not bound' in run.stdout
    run = subprocess.run(['bash', str(hw / 'run_block_frozen.sh'), str(out), 'candidate_campaign', str(good), 'r2'],
                         stdin=subprocess.DEVNULL, capture_output=True, text=True)
    assert run.returncode == 0 and marker.exists()                 # the same freeze admits its own config


def test_v3_refuses_a_compile_of_another_source(tmp_path, repo):
    """Review finding 1: a compile directory replaced by a consistent compile of another source."""
    root, build, _ = repo
    write_manifest(build / 'compile_switch_9132', 'a' * 64)
    with pytest.raises(SystemExit, match='not bound to the source'):
        freeze_v3(tmp_path, build, [block_config(root, build)])


def test_v3_pins_every_manifest_artifact(tmp_path, repo):
    """Review finding 2: context.json is loaded too, so a change to it fails the check."""
    root, build, _ = repo
    config = block_config(root, build)
    out = freeze_v3(tmp_path, build, [config])
    assert any(f.endswith('compile_switch_9132/out/p0/context.json') for f in json.loads(out.read_text())['files'])
    (build / 'compile_switch_9132/out/p0/context.json').write_text('changed\n')
    assert fg.main(['check', str(out), '--config', str(config)]) == 1


def test_v3_rechecks_the_model_verdict_before_every_block(tmp_path, repo, monkeypatch):
    """Review finding 3: a later failing attempt after the freeze blocks the next load."""
    root, build, _ = repo
    config = block_config(root, build)
    out = freeze_v3(tmp_path, build, [config])
    monkeypatch.setattr(fg, 'model_summary_module', lambda: FakeSummary(dict(
        qualification='blocked', blocked_reasons=['contention: latest attempt _02 failed'],
        latest_by_driver={'contention': 'model_contention_x_01_02'})))
    assert fg.main(['check', str(out), '--config', str(config)]) == 1
