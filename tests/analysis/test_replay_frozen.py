import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
import replay_frozen  # noqa: E402
import replay_scenario_adapter  # noqa: E402

CAMPAIGN = ROOT / 'results/hardware/campaigns/rc01_hw_c72_20261027_02'
INDEX = ROOT / 'results/hardware/rc01_hw_c72_20261027_02_index.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def test_materialize_writes_only_files_whose_bytes_match_the_freeze(tmp_path):
    freeze_files = {'scripts/a.py': {'sha256': sha(b'x')}, 'scripts/b.py': {'sha256': sha(b'y')},
                    'scripts/c.py': {'sha256': sha(b'z')}, 'p4/other.p4': {'sha256': sha(b'p')}}
    blobs = {'scripts/a.py': b'x', 'scripts/b.py': b'WRONG'}
    report = replay_frozen.materialize(freeze_files, blobs.get, tmp_path)
    assert report == dict(verified=['scripts/a.py'], mismatched=['scripts/b.py'], missing=['scripts/c.py'])
    assert (tmp_path / 'scripts/a.py').read_bytes() == b'x'
    assert not (tmp_path / 'scripts/b.py').exists() and not (tmp_path / 'scripts/c.py').exists()


def test_adapter_reads_the_scenario_record_only_when_the_trial_has_no_result(tmp_path):
    (tmp_path / 'scenario.json').write_text(json.dumps({'ok': True, 'kind': 'scenario'}))
    assert replay_scenario_adapter.endpoint_path(tmp_path / 'result.json') == tmp_path / 'scenario.json'
    (tmp_path / 'result.json').write_text(json.dumps({'ok': False, 'kind': 'single'}))
    assert replay_scenario_adapter.endpoint_path(tmp_path / 'result.json') == tmp_path / 'result.json'
    assert replay_scenario_adapter.endpoint_path(tmp_path / 'trial.json') == tmp_path / 'trial.json'


def test_loaded_modules_outside_the_verified_set_are_reported(tmp_path):
    good, bad = tmp_path / 'scripts/checks/good.py', tmp_path / 'scripts/checks/bad.py'
    live = ROOT / 'scripts/checks/standards.py'            # the live repository, outside the frozen tree
    audit = replay_frozen.audit_loaded({'good': str(good), 'bad': str(bad), 'standards': str(live),
                                        'os': '/usr/lib/python3/os.py', 'sys': ''},
                                       tmp_path, verified={'scripts/checks/good.py'})
    assert audit['verified'] == ['scripts/checks/good.py']
    assert audit['unverified'] == ['scripts/checks/bad.py', 'scripts/checks/standards.py (live repository)']
    assert audit['environment'] == ['os']


def test_frozen_module_names_already_loaded_are_refused():
    assert replay_frozen.preloaded({'campaign_base', 'standards'}, {'json': 1, 'standards': 1}) == ['standards']


def run(mode, out, code):
    result = subprocess.run([sys.executable, str(ROOT / 'scripts/analysis/replay_frozen.py'), '--campaign',
                             str(CAMPAIGN), '--index', str(INDEX), '--mode', mode, '--output', str(out)],
                            capture_output=True, text=True)
    assert result.returncode == code, result.stderr[-500:]
    return json.loads(out.read_text())


def test_original_frozen_replay_and_the_scenario_adapter_are_reported_separately(tmp_path):
    original = run('original', tmp_path / 'original.json', 1)        # the replay itself does not complete
    assert original['loaded_modules']['unverified'] == [] and original['adapter'] is None
    assert original['replay']['ok'] is False and original['replay']['exchanges'] == 1934
    assert any('result.json' in failure for failure in original['replay']['failures'])
    adapted = run('scenario_adapter', tmp_path / 'adapted.json', 0)
    assert adapted['loaded_modules']['unverified'] == []
    assert adapted['adapter']['sha256'] == sha((ROOT / 'scripts/analysis/replay_scenario_adapter.py').read_bytes())
    assert adapted['replay']['exchanges'] == 2440 and adapted['replay']['failures'] == []
    outcomes = adapted['recorded_block_outcomes']
    assert [b for b, o in outcomes.items() if o['recorded_fail']] == ['10_d20_loss_full']
    assert outcomes['10_d20_loss_full']['recorded_fail'] == ['rc01_hw_c72_20261027_02_10_d20_loss_full_'
                                                             'physical_relay_combined_t3']
    assert 'accounted for' in adapted['statement'] and 'passed' not in adapted['statement']
