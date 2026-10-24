import importlib.util
import json
from pathlib import Path

import pytest

HW = Path(__file__).resolve().parents[3] / 'integration/evidence/rearm_01/hw'
spec = importlib.util.spec_from_file_location('relay_freeze_test', HW / 'freeze_gate.py')
fg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fg)


def test_baseline_freeze_cannot_authorize_candidate_load(tmp_path):
    cfg = tmp_path / 'candidate.json'
    cfg.write_text(json.dumps(dict(endpoint_profile='sel751', purpose='relay-native-baseline',
                                   builds={'candidate': {'source_sha256': 'a' * 64}})))
    frozen = dict(freeze_version='production-baseline-v1', files={})
    assert fg.candidate_binding(frozen, cfg)


def test_baseline_requires_native_config_and_production_hashes():
    with pytest.raises(ValueError):
        fg.baseline_files({'endpoint_profile': 'sel751', 'builds': {}}, [])


def test_native_plan_includes_real_guarded_master_and_full_restore():
    import sys
    sys.path.insert(0, str(HW))
    import candidate_relay_native as native
    cfg = json.loads((HW.parents[3] / 'protocol/hw_vepa/config/sel751_native_20261024.json').read_text())
    runner = native.cp.DryRunner()
    run = native.RelayNative(cfg, runner, 'native_offline_regression', out=lambda *a: None)
    assert run.execute() == 0
    assert run.record['candidate_loaded'] is False
    assert len(run.record['restore']) == 5
    privileged = [command for where, command in runner.calls if where == 'vision' and
                  ('relay_master.py --preflight' in command or 'vision_run.py run ' in command)]
    assert len(privileged) == 2
    assert all('sudo env' not in command for command in privileged)
    assert all(command.startswith('sudo -n /usr/bin/python3 ') for command in privileged)
    assert '--apply' in next(command for command in privileged if 'vision_run.py run ' in command)


def test_production_baseline_wrong_program_is_refused_before_deployment():
    import sys
    sys.path.insert(0, str(HW))
    import candidate_relay_native as native
    cfg = json.loads((HW.parents[3] / 'protocol/hw_vepa/config/sel751_native_20261024.json').read_text())
    cfg['production']['program'] = 'response_only'
    run = native.RelayNative(cfg, native.cp.DryRunner(), 'native_bad_program')
    with pytest.raises(ValueError):
        run.execute()


def test_baseline_freeze_covers_deployed_framework_restore_tools():
    cfg = json.loads((HW.parents[3] / 'protocol/hw_vepa/config/sel751_native_20261024.json').read_text())
    files = fg.baseline_files(cfg, [])
    assert 'defense4/timing/framework/control/restore_ports.py' in files
    assert 'defense4/timing/framework/control/live_snapshot.py' in files


def test_frozen_framework_restore_tool_mutation_is_refused(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import hashlib
    root = tmp_path / 'repo'
    relative = 'defense4/timing/framework/control/restore_ports.py'
    helper = root / relative
    helper.parent.mkdir(parents=True)
    helper.write_text('original restore helper\n')
    frozen = tmp_path / 'freeze.json'
    frozen.write_text(json.dumps(dict(freeze_version='production-baseline-v1', source_sha256=None,
                         files={relative: dict(sha256=hashlib.sha256(helper.read_bytes()).hexdigest())})))
    monkeypatch.setattr(fg, 'REPO', root)
    args = SimpleNamespace(freeze=str(frozen), config=None, record=None)
    assert fg.check(args) == 0
    helper.write_text('changed after freeze\n')
    assert fg.check(args) == 1


def test_failed_native_traffic_retains_command_stdout_stderr_before_collection(tmp_path):
    import sys
    sys.path.insert(0, str(HW))
    import candidate_relay_native as native
    cfg = json.loads((HW.parents[3] / 'protocol/hw_vepa/config/sel751_native_20261024.json').read_text())
    cfg['evidence_dir'] = str(tmp_path)
    class Fake(native.RelayNative):
        def deploy_switch(self): pass
        def switch_toolkit(self): pass
        def vision_identity(self): pass
        def vision_setup(self): pass
        def check_hash(self, *args): pass
        def step(self, where, label, command, **kwargs):
            if label == 'physical relay native master and capture':
                return native.cp.Result(1, 'partial native stdout\n', 'exact import failure\n')
            if 'running production conf' in label:
                return native.cp.Result(0, json.dumps(dict(conf=self.cfg['production']['conf'])), '')
            if 'slot, padding disabled' in label:
                return native.cp.Result(0, json.dumps(dict(which='relay', enable=0, master_port=59410,
                    passthrough=True, **{'Ingress.forwarding': [dict(key={'ig.ingress_port': 9}, data=dict(port=64)),
                    dict(key={'ig.ingress_port': 64}, data=dict(port=9))], 'Egress.conn': [], 'Egress.odd_ip_t': []})), '')
            return native.cp.Result(0, '', '')
        def collect(self, *args, **kwargs):
            traffic = json.loads((Path(self.root) / 'traffic_result.json').read_text())
            assert traffic['rc'] == 1 and traffic['stderr'] == 'exact import failure\n'
            assert 'sudo -n /usr/bin/python3' in traffic['command'] and '--apply' in traffic['command']
        def restore(self): return True
    runner = native.cp.DryRunner()
    runner.dry = False
    run = Fake(cfg, runner, 'failed_native_traffic')
    import os
    from unittest.mock import patch
    with patch.dict(os.environ, DEFENSE4_HW_AUTHORIZED='1'):
        assert run.execute() == 1
    assert 'exact import failure' in (Path(run.root) / 'vision_run.out').read_text()
