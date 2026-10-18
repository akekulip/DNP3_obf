import importlib.util
from pathlib import Path
import subprocess
import sys
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('detached_campaign', HERE / 'campaign.py')
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)


def test_fresh_ssh_and_scp_do_not_depend_on_laptop_agent_or_mux():
    runner = campaign.ShellRunner({'switch': 'switch', 'vision': 'vision'})
    with mock.patch.object(campaign.subprocess, 'run', return_value=mock.Mock(returncode=0, stdout='', stderr='')) as call:
        runner.run('vision', 'true')
        argv = call.call_args[0][0]
        assert 'IdentityAgent=none' in argv and 'ControlPath=none' in argv
        runner.run('local', 'scp -q switch:evidence/run local_copy')   # strings only: the runner is mocked
        argv = call.call_args[0][0]
        assert argv[0] == 'scp'
        assert 'IdentityAgent=none' in argv and 'ControlMaster=no' in argv


def test_timeout_retains_partial_remote_logs():
    runner = campaign.ShellRunner({'vision': 'vision'})
    with mock.patch.object(campaign.subprocess, 'run', side_effect=subprocess.TimeoutExpired(
            ['ssh'], 1, output=b'partial endpoint evidence\n', stderr=b'partial stderr\n')):
        result = runner.run('vision', 'true', timeout=1)
    assert result.rc == 124
    assert 'partial endpoint evidence' in result.out
    assert 'partial stderr' in result.err
