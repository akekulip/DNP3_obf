import copy
import sys
import json
import shlex
import subprocess
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import candidate_isolation as ci


def config():
    cfg=ci.base.load_config(str(ci.ARCH/'protocol/hw_vepa/config/precision_5ms_gap800us_14892.json'))
    cfg['builds']['mirror_fix_01']['lifecycle_rearm']=True
    cfg['trials']=dict(reads_per_trial=1,trials_per_arm=1)
    cfg['evaluation']=dict(purpose='stale_source_characterization',read_precision=False)
    cfg['traffic']['master_port_range']=dict(first=59412,last=59412)
    cfg['hosts']['vision_run_dir']=ci.BARRIER_DIRECTORY
    cfg['endpoint']['binary_sha256']=ci.BARRIER_BINARY
    return cfg


def test_diagnostic_cannot_use_legacy_endpoint_or_qualify_precision():
    cfg=config()
    run=ci.TokenIsolationCampaign(cfg,ci.base.DryRunner(),'token_test',arms=['combined'],fixtures=['separate_ack'])
    assert run.units()[0]['reads']==1
    for field,value in [('trials',dict(reads_per_trial=20,trials_per_arm=1)),
                        ('evaluation',dict(purpose='qualification',read_precision=True))]:
        wrong=copy.deepcopy(cfg);wrong[field]=value
        with pytest.raises(ValueError):ci.TokenIsolationCampaign(wrong,ci.base.DryRunner(),'bad',arms=['combined'],fixtures=['separate_ack'])
    wrong=copy.deepcopy(cfg);wrong['endpoint']['binary_sha256']='a'*64
    with pytest.raises(ValueError):ci.TokenIsolationCampaign(wrong,ci.base.DryRunner(),'bad',arms=['combined'],fixtures=['separate_ack'])


def test_fixed_isolation_command_has_one_read_and_no_external_replay():
    run=ci.TokenIsolationCampaign(config(),ci.base.DryRunner(),'token_cmd',arms=['combined'],fixtures=['separate_ack'])
    run._series_padding=1
    command=run.series_vision_cmd('fixed',59412,1,8,0)
    assert 'vision_isolation.py fixed --master-port 59412 --padding 1 --apply' in command
    assert 'vision_candidate.py' not in command and 'replay' not in command


def test_marker_reader_command_never_prints_arbitrary_files():
    command=ci.marker_command('/safe/run/c2/pre_read_ready.json')
    assert 'pre_read_ready.json' in command and 'monotonic_ns' in command
    assert 'read_bytes' not in command


def test_marker_reader_retries_partial_write_without_accepting_it(tmp_path):
    path=tmp_path/'pre_read_ready.json';path.write_text('{')
    result=subprocess.run(shlex.split(ci.marker_command(str(path))),capture_output=True,text=True)
    assert result.returncode==0
    assert json.loads(result.stdout)['marker_status']=='incomplete'
    assert json.loads(result.stdout)['marker'] is None
    path.write_text(json.dumps(dict(tcp_open=True,opens=1)))
    result=subprocess.run(shlex.split(ci.marker_command(str(path))),capture_output=True,text=True)
    assert json.loads(result.stdout)['marker_status']=='complete'


def test_hardware_execute_refuses_missing_local_authorization_before_any_step(monkeypatch):
    runner=ci.base.DryRunner();runner.dry=False
    run=ci.TokenIsolationCampaign(config(),runner,'no_auth',arms=['combined'],fixtures=['separate_ack'])
    monkeypatch.delenv('DEFENSE4_HW_AUTHORIZED',raising=False)
    with pytest.raises(ValueError,match='DEFENSE4_HW_AUTHORIZED'):run.execute()


def test_new_barrier_config_is_pinned_to_its_isolated_directory():
    cfg=config()
    cfg['hosts']['vision_run_dir']='/home/decps/pad58b_rearm_barrier_20261012'
    with pytest.raises(ValueError,match='exact pinned'):
        ci.TokenIsolationCampaign(cfg,ci.base.DryRunner(),'old_barrier',arms=['combined'],fixtures=['separate_ack'])
