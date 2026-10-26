"""Offline c69 campaign config ABI and installer-command dispatch."""
import json
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import campaign

ARCH = HERE.parents[2]
NO_J = 'response_ready_ack_d_no_j_v3'
V2 = 'response_ready_ack_d_v2'


def no_j_config():
    path = ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01/hw/config/rc01_m12p_c52_sdk9132_sel751_reference.json'
    cfg = json.loads(path.read_text())
    cfg['timing_contract'] = NO_J
    cfg['timing_params_ns'] = dict(gap=5000000, budget=240000, enabled=1)
    for build in cfg['builds'].values():
        build.update(timing_contract=NO_J, piggyback_bound=False, switch_telemetry=False)
    return cfg


def load(tmp_path, cfg):
    path = tmp_path / 'config.json'
    path.write_text(json.dumps(cfg))
    return campaign.load_config(path)


@pytest.mark.parametrize('gap', [5000000, 10000000, 15000000, 20000000])
def test_no_j_loads_explicit_contract_and_generates_only_three_timing_flags(tmp_path, gap):
    cfg = no_j_config()
    cfg['timing_params_ns']['gap'] = gap
    loaded = load(tmp_path, cfg)
    runner = campaign.Campaign(loaded, campaign.DryRunner(), 'offline_no_j_contract')
    build = next(iter(cfg['builds']))
    runner.bound = {build: {}}
    command = runner.installer_cmd(build, 1, '/offline/out', 59410)
    assert '--t-gap %d' % gap in command
    assert '--t-budget 240000' in command and '--t-enabled 1' in command
    assert all(flag not in command for flag in ('--t-op-j', '--t-da', '--t-readiness', '--t-cap', '--t-pb'))


@pytest.mark.parametrize('mutate', [
    lambda cfg: cfg['timing_params_ns'].update(op_j=2400000),
    lambda cfg: cfg['timing_params_ns'].update(gap=True),
    lambda cfg: cfg['timing_params_ns'].update(gap=8000000),
    lambda cfg: cfg['timing_params_ns'].update(budget=0),
    lambda cfg: cfg['timing_params_ns'].update(budget=True),
    lambda cfg: cfg['timing_params_ns'].update(enabled=2),
    lambda cfg: cfg['timing_params_ns'].update(enabled=True),
    lambda cfg: cfg.pop('timing_contract'),
    lambda cfg: next(iter(cfg['builds'].values())).update(timing_contract=V2),
    lambda cfg: cfg.update(endpoint_profile='software'),
])
def test_no_j_load_rejects_j_wrong_params_or_missing_explicit_contract(tmp_path, mutate):
    cfg = no_j_config()
    mutate(cfg)
    with pytest.raises(ValueError):
        load(tmp_path, cfg)


def test_legacy_v2_still_requires_j(tmp_path):
    cfg = no_j_config()
    cfg['timing_contract'] = V2
    for build in cfg['builds'].values():
        build['timing_contract'] = V2
    with pytest.raises(ValueError):
        load(tmp_path, cfg)
