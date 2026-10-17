"""candidate_interleave.py: plan from the config's probe tuple, and the verdict mapping (offline; no hosts)."""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / 'tests'))
import candidate_interleave as ci  # noqa: E402
import contention_probe as cp  # noqa: E402

CONFIG = HERE.parents[2] / 'core/response_only_rearm/stage_experiments/seg61_02/hw/config/ctl_m10_interleave_950.json'


def cfg():
    return json.loads(CONFIG.read_text())


def test_plan_uses_the_configs_probe_tuple_and_image_length():
    c = cfg()
    plan = ci.plan_for(c)
    assert plan['tuple'] == [c['endpoints']['master_ip'], c['endpoints']['outstation_ip'],
                             c['traffic']['master_port_range']['first'], c['endpoints']['outstation_port']]
    assert plan['image_len'] == 61 and plan['tuple'][0].startswith('192.0.2.')


def test_a_port_range_wider_than_one_is_refused():
    c = cfg()
    c['traffic']['master_port_range']['last'] = c['traffic']['master_port_range']['first'] + 1
    with pytest.raises(ValueError, match='one master port'):
        ci.plan_for(c)


def _verdict(tmp_path, restarts, with_snapshots=True, rc=0):
    """Run the tool's verdict on a synthetic correct switch output (test_interleave_probe's builder)."""
    import test_interleave_probe as tip
    camp = ci.CandidateInterleaveCampaign.__new__(ci.CandidateInterleaveCampaign)
    camp.rn = SimpleNamespace(dry=False)
    camp.plan = ci.plan_for(cfg())
    label, dest = 'unit', tmp_path
    (dest / 'snapshots').mkdir()
    cp.write_pcap(dest / 'out.pcap', [(e['t_ns'], bytes.fromhex(e['bytes'])) for e in camp.plan['schedule']])
    cp.write_pcap(dest / 'in.pcap', [(i * 1000, bytes.fromhex(x))
                                     for i, x in enumerate(tip.switch_output(camp.plan))])
    (dest / 'inject.json').write_text(json.dumps(tip.INJECT(camp.plan)))
    if with_snapshots:
        for tag, n in (('before', 0), ('after', restarts)):
            (dest / 'snapshots' / ('%s_%s.json' % (label, tag))).write_text(json.dumps(tip.snap(n)))
    trial = {'failures': []}
    try:
        camp.verdict(trial, None, label, str(dest), SimpleNamespace(rc=rc), None, None)
        trial['raised'] = False
    except ci.base.StepFailed:
        trial['raised'] = True
    return trial


def test_verdict_pass_needs_delivery_and_a_restart(tmp_path):
    t = _verdict(tmp_path, restarts=2)
    assert t['ok'] is True and t['interleave_verdict'] == 'PASS' and t['raised'] is False
    assert (tmp_path / 'trial.json').is_file() and (tmp_path / 'interleave.json').is_file()


def test_every_non_pass_verdict_fails_the_block(tmp_path):
    """Code review, critical: trial['ok'] alone left run_block's rc at 0."""
    t = _verdict(tmp_path, restarts=0)
    assert t['interleave_verdict'] == 'NOT_EXERCISED' and t['raised'] is True


def test_verdict_without_snapshots_is_invalid_and_fails_the_block(tmp_path):
    t = _verdict(tmp_path, restarts=1, with_snapshots=False)
    assert t['interleave_verdict'] == 'INVALID' and t['raised'] is True


def test_a_failed_injector_is_invalid(tmp_path):
    t = _verdict(tmp_path, restarts=1, rc=2)
    assert t['interleave_verdict'] == 'INVALID' and t['raised'] is True


def test_dry_mode_judges_nothing(tmp_path):
    camp = ci.CandidateInterleaveCampaign.__new__(ci.CandidateInterleaveCampaign)
    camp.rn = SimpleNamespace(dry=True)
    trial = {'failures': []}
    camp.verdict(trial, None, 'u', str(tmp_path), None, None, None)
    assert trial['interleave_verdict'] == 'DRY' and not (tmp_path / 'interleave.json').exists()
