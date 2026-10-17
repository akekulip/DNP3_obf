"""isolation_v3.py on the retained blocks (review of 7637390c1, findings 2 and 4)."""
import importlib.util
import json
import shutil
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('isolation_v3', HERE.parent / 'analysis/isolation_v3.py')
iso = importlib.util.module_from_spec(spec)
spec.loader.exec_module(iso)
H = HERE.parent / 'evidence/hw_campaigns'


def copy_run(tmp_path, name):
    target = tmp_path / name
    shutil.copytree(H / name, target, ignore=shutil.ignore_patterns('*.pcap', '*.log', 'isolation_v3.json'))
    return target


@pytest.mark.parametrize('name, verdicts', (
    ('ctl_m5_stale_iso20_950_01', ('PASS', 'PASS', 'INDETERMINATE')),     # no poller
    ('ctl_m5_c3diag_iso20_950_01', ('PASS', 'PASS', 'INDETERMINATE')),    # poller: bracket overlaps the deadline
    ('ctl_m5_c3diag_control_950_01', ('PASS', 'PASS', 'NOT_APPLICABLE')),
    ('ctl_m9_stale_iso20_950_01', ('PASS', 'PASS', 'INDETERMINATE')),     # no poller
))
def test_retained_blocks(tmp_path, name, verdicts):
    r = iso.recompute(copy_run(tmp_path, name))
    assert (r['old_tokens_rejected']['verdict'], r['traffic_correct']['verdict'],
            r['cleanup_deadline']['verdict']) == verdicts
    assert r['unattributed_v1_failures'] == []


def test_d1_drain_bracket_overlaps_the_deadline():
    r = iso.recompute(H / 'ctl_m5_c3diag_iso20_950_01')
    lo, hi = r['cleanup_deadline']['drain_ns_interval']
    assert lo <= r['cleanup_deadline']['emission_bound_ns'] < hi


def test_an_unattributed_v1_failure_blocks(tmp_path):
    run = copy_run(tmp_path, 'ctl_m5_c3diag_control_950_01')
    verdict = next(run.glob('*/*/*/isolation_verdict.json'))
    v = json.loads(verdict.read_text())
    v['failures'] = list(v['failures']) + ['switch: something nobody has classified']
    verdict.write_text(json.dumps(v))
    r = iso.recompute(run)
    assert r['traffic_correct']['verdict'] == 'FAIL' and len(r['unattributed_v1_failures']) == 1


def test_a_missing_traffic_component_blocks(tmp_path):
    run = copy_run(tmp_path, 'ctl_m5_c3diag_control_950_01')
    verdict = next(run.glob('*/*/*/isolation_verdict.json'))
    v = json.loads(verdict.read_text())
    v.pop('bank_isolation')
    verdict.write_text(json.dumps(v))
    assert iso.recompute(run)['traffic_correct']['verdict'] == 'FAIL'


def test_binding_requires_the_runs_own_config_and_this_acceptance_version(tmp_path):
    run = copy_run(tmp_path, 'ctl_m5_c3diag_control_950_01')
    record = json.loads((run / 'campaign_run.json').read_text())
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'acceptance_version': iso.tw.ACCEPTANCE_V3}))
    import hashlib
    record['config_file_sha256'] = hashlib.sha256(config.read_bytes()).hexdigest()
    (run / 'campaign_run.json').write_text(json.dumps(record))
    assert iso.recompute(run, config)['acceptance_binding']['ok'] is True
    config.write_text(json.dumps({'acceptance_version': 'isolation-v2-20261016'}))
    r = iso.recompute(run, config)
    assert r['acceptance_binding']['ok'] is False and r['verdict'] == 'FAIL'
