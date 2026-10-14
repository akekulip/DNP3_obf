"""repeat_sbo_report.py on a retained repeated-SBO silicon trial, and on mutated copies of it."""
import json
import shutil
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / 'analysis'))
import repeat_sbo_report as rr  # noqa: E402

TRIAL = (HERE / 'evidence/hw_campaigns/candidate61_repeat_sbo_950_b1_02/separate_ack/combined/'
         'candidate61_repeat_sbo_950_b1_02_separate_ack_combined_t0')
pytestmark = pytest.mark.skipif(not (TRIAL / 'in.pcap').is_file(), reason='retained repeated-SBO capture absent')


def copy(tmp_path):
    d = tmp_path / 'trial'
    shutil.copytree(TRIAL, d, ignore=shutil.ignore_patterns('snapshots', '*.log', 'calibration_*'))
    return d


def rewrite_last_json(path, change):
    lines = path.read_text().splitlines()
    i = max(k for k, line in enumerate(lines) if line.startswith('{'))
    record = json.loads(lines[i])
    change(record)
    lines[i] = json.dumps(record)
    path.write_text('\n'.join(lines) + '\n')


def test_retained_trial_has_64_clean_cycles():
    t = rr.trial_cycles(TRIAL, 950.0)
    assert t['ok'], t['failures'][:3]
    assert t['cycles'] == 64 and sum(r['ok'] for r in t['rows']) == 64
    assert [w['on_time_ms'] for w in t['rows'][63]['wire_echo']] == [163, 163]
    assert set(t['resp_lens']) == {('READ', 61), ('SELECT', 61), ('OPERATE', 61)}


@pytest.mark.parametrize('name, target, change', [
    ('duplicate master callback', 'master.json', lambda r: r['cycles'][5].update(callbacks=2)),
    ('failed master status', 'master.json', lambda r: r['cycles'][9].update(status=3)),
    ('master timestamps reversed', 'master.json', lambda r: r['cycles'][2].update(completed_ns=r['cycles'][2]['issued_ns'] - 1)),
    ('outstation OPERATE before SELECT', 'outstation.json',
     lambda r: r['events'].__setitem__(slice(0, 2), [r['events'][1], r['events'][0]])),
    ('outstation duplicate OPERATE', 'outstation.json', lambda r: r['events'].insert(3, dict(r['events'][3]))),
    ('outstation wrong cycle on-time', 'outstation.json', lambda r: r['events'][7].update(on_time_ms=999)),
])
def test_endpoint_record_mutations_fail(tmp_path, name, target, change):
    d = copy(tmp_path)
    rewrite_last_json(d / target, change)
    t = rr.trial_cycles(d, 950.0)
    assert not t['ok'], name


def test_wire_duplicate_or_reordered_exchange_fails(tmp_path):
    d = copy(tmp_path)
    timing = json.loads((d / 'timing.json').read_text())
    selects = [e for e in timing['exchanges'] if e['kind'] == 'SELECT']
    selects[10]['attempts'] = 2                                   # a retransmitted SELECT on the wire
    (d / 'timing.json').write_text(json.dumps(timing))
    assert any('SELECT attempts=2' in f for f in rr.trial_cycles(d, 950.0)['failures'])
    timing['exchanges'] = [e for e in timing['exchanges'] if e is not selects[20]]
    (d / 'timing.json').write_text(json.dumps(timing))
    assert not rr.trial_cycles(d, 950.0)['ok']


def test_wire_echo_is_read_from_the_capture(tmp_path):
    d = copy(tmp_path)
    data = (d / 'in.pcap').read_bytes()
    # the 15/6/1 split puts CROB code, count and the on-time's two low octets at the end of segment 1
    echo = b'\x01\x01' + (100 + 30).to_bytes(2, 'little')
    assert data.count(echo) >= 1
    (d / 'in.pcap').write_bytes(data.replace(echo, b'\x01\x01' + (999).to_bytes(2, 'little')))
    failures = rr.trial_cycles(d, 950.0)['failures']
    assert any(f.startswith('cycle 30: wire echo') or 'unreadable' in f for f in failures), failures[:3]
