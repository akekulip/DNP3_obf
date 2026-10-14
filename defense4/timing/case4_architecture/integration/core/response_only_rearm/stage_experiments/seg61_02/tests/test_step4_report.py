"""step4_report.py on the committed candidate61_fourarm_smoke_03 evidence (silicon, 2026-10-14)."""
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
RUN = HERE / 'evidence/hw_campaigns/candidate61_fourarm_smoke_03'


def test_report_on_smoke_03(tmp_path):
    out = tmp_path / 's4.json'
    r = subprocess.run([sys.executable, str(HERE / 'analysis/step4_report.py'), '--candidate', str(RUN), '-o', str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    d = json.loads(out.read_text())['candidate61']
    assert set(d['arms']) == {'off', 'timing_only', 'size_only', 'combined'}
    for t in d['trials']:
        lens = dict(t['resp_lens'])
        padded = t['arm'] in ('size_only', 'combined')
        assert lens == ({'READ': 61, 'SELECT': 61, 'OPERATE': 61} if padded else {'READ': 49, 'SELECT': 37, 'OPERATE': 37})
        assert t['growth_check']['expected_fresh_bytes'] == (12 * 20 + 24 * 2 if padded else 0)
        assert t['growth_bytes'] == t['growth_check']['expected_fresh_bytes']
        assert len(t['sbo_completion_us']) == 1 and t['sbo_completion_us'][0] > 0
        assert t['read_piggybacked'] == 0
    assert d['arms']['combined']['metric'] == 'clrt_minus_gap_us'
    assert d['arms']['off']['metric'] == 'raw_clrt_us'
    assert d['arms']['combined']['pooled']['n'] == 20


STRICT = HERE / 'evidence/hw_campaigns/strict_comparison_59570_950_b1'


def test_strict_growth_comes_from_its_own_bound_lengths(tmp_path):
    out = tmp_path / 's4s.json'
    r = subprocess.run([sys.executable, str(HERE / 'analysis/step4_report.py'), '--candidate', str(STRICT), '-o', str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    for t in json.loads(out.read_text())['candidate61']['trials']:
        padded = t['arm'] in ('size_only', 'combined')
        assert t['growth_check']['per_kind'] == ({'READ': 9, 'SELECT': 0, 'OPERATE': 0} if padded
                                                 else {'READ': 0, 'SELECT': 0, 'OPERATE': 0})
        assert t['growth_bytes'] == t['growth_check']['expected_fresh_bytes'] == (9 * 500 if padded else 0)


def _mod():
    import importlib.util
    spec = importlib.util.spec_from_file_location('step4_report', HERE / 'analysis/step4_report.py')
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _ex(kind, t_req, rt, retx=False, attempts=1):
    return {'kind': kind, 't_req': t_req, 'rt_us': rt, 'ack_lat_us': 100, 'clrt_us': rt - 100, 'complete': True,
            'retransmitted': retx, 'attempts': attempts}


def test_sbo_completion_pairs_each_operate_with_the_latest_earlier_select_only():
    m = _mod()
    ex = [_ex('SELECT', 1000, 50), _ex('OPERATE', 2000, 70), _ex('SELECT', 9000, 50), _ex('OPERATE', 9500, 80)]
    assert m.control_timing(ex)['sbo_completion_us'] == [2000 + 70 - 1000, 9500 + 80 - 9000]


def test_retransmitted_or_multi_attempt_exchanges_are_excluded_everywhere():
    m = _mod()
    ex = [_ex('SELECT', 1000, 50), _ex('OPERATE', 2000, 70, retx=True), _ex('READ', 3000, 40, attempts=2)]
    ctl = m.control_timing(ex)
    assert ctl['OPERATE']['rt_us'] == [] and ctl['sbo_completion_us'] == []
    assert m.tails('r', 'combined', 'l', [dict(_ex('READ', 1, 2000), clrt_us=2000, attempts=2)], 950.0) == []


def test_growth_check_tolerates_no_sbo_and_unknown_kinds_and_reports_the_match(tmp_path):
    m = _mod()
    (tmp_path / 'standards.json').write_text(json.dumps({'expected': {'lengths': {'READ': [61]}}}))
    ex = [_ex('READ', 1, 10), _ex('READ', 2, 10), _ex('F7', 3, 10)]
    g = m.growth_check(tmp_path, ex, measured=24)
    assert g['expected_fresh_bytes'] == 24 and g['growth_match'] is True and g['unknown_kinds'] == ['F7']
    assert m.growth_check(tmp_path, ex, measured=36)['growth_match'] is False
