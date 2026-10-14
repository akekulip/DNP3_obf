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
    assert d['arms']['combined']['metric'] == 'clrt_minus_gap_us'
    assert d['arms']['off']['metric'] == 'raw_clrt_us'
    assert d['arms']['combined']['pooled']['n'] == 20
