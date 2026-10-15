"""cost_report.py on a retained repeated-SBO block: internal receives counted once per loop role, per exchange."""
import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / 'analysis'))
import cost_report as cr  # noqa: E402

RUN = HERE / 'evidence/hw_campaigns/candidate61_repeat_sbo_950_b2'
pytestmark = pytest.mark.skipif(not (RUN / 'campaign_run.json').is_file(), reason='retained block absent')


def test_untimed_arms_do_almost_no_internal_work_and_timed_arms_do_much_more():
    out = cr.report([str(RUN)])
    off = out['arms']['separate_ack/off']['per_exchange']
    timed = out['arms']['separate_ack/combined']['per_exchange']
    assert off['held_rewaits']['median'] == 0 and off['blocker_packets']['median'] == 0
    assert timed['rx_frames']['median'] > 50 * off['rx_frames']['median']
    for row in out['runs']:
        assert sum(row['exchanges'].values()) == 65 + 2 * 64
        assert row['internal_rx_frames'] == sum(row['rx_frames_by_role'].values())


def test_missing_snapshot_is_reported_not_guessed(tmp_path):
    rec = json.loads((RUN / 'campaign_run.json').read_text())
    arm = rec['arms'][0]
    label = arm['trials'][0]['label']
    trial = tmp_path / arm['fixture'] / arm['arm'] / label
    trial.mkdir(parents=True)
    (trial / 'timing.json').write_text((RUN / arm['fixture'] / arm['arm'] / label / 'timing.json').read_text())
    (tmp_path / 'campaign_run.json').write_text(json.dumps(rec))
    out = cr.report([str(tmp_path)])
    assert 'error' in out['runs'][0]
