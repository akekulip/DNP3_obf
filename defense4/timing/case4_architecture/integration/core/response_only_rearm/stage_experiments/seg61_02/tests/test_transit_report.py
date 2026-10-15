"""transit_report.py on the retained candidate61 eval block 1 off arm: every packet matched tap to tap, and the
~1.1 ms outstation-side events found 128 exchanges apart."""
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / 'analysis'))
import transit_report as tr  # noqa: E402

TRIAL = (HERE / 'evidence/hw_campaigns/candidate61_eval_59570_950_b1/separate_ack/off/'
         'candidate61_eval_59570_950_b1_separate_ack_off_t0')
pytestmark = pytest.mark.skipif(not (TRIAL / 'in.pcap').is_file(), reason='retained eval capture absent')


def test_off_arm_events_and_spacing():
    t = tr.trial_transit(TRIAL, 500)
    assert t['unmatched_tx'] == 0 and t['requests'] == 502
    acks = [e for e in t['events'] if e['leg'] == 'outstation_ack']
    assert [e['after_request'] for e in acks] == [127, 255]
    assert all(1000 < e['transit_us'] < 1200 for e in acks)
    assert t['legs']['response']['over_threshold'] == 0
