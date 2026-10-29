import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
import recovery_e3  # noqa: E402

T3 = (ROOT / 'results/hardware/blocks/rc01_hw_c72_20261027_02_10_d20_loss_full/physical_relay/combined/'
      'rc01_hw_c72_20261027_02_10_d20_loss_full_physical_relay_combined_t3')


def test_the_retained_qualification_t3_timeline_is_reproduced_from_its_captures():
    row = recovery_e3.trial(T3)
    assert row['select_response_copies'] == 2
    assert row['ms_from_select_request'] == dict(relay_ack_of_select=4.497, first_select_response_copy=23.914,
                                                 retransmitted_select_response_copy=1016.368, operate_request=1017.437,
                                                 relay_ack_of_operate=1024.263, operate_response=1045.203)
    assert row['select_points'] == [[1, 'SUCCESS'], [3, 'SUCCESS']]
    assert row['operate_points'] == [[1, 'TIMEOUT'], [3, 'TIMEOUT']]
    assert row['verdict_ok'] is False
