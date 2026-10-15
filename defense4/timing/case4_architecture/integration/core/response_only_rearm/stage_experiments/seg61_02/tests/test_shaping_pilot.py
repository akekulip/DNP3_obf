"""shaping_pilot.compare: correctness on the full, unfiltered gates; shared failures fail the pilot (PLAN_m5.md S0)."""
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / 'analysis'))
import shaping_pilot as sp  # noqa: E402

RUNS = HERE / 'evidence/hw_campaigns'


def fake(run, fails=(), frames=1000.0, octets=90000.0, ack=5000.0, retro_pass=True, hold=True, trial_failures=None):
    lat = {k: {'clrt_pass': k not in fails, 'ack_median_us': ack,
               'retrospective_exclusion': {'clrt_pass': retro_pass}} for k in ('READ', 'SELECT', 'OPERATE')}
    return {'run': run, 'latency': lat, 'operate_hold': {'pass': hold}, 'trial_failures': trial_failures or [],
            'cost': {'per_exchange': {'rx_frames': frames, 'rx_octets': octets}}}


def test_shared_failure_is_not_correct_even_when_savings_are_large():
    c = sp.compare(fake('b', fails={'SELECT'}), fake('p', fails={'SELECT'}, frames=700, octets=60000))
    assert c['decision'] == 'not_correct' and not c['pilot_correct']
    assert c['pilot_failures'] == ['SELECT'] and c['pilot_new_failures'] == []
    assert c['efficiency_only']['frames_change'] == -0.3


def test_retrospective_exclusion_never_rescues_a_failed_gate():
    c = sp.compare(fake('b'), fake('p', fails={'READ'}, retro_pass=True, frames=500, octets=40000))
    assert c['decision'] == 'not_correct' and c['pilot_new_failures'] == ['READ']


def test_hold_and_non_precision_trial_failures_count():
    assert sp.compare(fake('b'), fake('p', hold=False))['pilot_failures'] == ['operate_hold']
    c = sp.compare(fake('b'), fake('p', trial_failures=['delivery: 1 lost', 'SELECT precision: x']))
    assert c['pilot_failures'] == ['delivery']


def test_correct_pilot_decisions():
    assert sp.compare(fake('b'), fake('p', frames=800, octets=80000))['decision'] == 'promising'
    assert sp.compare(fake('b'), fake('p', frames=980, octets=80000))['decision'] == 'inconclusive'
    assert sp.compare(fake('b'), fake('p', frames=800, octets=80000, ack=6100))['decision'] == 'stop'


def test_correctness_decides_before_the_ack_budget():
    c = sp.compare(fake('b'), fake('p', fails={'SELECT'}, ack=6100))
    assert c['decision'] == 'not_correct' and not c['within_ack_budget']


@pytest.mark.skipif(not (RUNS / 'ctl_m4_shape_ack14892_b2_01/campaign_run.json').is_file(),
                    reason='retained blocks absent')
def test_retained_ack14892_pair_b2_is_not_correct_on_full_gates():
    base, pilot = sp.block(RUNS / 'ctl_m4_shape_59570_b2_01'), sp.block(RUNS / 'ctl_m4_shape_ack14892_b2_01')
    c = sp.compare(base, pilot)
    assert c['decision'] == 'not_correct' and 'SELECT' in c['pilot_failures']
    assert pilot['latency']['SELECT']['retrospective_exclusion']['clrt_pass'] is True
    assert c['efficiency_only']['frames_change'] < -0.05
