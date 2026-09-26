import pytest
from defense4.timing.latency_search.evaluate_random import paired_rows


def row(block, time, arm='native', group='replicate_00', score=0):
    return {'block':block,'t_req_ns':str(time),'arm':arm,'session':group,
            'policy_name':'candidate' if arm=='obfuscated' else 'OFF',
            'txn_index':0,'ack_ms':score,'txn_class':'READ'}


def test_pairing_uses_time_and_earlier_tie_without_measured_features():
    rows=[row('protected',100,'obfuscated'),row('late',110,score=0),
          row('early',90,score=999),row('far',1000),row('another_group',100,group='replicate_01')]
    paired,chosen=paired_rows(rows,'candidate')
    assert chosen['replicate_00']['block']=='early'
    assert {r['block'] for r in paired}=={'protected','early'}


def test_pairing_requires_off_in_every_protected_group():
    with pytest.raises(ValueError,match='no paired OFF'):
        paired_rows([row('protected',100,'obfuscated'),row('wrong',100,group='replicate_01')],'candidate')


def test_pairing_preserves_all_samples_from_chosen_block():
    rows=[row('protected',100,'obfuscated'),row('near',90),row('near',92),row('far',1000)]
    paired,chosen=paired_rows(rows,'candidate')
    assert len(paired)==3 and chosen['replicate_00']['midpoint_ns']==91
