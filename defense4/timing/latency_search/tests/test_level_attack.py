import copy
import pytest
from defense4.timing.latency_search.evaluate_level_attack import nearest, project, load
from pathlib import Path


def test_projection_cannot_use_true_selection_or_operation_code():
    row = dict(session='r0',block='b',arm='obfuscated',txn_class='READ',txn_index=0,
               ack_ms=5.11,clrt_ms=1.02,selected_da_ms=5,selected_gap_ms=1,rand8=30,func=1)
    levels = dict(da_ms=[4,5,6],gap_ms=[1,2,3])
    a = project(row,levels)
    changed = copy.deepcopy(row)
    changed.update(selected_da_ms=99,selected_gap_ms=-5,rand8=240,func=5)
    b = project(changed,levels)
    assert a == b
    assert a['ack_ms'] == pytest.approx(.11)
    assert a['clrt_ms'] == pytest.approx(.02)
    assert set(a) == {'session','block','arm','txn_class','txn_index','ack_ms','clrt_ms'}


def test_projection_does_not_use_the_class_label_for_subtraction():
    row = dict(session='r0',block='b',arm='obfuscated',txn_class='READ',txn_index=0,
               ack_ms=5.11,clrt_ms=1.02)
    levels = dict(da_ms=[4,5,6],gap_ms=[1,2,3])
    a = project(row,levels)
    row['txn_class']='OPERATE'
    b = project(row,levels)
    assert (a['ack_ms'],a['clrt_ms']) == (b['ack_ms'],b['clrt_ms'])


def test_nearest_ties_use_lower_public_value():
    assert nearest(2,[3,1]) == 1


def test_partial_checkpoint_cannot_enter_classifier_evaluation():
    root=Path(__file__).resolve().parents[1]
    path=root/'results/checkpoints/random_screen_20260926T181911Z_first20'
    with pytest.raises(ValueError,match='completed acquisition'):
        load(path/'measurements.json',path/'primarytransactions.csv',False)
