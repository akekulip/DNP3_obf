from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from token_window import window_proof, require_marker, rejection_delta


def app(packets):
    return dict(trigger_counter=1, batch_counter=1, pkt_counter=packets, ipg=2_500_000_000)


def test_only_real_old_tokens_arriving_during_current_quiet_window_qualify():
    before=dict(read_app_before=app(3),read_app_after=app(3))
    after=dict(read_app_before=app(4),read_app_after=app(4))
    marker=dict(tcp_open=True,opens=1,pre_read_grace_ms=5000,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=0)
    master=dict(pre_read_grace_ms=5000,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=15_100_000_000)
    result=window_proof(marker,master,before,after,restored_vision_ns=14_000_000_000)
    assert result['ok'] and result['old_packets_during_pause']==1


def test_late_ready_or_new_trigger_cannot_masquerade_as_delayed_old_tokens():
    marker=dict(tcp_open=True,opens=1,pre_read_grace_ms=5000,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=0)
    master=dict(pre_read_grace_ms=5000,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=15_100_000_000)
    for count in (4,5):
        before=dict(read_app_before=app(count),read_app_after=app(count))
        assert not window_proof(marker,master,before,dict(read_app_before=app(4),read_app_after=app(4)),14_000_000_000)['ok']
    before=dict(read_app_before=app(3),read_app_after=app(3)); after=dict(read_app_before=app(4),read_app_after=app(4))
    after['read_app_after']['trigger_counter']=2
    assert not window_proof(marker,master,before,after,14_000_000_000)['ok']


def test_restore_deadline_requires_both_bounded_pause_and_actual_issue():
    marker=dict(tcp_open=True,opens=1,pre_read_grace_ms=5000,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=0)
    master=dict(pre_read_grace_ms=5000,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=15_100_000_000)
    before=dict(read_app_before=app(3),read_app_after=app(3)); after=dict(read_app_before=app(4),read_app_after=app(4))
    for restored in (9_000_000_000,15_000_000_000,15_200_000_000):
        assert not window_proof(marker,master,before,after,restored)['ok']


def test_marker_is_strict_typed_and_requires_established_unissued_read():
    marker=dict(tcp_open=True,opens=1,pre_read_grace_ms=5000,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=0)
    assert require_marker(marker)==10_000_000_000
    for key,value in [('tcp_open',False),('opens',True),('first_read_issued_ns',1),('pre_read_grace_ms',5001)]:
        with pytest.raises(ValueError): require_marker(dict(marker,**{key:value}))


def test_only_stale6_and_old_epoch14_count_as_token_rejection():
    before={'old_reject_after':{'6':{'outcomes.f1':[0]},'14':{'outcomes.f1':[0]},'8':{'outcomes.f1':[0]}}}
    after={'old_reject_before':{'6':{'outcomes.f1':[1]},'14':{'outcomes.f1':[0]},'8':{'outcomes.f1':[0]}}}
    assert rejection_delta(before,after)==1
    after['old_reject_before']['6']['outcomes.f1']=[0]
    after['old_reject_before']['8']['outcomes.f1']=[7]
    assert rejection_delta(before,after)==0
    after['old_reject_before']['14']['outcomes.f1']=[2]
    assert rejection_delta(before,after)==2
