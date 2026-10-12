from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from token_window import PRE_READ_GRACE_MS, window_proof, require_marker, rejection_delta, full_run_rejections


def app(packets):
    return dict(batch_count_cfg=0,packets_per_batch_cfg=3,trigger_counter=1, batch_counter=1, pkt_counter=packets, ipg=2_500_000_000)


def test_only_real_old_tokens_arriving_during_current_quiet_window_qualify():
    before=dict(operate_app_before=app(4),operate_app_after=app(4),read_app_before=app(3),read_app_after=app(3))
    after=dict(operate_app_before=app(4),operate_app_after=app(4),read_app_before=app(4),read_app_after=app(4))
    marker=dict(tcp_open=True,opens=1,pre_read_grace_ms=PRE_READ_GRACE_MS,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=0)
    master=dict(pre_read_grace_ms=PRE_READ_GRACE_MS,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=20_100_000_000)
    result=window_proof(marker,master,before,after,restored_vision_ns=19_000_000_000)
    assert result['ok'] and result['old_packets_during_pause']==1


def test_late_ready_or_new_trigger_cannot_masquerade_as_delayed_old_tokens():
    marker=dict(tcp_open=True,opens=1,pre_read_grace_ms=PRE_READ_GRACE_MS,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=0)
    master=dict(pre_read_grace_ms=PRE_READ_GRACE_MS,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=20_100_000_000)
    for count in (4,5):
        before=dict(operate_app_before=app(4),operate_app_after=app(4),read_app_before=app(count),read_app_after=app(count))
        assert not window_proof(marker,master,before,dict(operate_app_before=app(4),operate_app_after=app(4),read_app_before=app(4),read_app_after=app(4)),19_000_000_000)['ok']
    before=dict(operate_app_before=app(4),operate_app_after=app(4),read_app_before=app(3),read_app_after=app(3)); after=dict(operate_app_before=app(4),operate_app_after=app(4),read_app_before=app(4),read_app_after=app(4))
    after['read_app_after']['trigger_counter']=2
    assert not window_proof(marker,master,before,after,19_000_000_000)['ok']


def test_restore_deadline_requires_both_bounded_pause_and_actual_issue():
    marker=dict(tcp_open=True,opens=1,pre_read_grace_ms=PRE_READ_GRACE_MS,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=0)
    master=dict(pre_read_grace_ms=PRE_READ_GRACE_MS,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=20_100_000_000)
    before=dict(operate_app_before=app(4),operate_app_after=app(4),read_app_before=app(3),read_app_after=app(3)); after=dict(operate_app_before=app(4),operate_app_after=app(4),read_app_before=app(4),read_app_after=app(4))
    for restored in (9_000_000_000,20_000_000_000,20_200_000_000):
        assert not window_proof(marker,master,before,after,restored)['ok']


def test_marker_is_strict_typed_and_requires_established_unissued_read():
    marker=dict(tcp_open=True,opens=1,pre_read_grace_ms=PRE_READ_GRACE_MS,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=0)
    assert require_marker(marker)==10_000_000_000
    for key,value in [('tcp_open',False),('opens',True),('first_read_issued_ns',1),('pre_read_grace_ms',PRE_READ_GRACE_MS + 1)]:
        with pytest.raises(ValueError): require_marker(dict(marker,**{key:value}))


def raw_snapshot(suffix, blocker=0, cleanup=0, op=0, read=0):
    return {'operate_app_after':app(4), 'timer_rejection_layout':'split_raw_timer_23_24', 'old_reject_'+suffix:
            {str(i):{'outcomes.f1':[v]} for i,v in zip((6,14,23,24),(blocker,cleanup,op,read))}}


def outcomes(blocker=0, cleanup=0, op=0, read=0):
    return {'pktgen':{role:dict(trigger_counter=0,batch_counter=0,pkt_counter=0) for role in ('READ','OPERATE')},'outcomes':dict(STALE_BLOCKER=blocker, RAW_OPERATE_TIMER_STALE=op,
                           RAW_READ_TIMER_STALE=read, OUT_TOKEN_STALE=blocker+op+read, index_14=cleanup)}


def test_only_split_read_timer_rejects_count_as_read_packets():
    before=raw_snapshot('after')
    after=raw_snapshot('before',blocker=7,cleanup=2,op=4,read=1)
    assert rejection_delta(before,after)==1
    after['old_reject_before']['24']['outcomes.f1']=[0]
    assert rejection_delta(before,after)==0
    before['timer_rejection_layout']='aggregate_6'
    with pytest.raises(ValueError,match='unsupported layout'):
        rejection_delta(before,after)


def test_full_run_records_old_cleanup_and_no_stale_suffix_from_new_connections():
    before=outcomes();after=outcomes(blocker=2,cleanup=2,op=4,read=3)
    end=raw_snapshot('after',blocker=2,cleanup=1,op=4,read=3)
    proof=full_run_rejections(before,after,end)
    assert proof==dict(expected_old_tokens=3,raw_timer_rejections=3,raw_operate_rejections=4,
                       stale_blocker_rejections=2,strict_stale_total=9,post_quiet_stale_rejections=0,
                       old_epoch_cleanup=2,old_rejections_total=11)
    for name in ('STALE_BLOCKER','RAW_OPERATE_TIMER_STALE','RAW_READ_TIMER_STALE'):
        changed=outcomes(blocker=2,cleanup=2,op=4,read=3)
        changed['outcomes'][name]+=1
        with pytest.raises(ValueError,match='after old batches drained'):
            full_run_rejections(before,changed,end)


@pytest.mark.parametrize('stale,cleanup', [(2,0),(4,0),(3,-1),(True,0)])
def test_full_run_rejects_missing_extra_or_unreadable_raw_timer_evidence(stale,cleanup):
    before=outcomes();after=outcomes(read=stale,cleanup=cleanup)
    end=raw_snapshot('after',read=stale,cleanup=cleanup)
    with pytest.raises(ValueError):
        full_run_rejections(before,after,end)


def test_unobserved_or_incomplete_operate_batch_cannot_qualify():
    marker=dict(tcp_open=True,opens=1,pre_read_grace_ms=PRE_READ_GRACE_MS,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=0)
    master=dict(pre_read_grace_ms=PRE_READ_GRACE_MS,pre_read_ready_ns=10_000_000_000,first_read_issued_ns=20_100_000_000)
    before=dict(read_app_before=app(3),read_app_after=app(3),operate_app_before=app(0),operate_app_after=app(0))
    after=dict(read_app_before=app(4),read_app_after=app(4),operate_app_before=app(3),operate_app_after=app(3))
    assert not window_proof(marker,master,before,after,19_000_000_000)['ok']
    after.update(operate_app_before=app(4),operate_app_after=app(4))
    result=window_proof(marker,master,before,after,19_000_000_000)
    assert result['ok'] and result['old_operate_packets_during_pause']==4


def test_operate_attribution_includes_one_generated_but_inflight_prefix_token():
    from token_window import operate_rejection_proof
    before=raw_snapshot('after',op=0)
    before['operate_app_after']=app(1)
    after=raw_snapshot('before',op=4)
    after['operate_app_before']=app(4)
    proof=operate_rejection_proof(before,after,outcomes())
    assert proof==dict(generated_during_pause=3,prefix_inflight_rejected=1,
                       rejected_during_pause=4,total_old_operate_rejected=4)
    for value in (3,5):
        after['old_reject_before']['23']['outcomes.f1']=[value]
        with pytest.raises(ValueError):operate_rejection_proof(before,after,outcomes())


def test_dirty_baseline_or_changed_batch_cannot_qualify():
    before=outcomes();after=outcomes(op=4,read=3);end=raw_snapshot('after',op=4,read=3)
    before['pktgen']['OPERATE']['pkt_counter']=1
    with pytest.raises(ValueError,match='dirty old-batch'):
        full_run_rejections(before,after,end)
    before=outcomes(op=1)
    with pytest.raises(ValueError,match='dirty raw rejection'):
        full_run_rejections(before,after,end)
