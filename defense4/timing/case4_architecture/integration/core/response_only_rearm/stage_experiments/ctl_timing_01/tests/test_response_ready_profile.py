"""Source-bound v2 ABI and independent model-verdict regression checks."""
import copy
import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest

CTL=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(CTL))
import model_profile
import model_summary
import model_response_ready as ready
import run_model


def successor(tmp_path):
    source=tmp_path/'response_only.p4'
    source.write_text('''// timing_contract: response_ready_ack_d_v2
    action set_params(bit<32> gap, bit<32> op_j, bit<32> budget, bit<32> enabled) {}
    action clock_sample() { md.now = ig_prsr_md.global_tstamp[39:8] & 32w0xfffffffe; }
    ''')
    sha=hashlib.sha256(source.read_bytes()).hexdigest()
    profile=dict(reset_restart_required=True,t_child_count=1,candidate=dict(source_sha256=sha),
        endpoint_profile='sel751',timing_contract='response_ready_ack_d_v2',
        timing_ns=dict(D_release_budget=5000000,J_operate_hold=2400000),clock=dict(t_unit_ns=256,t_grid_ns=512))
    inputs=dict(source_sha256=sha,milestone='response_ready',supported_profile=profile)
    (tmp_path/'response_only.inputs.json').write_text(json.dumps(inputs))
    return source,inputs


def test_v2_requires_seventeenth_driver_and_exact_four_field_writer(tmp_path):
    source,inputs=successor(tmp_path)
    profile=model_profile.resolve(inputs,source)
    assert model_summary.required_drivers(tmp_path)==model_summary.RELAY_REQUIRED+('response_ready',)
    assert run_model.DRIVERS['response_ready'].name=='model_response_ready.py'
    assert 'readiness' not in run_model.DRIVERS
    legacy=dict(da=1000000,readiness=2000000000,cap=1500000000,pb=1000000000,
                gap=20000000,op_j=2400000,budget=240000,enabled=1)
    assert model_profile.model_params(profile,legacy)==dict(gap=20000000,op_j=2400000,budget=240000,enabled=1)
    assert model_profile.model_params({},legacy)==legacy
    for extra in ('response_wait_timeout','mystery'):
        with pytest.raises(ValueError):model_profile.model_params(profile,dict(legacy,**{extra:1}))


@pytest.mark.parametrize('mutation',('old_timeout','old_readiness','clock','endpoint','contract','ABI','hash'))
def test_profile_source_and_abi_mismatches_fail_closed(tmp_path,mutation):
    source,inputs=successor(tmp_path);p=inputs['supported_profile']
    if mutation=='old_timeout':p['timing_ns']['response_wait_timeout']=500000000
    elif mutation=='old_readiness':p['timing_ns']['readiness']=2000000000
    elif mutation=='clock':p['clock']['t_unit_ns']=1
    elif mutation=='endpoint':p['endpoint_profile']='software'
    elif mutation=='contract':p['timing_contract']='response_ready_ack_d_v1'
    elif mutation=='ABI':
        source.write_text('legacy source')
        inputs['source_sha256']=p['candidate']['source_sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
    else:p['candidate']['source_sha256']='0'*64
    with pytest.raises(ValueError):model_profile.resolve(inputs,source)


def point():
    p=dict(order='ack_first',request_arrival_units=1000,held_ack_units=1500,
        ack_arrival_ordinal=1,response_arrival_units=2000,response_arrival_ordinal=3,
        ack_release_units=2002,response_release_units=30000,
        lane=dict(ACK_COMMIT=1,RESP_RELEASE=1,REQ_DUP_DROP=0,REQ_DUP_FORWARD=0,OP_DUP_DROP=0),
        master_frames=['ack','response'],generation_before=8,generation_after=9,epoch=7,fc=3,
        written_units=dict(gap=19534,op_j=9377,budget=240000,enabled=1),
        ack_state_transitions=[dict(t_units=1000,before=8,after=8),dict(t_units=2002,before=8,after=9),
                               dict(t_units=30000,before=9,after=9)])
    p['lane_registers']={name:[dict(t_units=2002,before=value,after=value)] for name,value in
        (('gen_alloc_reg',9),('cur_epoch_reg',7),('ack_commit_at_reg',2002),('ack_commit_gen_reg',9))}
    return p


def test_whole_response_and_full_D_proof_has_no_exchange_age_cap():
    p=point();p['request_arrival_units']=-(1<<30)
    assert ready.committed_problems(p,19534)==[]
    assert ready.lane_integrity_problems(p)==[]


@pytest.mark.parametrize('mutation',('early_ACK','short_D','missing_clock','two_commits','wire_order','new_generation','D_restart','word_corruption'))
def test_actual_clock_and_ownership_proofs_reject_bad_paths(mutation):
    p=point()
    if mutation=='early_ACK':p['response_arrival_units']=2003
    elif mutation=='short_D':p['response_release_units']=21535
    elif mutation=='missing_clock':p['ack_release_units']=None
    elif mutation=='two_commits':p['lane']['ACK_COMMIT']=2
    elif mutation=='wire_order':p['master_frames']=['response','ack']
    elif mutation=='new_generation':p['generation_after']=10
    elif mutation=='D_restart':p['lane_registers']['ack_commit_at_reg'][0]['after']+=1
    else:p['ack_state_transitions'][-1]['after']=8
    assert ready.committed_problems(p,19534)+ready.lane_integrity_problems(p)


@pytest.mark.parametrize('order,ack,response,aordinal,rordinal,ok',[
    ('ack_first',100,101,1,2,True),('response_first',101,100,2,1,True),
    ('ack_first',101,100,1,2,False),('response_first',100,101,2,1,False),
    ('ack_first',100,100,1,2,True),('response_first',100,100,2,1,True),
    ('ack_first',100,100,2,1,False),('ack_first',(1<<32)-1,0,1,2,True)])
def test_actual_arrival_order_clock_and_ties(order,ack,response,aordinal,rordinal,ok):
    p=dict(order=order,held_ack_units=ack,response_arrival_units=response,
           ack_arrival_ordinal=aordinal,response_arrival_ordinal=rordinal)
    assert (ready.arrival_order_problems(p)==[])==ok


def retry_point(phase):
    p=point();p['request_retry']=dict(phase=phase,relay_request_copies=2 if phase in ('waiting','after_release','disabled') else 1)
    if phase=='disabled':
        p.update(generation_after=8,op_generation_before=4,op_generation_after=4,operate_release_count=0)
        p['lane']=dict(ACK_COMMIT=0,RESP_RELEASE=0,REQ_DUP_DROP=0,REQ_DUP_FORWARD=1,OP_DUP_DROP=0)
        p['request_retry']['ingress_units']=31000;return p
    key='OP_DUP_DROP' if phase=='op_J' else 'REQ_DUP_DROP' if phase=='response_D' else 'REQ_DUP_FORWARD'
    p['lane'][key]=1
    p['request_retry']['ingress_units']={'op_J':1200,'response_D':2500,'waiting':1750,'after_release':31000}[phase]
    if phase=='op_J':
        p.update(fc=4,op_generation_before=3,op_generation_after=4,operate_anchor_units=1100,operate_release_units=1300)
        p['lane_registers'].update(op_gen_alloc_reg=[dict(t_units=1100,before=3,after=4)],
                                  op_t0_reg=[dict(t_units=1100,before=0,after=1101)])
    return p


@pytest.mark.parametrize('phase',('op_J','response_D','waiting','after_release','disabled'))
def test_qualified_request_retry_windows_and_counters(phase):
    assert ready.retry_problems(retry_point(phase))==[]
    p=retry_point(phase);p['generation_after']+=1
    assert ready.retry_problems(p)
    p=retry_point(phase);p['request_retry']['relay_request_copies']+=1
    assert ready.retry_problems(p)
    p=retry_point(phase);p['lane']['REQ_DUP_FORWARD']+=1
    assert ready.retry_problems(p)


def token_point():
    buffer=bytes.fromhex('000000000800')+bytes(54)
    seed=bytes.fromhex('e1000008')+struct.pack('!IIIBBH',6,0,0,9,0,0)+b'original'
    timer=bytes.fromhex('080000080000')+buffer;ingress=timer+bytes(4)
    blocker=struct.pack('!BBHI',11,0,8,240000)+ingress[6:]
    return dict(generation_after=8,response_release_units=30000,artifacts=dict(seed=seed.hex(),token=blocker.hex()),
        token_source=dict(seed_frame_hex=seed.hex(),timer_frame_hex=timer.hex(),timer_ingress_frame_hex=ingress.hex(),
            blocker_frame_hex=blocker.hex(),source_action='t_Ingress.seed_ack_blocker',timer_port=196,blocker_port=182,
            source_t_units=40000,blocker_t_units=41000,state_after=8,lane_delta={name:0 for name in ready.LANE}))


def test_source_produced_token_identity_and_plain_generation_word():
    p=token_point();assert ready.token_source_problems(p)==[]
    for field in ('timer_ingress_frame_hex','blocker_frame_hex'):
        bad=copy.deepcopy(p);bad['token_source'][field]=bad['token_source'][field][:-2]+'01'
        assert ready.token_source_problems(bad)
    p['token_source']['state_after']=0x20008
    assert ready.token_source_problems(p)


def test_model_timer_uses_existing_format_and_captured_generation():
    p=token_point();seed=bytes.fromhex(p['artifacts']['seed']);calls=[]
    def header(**kwargs):calls.append(kwargs);return bytes.fromhex('080000080000')+bytes(58)
    buf=bytes.fromhex('000000000800')+bytes(54)
    assert ready.timer_from_read_seed(seed,header,buf)==bytes.fromhex('080000080000')+buf
    assert calls==[dict(gen=8,packet_id=0,profile=0,pipe=1)]


def child_results():
    names={'N':('owner','epoch','client','server'),'E':('epoch','mode','front','acct','img_end','img_start','img_wend'),
           'T':('cur_epoch_reg','gen_alloc_reg','op_gen_alloc_reg','op_t0_reg','ack_done_reg','resp_done_reg','op_done_reg',
                'child_seen0_reg','ack_commit_at_reg','ack_commit_gen_reg')}
    before={role:{name:{'f1':[7]} for name in regs} for role,regs in names.items()};before['T']['outcomes']=[0]*25
    for register,value in (('gen_alloc_reg',9),('op_gen_alloc_reg',10),('ack_done_reg',9),
                           ('resp_done_reg',9),('op_done_reg',10)):
        before['T'][register]['f1']=[value]
    cases=[('response',None,child) for child in (1,2,255)]+[('held',role,child) for role in (14,15,16) for child in (1,2,255)]+[
        ('blocker',role,child) for role in (11,12,13) for child in (0,1,2,255)]
    rows=[]
    for kind,role,child in cases:
        after=copy.deepcopy(before)
        port=181 if role in (13,16) else 182 if role is not None else 180
        gen=10 if role in (13,16) else 9
        frame=(struct.pack('!IIIBBH',7,0,0,11,child,0) if kind=='response' else
               struct.pack('!BBHI',role,child,gen,240000 if kind=='blocker' else 7))+bytes(60)
        ingress=dict(pipe=1,port=port,frame=(frame+bytes(4)).hex(),t_units=100,ordinal=0,
                     actions=['t_Ingress.stop_blocking'] if kind=='blocker' and child==0 else [])
        rows.append(dict(kind=kind,role=role,child=child,policy_off=kind=='blocker',epoch=7,read_generation=9,
            operate_generation=10,before=copy.deepcopy(before),expected_after=copy.deepcopy(after),after=after,output_frames=0,
            stimulus_port=port,stimulus_frame_hex=frame.hex(),model_ingress=[ingress]))
    return dict(meta=dict(single_child_probes=rows))


def test_all_24_invalid_child_proofs_and_positive_controls_are_required():
    d=child_results();assert model_summary._single_child_problems(d)==[]
    for index in (0,3,12):
        bad=copy.deepcopy(d);bad['meta']['single_child_probes'].pop(index)
        assert model_summary._single_child_problems(bad)
    d['meta']['single_child_probes'][0]['after']['T']['ack_done_reg']['f1'][0]+=1
    assert model_summary._single_child_problems(d)


def test_child_zero_canary_requires_actual_stop_action_with_zero_counter_delta():
    results=child_results()
    assert model_summary._single_child_problems(results)==[]
    for role in (11,12,13):
        row=next(r for r in results['meta']['single_child_probes'] if r['role']==role and r['child']==0)
        assert row['after']==row['before']
        assert ready.child_ingress_problems(row)==[]
        for field,value in (('actions',[]),('port',999),('frame','00'),('pipe',0),('t_units',None)):
            bad=copy.deepcopy(row);bad['model_ingress'][0][field]=value
            assert ready.child_ingress_problems(bad)
        bad=copy.deepcopy(row);bad['model_ingress'].append(copy.deepcopy(bad['model_ingress'][0]))
        assert ready.child_ingress_problems(bad)
        bad=copy.deepcopy(row);bad['read_generation']+=1;bad['operate_generation']+=1
        assert ready.child_ingress_problems(bad)
        bad=copy.deepcopy(row)
        bad['before']['T'][{11:'ack_done_reg',12:'resp_done_reg',13:'op_done_reg'}[role]]['f1']=[0]
        assert ready.child_ingress_problems(bad)
    negative=copy.deepcopy(results['meta']['single_child_probes'][12+1])
    negative['model_ingress'][0]['actions']=['t_Ingress.stop_blocking']
    assert ready.child_ingress_problems(negative)
    bad=copy.deepcopy(results);bad['meta']['single_child_probes'][12]['model_ingress'][0]['actions']=[]
    assert model_summary._single_child_problems(bad)


def test_partial_positive_matrix_cannot_qualify_v2():
    assert model_summary._response_ready_problems(dict(meta=dict(timing_contract=model_profile.RESPONSE_READY,points=[])))


def test_compiled_state_requires_unique_stage_and_allocation():
    context=dict(tables=[dict(name='t_Ingress.resp_done_reg',table_type='stateful',stage_tables=[dict(stage_number=7)])])
    assert model_profile.compiled_t_state_audit(context)['problems']==[]
    context['tables'][0]['stage_tables'].append(dict(stage_number=7))
    assert model_profile.compiled_t_state_audit(context)['problems']


def test_contention_v2_requires_real_clock_proof_not_a_pass_flag():
    case=dict(name='sweep_READ_0_delivered_once_committed',response_ready_clock_proof=dict(
        held_ack_units=100,response_arrival_units=200,ack_release_units=201,response_release_units=301,gap_units=100,passed=True))
    assert model_summary._contention_v2_clock_problems(dict(cases=[case]))==[]
    case['response_ready_clock_proof']['response_release_units']=300
    assert model_summary._contention_v2_clock_problems(dict(cases=[case]))
    case.pop('response_ready_clock_proof')
    assert model_summary._contention_v2_clock_problems(dict(cases=[case]))



@pytest.mark.parametrize('kind',('late_ACK','stale_response','stale_token'))
@pytest.mark.parametrize('phase',('waiting','committed'))
def test_v2_generation_isolation_preserves_plain_completion_and_original_D(kind,phase):
    p=point()
    p['stale_probe']=dict(kind=kind,phase=phase,source_generation=8,source_epoch=6 if kind=='stale_token' else 7,
        ingress_ordinal=2 if phase=='waiting' else 5,held_ack_ordinal=1,response_arrival_ordinal=3,
        ack_commit_ordinal=4,response_release_ordinal=9)
    assert ready.generation_isolation_problems(p)==[]
    p['lane_registers']['ack_commit_at_reg'][0]['after']+=1
    assert ready.generation_isolation_problems(p)


@pytest.mark.parametrize('phase',('ack_held','response_held'))
def test_cleanup_must_observe_an_actual_retained_original_and_valid_frontier_reset(phase):
    p=point();p.update(reset_application_units=3000,reset_forwarded_count=1,response_release_units=None)
    p['lane']['RESP_RELEASE']=0
    if phase=='ack_held':
        p['lane']['ACK_COMMIT']=0;p['ack_release_units']=None;p['master_frames']=[]
    else:p['master_frames']=['ack']
    assert ready.cleanup_problems(p,phase)==[]
    p['reset_forwarded_count']=0
    assert ready.cleanup_problems(p,phase)
