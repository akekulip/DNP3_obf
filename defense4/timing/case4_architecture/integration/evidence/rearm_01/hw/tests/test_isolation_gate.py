import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from isolation_gate import compare_quiet_generation


def snapshot():
    registers = {
        'p0.n_Ingress.owner': {'owner': [0x70002]},
        'p0.n_Ingress.epoch': {'epoch': [2]},
        'p0.n_Ingress.client': {'client': [101]},
        'p0.n_Ingress.server': {'server': [201]},
        'p0.n_Ingress.counter': {'counter': [10]},
        'p0.n_Ingress.count_busy': {'busy': [0]},
        'p0.n_Ingress.work.work': {'generation': [10], 'phase': [4]},
        'p0.r_Egress.epoch': {'epoch': [0x80000002]},
        'p0.r_Egress.front': {'front': [202]},
        'p0.r_Egress.acct.acct': {'lo': [202], 'hi': [0]},
        'p0.r_Egress.image': {'image': [0]},
        'p1.t_Ingress.cur_epoch_reg': {'epoch': [2]},
        'p1.t_Ingress.gen_alloc_reg': {'generation': [3]},
        'p1.t_Ingress.anchors': {'lo': [0], 'hi': [0]},
    }
    return dict(valid=True, errors=[], software_read_fallbacks=[], registers=registers,
                expected_registers=sorted(registers),
                bfrt_sha256='a'*64, context_sha256={'p0':'b'*64,'p1':'c'*64}, optimized_away=[])


def test_old_replay_can_only_advance_n_diagnostics_and_free_packet_allocator():
    before = snapshot(); after = copy.deepcopy(before)
    after['registers']['p0.n_Ingress.counter']['counter'] = [20]
    after['registers']['p0.n_Ingress.count_busy']['busy'] = [4]
    after['registers']['p0.n_Ingress.work.work']['generation'] = [20]
    result = compare_quiet_generation(before, after, epoch=2, server_isn=201)
    assert result['ok'] and len(result['allowed_changes']) == 3


def test_any_mapping_owner_or_timing_authority_mutation_fails():
    for name, field in [('p0.n_Ingress.owner','owner'), ('p0.r_Egress.image','image'),
                        ('p0.r_Egress.acct.acct','hi'), ('p1.t_Ingress.gen_alloc_reg','generation'),
                        ('p1.t_Ingress.anchors','lo')]:
        before = snapshot(); after = copy.deepcopy(before)
        after['registers'][name][field][0] += 1
        assert not compare_quiet_generation(before,after,epoch=2,server_isn=201)['ok']


def test_missing_or_software_reads_cannot_prove_isolation():
    for key, value in [('valid',False),('errors',['failed']),('software_read_fallbacks',['epoch'])]:
        before = snapshot(); before[key] = value
        assert not compare_quiet_generation(before,snapshot(),epoch=2,server_isn=201)['ok']
    after = snapshot(); after['registers'].pop('p0.r_Egress.image')
    assert not compare_quiet_generation(snapshot(),after,epoch=2,server_isn=201)['ok']
    before=snapshot();after=snapshot()
    for name in ('p0.n_Ingress.client','p0.n_Ingress.server','p0.r_Egress.image'):
        before['registers'].pop(name);after['registers'].pop(name)
    assert not compare_quiet_generation(before,after,epoch=2,server_isn=201)['ok']


def test_both_snapshots_must_show_fresh_mapping_and_current_epochs():
    for name, field, value in [('p0.r_Egress.front','front',999),
                               ('p0.r_Egress.acct.acct','hi',58),
                               ('p0.r_Egress.epoch','epoch',0x80000001),
                               ('p1.t_Ingress.cur_epoch_reg','epoch',1)]:
        before = snapshot(); before['registers'][name][field] = [value]
        assert not compare_quiet_generation(before,copy.deepcopy(before),epoch=2,server_isn=201)['ok']


def test_busy_work_or_generation_regression_is_not_diagnostic_only():
    for field,value in [('phase',[0]),('generation',[9])]:
        after = snapshot(); after['registers']['p0.n_Ingress.work.work'][field] = value
        assert not compare_quiet_generation(snapshot(),after,epoch=2,server_isn=201)['ok']
