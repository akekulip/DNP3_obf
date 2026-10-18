"""Bounded placement probes preserve the corrected baseline's source behavior."""
import re
import sys
from pathlib import Path

import pytest

CT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(CT), str(CT / 'tests')]
import contention_source as cs
import efficiency_candidates as gen


@pytest.mark.parametrize('initial', (0, 0xffffffff))
def test_direct_outcome_index_matches_every_8_bit_code_and_wraps_once(tmp_path, initial):
    baseline = tmp_path / 'baseline'
    candidate = tmp_path / 'candidate'
    gen.generate(baseline)
    gen.generate(candidate, ('t_outcome_direct',))
    old = cs.LapPipeline(baseline / 'response_only.p4')
    new = cs.LapPipeline(candidate / 'response_only.p4')
    valid = set(range(17)) | {23, 24}
    for code in range(256):
        wanted = [initial] * 25
        if code in valid:
            wanted[code] = (initial + 1) & 0xffffffff
        for pipeline in (old, new):
            src = pipeline.t.src
            src.cells[('', 'outcomes')] = [initial] * 25
            src.begin_pass(0)
            src.env['m.outcome_code'] = code
            src.exec_stmt(src.controls['Ingress'].apply_body[-1])
            assert src.cells[('', 'outcomes')] == wanted, code
            assert sum('register outcomes.bump_outcome' == e for e in src.events) == (1 if code in valid else 0)
    old.close()
    new.close()


def test_relaxed_n_crc_probe_changes_only_placement_annotations():
    baseline = gen.source_for()
    changed = gen.source_for(('n_relax_crc_stage',))
    assert changed != baseline
    assert baseline.count('@stage(1) table crc_t') == 1 and '@stage(1) table crc_t' not in changed
    assert changed.count('@stage(2)') == baseline.count('@stage(2)')
    remove_stage = lambda text: re.sub(r'@stage\([12]\) ', '', text)
    assert remove_stage(changed) == remove_stage(baseline)
    assert gen.combined.segment(changed, 'E') == gen.combined.segment(baseline, 'E')
    assert gen.combined.segment(changed, 'T') == gen.combined.segment(baseline, 'T')


@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
@pytest.mark.parametrize('offset', (0, 1, 3))
def test_relaxed_n_crc_preserves_contended_exchange_and_state(tmp_path, kind, offset):
    baseline, candidate = tmp_path / 'baseline', tmp_path / 'candidate'
    gen.generate(baseline)
    gen.generate(candidate, ('n_relax_crc_stage',))
    old = cs.contended(baseline / 'response_only.p4', kind, offset)
    new = cs.contended(candidate / 'response_only.p4', kind, offset)
    assert cs.delivered_once_after_ack(old) and cs.delivered_once_after_ack(new)
    assert new['master'] == old['master']
    assert new['busy'] == old['busy'] and new['outcomes'] == old['outcomes']
    assert cs.n_state(new['pipeline']) == cs.n_state(old['pipeline'])
    old['pipeline'].close()
    new['pipeline'].close()


@pytest.mark.parametrize('child', (0, 1, 2, 255))
@pytest.mark.parametrize('role', (11, 12, 13, 14, 15, 16))
def test_single_child_ladder_rejects_unknown_ids_before_state(tmp_path, role, child):
    import copy
    import struct
    build = tmp_path / 'single_child'
    gen.generate(build, ('t_single_child',))
    pipeline = cs.LapPipeline(build / 'response_only.p4')
    t = pipeline.t
    before = copy.deepcopy(t.src.cells)
    port = t.consts()['HB_RETURN' if role in (13, 16) else 'HELD_RETURN']
    frame = struct.pack('!BBHI', role, child, 0, 1) + bytes.fromhex('001122334455aabbccddeeff0800') + bytes(46)
    t.ingress(1 << 24, port, frame)
    if child:
        assert t.log[-1][3] == ['parser reject']
        assert t.src.cells == before
        assert not t.emitted and not t.enqueued
    else:
        assert t.log[-1][3] != ['parser reject']
    pipeline.close()


@pytest.mark.parametrize('child', (0, 1, 2, 255))
def test_single_child_response_event_id_is_validated_before_state(tmp_path, child):
    import copy
    import struct
    build = tmp_path / 'single_child'
    gen.generate(build, ('t_single_child',))
    pipeline = cs.LapPipeline(build / 'response_only.p4')
    t = pipeline.t
    before = copy.deepcopy(t.src.cells)
    frame = struct.pack('!IIIBBH', 1, 0, 0, 11, child, 0) + bytes.fromhex('001122334455aabbccddeeff0800') + bytes(46)
    t.ingress(1 << 24, t.consts()['T_IN'], frame)
    if child:
        assert t.log[-1][3] == ['parser reject']
        assert t.src.cells == before
        assert not t.emitted and not t.enqueued
    else:
        assert t.log[-1][3] != ['parser reject']
    pipeline.close()


@pytest.mark.parametrize('role', (11, 12, 13))
@pytest.mark.parametrize('child', (0, 1, 2, 255))
def test_policy_off_blocker_vectors_detect_a_removed_child_guard(tmp_path, role, child):
    import copy
    import struct
    guarded = gen.source_for(('t_single_child',))
    unguarded = guarded.replace(
        'transition select(hdr.ladder.child) { 0: single_ladder_role; default: reject; }',
        'transition single_ladder_role;').replace(
        '(!hdr.ladder.isValid() || hdr.ladder.child == 0) &&', 'true &&')
    for label, source in (('guarded', guarded), ('guard_removed', unguarded)):
        path = tmp_path / (label + '.p4')
        path.write_text(source)
        pipeline = cs.LapPipeline(path, enabled=0)
        t = pipeline.t
        for name, value in (('cur_epoch_reg', 1), ('gen_alloc_reg', 7), ('op_gen_alloc_reg', 5),
                            ('ack_done_reg', 7), ('resp_done_reg', 7), ('op_done_reg', 5), ('child_seen0_reg', 7)):
            t.src.cells[('', name)][0] = value
        before = copy.deepcopy(t.src.cells)
        port = t.consts()['HB_RETURN' if role == 13 else 'HELD_RETURN']
        generation = 5 if role == 13 else 7
        frame = struct.pack('!BBHI', role, child, generation, 240000)
        t.ingress(1 << 24, port, frame)
        wanted = copy.deepcopy(before)
        # TOKEN_OFF's counted row precedes the already-done silent stop. Thus these vectors discriminate the
        # child validation even when both legitimate lanes finished, rather than passing by silent disposal.
        if child == 0 or label == 'guard_removed':
            wanted[('', 'outcomes')][12] += 1
        assert t.src.cells == wanted
        assert not t.emitted and not t.enqueued
        pipeline.close()


@pytest.mark.parametrize('kind,role', (('tev', 11),) + tuple(('ladder', role) for role in range(11, 17)))
@pytest.mark.parametrize('child', (0, 1, 2, 255))
@pytest.mark.parametrize('parser_err', (0, 1))
def test_parser_reject_continuing_into_t_control_has_no_stateful_effects(tmp_path, kind, role, child, parser_err):
    import copy
    import struct
    path = tmp_path / 'candidate.p4'
    path.write_text(gen.source_for(('t_single_child',)))
    pipeline = cs.LapPipeline(path, enabled=0)
    src = pipeline.t.src
    src.width['ig.parser_err'] = 16
    for name, value in (('cur_epoch_reg', 1), ('gen_alloc_reg', 7), ('op_gen_alloc_reg', 5),
                        ('ack_done_reg', 7), ('resp_done_reg', 7), ('op_done_reg', 5), ('child_seen0_reg', 7)):
        src.cells[('', name)][0] = value
    before = copy.deepcopy(src.cells)
    opaque = bytes.fromhex('001122334455aabbccddeeff0800') + bytes(46)
    port = pipeline.t.consts()['T_IN' if kind == 'tev' else
                                'HB_RETURN' if role in (13, 16) else 'HELD_RETURN']
    frame = (struct.pack('!IIIBBH', 1, 7, 0, 11, child, 0) if kind == 'tev' else
             struct.pack('!BBHI', role, child, 5 if role in (13, 16) else 7,
                         240000 if role < 14 else 1)) + opaque
    src.begin_pass(port)
    src.env['ig.global_tstamp'] = 1 << 24
    accepted, _ = src.packet_parser(frame)
    assert accepted is (child == 0)
    # Actual m11_02 and m11_04 targets continue into ingress after explicit reject, including parser_err=0.
    # Exercise that continuation directly rather than using the source scheduler's reject shortcut.
    src.env['ig.parser_err'] = parser_err
    src.apply_control('Ingress')
    if child:
        assert src.cells == before
        assert not any(e.startswith('register ') for e in src.events)
        assert src.env.get('md.drop_ctl') == 1
        assert src.env.get('md.mirror_type') == pipeline.t.consts()['MIRROR_TYPE_CLONE']
        assert src.env.get('m.clone_ses') == pipeline.t.consts()['NO_MIRROR_SESSION']
    else:
        assert any(e.startswith('register ') for e in src.events)
    pipeline.close()
