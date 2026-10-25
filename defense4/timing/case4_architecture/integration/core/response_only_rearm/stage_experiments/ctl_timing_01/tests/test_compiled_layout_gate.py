"""Enforce approved physical stage bounds before the new-contract model gate."""
import copy
import json
import sys
from pathlib import Path

import pytest

CTL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CTL))
import model_profile


def contexts():
    def table(name, direction, stages, kind='match'):
        return dict(name=name, direction=direction, table_type=kind,
                    stage_tables=[dict(stage_number=stage) for stage in stages])
    return {'p0': dict(tables=[table('n_Ingress.test', 'ingress', range(11)),
                               table('r_Egress.test', 'egress', range(11))]),
            'p1': dict(tables=[table('t_Ingress.test', 'ingress', range(11)),
                               table('t_Ingress.resp_done_reg', 'ingress', [5], 'stateful'),
                               table('read_pad_Egress.test', 'egress', range(4))])}


def write(build, docs):
    for pipe, context in docs.items():
        path = build / 'compile_local/out' / pipe / 'context.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(context))


def test_project_limits_and_single_bank_pass_together(tmp_path):
    docs = contexts()
    for pipe in docs:
        docs[pipe]['tables'].append(dict(name='parser.$PORT_METADATA', direction='ingress', table_type='match',
            match_attributes=dict(stage_tables=[dict(stage_number=-1, stage_table_type='phase_0_match')])))
    write(tmp_path, docs)
    audit = model_profile.compiled_t_state_of_build(tmp_path)
    assert audit['problems'] == []
    assert audit['layout']['N']['maximum_occupied_stage'] == 10
    assert audit['layout']['E']['maximum_occupied_stage'] == 10
    assert audit['layout']['T']['occupied_count'] == 11
    assert audit['layout']['p1_egress']['occupied_count'] == 4


@pytest.mark.parametrize('role,pipe,index,extra', [('N', 'p0', 0, 11), ('E', 'p0', 1, 11),
                                                 ('T', 'p1', 0, 11), ('p1_egress', 'p1', 2, 4)])
def test_actual_compiled_layout_overruns_block_gate(tmp_path, role, pipe, index, extra):
    docs = contexts()
    docs[pipe]['tables'][index]['stage_tables'].append(dict(stage_number=extra))
    write(tmp_path, docs)
    audit = model_profile.compiled_t_state_of_build(tmp_path)
    assert any(role + ':' in problem for problem in audit['problems'])


@pytest.mark.parametrize('mutation', ('same_stage_twice', 'same_register_twice'))
def test_one_stage_number_cannot_hide_multiple_physical_state_allocations(mutation):
    doc = contexts()['p1']
    register = doc['tables'][1]
    if mutation == 'same_stage_twice':
        register['stage_tables'].append(dict(stage_number=5))
    else:
        doc['tables'].append(copy.deepcopy(register))
    assert model_profile.compiled_t_state_audit(doc)['problems']


def test_missing_p0_context_is_not_a_resource_pass(tmp_path):
    write(tmp_path, {'p1': contexts()['p1']})
    assert model_profile.compiled_t_state_of_build(tmp_path)['problems']
