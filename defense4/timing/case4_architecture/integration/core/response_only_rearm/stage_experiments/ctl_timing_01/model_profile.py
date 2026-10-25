"""Resolve model expectations from a build's source-bound supported profile.

Retained builds keep their recorded milestone expectations. A successor must declare the current reset contract
and child layout; renaming a build cannot select weaker expectations.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HISTORICAL_BUILDS = {
    'm1': ('m1_01', 'm1_02'), 'm2': ('m2_01',), 'm3': ('m3_01',), 'm4': ('m4_01',),
    'm5': tuple('m5_%02d' % n for n in range(1, 11)),
    'm6': tuple('m6_%02d' % n for n in range(1, 8)),
    'm7': ('m7_01', 'm7_02', 'm7_03'), 'm8': ('m8_01', 'm8_02'),
    'm9': ('m9_01', 'probe_n_bank_diffs_m9_01', 'probe_n_zero_unused_timestamp_m9_01',
           'probe_t_single_child_m9_01'), 'm9d': ('m9d_01',), 'm10': ('m10_01', 'm10_02', 'm10_03'),
}


def resolve(inputs, source, milestone=None):
    """Return effective semantics after verifying inputs and profile refer to ``source``.

    ``inputs`` is the existing response_only.inputs.json object; ``source`` is a .p4 path. New profiles use the
    existing inline ``supported_profile`` field. The returned milestone is an expectation version, not a build ID.
    """
    if not isinstance(inputs, dict):
        raise ValueError('build inputs must be an object')
    sha = hashlib.sha256(Path(source).read_bytes()).hexdigest()
    if inputs.get('source_sha256') != sha:
        raise ValueError('build inputs do not bind this source')
    recorded = inputs.get('milestone')
    if milestone is not None and recorded is not None and milestone != recorded:
        raise ValueError('requested milestone does not match build inputs')
    selected = recorded if recorded is not None else milestone
    profile = inputs.get('supported_profile')
    if profile is not None:
        if not isinstance(profile, dict) or profile.get('reset_restart_required') is not True:
            raise ValueError('successor profile must require reset restart coverage')
        children = profile.get('t_child_count')
        if type(children) is not int or children not in (1, 2, 3):
            raise ValueError('supported T child count must be 1, 2 or 3')
        candidate = profile.get('candidate')
        if not isinstance(candidate, dict) or candidate.get('source_sha256') != sha:
            raise ValueError('supported profile does not bind this source')
        if inputs.get('segment_sha256') is not None and \
                candidate.get('segment_sha256') != inputs['segment_sha256']:
            raise ValueError('supported profile segment hashes do not match build inputs')
        validate_timing_contract(profile)
        sys.path.insert(0, str(HERE.parents[2] / 'response_only/hw'))
        import t_config
        actual_contract = t_config.timing_contract_of_source(Path(source).read_text())
        if actual_contract != profile.get('timing_contract'):
            raise ValueError('source parameter ABI and supported timing_contract disagree')
        return dict(profile, milestone='m10', historical_build=None)
    for name in HISTORICAL_BUILDS.get(selected, ()):
        path = HERE / 'evidence' / name / 'response_only.inputs.json'
        if path.is_file() and json.loads(path.read_text()).get('source_sha256') == sha:
            return dict(milestone=selected, reset_restart_required=selected == 'm10',
                        t_child_count=1 if name == 'probe_t_single_child_m9_01' else 3,
                        historical_build=name)
    raise ValueError('unknown source/profile: a successor requires a source-bound supported_profile')


def from_env():
    path = Path(os.environ['PORT_MAP'])
    return resolve(json.loads(path.read_text()), path.with_name('response_only.p4'), os.environ.get('MILESTONE'))


RESPONSE_READY = 'response_ready_ack_d_v1'
RESPONSE_WAIT_NS = 500_000_000
RESPONSE_READY_KEYS = frozenset(('gap', 'op_j', 'response_wait_timeout', 'budget', 'enabled'))
LEGACY_ONLY_KEYS = frozenset(('da', 'readiness', 'cap', 'pb'))


def validate_timing_contract(profile):
    """An explicit contract cannot silently fall through to c52 expectations."""
    contract = profile.get('timing_contract')
    if contract is None:
        return
    if contract != RESPONSE_READY:
        raise ValueError('unknown timing_contract: %r' % contract)
    if profile.get('endpoint_profile') != 'sel751':
        raise ValueError('response-ready requires endpoint_profile=sel751')
    timing = profile.get('timing_ns')
    if not isinstance(timing, dict) or set(timing) != {
            'D_release_budget', 'J_operate_hold', 'response_wait_timeout'}:
        raise ValueError('response-ready timing_ns must contain only D, J and response_wait_timeout')
    if timing != dict(D_release_budget=5_000_000, J_operate_hold=2_400_000,
                      response_wait_timeout=RESPONSE_WAIT_NS):
        raise ValueError('response-ready profile must declare D=5ms, J=2.4ms and response_wait_timeout=500ms')
    clock = profile.get('clock') or {}
    if (clock.get('t_unit_ns'), clock.get('t_grid_ns')) != (256, 512):
        raise ValueError('response-ready requires the 256ns T clock and 512ns grid')


def model_params(profile, values_ns):
    """Adapt retained drivers only for the declared successor; never inflate its expiry.

    Drivers keep their stimulus-specific D and J. Legacy readiness/DA/cap/pb values have no
    successor meaning and are recorded by model_driver along with the five actual writes.
    """
    values = dict(values_ns)
    if profile.get('timing_contract') != RESPONSE_READY:
        return values
    validate_timing_contract(profile)
    unknown = set(values) - RESPONSE_READY_KEYS - LEGACY_ONLY_KEYS
    if unknown:
        raise ValueError('unknown model T parameters: %r' % sorted(unknown))
    for name in LEGACY_ONLY_KEYS:
        values.pop(name, None)
    values.setdefault('response_wait_timeout', RESPONSE_WAIT_NS)
    if values['response_wait_timeout'] != RESPONSE_WAIT_NS:
        raise ValueError('response-ready model must exercise the real 500ms expiry')
    if set(values) != RESPONSE_READY_KEYS:
        raise ValueError('response-ready requires all five set_params fields')
    return values



def compiled_t_state_audit(context):
    """One P4 state object must have one physical bank shared by all its actions.

    A compiled duplicate in a second MAU stage is separate state: a write in one
    bank cannot make a read of the other bank observe completion (c60 replay RED).
    """
    problems, banks = [], {}
    tables = context.get('tables') if isinstance(context, dict) else None
    if not isinstance(tables, list):
        return dict(banks_by_register={}, problems=['compiled context has no tables list'])
    for table in tables:
        if not isinstance(table, dict) or table.get('table_type') != 'stateful':
            continue
        name = table.get('name')
        if not isinstance(name, str) or not name.startswith(('t_Ingress.', 't_Egress.')):
            continue
        if name in banks:
            problems.append(name + ': duplicate logical state allocation entry')
        stages = table.get('stage_tables')
        if not isinstance(stages, list) or not stages:
            problems.append(name + ': no physical stage allocation')
            banks.setdefault(name, set())
            continue
        if len(stages) != 1:
            problems.append('%s: %d physical state allocations; exactly one required' % (name, len(stages)))
        for stage in stages:
            number = stage.get('stage_number') if isinstance(stage, dict) else None
            if type(number) is not int or number < 0:
                problems.append(name + ': invalid physical stage allocation')
            else:
                banks.setdefault(name, set()).add(number)
    if not banks:
        problems.append('compiled context has no T logical stateful registers')
    for name, stages in sorted(banks.items()):
        if len(stages) != 1:
            problems.append('%s: logical state occupies physical stages %r; exactly one required' % (name, sorted(stages)))
    return dict(banks_by_register={name: sorted(stages) for name, stages in sorted(banks.items())}, problems=problems)



def _compiled_stage_numbers(node):
    if isinstance(node, dict):
        if 'stage_number' in node:
            # SDK phase-0 port metadata lives in the ingress buffer, outside MAU.
            if not (node['stage_number'] == -1 and node.get('stage_table_type') == 'phase_0_match'):
                yield node['stage_number']
        for value in node.values():
            yield from _compiled_stage_numbers(value)
    elif isinstance(node, list):
        for value in node:
            yield from _compiled_stage_numbers(value)


def compiled_t_state_of_build(build):
    """New-contract preflight: one T bank per object and the approved actual MAU bounds.

    run_model and summary_v3 call this only for response_ready_ack_d_v1; retained
    source profiles keep their historical resource and expectation contracts.
    """
    contexts, hashes = {}, {}
    for pipe in ('p0', 'p1'):
        path = Path(build) / 'compile_local/out' / pipe / 'context.json'
        try:
            content = path.read_bytes()
            contexts[pipe] = json.loads(content)
            hashes[pipe] = hashlib.sha256(content).hexdigest()
            if not isinstance(contexts[pipe], dict) or not isinstance(contexts[pipe].get('tables'), list):
                raise ValueError('no compiled tables list')
        except (OSError, ValueError, TypeError) as error:
            return dict(banks_by_register={}, layout={}, problems=[
                'cannot read compiled %s state/layout context: %s' % (pipe, error)])
    audit = compiled_t_state_audit(contexts['p1'])
    problems, layout = list(audit['problems']), {}
    roles = (('N', 'p0', 'ingress', 'max_index', 10), ('E', 'p0', 'egress', 'max_index', 10),
             ('T', 'p1', 'ingress', 'occupied_count', 11), ('p1_egress', 'p1', 'egress', 'occupied_count', 4))
    for role, pipe, direction, bound_kind, limit in roles:
        tables = [table for table in contexts[pipe]['tables'] if isinstance(table, dict)
                  and (table.get('direction') or table.get('gress')) == direction]
        raw = [number for table in tables for number in _compiled_stage_numbers(table)]
        stages = sorted({number for number in raw if type(number) is int and number >= 0})
        layout[role] = dict(occupied_indices=stages, occupied_count=len(stages),
                            maximum_occupied_stage=max(stages) if stages else None)
        if not stages or any(type(number) is not int or number < 0 for number in raw):
            problems.append(role + ': missing or invalid compiled physical stage placement')
            continue
        actual = max(stages) if bound_kind == 'max_index' else len(stages)
        if actual > limit:
            problems.append('%s: compiled %s %d exceeds approved limit %d' % (role, bound_kind, actual, limit))
    return dict(audit, layout=layout, problems=problems, context_sha256=hashes['p1'],
                context_sha256_by_pipeline=hashes)
