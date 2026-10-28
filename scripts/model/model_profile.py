"""Resolve the current D-only model contract from actual source and matching profile files."""
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

HERE = Path(__file__).resolve().parent
def resolve(inputs, source, milestone=None):
    """Resolve current semantics only after checking actual source and both profiles."""
    if not isinstance(inputs, dict):
        raise ValueError('build inputs must be an object')
    digest = hashlib.sha256(Path(source).read_bytes()).hexdigest()
    if inputs.get('source_sha256') != digest:
        raise ValueError('build inputs do not bind this source')
    package_spec = importlib.util.spec_from_file_location('current_source_package', HERE.parent / 'profile.py')
    package = importlib.util.module_from_spec(package_spec)
    package_spec.loader.exec_module(package)
    if not all(package.verify_package(Path(source).parent).values()):
        raise ValueError('current source package inputs or provenance changed')
    if milestone is not None and milestone != inputs.get('milestone'):
        raise ValueError('requested milestone does not match build inputs')
    profile = inputs.get('supported_profile')
    if not isinstance(profile, dict) or profile.get('reset_restart_required') is not True:
        raise ValueError('current profile must require reset restart coverage')
    if profile.get('t_child_count') != 1 or profile.get('endpoint_profile') != 'sel751':
        raise ValueError('current profile requires SEL-751 and exactly one T child')
    if (profile.get('candidate') or {}).get('source_sha256') != digest:
        raise ValueError('supported profile does not bind this source')
    if (profile.get('candidate') or {}).get('segment_sha256') != inputs.get('segment_sha256'):
        raise ValueError('supported profile segment hashes do not match build inputs')
    separate = Path(source).with_name('supported_profile.json')
    if not separate.is_file() or json.loads(separate.read_text()) != profile:
        raise ValueError('inline and separate supported profiles must agree')
    if profile.get('timing_contract') != RESPONSE_READY_NO_J:
        raise ValueError('current build must use the D-only timing contract')
    validate_timing_contract(profile)
    sys.path.insert(0, str(HERE.parent / 'hardware'))
    import t_config
    if t_config.timing_contract_of_source(Path(source).read_text()) != profile['timing_contract']:
        raise ValueError('source parameter ABI and supported timing_contract disagree')
    # m10 is the internal scenario expectation version, never candidate identity.
    return dict(profile, milestone='m10', historical_build=None)


def from_env():
    path = Path(os.environ['PORT_MAP'])
    return resolve(json.loads(path.read_text()), path.with_name('response_only.p4'), os.environ.get('MILESTONE'))


def compiled_n_registers(build):
    """Every physical N bank in this exact build; packed fields stay real readbacks."""
    build = Path(build)
    inputs = json.loads((build / 'response_only.inputs.json').read_text())
    expected = inputs['supported_profile']['candidate']['artifact_sha256']['compile_local']['bfrt.json']
    schema = build / 'compile_local/out/bfrt.json'
    raw = schema.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError('N state inventory is not this build\'s pinned BFRT schema')
    tables = [table for table in json.loads(raw)['tables']
              if table.get('table_type') == 'Register' and table.get('name', '').startswith('p0.n_Ingress.')]
    if not tables or any(table.get('size') != 1 for table in tables):
        raise ValueError('current model requires explicit single-entry N register banks')
    return tuple(sorted(table['name'] for table in tables))


RESPONSE_READY = 'response_ready_ack_d_v2'
RESPONSE_READY_NO_J = 'response_ready_ack_d_no_j_v3'
RESPONSE_READY_CONTRACTS = (RESPONSE_READY, RESPONSE_READY_NO_J)
OPERATE_HOLD_REGISTERS = frozenset(('op_gen_alloc_reg', 'op_t0_reg', 'op_done_reg'))
RESPONSE_READY_KEYS = frozenset(('gap', 'op_j', 'budget', 'enabled'))
LEGACY_ONLY_KEYS = frozenset(('da', 'readiness', 'cap', 'pb'))


def validate_timing_contract(profile):
    """An explicit contract cannot silently fall through to c52 expectations."""
    contract = profile.get('timing_contract')
    if contract is None:
        return
    if contract not in RESPONSE_READY_CONTRACTS:
        raise ValueError('unknown timing_contract: %r' % contract)
    if profile.get('endpoint_profile') != 'sel751':
        raise ValueError('response-ready requires endpoint_profile=sel751')
    timing = dict(D_release_budget=5_000_000)
    if contract == RESPONSE_READY:
        timing['J_operate_hold'] = 2_400_000
    if profile.get('timing_ns') != timing:
        raise ValueError('response-ready timing_ns must exactly match its declared contract')
    clock = profile.get('clock') or {}
    if (clock.get('t_unit_ns'), clock.get('t_grid_ns')) != (256, 512):
        raise ValueError('response-ready requires the 256ns T clock and 512ns grid')


def model_params(profile, values_ns):
    """Translate retained model stimuli only for an explicit source-bound timing ABI.

    D remains caller-specific for model constructions; J exists only in v2.
    An exchange timeout has no v2 meaning and is rejected rather than translated.
    """
    values = dict(values_ns)
    if profile.get('timing_contract') not in RESPONSE_READY_CONTRACTS:
        return values
    validate_timing_contract(profile)
    unknown = set(values) - RESPONSE_READY_KEYS - LEGACY_ONLY_KEYS
    if unknown:
        raise ValueError('unknown model T parameters: %r' % sorted(unknown))
    for name in LEGACY_ONLY_KEYS:
        values.pop(name, None)
    required = RESPONSE_READY_KEYS
    if profile['timing_contract'] == RESPONSE_READY_NO_J:
        values.pop('op_j', None)
        required = RESPONSE_READY_KEYS - {'op_j'}
    if set(values) != required:
        raise ValueError('response-ready requires the exact declared set_params fields')
    return values



def compiled_t_state_audit(context, timing_contract=None):
    """One P4 state object must have one physical bank shared by all its actions.

    A compiled duplicate in a second MAU stage is separate state: a write in one
    bank cannot make a read of the other bank observe completion (c60 replay RED).
    """
    problems, banks = [], {}
    if timing_contract == RESPONSE_READY_NO_J:
        forbidden = OPERATE_HOLD_REGISTERS | {'op_j', 'hold_operate', 'arm_operate_anchor',
            'release_operate_counted', 'seed_operate_blocker'}
        def strings(node):
            if isinstance(node, dict):
                for key, value in node.items():
                    yield str(key)
                    yield from strings(value)
            elif isinstance(node, list):
                for value in node:
                    yield from strings(value)
            elif isinstance(node, str):
                yield node
        found = sorted({name for value in strings(context) for name in forbidden
                        if re.search(r'(?<![A-Za-z0-9_])' + name + r'(?![A-Za-z0-9_])', value)})
        if found:
            problems.append('no-J contract retains compiled OPERATE hold state/ABI: ' + ', '.join(found))
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


def compiled_t_state_of_build(build, timing_contract=None):
    """New-contract preflight: one T bank per object and the approved actual MAU bounds.

    run_model and summary_v3 pass the explicit response-ready contract; retained
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
    audit = compiled_t_state_audit(contexts['p1'], timing_contract)
    problems, layout = list(audit['problems']), {}
    roles = (('N', 'p0', 'ingress', 'max_index', 9), ('E', 'p0', 'egress', 'max_index', 9),
             ('T', 'p1', 'ingress', 'max_index', 7), ('p1_egress', 'p1', 'egress', 'max_index', 3))
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
