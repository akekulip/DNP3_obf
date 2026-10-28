"""Current source/artifact-bound one-child schema; no historical profile lookup."""
import hashlib
import json
import re
from pathlib import Path
import t_config

def child_registers(descriptor):
    count = descriptor.get('t_child_count')
    if type(count) is not int or count != 1:
        raise ValueError('unsupported T child count')
    return tuple('child_seen%d_reg' % index for index in range(count))


def validate_timing_contract(supported, text):
    if supported.get('timing_contract') != t_config.RESPONSE_READY_NO_J_CONTRACT:
        raise ValueError('current profile requires the D-only timing contract')
    if supported.get('timing_ns') != dict(D_release_budget=5000000):
        raise ValueError('current timing profile must bind D only')
    return t_config.timing_contract_of_source(text, supported['timing_contract'])


def _source_profile(out):
    """Locate unchanged build metadata locally or in the deployed out/profile copy."""
    if (out / 'profile').is_dir():
        directory = out / 'profile'
        names = [name for name in ('compile_local',)
                 if (directory / name / 'manifest.json').is_file()]
        if len(names) != 1:
            raise ValueError('deployed profile requires one selected compile manifest')
        compile_name = names[0]
    else:
        directory, compile_name = out.parent.parent, out.parent.name
    inputs_path = directory / 'response_only.inputs.json'
    if not inputs_path.is_file():
        if directory == out / 'profile':
            raise ValueError('deployed supported profile inputs are missing')
        raise ValueError('current supported profile is missing')
    inputs = json.loads(inputs_path.read_text())
    if not isinstance(inputs, dict):
        raise ValueError('supported profile inputs must be an object')
    supported = inputs.get('supported_profile')
    if supported is None:
        raise ValueError('current supported profile is missing')
    if not isinstance(supported, dict) or supported.get('reset_restart_required') is not True:
        raise ValueError('successor supported profile must require reset restart coverage')
    child_registers(supported)
    candidate = supported.get('candidate')
    if not isinstance(candidate, dict):
        raise ValueError('supported profile candidate identity is missing')
    source = directory / 'response_only.p4'
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if inputs.get('source_sha256') != digest or candidate.get('source_sha256') != digest:
        raise ValueError('supported profile source/input hashes differ')
    separate = directory / 'supported_profile.json'
    if not separate.is_file() or json.loads(separate.read_text()) != supported:
        raise ValueError('supported profile file differs from its build inputs')
    contract = validate_timing_contract(supported, source.read_text())
    compiles = candidate.get('artifact_sha256')
    if not isinstance(compiles, dict):
        raise ValueError('supported profile requires artifact hashes for the selected SDK compile')
    required = {'bfrt.json', 'response_only.p4pp', 'p0/context.json', 'p1/context.json',
                'p0/tofino.bin', 'p1/tofino.bin'}
    local_manifest = directory / 'compile_local' / 'manifest.json'
    if not local_manifest.is_file() or not re.match(r'^p4c\s+9\.13\.2(?:\s|$)',
            json.loads(local_manifest.read_text()).get('compiler', '')):
        raise ValueError('current profile requires SDK 9.13.2')
    if set(compiles) != {'compile_local'}:
        raise ValueError('current profile requires exactly the local SDK compile')
    pins = compiles['compile_local']
    if not isinstance(pins, dict) or not required.issubset(pins):
        raise ValueError('current profile requires complete artifact hashes')
    if compile_name not in compiles:
        raise ValueError('unsupported selected SDK compile')
    manifest = json.loads((directory / compile_name / 'manifest.json').read_text())
    if manifest.get('source_sha256') != digest or manifest.get('exit_code') != 0:
        raise ValueError('compile manifest does not bind a successful build of this source')
    pins = compiles[compile_name]
    artifacts = manifest.get('artifact_sha256')
    if not isinstance(artifacts, dict) or not artifacts or \
            any(pins.get(name) != value for name, value in artifacts.items()):
        raise ValueError('compile manifest artifact hashes differ from the supported profile')
    for name, expected in pins.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('invalid supported profile artifact path')
        path = out / relative
        if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('supported profile artifact differs or is missing: ' + name)
    return dict(sealed=True, t_child_count=supported['t_child_count'], source_sha256=digest,
                compile_name=compile_name, timing_contract=contract)


def describe(build_out):
    """Select the current source/artifact-bound T schema."""
    out = Path(build_out)
    descriptor = _source_profile(out)
    tables = json.loads((out / 'bfrt.json').read_bytes())['tables']
    if descriptor.get('timing_contract') is not None:
        validate_timing_contract(dict(timing_contract=descriptor['timing_contract'],
            timing_ns=dict(D_release_budget=5000000)),
            (out / 'response_only.p4pp').read_text())
    if descriptor.get('timing_contract') == 'response_ready_ack_d_no_j_v3':
        params = next((table for table in tables if table['name'] == 'p1.t_Ingress.params'), {})
        actions = [action for action in params.get('action_specs', [])
                   if action.get('name') == 't_Ingress.set_params']
        if len(actions) != 1 or tuple(field['name'] for field in actions[0].get('data', [])) != \
                ('gap', 'budget', 'enabled'):
            raise ValueError('no-J compiled BFRT parameter ABI mismatch')
        retired = {'op_gen_alloc_reg', 'op_t0_reg', 'op_done_reg', 'operate_generation_access',
                   'operate_anchor_access', 'op_go_check', 'operate_completion_access', 'hb_verdict'}
        observed_retired = {item['name'] for item in tables
                            if item['name'].startswith('p1.t_Ingress.') and item['name'].split('.')[-1] in retired}
        if observed_retired:
            raise ValueError('no-J compiled ABI retains OPERATE hold resources: %s' % sorted(observed_retired))
    observed = {item['name'] for item in tables
                if re.fullmatch(r'p1\.t_Ingress\.child_seen[0-9]+_reg', item['name'])}
    expected = {'p1.t_Ingress.' + name for name in child_registers(descriptor)}
    if observed != expected:
        raise ValueError('compiled T child banks differ from the selected profile: expected %s, observed %s'
                         % (sorted(expected), sorted(observed)))
    return descriptor


def select(build_out):
    """Compatibility wrapper for callers that only need the sealed-layout boolean."""
    return describe(build_out)['sealed']

def read_diagnostics(read_outcome, outcomes, expected=False):
    if any(value is not None for value in outcomes.values()):
        raise ValueError('current profile has no switch measurement counters')
    return dict(present=False, layout='no_switch_telemetry', rewait={}, blocker_laps={}, stale={},
                read_errors=[], stale_sources={}, stale_total=None)
