"""A complete mutation inventory, gated by a registered source/schema qualification.

There is currently NO qualified complete Case 4 mapping. Component compiler
passes do not populate this registry. The generic inventory/rollback tests use
explicit mock-only fixtures; they are not complete target compilation evidence.
Hardware activation additionally needs applicable admission and quiescence.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, replace
from pathlib import Path

from profiles import ActivationError, MAX_HOLD_MS, hold_bound_ms, problems
from schema import WriteOperation

REQUIRED_CAPABILITIES = frozenset(('validated_association', 'control_padding', 'response_carving',
    'tcp_translation_two_boundaries', 'independent_recovery', 'control_scheduler',
    'queue_loopback', 'pktgen', 'mirror_pre', 'tuple_cookie_ledger_init', 'controller_restore'))
# Source-reviewed complete compiled mappings must be added here explicitly.
# A declaration, arbitrary JSON capability list or component fit cannot do so.
QUALIFIED_BINDINGS = {}


def profile_configuration(profile):
    """Settings whose actual table values the registered inventory implements."""
    return {name:getattr(profile,name) for name in ('d_a_ms','gap_ms',
        'readiness_expiry_ms','heartbeat_request_us','completion_deadline_ms',
        'padding_profile','split_profile','translation_capacity')}


def _artifact_gate(binding, qualification):
    """The registered verifier must recheck retained/local compiler artifacts.

    Its result must bind this exact source/schema/build/program, verify required
    binary/report hashes, and qualify the complete target and compiler identity.
    Missing ignored SDK artifacts therefore stay blocked in a fresh checkout.
    """
    verifier = qualification.get('verify_artifacts')
    if not callable(verifier):
        raise ActivationError('fresh full-target binary/report verification is unavailable')
    result = verifier(binding)
    if not isinstance(result, dict) or result.get('identity') != binding.identity():
        raise ActivationError('artifact verifier identity differs from the mapping')
    if any(result.get(flag) is not True for flag in (
            'verified', 'full_target', 'compiler_identity_approved', 'artifact_hashes_verified')):
        raise ActivationError('full-target compiler/artifact gate remains blocked')
    return result


@dataclass(frozen=True)
class Case4Binding:
    source_path: str
    source_sha256: str
    schema_sha256: str
    build_id: str
    program_name: str
    operations: tuple[WriteOperation, ...]
    capabilities: frozenset[str]
    operation: str
    operation_profile_sha256: str
    configuration: dict

    def identity(self):
        return {name:getattr(self, name) for name in (
            'source_sha256', 'schema_sha256', 'build_id', 'program_name')}

    def fingerprint(self):
        value = dict(self.identity(), operations=[asdict(op) for op in self.operations],
                     capabilities=sorted(self.capabilities), operation=self.operation,
                     operation_profile_sha256=self.operation_profile_sha256,
                     configuration=self.configuration)
        return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _key(operation):
    return json.dumps([operation.table, operation.kind, operation.key], sort_keys=True)


def preflight(schema, profile, binding, *, mock=False):
    """Check the entire inventory and qualification before any device call."""
    if profile.case != 'case4':
        raise ActivationError('a Case4Binding cannot configure another policy')
    if problems(profile, {}):
        raise ActivationError('; '.join(problems(profile, {})))
    if (binding.operation != profile.operation or
            binding.operation_profile_sha256 != profile.operation_profile_sha256):
        raise ActivationError('mutation inventory describes another operation/profile')
    if binding.configuration != profile_configuration(profile):
        raise ActivationError('mutation inventory does not implement the selected policy configuration')
    if not mock and hold_bound_ms(profile) is None:
        raise ActivationError('measured heartbeat/drain/release/completion bounds are unavailable')
    if (not Path(binding.source_path).is_file() or
            hashlib.sha256(Path(binding.source_path).read_bytes()).hexdigest() != binding.source_sha256):
        raise ActivationError('Case 4 source identity differs from its registered mapping')
    if schema.sha256 != binding.schema_sha256 or profile.build_id != binding.build_id:
        raise ActivationError('Case 4 schema/build identity does not match')
    if not REQUIRED_CAPABILITIES <= binding.capabilities:
        raise ActivationError('complete Case 4 mapping lacks required joint capabilities')
    qualification = QUALIFIED_BINDINGS.get(binding.fingerprint())
    if qualification is None:
        raise ActivationError('complete source-bound compiled Case 4 mapping is unavailable; component fit is insufficient')
    if any(qualification.get(name) != value for name, value in binding.identity().items()):
        raise ActivationError('registered qualification identity differs')
    if (profile.operation not in qualification.get('allowed_operations', ()) or
            qualification.get('operation_profile_sha256') != profile.operation_profile_sha256):
        raise ActivationError('registered qualification does not permit this operation/profile')
    if profile.operation == 'READ':
        if (profile.padding_profile != 'none' or
                qualification.get('control_processing_enabled') is not False or
                any(op.role in ('control_padding', 'control_codebook', 'control_scheduler')
                    for op in binding.operations)):
            raise ActivationError('READ inventory must explicitly disable control processing and padding')
    elif (len(profile.operation_profile_sha256) != 64 or
            any(c not in '0123456789abcdef' for c in profile.operation_profile_sha256)):
        raise ActivationError('control inventory requires an exact operation profile hash')
    if not REQUIRED_CAPABILITIES <= set(qualification.get('capabilities', [])):
        raise ActivationError('registered compiler qualification is incomplete')
    if not mock and (qualification.get('mock_only') or qualification.get('deployment_allowed') is not True):
        raise ActivationError('offline/mock compiler qualification does not permit deployment')
    if not mock:
        _artifact_gate(binding, qualification)
    operations = schema.check_operations(binding.operations)
    phases = [op.phase for op in operations]
    if not phases or phases[0] != 'disable' or phases[-1] != 'enable':
        raise ActivationError('Case 4 mutations must disable first and enable last')
    if any(phase not in ('disable', 'configure', 'enable') for phase in phases):
        raise ActivationError('unknown Case 4 mutation phase')
    order = {'disable':0, 'configure':1, 'enable':2}
    if [order[phase] for phase in phases] != sorted(order[phase] for phase in phases):
        raise ActivationError('Case 4 enable cannot precede configuration/readback')
    disable_targets = {_key(op) for op in operations if op.phase == 'disable'}
    if any(_key(op) not in disable_targets for op in operations if op.phase == 'enable'):
        raise ActivationError('every enabled component requires an explicit disable operation')
    for phase in ('disable', 'enable'):
        if not {'processing', 'pktgen'} <= {op.role for op in operations if op.phase == phase}:
            raise ActivationError('processing and packet generation must both disable first/enable last')
    if not any(op.role == 'tuple_cookie_ledger_seed' for op in operations):
        raise ActivationError('mapping has no verified tuple/cookie/ledger initialization')
    return operations


def _admission_problem(profile, admission):
    if not isinstance(admission, dict) or admission.get('verdict') != 'admitted_conditional':
        return 'applicable current admission is required'
    policy = admission.get('policy', {})
    context = policy.get('context', {})
    if policy.get('policy_cap_ms') != MAX_HOLD_MS or admission.get('policy_cap', {}).get('cap_ms') != MAX_HOLD_MS:
        return 'admission must preserve the independent fixed 40 ms policy cap'
    if (admission.get('claim', {}).get('kind') != 'admitted_conditional'
            or admission.get('unknown_inputs') or admission.get('inputs_not_authoritative')):
        return 'admission has unknown/unqualified inputs or a conflicting claim'
    if (context.get('connection_id') != profile.connection_id or context.get('build_id') != profile.build_id
            or policy.get('anchor') != 'request' or policy.get('d_a_ms') != profile.d_a_ms
            or policy.get('clrt_new_ms') != profile.gap_ms or admission.get('policy_cap', {}).get('ok') is not True):
        return 'admission identity/anchor/policy does not match this trial'
    if context.get('operation', 'READ') != profile.operation:
        return 'admission describes another operation'
    if context.get('operation_profile_sha256', '') != profile.operation_profile_sha256:
        return 'admission describes another operation profile'
    if not profile.connection_id or (profile.operation in ('SELECT','OPERATE','SBO') and
            (len(profile.operation_profile_sha256) != 64 or
             any(c not in '0123456789abcdef' for c in profile.operation_profile_sha256))):
        return 'fresh control connection and exact operation/profile identity are required'
    required = {'master TCP retransmission', 'outstation TCP retransmission', 'master application deadline',
        'master TCP recovery', 'outstation TCP recovery', 'master application recovery'}
    if profile.operation in ('SELECT', 'OPERATE', 'SBO'):
        required |= {'outstation SELECT retention normal', 'outstation SELECT retention recovery'}
        clock = admission.get('sbo_clock') or {}
        if (clock.get('origin') != 'outstation_successful_select_accept' or
                clock.get('endpoint') != 'outstation_matching_operate_accept'):
            return 'SBO retention origin/endpoint is unavailable'
    checks = {check.get('constraint'):check.get('ok') for check in admission.get('checks', [])}
    if any(checks.get(name) is not True for name in required):
        return 'admission omits a required whole-interval/retention check'
    return ''


def _snapshot(device, binding, operations):
    entries, seen = [], set()
    for op in operations:
        if _key(op) in seen:
            continue
        seen.add(_key(op))
        prior = device.read_operation(op)
        if prior is None and op.kind != 'entry':
            raise ActivationError('required default/register state is unreadable; refusing to guess restore')
        if prior is not None:
            device.schema.check_operation(replace(op, fields=prior))
        entries.append({'operation':asdict(op), 'before':prior})
    return dict(version=1, identity=binding.identity(), binding_sha256=binding.fingerprint(), entries=entries)


def _emergency_disable(device, operations):
    """Try every validated disable even if one fails or is interrupted."""
    steps=[]
    for op in operations:
        if op.phase != 'disable':
            continue
        step=dict(operation=asdict(op),match=None)
        try:
            device.write_operation(op)
            step['read_back']=device.read_operation(op)
            step['match']=step['read_back']==op.fields
        except BaseException as exc:
            step['failure']=type(exc).__name__+': '+str(exc)
        steps.append(step)
    return steps


def restore(device, binding, snapshot, *, mock=False):
    """Restore every touched state with disable-first/readback/enable-last ordering.

    This restores configuration of the bound program. It never claims to restore
    a previously loaded different program or replay in-flight transactions.
    """
    if snapshot.get('identity') != binding.identity() or snapshot.get('binding_sha256') != binding.fingerprint():
        raise ActivationError('snapshot belongs to another source/schema/mutation inventory')
    qualification = QUALIFIED_BINDINGS.get(binding.fingerprint(), {})
    if not mock and (qualification.get('mock_only') or qualification.get('deployment_allowed') is not True):
        raise ActivationError('unqualified mapping cannot mutate during restore')
    if not mock:
        _artifact_gate(binding, qualification)
        if getattr(device, 'loaded_identity', None) != binding.identity():
            raise ActivationError('loaded program/artifact identity is unavailable or differs')
    if device.schema.sha256 != binding.schema_sha256:
        raise ActivationError('restore schema identity differs')
    original = {_key(op) for op in device.schema.check_operations(binding.operations)}
    saved = {}
    restore_ops = []
    for entry in snapshot.get('entries', []):
        op = WriteOperation(**entry['operation'])
        device.schema.check_operation(op)
        if _key(op) in saved:
            raise ActivationError('duplicate snapshot entry')
        saved[_key(op)] = entry['before']
        if entry['before'] is not None:
            restore_ops.append(device.schema.check_operation(replace(op, fields=entry['before'])))
        elif op.kind != 'entry':
            raise ActivationError('snapshot omits required default/register state')
    if set(saved) != original:
        raise ActivationError('snapshot does not cover the complete mutation inventory')
    disable = device.schema.check_operations(op for op in binding.operations if op.phase == 'disable')
    # Validate all saved writes before the first disable, including prior actions.
    enable_keys = {_key(op) for op in disable}
    order = list(disable) + [op for op in restore_ops if _key(op) not in enable_keys]
    reenable = [op for op in restore_ops if _key(op) in enable_keys]
    steps = []
    try:
        for op in order:
            device.write_operation(op)
            got = device.read_operation(op)
            steps.append(dict(operation=asdict(op), read_back=got, match=got == op.fields))
            if got != op.fields:
                raise ActivationError('restore readback mismatch')
        for entry in snapshot['entries']:
            if entry['before'] is None:
                op = WriteOperation(**entry['operation'])
                device.delete_operation(op)
                if device.read_operation(op) is not None:
                    raise ActivationError('created entry remains after restore')
        for op in reenable:
            device.write_operation(op)
            got = device.read_operation(op)
            steps.append(dict(operation=asdict(op), read_back=got, match=got == op.fields))
            if got != op.fields:
                raise ActivationError('restore enable readback mismatch')
    except BaseException as exc:
        failure=dict(restored=False,reason=type(exc).__name__+': '+str(exc),steps=steps,
                     traffic_must_remain_stopped=True,disable_attempts=_emergency_disable(device,disable))
        if not isinstance(exc,Exception):
            exc.record=failure
            raise
        raise ActivationError(str(exc),failure) from exc
    return dict(restored=True, steps=steps, program_restore=False,
                is_evidence_of_switch_state=not mock)


def activate(device, profile, binding, *, mock=False, admission=None, backup_path=None, quiesced=False):
    operations = preflight(device.schema, profile, binding, mock=mock)
    record = dict(source='mock' if mock else 'switch', is_evidence_of_switch_state=not mock,
        profile=profile.__dict__.copy(), identity=binding.identity(), steps=[])
    if not mock:
        if getattr(device, 'loaded_identity', None) != binding.identity():
            raise ActivationError('loaded program/artifact identity is unavailable or differs', record)
        why = _admission_problem(profile, admission)
        if why or not quiesced:
            raise ActivationError(why or 'traffic stop and physical drain must be verified', record)
    if backup_path is None:
        raise ActivationError('exclusive backup path is required', record)
    snapshot = _snapshot(device, binding, operations)
    with Path(backup_path).open('x', encoding='utf-8') as stream:
        json.dump(snapshot, stream, indent=2, sort_keys=True)
        stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    record['before'] = snapshot
    try:
        for op in operations:
            device.write_operation(op)
            got = device.read_operation(op)
            record['steps'].append(dict(operation=asdict(op),read_back=got,match=got == op.fields))
            if got != op.fields:
                raise ActivationError('Case 4 readback differs from the complete plan')
        final = {_key(op):op for op in operations}
        if any(device.read_operation(op) != op.fields for op in final.values()):
            raise ActivationError('final Case 4 inventory readback differs')
    except BaseException as exc:
        record['failure'] = dict(reason=str(exc), exception_type=type(exc).__name__, stage='mutation/readback')
        try:
            record['rollback'] = restore(device, binding, snapshot, mock=mock)
        except BaseException as rollback:
            record['rollback'] = getattr(rollback,'record',{}) or dict(restored=False,
                reason=type(rollback).__name__+': '+str(rollback),traffic_must_remain_stopped=True,
                disable_attempts=_emergency_disable(device,operations))
        if not isinstance(exc,Exception):
            exc.record=record
            raise
        raise ActivationError(str(exc), record) from exc
    return record
