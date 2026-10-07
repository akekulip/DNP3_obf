#!/usr/bin/env python3
"""Prepare an inert exact-source/schema inventory; never contacts a device.

A primitive compiler PASS cannot qualify the full mechanism. The reviewed full
registry is empty. Mock-only fixtures exercise package structure and refusal,
not target compilation or deployment. No execute/connect path is provided.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE=Path(__file__).resolve()
ARCH=HERE.parents[2]
CONTROL=HERE.parents[3]/'framework/control'
sys.path.insert(0,str(CONTROL))
from schema import Schema,WriteOperation

QUALIFIED_TARGETS={}
REQUIRED_BEHAVIORS=frozenset((
 'full_frame_profile_crc_validation','full_tcp_app_association','connection_epoch_lifecycle',
 'original_conservation','owner_work_terminal_credits','independent_recovery',
 'operate_deadline_sbo_statuses','switch_padding35_55','carving57_28_29',
 'two_boundary_sequences_both_window_edges','exact_replay_native_sender_tail_repair',
 'supported_fragment_assembly','policy_off_continuing_translation','configuration_restore_without_runtime_owner'))
RUNTIME_LIFETIMES=frozenset(('connection','timing','work','original','translation','image'))


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _relative(value):
    p=Path(value)
    if p.is_absolute() or '..' in p.parts or not p.parts:
        raise ValueError('evidence artifact path must stay within its retained root')
    return p


def _builder():
    spec=importlib.util.spec_from_file_location('case4_integration_build',ARCH/'build.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


def _profile(profile):
    if set(profile.get('operations',[]))!={'READ','SELECT','OPERATE'}:
        raise ValueError('full Case4 scope requires READ and both control phases')
    if profile.get('da_ms') not in (5,10,15,20):raise ValueError('D_A must retain accepted grid')
    exact=dict(gap_ms=1,readiness_ms=30,heartbeat_request_us=100,policy_cap_ms=40,
        translation_capacity=2,padding='35_55_crob',split='57_28_29')
    if any(type(profile.get(k)) is bool or profile.get(k)!=v for k,v in exact.items()):
        raise ValueError('profile does not match the full accepted Case4 bounds/size contract')


def _inventory(schema,inventory):
    if not isinstance(inventory,list) or not inventory:raise ValueError('complete inventory is unavailable')
    operations=[]
    for entry in inventory:
        if entry.get('lifetime') not in RUNTIME_LIFETIMES|{'configuration'}:
            raise ValueError('every mutation needs a configuration or runtime lifetime')
        values={name:entry.get(name) for name in ('table','fields','key','kind','phase','role')}
        operations.append(schema.check_operation(WriteOperation(**values)))
    phases=[op.phase for op in operations];ranks={'disable':0,'configure':1,'enable':2}
    if (phases[0]!='disable' or phases[-1]!='enable' or any(p not in ranks for p in phases)
            or [ranks[p] for p in phases]!=sorted(ranks[p] for p in phases)):
        raise ValueError('inventory must disable first, configure/readback, then enable last')
    def target(op):return digest([op.table,op.key,op.kind])
    disabled={target(op) for op in operations if op.phase=='disable'}
    if any(target(op) not in disabled for op in operations if op.phase=='enable'):
        raise ValueError('enabled targets need explicit disable operations')
    for phase in ('disable','enable'):
        if not {'holding_gate','packet_generator'}<={op.role for op in operations if op.phase==phase}:
            raise ValueError('holding and packet generation must disable first and enable last')
    return operations


def candidate_identity(evidence):
    evidence=Path(evidence);manifest=json.loads((evidence/'manifest.json').read_text())
    binaries={name:manifest['artifact_sha256'].get(str(path.parent/'tofino.bin'))
        for name,path in _builder().pipeline_contexts(evidence/'out').items()}
    return dict(binary_sha256_by_pipeline=binaries,manifest_sha256=sha(evidence/'manifest.json'),source_sha256=manifest['source_sha256'],
        schema_sha256=manifest['artifact_sha256'].get('bfrt.json'),
        binary_sha256=manifest['artifact_sha256'].get('pipe/tofino.bin'))


def prepare(evidence,profile,inventory,*,mock=False):
    result=dict(prepared=False,hardware_authorized=False,actions=[],blockers=[],
        evidence_kind='mock_only' if mock else'offline_preparation',
        runtime_preconditions=['exact_loaded_source_binary_schema_readback','exclusive_snapshot_before_first_write',
            'traffic_stopped','all_connections_retired','actual_original_and_producer_credits_zero',
            'current_timer_feedback_release_and_SBO_admission','captures_running',
            'attended_authorized_inert_OPERATE','readback_after_every_write','saved_workload_restore_verified'],
        policy_off=dict(translation='retain until verified connection retirement',
            tail_repair='native sender retransmission; no manufactured ACK',
            held_originals='forward ACK/response; abort unsent OPERATE; debit actual terminal outcomes'),
        restore_scope='configuration only; no stale owner, ledger, work or cached packet resurrection')
    evidence=Path(evidence)
    try:
        manifest=json.loads((evidence/'manifest.json').read_text());identity=candidate_identity(evidence)
        result['identity']=dict(identity,profile_sha256=digest(profile),inventory_sha256=digest(inventory))
        for group in ('source_files','artifact_sha256'):
            for name in manifest[group]:_relative(name)
        if not _builder().required_artifacts(evidence/'out')<=set(manifest['artifact_sha256']):
            result['blockers'].append('required binary/context/schema artifact identities are missing')
        primary=Path(manifest['source']).name
        if manifest['source_files'].get(primary)!=manifest['source_sha256']:
            result['blockers'].append('primary source identity differs from retained/current source map')
        builder=_builder()
        verification=builder.verify_evidence(evidence)
        result['compiler_verification']=verification
        if not verification['compiled_artifacts_verified']:
            result['blockers'].append('source/snapshot/log/binary/schema compiler evidence is unavailable or stale')
        compiler=Path(manifest['compiler_path'])
        if not compiler.is_file() or sha(compiler)!=manifest.get('compiler_sha256'):
            result['blockers'].append('current compiler binary identity differs or is unavailable')
        if not re.search(r'(?<!\d)9\.13\.2(?!\d)',manifest.get('compiler','')):
            result['blockers'].append('deployment requires source-current licensed SDE9.13.2 evidence')
        resources=manifest.get('resources',{})
        if verification['compiled_artifacts_verified'] and builder.resource_summary(evidence/'out')!=resources:
            result['blockers'].append('resource costs differ from hash-bound compiled context/reports')
        reports=resources.get('report_sha256',{})
        if not reports or any(not(evidence/'out'/_relative(name)).is_file() or
                sha(evidence/'out'/name)!=expected for name,expected in reports.items()):
            result['blockers'].append('required source-bound resource reports are missing or changed')
        if any(type(resources.get('stages',{}).get(d)) is not int or not 0 <=resources['stages'][d]<=12
                for d in ('ingress','egress')):
            result['blockers'].append('resource stage counts must bind both directions within12 stages')
        _profile(profile)
        schema=Schema.from_file(evidence/'out/bfrt.json')
        if schema.sha256!=identity['schema_sha256']:
            result['blockers'].append('compiled schema does not match its bound artifact')
        _inventory(schema,inventory)  # Entire inventory before preparing even a mock action list.
        qualification=QUALIFIED_TARGETS.get(identity['manifest_sha256'])
        if not qualification:
            result['blockers'].append('reviewed complete qualification is unavailable; primitive fit is insufficient')
        else:
            if any(qualification.get(name) is not True for name in (
                    'reviewed_complete','compiler_identity_approved','schema_mapping_reviewed')):
                result['blockers'].append('complete source/schema/compiler review remains blocked')
            if not REQUIRED_BEHAVIORS<=set(qualification.get('required_behaviors',())):
                result['blockers'].append('reviewed candidate omits required mechanism behavior')
            if any(qualification.get(name)!=result['identity'][name] for name in ('profile_sha256','inventory_sha256')):
                result['blockers'].append('selected profile or exact mutation inventory differs from qualification')
            if qualification.get('mock_only') and not mock:
                result['blockers'].append('mock fixture cannot prepare a deployable target package')
        if not result['blockers']:
            result.update(prepared=True,actions=[dict(op,readback_required=True) for op in inventory],
                snapshot_policy='save immutable configuration; runtime state is inspected and retired, never replayed')
    except (KeyError,ValueError,TypeError,OSError) as exc:
        result['blockers'].append(type(exc).__name__+': '+str(exc))
    return result


def configuration_rollback(snapshot,schema_path,*,expected_identity=None,inventory=None):
    """Pure configuration restore planning. Runtime snapshots are never restored."""
    schema=Schema.from_file(schema_path)
    identity=snapshot.get('identity',{})
    if (not expected_identity or identity!=expected_identity or
            identity.get('schema_sha256')!=schema.sha256 or
            any(not identity.get(k) for k in ('source_sha256','binary_sha256','manifest_sha256'))
            or inventory is None or identity.get('inventory_sha256')!=digest(inventory)):
        raise ValueError('exact source/artifact/schema restore identity is unavailable or differs')
    _inventory(schema,inventory)
    def target(entry):return digest([entry['table'],entry.get('key'),entry['kind']])
    canonical={target(entry):entry for entry in inventory}
    entries=snapshot.get('entries',[])
    if not entries:raise ValueError('configuration restore snapshot is empty')
    if any(entry.get('lifetime')!='configuration' or
            canonical.get(target(entry),{}).get('lifetime')!='configuration' for entry in entries):
        raise ValueError('runtime owner/connection/work/original/translation/image state cannot be restored')
    prior={target(entry):entry for entry in entries}
    config_targets={key for key,entry in canonical.items() if entry['lifetime']=='configuration'}
    if len(prior)!=len(entries) or set(prior)!=config_targets:
        raise ValueError('snapshot must cover each exact configuration target once')
    for key,entry in prior.items():
        if entry['fields'] is None:
            if entry['kind']!='entry':raise ValueError('cannot guess an unreadable default/register restore value')
            continue
        schema.check_operation(WriteOperation(**{name:entry.get(name) for name in
            ('table','fields','key','kind','phase','role')}))
    disable=[dict(entry,readback_required=True) for entry in inventory if entry['phase']=='disable']
    disabled={target(entry) for entry in disable}
    restore=[];reenable=[]
    for key,entry in prior.items():
        if entry['fields'] is None:
            restore.append(dict(entry,phase='configure',mutation='delete_entry',readback_is_absent=True))
        else:
            action=dict(entry,phase='enable' if key in disabled else'configure',readback_required=True)
            (reenable if key in disabled else restore).append(action)
    return dict(actions=disable+restore+reenable,
        program_restore=False,physical_drain_verified=False,runtime_state_restored=False,
        preconditions=['traffic_stopped','all_connections_retired','exact_loaded_identity'])


def write_package(path,value):
    with Path(path).open('x',encoding='utf-8') as stream:
        json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence',type=Path);parser.add_argument('profile',type=Path)
    parser.add_argument('inventory',type=Path);parser.add_argument('output',type=Path)
    args=parser.parse_args()
    result=prepare(args.evidence,json.loads(args.profile.read_text()),json.loads(args.inventory.read_text()))
    write_package(args.output,result)
    print('inert package prepared' if result['prepared'] else 'blocked: '+'; '.join(result['blockers']))
    raise SystemExit(0 if result['prepared'] else 1)

if __name__=='__main__':main()
