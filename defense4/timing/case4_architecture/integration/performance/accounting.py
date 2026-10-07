#!/usr/bin/env python3
"""Bounded workload and packet/pass accounting; no traffic or fit qualification.

External counts use the declared fixed profiles and Ethernet L1 serialization:
FCS, padding, preamble/SFD and inter-frame gap. Transform paths are distinct from
holding circulation and the requested heartbeat. Missing measurements stay None.
"""
import argparse
import hashlib
import importlib.util
import json
import math
import sys
from pathlib import Path

HERE=Path(__file__).resolve()
ARCH=HERE.parents[2]
TIMING=HERE.parents[3]
sys.path.insert(0,str(HERE.parents[5]))
from defense4.timing.framework.runner import declaration

PATHS=('read_request','control_request','tcp_ack','read_response','control_response',
       'replay_request','fragment_piece')
FAMILIES={
 'same_pipe':('one_pipe_state_authority','owner_qualified_publication','original_conservation'),
 'bounded_resubmit':('one_pipe_state_authority','original_preserving_resubmit8',
                     'owner_qualified_publication','work_record_terminal_credit','original_conservation'),
 'bounded_recirculation':('one_pipe_state_authority','original_preserving_recirculation',
                     'actual_serialized_envelope','owner_qualified_publication',
                     'work_record_terminal_credit','original_conservation'),
 'cross_pipe':('pipe_local_state','physical_handoff_ports','typed_handoff_envelope',
               'return_to_authority','owner_qualified_publication','original_conservation',
               'handoff_backpressure_failure','native_sender_replay'),
}


def _count(value,name,minimum=0):
    if type(value) is not int or value<minimum:
        raise ValueError(name+' must be an integer in range')
    return value


def _positive(value,name):
    if isinstance(value,bool) or not isinstance(value,(int,float)) or not math.isfinite(value) or value<=0:
        raise ValueError(name+' must be finite and positive')
    return value


def load_workload(campaign_path=None):
    path=Path(campaign_path or TIMING/'framework/declarations/case4_campaign.json')
    campaign=json.loads(path.read_text())
    declarations=[json.loads((path.parent/name).read_text()) for name in campaign['declarations']]
    problems=declaration.validate_campaign(declarations,max_total_attempts=campaign['max_total_attempts'],
        max_duration_ms=campaign['max_duration_ms'])
    if problems:raise ValueError('; '.join(problems))
    summaries=[declaration.budget_summary(d) for d in declarations]
    rows=[];counts={name:0 for name in ('READ','SELECT','OPERATE')};by_arm={}
    units=spacing=0
    for d in declarations:
        for row in d['workload']['run_list']:
            if row['interval_ms']!=400:raise ValueError('accepted workload spacing is400 ms')
            r=dict(row,declaration_id=d['id']);rows.append(r)
            total=row['blocks']*sum(row[name] for name in (
                'primary_per_block','warmup_per_block','precheck_per_block'))
            states=row['blocks']*row['state_reads_per_block']
            units+=total+states;spacing+=(total+states)*400
            arm=by_arm.setdefault(row['arm'],{name:0 for name in counts})
            phases=('SELECT','OPERATE') if row['op']=='SBO' else (row['op'],)
            for op in phases:counts[op]+=total;arm[op]+=total
            counts['READ']+=states;arm['READ']+=states
    blocks=sum(s['blocks'] for s in summaries);attempts=sum(s['attempted_transactions'] for s in summaries)
    if (blocks,attempts,campaign['max_total_attempts'])!=(44,16168,18360):
        raise ValueError('accepted44-block/16168-attempt workload and18360 ceiling must remain unchanged')
    return dict(blocks=blocks,attempts=attempts,ceiling=18360,unused_attempts_not_allocated=2192,
        counts=counts,by_arm=by_arm,trial_units=units,spacing_ms=spacing,
        max_duration_ms=sum(s['max_duration_ms'] for s in summaries),rows=rows,
        sources_sha256={str(p):hashlib.sha256(p.read_bytes()).hexdigest()
            for p in [path]+[path.parent/name for name in campaign['declarations']]},
        retry_policy='none; native TCP packet repair is not a new application trial',
        heartbeat_request_us=100,holding_policy_cap_ms=40)


def wire_bytes(payload_bytes):
    """One untagged Ethernet transmission, IPv4/TCP20-byte headers, including IFG."""
    _count(payload_bytes,'payload_bytes')
    return max(64,14+20+20+payload_bytes+4)+8+12


def normal_wire_bytes(operation,transformed):
    """Both physical legs: request, one pure ACK, and complete response/carve.

    This declared-profile normal exchange does not bound loss/replay, optional
    TCP headers, fragments or an endpoint that combines ACK with its response.
    """
    if operation not in ('READ','SELECT','OPERATE') or type(transformed) is not bool:
        raise ValueError('unsupported operation/transform context')
    request=20 if operation=='READ' else 35
    response=49 if operation=='READ' else 37
    wire_request=55 if transformed and operation!='READ' else request
    wire_response=57 if transformed and operation!='READ' else response
    pieces=([28,wire_response-28] if transformed else [wire_response])
    return (wire_bytes(request)+wire_bytes(wire_request)+2*wire_bytes(0)
            +wire_bytes(wire_response)+sum(wire_bytes(size) for size in pieces))


def _layout(layout):
    if layout.get('family') not in FAMILIES:raise ValueError('unknown architecture family')
    _count(layout.get('authority_pipe'),'authority_pipe')
    if layout.get('shared_state_assumed'):
        raise ValueError('register state cannot be assumed shared across pipes')
    if (layout['family']=='bounded_resubmit' or 'resubmit_bytes' in layout) and layout.get('resubmit_bytes')!=8:
        raise ValueError('original-preserving resubmit WorkRef must remain exactly8 bytes')
    if layout['family']=='bounded_recirculation' or 'recirculation_envelope_bytes' in layout:
        _count(layout.get('recirculation_envelope_bytes'),'recirculation envelope bytes',1)
    if layout['family']=='cross_pipe':
        _count(layout.get('destination_pipe'),'destination_pipe')
        if layout['authority_pipe']==layout['destination_pipe']:
            raise ValueError('cross-pipe processing needs distinct authority/destination pipes')
    paths=layout.get('paths',{})
    for name,path in paths.items():
        if name not in PATHS:raise ValueError('unknown processing path '+name)
        if path.get('passes') is not None:_count(path['passes'],name+' passes',1)
        for transfer in path.get('internal_transfers',[]):
            if not isinstance(transfer.get('link'),str) or not transfer['link']:
                raise ValueError('each physical transfer must name its link')
            if 'envelope_bytes' in transfer or 'inner_frame_bytes' in transfer:
                if 'frame_bytes' in transfer:
                    raise ValueError('envelope cannot be added to an already serialized frame')
                _count(transfer.get('inner_frame_bytes'),'unpadded inner frame bytes including FCS',18)
                _count(transfer.get('envelope_bytes'),'serialized envelope bytes',1)
            else:_count(transfer.get('frame_bytes'),'frame_bytes',64)
            _count(transfer.get('count'),'transfer count',1)
    return paths


def _transfer_wire_bytes(transfer):
    # A prefix can consume existing minimum-frame padding. Do not add it to a
    # pre-padded frame and silently charge the wrong number of Ethernet bytes.
    frame=(max(64,transfer['inner_frame_bytes']+transfer['envelope_bytes'])
        if 'envelope_bytes' in transfer else transfer['frame_bytes'])
    return (frame+20)*transfer['count']


def _additional_packets(events,paths):
    """Additional transmissions relative to the normal exchange, never trials.

    A fragment row counts only extra transmissions; its caller must not count the
    baseline full frame a second time. Supplied counts are explicit scenarios,
    not a loss bound or an endpoint retransmission measurement.
    """
    if events is None:
        return dict(external_wire_bytes=None,internal_wire_bytes=None,
            processing_passes=None,evidence_kind='unavailable',
            reason='additional native repair and fragment frequency is unavailable')
    if not isinstance(events.get('source'),str) or not events['source']:
        raise ValueError('additional packet scenario must record its source')
    rows=events.get('rows')
    if not isinstance(rows,list):raise ValueError('additional packet rows must be explicit')
    external=internal=passes=0;internal_unknown=pass_unknown=False
    for row in rows:
        name=row.get('path')
        if name not in ('replay_request','fragment_piece'):
            raise ValueError('additional packets must describe replay or fragment work')
        count=_count(row.get('count'),'additional packet count')
        payloads=row.get('external_payload_bytes')
        if not isinstance(payloads,list) or not payloads:
            raise ValueError('additional packet transmissions require explicit payload sizes')
        external+=count*sum(wire_bytes(size) for size in payloads)
        path=paths.get(name,{})
        if path.get('passes') is None:pass_unknown=True
        else:passes+=count*path['passes']
        if 'internal_transfers' not in path:internal_unknown=True
        else:internal+=count*sum(_transfer_wire_bytes(t) for t in path['internal_transfers'])
    return dict(external_wire_bytes=external,internal_wire_bytes=None if internal_unknown else internal,
        processing_passes=None if pass_unknown else passes,evidence_kind='scenario',
        source=events['source'],rows=rows,reason='extra packet work; does not allocate application attempts')


def account(workload,layout,*,holding=None,heartbeat_frame_bytes=None,additional_packets=None):
    paths=_layout(layout)
    passes={name:paths.get(name,{}).get('passes') for name in PATHS}
    normal_wire=normal_passes=normal_internal=0;pass_unknown=False;internal_unknown=False
    for arm,counts in workload['by_arm'].items():
        for op,count in counts.items():
            transformed=arm=='CASE4'
            normal_wire+=count*normal_wire_bytes(op,transformed)
            names=('read_request' if op=='READ' else'control_request','tcp_ack',
                   'read_response' if op=='READ' else'control_response')
            for name in names:
                if passes[name] is None:pass_unknown=True
                else:normal_passes+=count*passes[name]
                if 'internal_transfers' not in paths.get(name,{}):internal_unknown=True
                normal_internal+=count*sum(_transfer_wire_bytes(t)
                    for t in paths.get(name,{}).get('internal_transfers',[]))
    hold=dict(internal_wire_bytes=None,packets_per_exchange=None,evidence_kind='unavailable',
        reason='blocker multiplicity, serialized size, achieved loop period and actual hold are unavailable')
    if holding is not None:
        frame=_count(holding.get('frame_bytes'),'holding frame_bytes',64)
        period=_positive(holding.get('loop_period_us'),'loop_period_us')
        copies=_count(holding.get('token_copies'),'token_copies',1)
        duration=_positive(holding.get('hold_ms'),'hold_ms')
        if not isinstance(holding.get('source'),str) or not holding['source']:
            raise ValueError('holding scenario must record its source')
        # An interval may start with a circulation immediately. Ceil retains that
        # phase rather than rounding a fractional loop down to zero.
        packets=copies*math.ceil(duration*1000/period)
        enabled=sum(workload['by_arm'].get('CASE4',{}).values())
        hold=dict(packets_per_exchange=packets,internal_wire_bytes=enabled*packets*(frame+20),
            nominal_packets_per_second_per_spaced_exchange=packets/0.4,evidence_kind='scenario',source=holding['source'],
            reason='assumed holding service; not measured or an admitted physical bound')
    heartbeat=dict(requested_packets_per_second=10000,requested_bits_per_second=None,
        serialized_frame_bytes=heartbeat_frame_bytes,achieved_period_us=None,evidence_kind='configured_request',
        reason='requested100 us is independent of holding; achieved service is unavailable')
    if heartbeat_frame_bytes is not None:
        _count(heartbeat_frame_bytes,'heartbeat_frame_bytes',64)
        heartbeat['requested_bits_per_second']=(heartbeat_frame_bytes+20)*8*10000
    return dict(workload=workload,layout_name=layout.get('name','unnamed'),family=layout['family'],
        path_passes=passes,normal_processing_passes=None if pass_unknown else normal_passes,
        normal_external_wire_bytes=normal_wire,normal_internal_wire_bytes=None if internal_unknown else normal_internal,
        worst_campaign_wire_bytes=None,holding=hold,heartbeat=heartbeat,
        additional_packets=_additional_packets(additional_packets,paths),
        capability_blockers=list(FAMILIES[layout['family']]),complete_fit_verified=False,
        authority=dict(pipe=layout['authority_pipe'],workref_bytes=layout.get('resubmit_bytes'),
            recirculation_envelope_bytes=layout.get('recirculation_envelope_bytes'),
            state_shared_across_pipes=False,
            handoff='explicit physical ports and owner-qualified return required' if layout['family']=='cross_pipe'
                    else'pipe-local authority; later passes return with protected WorkRef'),
        policy_off='Translation and native-sender replay continue until verified connection retirement',
        units='L1 bytes include FCS, minimum Ethernet padding,8-byte preamble/SFD and12-byte IFG',
        limitations=['normal wire total assumes one pure ACK and the declared fixed payloads',
            'native repair/fragment counts are unavailable, not zero',
            'SBO phases can burst without400 ms spacing within a pair; instantaneous rate is unavailable',
            'pass counts are supplied architecture scenarios, not compiler or target-model evidence',
            'holding, heartbeat, transform, replay and assembly compete for ports and pipeline service'])


def _safe_relative(value):
    path=Path(value)
    if path.is_absolute() or '..' in path.parts or not path.parts:
        raise ValueError('retained source/artifact path escapes evidence root')
    return path


def _phv_summary(path):
    """Count occupied source-bound PHV report containers; do not infer lifetimes."""
    report=json.loads(path.read_text())
    if report.get('schema_version')!='3.0.0':
        return dict(available=False,reason='unsupported PHV report schema')
    classes={};bits=0;slices=0;lifetime_events=0;placements=[]
    for container in report['containers']:
        key=':'.join(str(container[name]) for name in ('gress','container_type','bit_width'))
        classes[key]=classes.get(key,0)+1;bits+=container['bit_width']
        for piece in container['slices']:
            slices+=1;lifetime_events+=len(piece.get('reads',[]))+len(piece.get('writes',[]))
            locations=[event['location'] for name in ('reads','writes')
                for event in piece.get(name,[]) if 'location' in event]
            stages=[loc['stage'] for loc in locations if loc.get('type')=='mau' and 'stage' in loc]
            field=piece.get('field_slice',{})
            placements.append(dict(field=field.get('field_name'),gress=container['gress'],
                container=container['phv_number'],container_type=container['container_type'],
                container_width=container['bit_width'],
                container_bits=[piece['slice_info']['lsb'],piece['slice_info']['msb']],
                field_bits=[field['slice_info']['lsb'],field['slice_info']['msb']] if 'slice_info' in field else None,
                mau_stage_span=[min(stages),max(stages)] if stages else None,
                parser_access=any(loc.get('type')=='parser' for loc in locations),
                deparser_access=any(loc.get('type')=='deparser' for loc in locations)))
    return dict(available=True,container_classes=classes,full_container_bits=bits,
        field_slices=slices,reported_lifetime_events=lifetime_events,placements=placements,
        alignment_and_live_ranges_verified=False,
        scope='allocated report containers, not aggregate-capacity or full-composition proof')


def load_resources(evidence,*,allow_historical=False):
    """Recheck local primitive artifacts and report verified costs without full fit."""
    evidence=Path(evidence)
    spec=importlib.util.spec_from_file_location('case4_architecture_build',ARCH/'build.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    manifest=json.loads((evidence/'manifest.json').read_text())
    for group in ('source_files','artifact_sha256'):
        for name in manifest[group]:_safe_relative(name)
    verified=builder.verify_evidence(evidence)
    reports=manifest.get('resources',{}).get('report_sha256',{})
    reports_ok=bool(reports) and all((evidence/'out'/name).is_file() and
        hashlib.sha256((evidence/'out'/_safe_relative(name)).read_bytes()).hexdigest()==digest for name,digest in reports.items())
    compiler=Path(manifest['compiler_path'])
    compiler_ok=compiler.is_file() and hashlib.sha256(compiler.read_bytes()).hexdigest()==manifest.get('compiler_sha256')
    artifacts=manifest.get('artifact_sha256',{})
    required=builder.required_artifacts(evidence/'out')
    artifact_ok=required<=set(artifacts) and all((evidence/'out'/name).is_file() and
        hashlib.sha256((evidence/'out'/name).read_bytes()).hexdigest()==expected for name,expected in artifacts.items())
    log=evidence/'compile.log'
    log_ok=log.is_file() and hashlib.sha256(log.read_bytes()).hexdigest()==manifest.get('compile_log_sha256')
    contexts=builder.pipeline_contexts(evidence/'out')
    derived=builder.resource_summary(evidence/'out') if artifact_ok else None
    context_ok=derived==manifest.get('resources')
    primary=Path(manifest['source']).name
    primary_ok=manifest['source_files'].get(primary)==manifest['source_sha256']
    snapshot_ok=bool(primary_ok and manifest['exit_code']==0 and manifest['milestone']=='primitive_compiled' and
        verified['snapshots_match'] and artifact_ok and log_ok and reports_ok and compiler_ok and context_ok)
    valid=snapshot_ok and verified['source_matches']
    show=valid or (allow_historical and snapshot_ok)
    phvs={name:_phv_summary(evidence/'out'/path.parent/'logs/phv.json')
        if show and str(path.parent/'logs/phv.json') in reports else None
        for name,path in contexts.items()}
    phv=phvs['pipe'] if set(phvs)=={'pipe'} else dict(pipes=phvs,
        scope='per-pipeline allocation; no cross-pipeline shared state or fit inferred')
    return dict(evidence=str(evidence),manifest_sha256=hashlib.sha256((evidence/'manifest.json').read_bytes()).hexdigest(),
        source_sha256=manifest['source_sha256'],compiler=manifest.get('compiler'),
        milestone=manifest['milestone'],primitive_resources_verified=valid,snapshot_resources_verified=snapshot_ok,
        resources=derived if show else None,
        phv=phv if show else None,
        full_target_verified=False,verification=verified,resource_reports_verified=reports_ok,
        compiler_binary_verified=compiler_ok,context_resources_verified=context_ok,
        resource_scope='current primitive' if valid else'retained snapshot only' if show else'unverified')


def write_report(path,value):
    with Path(path).open('x',encoding='utf-8') as stream:
        json.dump(value,stream,indent=2,sort_keys=True);stream.write('\n')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path)
    parser.add_argument('--layout',type=Path,help='explicit architecture/pass scenario JSON')
    parser.add_argument('--evidence',type=Path,action='append',default=[])
    parser.add_argument('--allow-historical',action='store_true',help='report retained snapshot costs; never current fit')
    parser.add_argument('--additional-packets',type=Path,help='explicit extra repair/fragment scenario JSON')
    parser.add_argument('--holding',type=Path,help='explicit circulation scenario JSON; never a measured bound')
    parser.add_argument('--heartbeat-frame-bytes',type=int,help='serialized frame size including FCS, excluding preamble/IFG')
    args=parser.parse_args()
    layout=json.loads(args.layout.read_text()) if args.layout else dict(
        name='unqualified same-pipe contract',family='same_pipe',authority_pipe=0,paths={})
    result=account(load_workload(),layout,
        holding=json.loads(args.holding.read_text()) if args.holding else None,
        additional_packets=json.loads(args.additional_packets.read_text()) if args.additional_packets else None,
        heartbeat_frame_bytes=args.heartbeat_frame_bytes)
    result['compiler_resources']=[load_resources(path,allow_historical=args.allow_historical) for path in args.evidence]
    write_report(args.output,result)
    print('accounted44 blocks /16168 attempted exchanges; complete target qualification unavailable')

if __name__=='__main__':main()
