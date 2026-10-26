#!/usr/bin/env python3
"""Offline-only audit of completed retained c68 D20 recovery evidence."""
import argparse, collections, hashlib, importlib.util, json, sys, time
from pathlib import Path
sys.dont_write_bytecode = True
REPO = Path('/home/philip/Projects/DNP3')
ARCH = REPO / 'defense4/timing/case4_architecture'
RC = ARCH / 'integration/core/response_only_rearm/stage_experiments/read_complete_01'
HW = ARCH / 'integration/evidence/rearm_01/hw'
sys.path[:0] = [str(RC/'analysis'), str(ARCH/'protocol/hw_vepa')]
import replay_physical, relay_loss
sys.path.insert(0,str(REPO/'defense4/timing/active_harness'))
import dnp3_codec
sp=importlib.util.spec_from_file_location('restore_verify_readonly', HW/'restore_verify.py')
rv=importlib.util.module_from_spec(sp);sp.loader.exec_module(rv)
def read(p):return json.loads(Path(p).read_text())
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def audit(campaign, suffix):
 b=RC/'evidence/hw_blocks'/(campaign+'_'+suffix)
 c=RC/'evidence/hw_campaigns'/campaign
 errors=[]
 def check(value,message):
  if not value:errors.append(message)
 state=read(c/'state.json'); report=read(c/'campaign_report.json')
 check(state['phase']=='complete' and report['result']=='COMPLETE' and report['phase']=='complete','supervised campaign not COMPLETE')
 step=state['steps'][b.name]
 check(step['status']=='completed' and step['rc']==0,'supervised block did not complete rc=0')
 check(not report['failed'] and not report['unexecuted'],'supervisor reports failed/unexecuted blocks')
 run=read(b/'campaign_run.json');frozen=read(b/'freeze_check.json');cfg=read(REPO/frozen['config']); freeze=read(REPO/frozen['freeze'])
 check(run['ok'] is True and run['gate_ok'] is True and run['failure'] is None,'campaign/gate verdict is not success')
 check(frozen['ok'] is True and not frozen['changed'] and not frozen['missing'] and frozen['qualifies'] is True,'pre-run freeze verdict failed')
 source=REPO/freeze['build']/'response_only.p4'
 source_hash=sha(source)
 check(source_hash==frozen['source_sha256']==freeze['source_sha256']==cfg['ctl_timing_identity']['source_sha256']=='825b7e6da3c24dd1705d43f1d921dbd2184a99fe47f75f4de1d2d372e160b289','candidate source identity differs')
 freeze_errors=[]
 for rel,entry in freeze['files'].items():
  p=REPO/rel
  if not p.is_file() or sha(p)!=entry['sha256']:freeze_errors.append(rel)
 check(not freeze_errors,'current frozen files missing or changed: '+repr(freeze_errors))
 replay=replay_physical.replay_block(b,'c68')
 replay_path=Path('/tmp')/(campaign+'_packet_replay.json');replay_path.write_text(json.dumps(replay,indent=2)+'\n')
 check(replay['completed'] and replay['recorded_run_ok'] and replay['recorded_gate_ok'],'packet replay missing completed successful block')
 for t in replay['trials']:
  for connection in t['connections']:
   check(connection['report_matches_retained'] and connection['wire_ok'] and connection['report_schema']=='sel751-wire-v2','packet checker mismatch or failed '+t['label'])
 arguments=cfg['evaluation']['campaign_block']['arguments'];lossname=arguments[arguments.index('--loss')+1]
 plans=cfg['loss']['presets'][lossname]
 trials=run['arms'][0]['trials']
 check(len(trials)==len(plans)==7,'planned or actual trial count is not seven')
 trial_summaries=[]
 for i,(t,planned_loss) in enumerate(zip(trials,plans)):
  td=b/'physical_relay'/run['arms'][0]['arm']/t['label']; trial=read(td/'trial.json'); result=read(td/'result.json'); master=read(td/'master.json');wire=read(td/'relay_wire.json')
  check(trial==t,'trial and campaign record differ '+td.name)
  loss=trial['loss'];expected_spec=relay_loss.parse_drop('%s:%d:%s'%(planned_loss['class'],planned_loss['n'],planned_loss['target']), cfg['traffic']['read_schedule'],1)
  check(loss['spec']==expected_spec,'loss spec differs from frozen plan '+td.name)
  check((loss['class'],loss['n'])==(planned_loss['class'],planned_loss['n']),'loss class/ordinal mismatch '+td.name)
  check(result['loss']==loss,'result loss and trial loss differ '+td.name)
  check(loss['exact'] is True and loss['dropped_packets']==1 and loss['earlier_matches']==0,'loss lacks exact single-drop proof '+td.name)
  check(loss['removed'] is True and loss['state_restored'] is True and not loss['remove_errors'] and loss['state_before']==loss['state_after'],'loss rule state not restored '+td.name)
  check(loss['restoration']['restored'] is True and not loss['restoration']['errors'],'loss ownership restoration failed '+td.name)
  check(len(loss['kernel_log'])==1 and loss['log_rc']==0,'kernel log proof missing '+td.name)
  counter={r['target']:r for r in loss['counters']}
  check(set(counter)=={'LOG','DROP'} and all(r['pkts']==1 and r['bytes']==expected_spec['ip_len'] for r in counter.values()),'LOG/DROP counters not exactly one expected packet '+td.name)
  target_errors=relay_loss.target_checks(loss,wire,trial['master_port'])
  check(not target_errors,'wrong target '+td.name+': '+repr(target_errors))
  identity=loss['identity'];spec=loss['spec'];packet=loss['kernel_packet'];row=[r for r in wire['exchanges'] if r['operation']==spec['operation']][spec['index']]
  frontier=row['request' if spec['frontier'] in ('request','request_ack') else 'response'];key='ACK' if spec['frontier'].endswith('_ack') else 'SEQ';value=frontier['sequence_end' if key=='ACK' else 'sequence_start']
  check(identity['key']==key and identity['value']==packet[key]==value and identity['operation']==spec['operation'] and identity['index']==spec['index'] and identity['armed'] and identity['error'] is None,'independent intended TCP frontier mismatch '+td.name)
  expected_counts={'READ':cfg['trials']['reads_per_trial'],'SELECT':1,'OPERATE':1}
  records=master['records'];counts=dict(collections.Counter(r['operation'] for r in records));success=dict(collections.Counter(r['operation'] for r in records if r['outcome']=='OK' and r['ok'] is True))
  check(master['ok'] is True and master['planned']==master['counts']==counts==success==expected_counts,'master planned/success counts differ '+td.name)
  check(all(not r['problems'] and r['remaining_ms_at_completion']>=0 and r['elapsed_ms']<=r['budget_ms'] for r in records),'application record failed or exceeded budget '+td.name)
  check(all(r.get('workload')==('mixed' if cfg['traffic']['read_schedule']=='mixed' else 'integrity') for r in records if r['operation']=='READ'),'READ workload differs from plan '+td.name)
  crobs=[]
  for r in records:
   raw=bytes.fromhex(r['response_wire_hex']);frames=[]
   while raw:
    frame,rest=dnp3_codec.parse_frame(raw)
    check(frame is not None and rest!=raw,'incomplete raw DNP3 frame '+td.name)
    if frame is None:break
    frames.append(frame);raw=rest
   apps=dnp3_codec.reassemble_application(frames)
   check(len(apps)==1 and apps[0].hex()==r['response_app_hex'],'raw response application differs from retained '+td.name)
   parsed=dnp3_codec.parse_application_response(apps[0])
   validation=dnp3_codec.validate_response(parsed,expect_seq=r['app_seq'],expect_function=r['function'],expect_points=[1,3] if r['operation']!='READ' else None,require_success=r['operation']!='READ',expect_read_workload=r.get('workload'))
   check(not validation and parsed.objects==r['response_objects'],'independent raw application decode failed '+td.name+': '+repr(validation))
   if r['operation']=='READ':continue
   objects=r['response_objects'];pts=[p for o in objects if (o['group'],o['variation'])==(12,1) for p in o['points']]
   check(r['points']==[[1,'SUCCESS'],[3,'SUCCESS']] and [p['index'] for p in pts]==[1,3] and all(p['status']==0 and p['code']==1 and p['count']==1 and p['on_ms']==200 and p['off_ms']==0 for p in pts),'two-point CROB response status mismatch '+td.name+' '+r['operation'])
   crobs.append({'operation':r['operation'],'points':r['points'],'statuses':{str(p['index']):p['status'] for p in pts}})
  check(trial['ok'] and not trial['failures'] and result['ok'] and result['master_rc']==0 and wire['ok'] and not wire['failures'],'trial/application/wire verdict failed '+td.name)
  check(all(result['tcpdump'][d]['dropped_kernel']==0 for d in ['in','out']),'capture reported kernel drops '+td.name)
  trial_summaries.append({'label':td.name,'directory':str(td),'master_port':trial['master_port'],'frozen_target':planned_loss,'expected_spec':expected_spec,'target_frontier':{'key':key,'value':value},'kernel_packet':packet,'drop_packets':loss['dropped_packets'],'counter_proof':loss['counters'],'target_check_failures':target_errors,'planned_counts':expected_counts,'successful_counts':success,'recorded_trial_ok':trial['ok'],'recorded_trial_failures':trial['failures'],'crob_responses':crobs,'exchanges':len(wire['exchanges']),'wire_schema':wire['schema'],'all_raw_application_responses_independently_decoded':True,'max_application_elapsed_ms':max(r['elapsed_ms'] for r in records)})
 manifest=read(b/'artifact_manifest.json');manifest_errors=[]
 for rel,identity in manifest['files'].items():
  p=b/rel
  if not p.is_file() or p.stat().st_size!=identity['size'] or sha(p)!=identity['sha256']:manifest_errors.append(rel)
 check(not manifest_errors,'artifact manifest bytes differ '+repr(manifest_errors))
 check(sha(b/'artifact_manifest.json')==step['artifact_manifest']['sha256'],'supervisor artifact manifest digest differs')
 restored=read(b/'restore_verify.json');rchecks=restored['checks'];pre=next(b.glob('*_prerun.json'));post=b/'restore_verify_postrun.json'
 snapshot_errors, compared=rv.compare_snapshots(read(pre),read(post))
 check(restored['ok'] is True and not restored['failures'],'independent restoration verdict failed')
 check(not snapshot_errors and compared==rchecks['snapshot']['tables_compared']==399,'retained snapshot comparison failed '+repr(snapshot_errors))
 check(rchecks['program']['program']==cfg['production']['program']=='case4_response_path','production program differs')
 required=set(rv.REQUIRED_STEPS)|{'reinstall the relay slot'}
 check({s['step'] for s in run['restore']}==required and all(s['ok'] and s['rc']==0 for s in run['restore']),'runner restoration steps failed/missing')
 check(rchecks['runner_restore']['steps']==run['restore'] and not rchecks['runner_restore']['missing'],'independent restore runner steps mismatch')
 check(rchecks['vision_state']['rc']==0 and rchecks['vision_state']['state']==Path(rchecks['vision_state']['baseline']).read_text(),'Vision state baseline mismatch')
 offload=rchecks['vision_receive_offloads'];base=read(b/'vision_offload_baseline.json')
 check(sha(b/'vision_offload_baseline.json')==run['vision_offload_baseline_sha256'],'pre-capture offload baseline identity mismatch')
 check(offload['rc']==0 and not rv.offload_failures(offload['ethtool'],base),'Vision receive-offload restoration failed')
 firewall=rchecks['vision_physical_loss_restoration']
 check(firewall['rc']==0 and firewall['actual']['pending_owner'] is False and firewall['actual']['chains']==firewall['baseline']==base['iptables'] and not firewall['failures'],'Vision physical loss rules or ownership not restored')
 rx=rchecks['vision_rx_coalescing'];cpu=rchecks['vision_cpu_latency']
 check(rx['rc']==0 and not rv.rx_coalesce_failures(rx['ethtool'],read(rx['baseline'])),'Vision RX coalescing differs from baseline')
 check(cpu['rc']==0 and not rv.cpu_latency_failures(cpu['probe'],read(cpu['baseline'])),'Vision CPU latency differs from baseline')
 check(rchecks['ping']['rc']==0,'retained restoration connectivity ping failed')
 check(sha(b/'restore_verify.json')==step['restoration']['sha256'] and step['restoration']['ok'] is True,'supervisor restoration file identity differs')
 result={'schema':'c68-d20-recovery-readonly-independent-audit-v1','campaign':campaign,'run_root':str(b),'campaign_root':str(c),'verified_at_unix':time.time(),'ok':not errors,'failures':errors,'campaign_result':report['result'],'block_rc':step['rc'],'candidate_source':{'path':str(source),'sha256':source_hash,'unchanged':source_hash==frozen['source_sha256']},'frozen_files':{'path':str(REPO/frozen['freeze']),'verified':len(freeze['files']),'failures':freeze_errors},'config':{'path':str(REPO/frozen['config']),'sha256':sha(REPO/frozen['config'])},'trials':trial_summaries,'totals':{'planned_trials':len(plans),'verified_trials':len(trial_summaries),'single_drops':sum(t['drop_packets'] for t in trial_summaries),'READ':sum(t['successful_counts'].get('READ',0) for t in trial_summaries),'SELECT':sum(t['successful_counts'].get('SELECT',0) for t in trial_summaries),'OPERATE':sum(t['successful_counts'].get('OPERATE',0) for t in trial_summaries),'exchanges':sum(t['exchanges'] for t in trial_summaries)},'packet_replay':{'path':str(replay_path),'report_matches_retained':True,'checker_revision':'working-tree','schema':'sel751-wire-v2','sha256':sha(replay_path)},'artifact_manifest':{'path':str(b/'artifact_manifest.json'),'sha256':sha(b/'artifact_manifest.json'),'files_verified':len(manifest['files']),'failures':manifest_errors},'restoration':{'path':str(b/'restore_verify.json'),'sha256':sha(b/'restore_verify.json'),'independent_record_ok':restored['ok'],'snapshot_pre':str(pre),'snapshot_post':str(post),'tables_independently_compared':compared,'snapshot_errors':snapshot_errors,'loss_ownership_restored':firewall['actual']['pending_owner'] is False},'claim_boundary':('All requested new c68 D20 recovery checks pass. ' if not errors else 'The new c68 D20 recovery block does not satisfy all requested pass conditions; failures are explicitly recorded. ')+'Observed at the master host only. A new c68 result does not alone prove the old c67 device-side defect fixed, switch residence, OPERATE J, independent packet-boundary calibration, or CLRT precision. Historical failures remain retained; no old evidence was modified.','side_effects':'Offline file reads plus outputs under /tmp only; no remote commands, network traffic, source/evidence mutations, hardware/model runs, commits, or child agents.'}
 out=Path('/tmp')/(campaign+'_independent_recovery_audit.json');out.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps({'out':str(out),'ok':result['ok'],'failures':errors,'totals':result['totals'],'artifact_files':len(manifest['files']),'snapshot_tables':compared}))
 return 0 if not errors else 1
if __name__=='__main__':
 ap=argparse.ArgumentParser();ap.add_argument('--campaign',required=True);ap.add_argument('--suffix',required=True);a=ap.parse_args();raise SystemExit(audit(a.campaign,a.suffix))
