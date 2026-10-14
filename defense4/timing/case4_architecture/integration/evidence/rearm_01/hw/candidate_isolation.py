#!/usr/bin/env python3
"""Real old READ-token isolation: one install, three RST connections, no register resets.

This diagnostic is separate from >=20 READ precision qualification and from
external packet replay. App0 emits its one old batch at 0/2.5/5/7.5seconds;
the next connection pauses10000ms after TCP open. Complete hardware banks are
compared before/after the remaining tokens and IPG is restored before new READ.
"""
import argparse
import copy
import json
from pathlib import Path
import sys
import threading
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import candidate_series as cs
from isolation_gate import compare_quiet_generation
from token_window import (PRE_READ_GRACE_MS, PRE_READ_GRACE_NS, require_marker, window_proof, rejection_delta,
                          rejection_counts, full_run_rejections, operate_rejection_proof)
from privileged_python import authorized_python

base, ARCH=cs.base,cs.ARCH
BARRIER_DIRECTORY='/home/decps/pad58b_rearm_barrier_10s_20261012'
BARRIER_BINARY='8270132ea76123e72cb5f4d196d5726c49f5f95d2516a468fc882bed84127158'


def marker_command(path):
    script=('import json,time\nfrom pathlib import Path\np=Path(%r)\nvalue=None\nstatus="absent"\n'
            'try:\n if p.exists():\n  value=json.loads(p.read_text())\n  status="complete"\n'
            'except (OSError,ValueError):\n status="incomplete"\n'
            'print(json.dumps(dict(marker=value,marker_status=status,vision_ns=time.monotonic_ns())))') % path
    return 'python3 -c '+base.q(script)


class TokenIsolationCampaign(cs.CandidateSeriesCampaign):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,close_mode='rst',rst_grace_ms=1000,**kwargs)
        self.window={}
        self.record['token_isolation']=self.window
        self.record['isolation_source_identity']={str(path):base.sha256_file(path) for path in
            (Path(__file__),HERE/'token_window.py',HERE/'isolation_gate.py',HERE/'candidate_series.py',
             HERE/'snapshot_lifecycle.py',HERE/'candidate_campaign.py',HERE/'privileged_python.py')}
        self.active_unit=None

    def _validate_series_shape(self):
        if len(self.arms)!=1 or self.arms[0].get('name')!='combined' or \
                (self.arms[0].get('T'),self.arms[0].get('padding'))!=(1,1):
            raise ValueError('isolation requires one combined timing/padding arm')
        if self.fixtures!=['separate_ack'] or self.cfg.get('trial_mode')!='per_trial_cold' or \
                self.cfg['trials']!={'reads_per_trial':1,'trials_per_arm':1}:
            raise ValueError('isolation requires exactly one cold one-READ separateACK block')
        if self.cfg.get('evaluation')!={'purpose':'stale_source_characterization','read_precision':False}:
            raise ValueError('isolation is explicit source characterization, never precision qualification')
        traffic=self.cfg['traffic']
        if (traffic['range'],traffic['gap_ms'],traffic['start_delay_ms'],traffic.get('read_pause_ms'),
                traffic.get('run_sbo'),self.cfg['seeds']['rng_seed'])!=(8,0,0,25,True,12345):
            raise ValueError('isolation requires range8/gap0/start0/pause25/SBO/seed12345')
        if self.cfg['hosts']['vision_run_dir']!=BARRIER_DIRECTORY or \
                self.cfg['endpoint']['binary_sha256']!=BARRIER_BINARY:
            raise ValueError('isolation requires the exact pinned pre-READ barrier endpoint')

    def _copy_verify(self,where,files,directory,identity_key):
        host=self.cfg['hosts'][where]
        self.step('local','copy '+identity_key,'scp -q %s %s:%s/' %
                  (' '.join(base.q(p) for p in files),host,base.q(directory)))
        result=self.step(where,'verify '+identity_key,'sha256sum '+
                         ' '.join(base.q(directory+'/'+p.name) for p in files))
        identity={p.name:base.sha256_file(p) for p in files}
        if not self.rn.dry:
            actual={line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in result.out.splitlines() if len(line.split())==2}
            if actual!=identity:
                raise base.StepFailed('deployed isolation helper hash mismatch')
        self.record[identity_key]=identity

    def vision_identity(self):
        super().vision_identity()
        self._copy_verify('vision',[HERE/'vision_isolation.py', HERE/'token_window.py', HERE/'snapshot_lifecycle.py'],
                          self.V,'isolation_vision_identity')

    def deploy_switch(self):
        super().deploy_switch()
        self._copy_verify('switch',[HERE/'delay_read_tokens.py'],self.R+'/aux','isolation_switch_identity')

    def series_vision_cmd(self,label,master_port,reads,*args,**kwargs):
        if reads!=1 or any(kwargs.get(key) for key in ('connect_must_fail','drop','scenario','reconnect_port')):
            raise ValueError('isolation requires a protected one-READ tuple')
        args = [label, '--master-port', master_port, '--padding', 1,
                '--control-padding', self._control_padding(), '--image-len', self._image_len(), '--apply']
        if self._qualify_capture():
            args.append('--qualify-capture')
        return authorized_python(base.runner.V_RUN + '/vision_isolation.py', args)

    def _qualify_capture(self):
        builds = {arm['build'] for arm in self.cfg['arms']}
        return any(self.cfg['builds'][build].get('profile') == 'candidate61' for build in builds)

    def _image_len(self):
        builds={arm['build'] for arm in self.cfg['arms']}
        return int(self.cfg['builds'][builds.pop()].get('image_len',58))

    def _control_padding(self):
        builds={arm['build'] for arm in self.cfg['arms']}
        if len(builds)!=1:
            raise ValueError('isolation expects one build')
        return int(self.cfg['builds'][builds.pop()].get('control_padding',True))

    def run_unit(self,unit,port):
        self.active_unit=(unit,port,self.label(unit))
        try:
            return super().run_unit(unit,port)
        finally:
            self.active_unit=None

    def delay_command(self,record,restore=None):
        unit,_,_=self.active_unit
        build=unit['arm']['build']; data=self.cfg['builds'][build]
        command=('python3 %s/aux/delay_read_tokens.py --build-out %s/out_%s '
                 '--expected-bfrt-sha256 %s --switch-tools %s/%s --record %s '
                 '--ipg-ns 2500000000 --apply') % (
            self.R,self.R,build,data['hashes']['bfrt.json'],self.R,base.HW,base.q(record))
        if restore:
            command+=' --restore '+base.q(restore)
        return self.hw_env(command)

    def snapshot(self,out_remote,name,check=True,preset=None):
        result=super().snapshot(out_remote,name,check,preset)
        if name.endswith('_before'):
            remote=self.R+'/snap/'+name+'_token_delay.json'
            self.window['delay_remote']=remote
            self.step('switch','delay fresh READ app only',self.delay_command(remote))
        return result

    def quiet_snapshot(self,label,suffix):
        unit,_,_=self.active_unit
        build=unit['arm']['build']; remote=self.R+'/snap/'+label+'_quiet_'+suffix+'.json'
        self.step('switch','quiet bank/app snapshot '+suffix,
                  'python3 %s/aux/snapshot_lifecycle.py --build-out %s/out_%s --switch-tools %s/%s '
                  '--read-app --output %s' % (self.R,self.R,build,self.R,base.HW,base.q(remote)),timeout=10)
        local=Path(self.root)/('quiet_'+suffix+'.json')
        self.step('local','collect quiet bank/app snapshot '+suffix,
                  'scp -q %s:%s %s' % (self.cfg['hosts']['switch'],base.q(remote),base.q(local)),timeout=5)
        return json.loads(local.read_text())

    def monitor(self,done):
        unit,port,label=self.active_unit
        marker=self.V+'/runs/'+label+'/c2/pre_read_ready.json'
        try:
            deadline=time.monotonic()+90
            observed=None
            while not done.is_set() and time.monotonic()<deadline:
                result=self.rn.run('vision',marker_command(marker),timeout=5,label='wait for c2 marker')
                if result.rc:
                    raise ValueError('c2 readiness observer failed')
                observed=json.loads(result.out)
                if observed['marker'] is not None:
                    require_marker(observed['marker']);break
                done.wait(0.1)
            else:
                raise ValueError('c2 marker did not arrive before bounded observer deadline')
            self.window['marker_observation']=observed
            before=self.quiet_snapshot(label,'before')
            self.window['before']=before
            if before.get('read_app_after',{}).get('pkt_counter',4)>=4:
                raise ValueError('c2 became ready after all old tokens; isolation cannot qualify')
            pause_deadline=observed['marker']['pre_read_ready_ns']+PRE_READ_GRACE_NS
            while not done.is_set():
                after=self.quiet_snapshot(label,'after_%02d' % len(self.window.setdefault('polls',[])))
                self.window['polls'].append(after)
                if after.get('read_app_before',{}).get('pkt_counter')==4 and \
                        after.get('operate_app_before',{}).get('pkt_counter')==4:
                    self.window['after']=after;break
                tick=self.rn.run('vision',marker_command(marker),timeout=5,label='observe bounded pause')
                if tick.rc or json.loads(tick.out)['vision_ns']>=pause_deadline-500_000_000:
                    raise ValueError('old batch did not finish with time to restore before new READ')
                done.wait(0.1)
            else:
                raise ValueError('Vision series ended before old batch completed')
            restored=self.R+'/snap/'+label+'_token_restore.json'
            self.step('switch','restore READ IPG after exactly one old batch',
                      self.delay_command(restored,self.window['delay_remote']),timeout=10)
            tick=self.step('vision','confirm IPG restore completion on Vision clock',marker_command(marker),timeout=5)
            self.window['restored_vision_ns']=json.loads(tick.out)['vision_ns']
            if self.window['restored_vision_ns']>=pause_deadline:
                raise ValueError('IPG restore confirmation missed bounded pre-READ pause')
            for name,remote in [('delay',self.window['delay_remote']),('restore',restored)]:
                self.step('local','collect token '+name,'scp -q %s:%s %s' % (
                    self.cfg['hosts']['switch'],base.q(remote),base.q(Path(self.root)/('token_'+name+'.json'))),timeout=5)
            self.window['monitor_ok']=True
        except Exception as error:
            self.window.update(monitor_ok=False,error=str(error))
        finally:
            (Path(self.root)/'token_window_observer.json').write_text(json.dumps(self.window,indent=2)+'\n')

    def step(self,where,label,cmd,cwd=None,check=True,timeout=3600):
        if where!='vision' or ': traffic + capture on master port ' not in label or self.rn.dry:
            return super().step(where,label,cmd,cwd,check,timeout)
        done=threading.Event(); worker=threading.Thread(target=self.monitor,args=(done,),daemon=True)
        worker.start()
        try:
            return super().step(where,label,cmd,cwd,check,timeout)
        finally:
            done.set();worker.join(timeout=45)
            if worker.is_alive():
                raise base.StepFailed('isolation observer did not stop before collection/restore')

    def verdict(self,trial,rec,label,dest,v,arm,fixture):
        if self.rn.dry:
            return
        failures=[]; previous=None; connections={}
        scenario=cs._load_json(Path(dest)/'scenario.json') or {}
        expected_sources={self.V+'/'+name:base.sha256_file(path) for name,path in cs.VISION_EXTRA.items()}
        expected_sources.update({self.V+'/vision_isolation.py':base.sha256_file(HERE/'vision_isolation.py'),
                                 self.V+'/vision_run.py':base.sha256_file(ARCH/'protocol/hw_vepa/vision_run.py'),
                                 self.V+'/token_window.py':base.sha256_file(HERE/'token_window.py'),
                                 self.V+'/snapshot_lifecycle.py':base.sha256_file(HERE/'snapshot_lifecycle.py')})
        if scenario.get('source_sha256')!=expected_sources:
            failures.append('collected Vision scenario source pins differ from deployed helpers')
        shape=dict(scenario='candidate_same_tuple_isolation',applied=True,padding=1,reads=1,
                   master_port=trial['master_port'],read_pause_ms=25,close_mode='rst',close_grace_ms=1000,
                   tuple=['192.168.10.61',trial['master_port'],'192.168.10.62',20000],
                   namespaces=['ns_vepa_a','ns_vepa_b'],nic='enp59s0f0np0',switch_mutations=False)
        if any(type(scenario.get(key)) is not type(value) or scenario.get(key)!=value for key,value in shape.items()):
            failures.append('collected isolation scenario has wrong effective tuple/controls')
        for cn in ('c1','c2','c3'):
            root=Path(dest)/cn; verdict=cs._load_json(root/'verdict.json') or {}
            for name in ('wire','timing'):
                source,backup=root/(name+'.json'),root/(name+'_vision.json')
                if source.exists() and not backup.exists():backup.write_bytes(source.read_bytes())
            for script,filename in (('wire_check.py','wire.json'),('clrt_check.py','timing.json')):
                result=self.step('local','independent '+cn+' '+script,'%s %s %s %s --json %s' %
                    (base.runner.PY,base.q(ARCH/'protocol/hw_vepa'/script),base.q(root/'out.pcap'),
                     base.q(root/'in.pcap'),base.q(root/filename)),check=False)
                self.save(str(root),script+'.log',result)
                if result.rc:failures.append(cn+': '+script+' failed rc'+str(result.rc))
            ev=self._connection_evidence(dest,cn)
            cfail=cs.checks.application_checks(self.cfg['expectations'],1,1,ev,True)
            fresh=None
            try:
                fresh=cs.freshness_gate(cs.wc.parse(root/'out.pcap')[0],cs.wc.parse(root/'in.pcap')[0],
                                        trial['master_port'],previous);previous=fresh
            except (OSError,ValueError,KeyError,IndexError) as error:
                cfail.append('fresh mapping: '+str(error))
            if verdict.get('ok') is not True:
                cfail.append('Vision application/RST/hook verdict failed')
            import vision_candidate as vc
            cfail.extend(vc.evaluate(root,trial['master_port'],'rst',1,
                                     cs._load_json(root/'result.json') or {},rst_grace_ms=1000,
                                     reads=1,pre_read_grace_ms=PRE_READ_GRACE_MS if cn=='c2' else 0,
                                     control_padding=self._control_padding(),image_len=self._image_len()))
            outstation = ev.get('outstation') or {}
            cfail.extend(self.validate_standards_file(
                str(root), trial, arm,
                {'out': {'path': str(root/'out.pcap')}, 'in': {'path': str(root/'in.pcap')}},
                self.standards_observed(
                    ev, list(cfail), transport_ok=(not any(f.endswith('wire_check.py failed rc1') for f in cfail)),
                    select_ok=outstation.get('select_real') == 1,
                    operate_ok=outstation.get('operate_real') == 1,
                    aggregate_ok=not cfail, precision_required=False,
                    precision_reason='isolation: stale_source_characterization, never precision qualification',
                    checker_result=self.run_standards_checker(str(root), trial, arm, cn)),
                connection_id=cn))
            connections[cn]=dict(ok=not cfail,failures=cfail,fresh_mapping=fresh)
            failures.extend(cn+': '+failure for failure in cfail)
        if v.rc or scenario.get('ok') is not True:
            failures.append('Vision isolation series failed')
        bank,window=dict(ok=False,failures=['missing quiet snapshots']),dict(ok=False,failures=['missing token window'])
        if self.window.get('monitor_ok') is True and connections['c2']['fresh_mapping']:
            marker=self.window['marker_observation']['marker']
            master=cs._load_json(Path(dest)/'c2/master.json') or {}
            bank=compare_quiet_generation(self.window['before'],self.window['after'],2,
                                           connections['c2']['fresh_mapping']['server_isn'])
            window=window_proof(marker,master,self.window['before'],self.window['after'],self.window['restored_vision_ns'])
        failures.extend('banks: '+f for f in bank['failures'])
        failures.extend('window: '+f for f in window['failures'])
        rejection_delta_value=None
        quiet_rejections=None
        if window.get('ok'):
            try:
                quiet_rejections=rejection_counts(self.window['before'],self.window['after'])
                rejection_delta_value=rejection_delta(self.window['before'],self.window['after'])
                if rejection_delta_value!=window['old_packets_during_pause']:
                    failures.append('old READ token rejections do not match generated packets during pause')
            except (KeyError,TypeError,ValueError) as error:
                failures.append('missing old-token rejection hardware evidence: '+str(error))
        snapdir=Path(dest)/'snapshots'
        snapshots=cs.checks.load_evidence_files(before=str(snapdir/(label+'_before.json')),
                                                after=str(snapdir/(label+'_after.json')))
        # Qualification stays strict0. This diagnostic permits only the exact
        # independently proven prefix while both old batches drain before c2 READ.
        diagnostic_cfg=copy.deepcopy(self.cfg)
        sobs={}
        try:
            prefix=full_run_rejections(snapshots['before'],snapshots['after'],self.window['after'])
            sobs['operate_cohort']=operate_rejection_proof(self.window['before'],self.window['after'],snapshots['before'])
            diagnostic_cfg['builds'][arm['build']]['max_token_stale']=prefix['strict_stale_total']
            sobs.update(prefix)
        except (KeyError,TypeError,ValueError) as error:
            failures.append('missing full-run rejection evidence: '+str(error))
        lifecycle=cs._load_json(snapdir/(label+'_after_lifecycle.json')) or {}
        sfail,switch_observed=cs.series_switch_gate(diagnostic_cfg,arm,1,snapshots,lifecycle)
        sobs.update(switch_observed)
        failures.extend('switch: '+failure for failure in sfail)
        lfail,lobs=cs.lifecycle_gate(lifecycle,'rst')
        failures.extend('lifecycle: '+failure for failure in lfail)
        if self.window.get('error'):
            failures.append(self.window['error'])
        trial.update(ok=not failures,failures=failures,scenario=dict(policy='real_old_token_isolation',connections=connections),
                     observed=dict(bank_isolation=bank,old_token_window=window,old_rejection_delta=rejection_delta_value,
                                   quiet_rejections=quiet_rejections,
                                   switch=sobs,lifecycle=lobs,precision_qualified=False))
        (Path(dest)/'trial.json').write_text(json.dumps(trial,indent=2)+'\n')
        if failures:
            raise base.StepFailed(label+' failed: '+'; '.join(failures))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('plan','run','validate'))
    parser.add_argument('--config',required=True);parser.add_argument('--run-id',required=True)
    parser.add_argument('--apply',action='store_true')
    args=parser.parse_args()
    cfg=base.load_config(args.config)
    if args.mode=='run' and not args.apply:
        parser.error('run requires --apply')
    runner=base.ShellRunner(cfg['hosts']) if args.mode=='run' else base.DryRunner()
    run=TokenIsolationCampaign(cfg,runner,args.run_id,arms=['combined'],fixtures=['separate_ack'],config_path=args.config)
    if args.mode=='validate':
        errors=base.check_bindings(cfg,run.arms)
        if errors:parser.error('; '.join(errors))
        print('isolated token diagnostic configuration OK');return 0
    return run.execute()


if __name__=='__main__':
    raise SystemExit(main())
