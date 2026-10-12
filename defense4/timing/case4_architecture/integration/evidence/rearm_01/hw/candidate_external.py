#!/usr/bin/env python3
"""Replay exact retained old native TCP frames while the current lifetime is quiet.

One guarded candidate install/rollback; three actual RST connections. This
diagnostic changes no connection, epoch, allocator, or pktgen register. Raw
old frames enter only the software endpoint's fixed external NIC. The Vision
helper retains raw captures and strictly filters declared injected frames from
the OUT comparison only; all returned traffic remains in the independent gate.
"""
import argparse
import json
from pathlib import Path
import sys
import shutil
import tempfile
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import candidate_isolation as ci
import candidate_series as cs
import replay_old_packets as replay
from isolation_gate import compare_quiet_generation
from privileged_python import authorized_python
from token_window import PRE_READ_GRACE_MS, PRE_READ_GRACE_NS, require_marker

base,ARCH=cs.base,cs.ARCH


class ExternalIsolationCampaign(ci.TokenIsolationCampaign):
    def __init__(self,*args,old_graceful,old_rst,**kwargs):
        super().__init__(*args,**kwargs)
        if self.ports()!=[59400]:
            raise ValueError('external archives require the fixed software source port59400')
        pools={}
        for kind,value in (('graceful',old_graceful),('rst',old_rst)):
            paths=[value] if isinstance(value,(str,Path)) else list(value)
            if not paths or len({Path(path).resolve() for path in paths})!=len(paths):
                raise ValueError('old '+kind+' archives must be one or more distinct directories')
            pools[kind]=[Path(path).resolve() for path in paths]
        self.old_pools=pools
        self.old_archives={kind:pool[0] for kind,pool in pools.items()}
        self.record.pop('token_isolation')
        self.record['external_packet_isolation']=self.window
        self.record['external_source_identity']={str(path):base.sha256_file(path) for path in
            (Path(__file__),HERE/'vision_replay.py',HERE/'replay_old_packets.py',HERE/'privileged_python.py')}
        self.record['old_capture_identity']={}
        for kind,pool in self.old_pools.items():
            self.record['old_capture_identity'][kind]={}
            for root in pool:
                manifest,_=replay.collect([root/'out.pcap',root/'in.pcap'],59400,dedupe=True)
                needed='FIN' if kind=='graceful' else 'RST'
                if not manifest['counts'][needed] or not any(p['class']=='READ_RESPONSE' and p['payload_bytes']==49
                                                            for p in manifest['packets']):
                    raise ValueError('old archive must contain native49 and '+needed)
                self.record['old_capture_identity'][kind].update({str(root/name):base.sha256_file(root/name)
                                                                  for name in ('out.pcap','in.pcap')})

    def deploy_switch(self):
        cs.CandidateSeriesCampaign.deploy_switch(self)

    def vision_identity(self):
        cs.CandidateSeriesCampaign.vision_identity(self)
        self._copy_verify('vision',[HERE/'vision_replay.py',HERE/'vision_isolation.py',HERE/'replay_old_packets.py',HERE/'token_window.py',HERE/'snapshot_lifecycle.py'],self.V,
                          'external_vision_identity')
        for kind,pool in self.old_pools.items():
          for index,root in enumerate(pool):
            remote=self.remote_archive(kind,index)
            self.step('vision','create fresh old '+kind+' archive directory',
                      'test ! -e %s && mkdir -p %s' % (base.q(remote),base.q(remote)))
            self.step('local','copy pinned old '+kind+' captures','scp -q %s %s %s:%s/' %
                (base.q(root/'out.pcap'),base.q(root/'in.pcap'),self.cfg['hosts']['vision'],base.q(remote)))
            result=self.step('vision','verify old '+kind+' capture pins','sha256sum '+
                ' '.join(base.q(remote+'/'+name) for name in ('out.pcap','in.pcap')))
            if not self.rn.dry:
                actual={line.split()[1].rsplit('/',1)[-1]:line.split()[0] for line in result.out.splitlines()
                        if len(line.split())==2}
                if actual!={name:base.sha256_file(root/name) for name in ('out.pcap','in.pcap')}:
                    raise base.StepFailed('old external capture hash mismatch')

    def remote_archive(self,kind,index):
        return self.V+'/old_replay/'+self.run_id+'/'+kind+'_'+str(index)

    def choose_archive(self,kind,fresh,port,isns):
        # The kernel picks the new ISNs after the archives are fixed, and the unchanged
        # replay guard needs each old frontier safely behind them (a coin flip per
        # direction). Take the first retained archive that passes; never relax the guard.
        for index,root in enumerate(self.old_pools[kind]):
            old,_=replay.collect([root/'out.pcap',root/'in.pcap'],port,dedupe=True)
            try:
                replay.fresh_guard(old,[fresh],port,isns['client'],isns['server'])
            except ValueError as error:
                if 'ambiguous old sequence range' not in str(error):raise
                continue
            self.old_archives[kind]=root
            return index
        raise ValueError('no retained old '+kind+' archive is unambiguous against the new ISNs')

    def series_vision_cmd(self,label,port,reads,*args,**kwargs):
        if port!=59400 or reads!=1:
            raise ValueError('external replay requires source59400 and one READ per incarnation')
        return authorized_python(base.runner.V_RUN+'/vision_replay.py',[label,'--master-port',port,'--padding',1,'--apply'])

    def snapshot(self,out_remote,name,check=True,preset=None):
        return cs.CandidateSeriesCampaign.snapshot(self,out_remote,name,check,preset)

    def monitor(self,done):
        _,port,label=self.active_unit
        dest=self.V+'/runs/'+label+'/c2'
        marker=dest+'/pre_read_ready.json'
        try:
            deadline=time.monotonic()+90
            while not done.is_set() and time.monotonic()<deadline:
                result=self.rn.run('vision',ci.marker_command(marker),timeout=5,label='wait for current established TCP')
                if result.rc:raise ValueError('current readiness observer failed')
                observed=json.loads(result.out)
                if observed['marker'] is not None:
                    require_marker(observed['marker']);break
                done.wait(0.1)
            else:raise ValueError('current TCP did not publish readiness within90seconds')
            self.window['marker_observation']=observed
            before=self.quiet_snapshot(label,'before')
            self.window['before']=before
            fresh=Path(self.root)/'current_handshake.pcap'
            self.step('local','collect current unchanged handshake',
                'scp -q %s:%s %s' % (self.cfg['hosts']['vision'],base.q(dest+'/in.pcap'),base.q(fresh)),timeout=5)
            current,_=replay.collect([fresh],port,dedupe=True)
            self.window['current_isns']=current['isns']
            chosen={kind:self.choose_archive(kind,fresh,port,current['isns']) for kind in self.old_pools}
            self.window['chosen_archives']={kind:str(self.old_archives[kind]) for kind in chosen}
            for kind,index in chosen.items():
                remote=self.remote_archive(kind,index)
                command=authorized_python(self.V+'/replay_old_packets.py',
                    [remote+'/out.pcap',remote+'/in.pcap','--master-port',port,'--dedupe',
                     '--interface','enp59s0f0np0','--new-pcap',dest+'/in.pcap',
                     '--new-client-isn',current['isns']['client'],'--new-server-isn',current['isns']['server'],
                     '--json',dest+'/replay_'+kind+'.json','--apply'])
                result=self.step('vision','replay exact old '+kind+' frames',command,timeout=5)
                self.save(self.root,'replay_'+kind+'_command.log',result)
            after=self.quiet_snapshot(label,'after')
            self.window['after']=after
            tick=self.step('vision','confirm replay completed during pre-READ pause',ci.marker_command(marker),timeout=5)
            self.window['completed_vision_ns']=json.loads(tick.out)['vision_ns']
            if self.window['completed_vision_ns']>=observed['marker']['pre_read_ready_ns']+PRE_READ_GRACE_NS:
                raise ValueError('old packet replay/snapshot exceeded bounded quiet window')
            self.window['monitor_ok']=True
        except Exception as error:
            self.window.update(monitor_ok=False,error=str(error))
        finally:
            (Path(self.root)/'external_window_observer.json').write_text(json.dumps(self.window,indent=2)+'\n')

    def verdict(self,trial,rec,label,dest,v,arm,fixture):
        if self.rn.dry:return
        import vision_candidate as vc
        failures=[];previous=None;connections={}
        scenario=cs._load_json(Path(dest)/'scenario.json') or {}
        expected={self.V+'/'+name:base.sha256_file(path) for name,path in cs.VISION_EXTRA.items()}
        expected.update({self.V+'/vision_run.py':base.sha256_file(ARCH/'protocol/hw_vepa/vision_run.py'),
                         self.V+'/vision_isolation.py':base.sha256_file(HERE/'vision_isolation.py'),
                         self.V+'/vision_replay.py':base.sha256_file(HERE/'vision_replay.py'),
                         self.V+'/replay_old_packets.py':base.sha256_file(HERE/'replay_old_packets.py'),
                         self.V+'/token_window.py':base.sha256_file(HERE/'token_window.py'),
                         self.V+'/snapshot_lifecycle.py':base.sha256_file(HERE/'snapshot_lifecycle.py')})
        if scenario.get('source_sha256')!=expected:failures.append('Vision replay source pins differ')
        if v.rc or scenario.get('ok') is not True:failures.append('Vision replay series failed')
        shape=dict(scenario='candidate_same_tuple_replay',applied=True,padding=1,reads=1,
                   master_port=59400,read_pause_ms=25,close_mode='rst',close_grace_ms=1000,
                   tuple=['192.168.10.61',59400,'192.168.10.62',20000],
                   namespaces=['ns_vepa_a','ns_vepa_b'],nic='enp59s0f0np0',switch_mutations=False)
        if any(type(scenario.get(key)) is not type(value) or scenario.get(key)!=value for key,value in shape.items()):
            failures.append('collected replay scenario has wrong effective tuple/controls')
        try:
            self.verify_current_derivation(Path(dest)/'c2')
        except (OSError,ValueError,KeyError,TypeError) as error:
            failures.append('independent replay filtering: '+str(error))
        for cn in ('c1','c2','c3'):
            raw=Path(dest)/cn;analysis=raw/'current' if cn=='c2' else raw
            for name in ('wire','timing'):
                source,backup=analysis/(name+'.json'),analysis/(name+'_vision.json')
                if source.exists() and not backup.exists():backup.write_bytes(source.read_bytes())
            for script,filename in (('wire_check.py','wire.json'),('clrt_check.py','timing.json')):
                result=self.step('local','independent '+cn+' '+script,'%s %s %s %s --json %s' %
                    (base.runner.PY,base.q(ARCH/'protocol/hw_vepa'/script),base.q(analysis/'out.pcap'),
                     base.q(analysis/'in.pcap'),base.q(analysis/filename)),check=False)
                self.save(str(analysis),script+'.log',result)
                if result.rc:failures.append(cn+': '+script+' failed rc'+str(result.rc))
            cfail=vc.evaluate(analysis,59400,'rst',1,cs._load_json(raw/'result.json') or {},
                              rst_grace_ms=1000,reads=1,pre_read_grace_ms=PRE_READ_GRACE_MS if cn=='c2' else 0)
            fresh=None
            try:
                fresh=cs.freshness_gate(cs.wc.parse(analysis/'out.pcap')[0],cs.wc.parse(analysis/'in.pcap')[0],59400,previous)
                previous=fresh
            except (OSError,ValueError,KeyError,IndexError) as error:cfail.append('fresh mapping: '+str(error))
            if (cs._load_json(raw/'verdict.json') or {}).get('ok') is not True:cfail.append('strict Vision replay leg verdict failed')
            connections[cn]=dict(ok=not cfail,failures=cfail,fresh_mapping=fresh)
            failures.extend(cn+': '+failure for failure in cfail)
        isolation=dict(ok=False,failures=['missing established quiet window'])
        if self.window.get('monitor_ok'):
            isolation=compare_quiet_generation(self.window['before'],self.window['after'],2,
                                               self.window['current_isns']['server'])
            master=cs._load_json(Path(dest)/'c2/master.json') or {}
            issued=master.get('first_read_issued_ns')
            if type(issued) is not int or issued<=self.window['completed_vision_ns']:
                failures.append('new READ was issued before old replay isolation completed')
        failures.extend('isolation: '+failure for failure in isolation['failures'])
        if self.window.get('error'):failures.append(self.window['error'])
        snap=Path(dest)/'snapshots'
        snapshots=cs.checks.load_evidence_files(before=str(snap/(label+'_before.json')),after=str(snap/(label+'_after.json')))
        lifecycle=cs._load_json(snap/(label+'_after_lifecycle.json')) or {}
        sfail,sobs=cs.series_switch_gate(self.cfg,arm,1,snapshots,lifecycle)
        failures.extend('switch: '+failure for failure in sfail)
        lfail,lobs=cs.lifecycle_gate(lifecycle,'rst')
        failures.extend('lifecycle: '+failure for failure in lfail)
        trial.update(ok=not failures,failures=failures,scenario=dict(policy='exact_old_external_replay',connections=connections),
                     observed=dict(bank_isolation=isolation,switch=sobs,lifecycle=lobs,precision_qualified=False))
        (Path(dest)/'trial.json').write_text(json.dumps(trial,indent=2)+'\n')
        if failures:raise base.StepFailed(label+' failed: '+'; '.join(failures))

    @staticmethod
    def verify_current_derivation(raw):
        import vision_replay as vr
        with tempfile.TemporaryDirectory(prefix='rearm_replay_verify_') as temporary:
            copied=Path(temporary)/'raw'
            shutil.copytree(raw,copied,ignore=shutil.ignore_patterns('current'))
            independently=vr.derive_current(copied)
            expected=independently['derived_hashes']
            actual={name:base.sha256_file(raw/'current'/name) for name in expected}
            if actual!=expected:
                raise ValueError('derived current bytes differ from independently checked raw captures')
            retained=cs._load_json(raw/'current/filter.json') or {}
            for key in ('removed','removed_sha_counts','classes','new_isns','old_isns','interval',
                        'manifest_hashes','raw_hashes','derived_hashes'):
                if retained.get(key)!=independently.get(key):
                    raise ValueError('retained replay filtering proof differs: '+key)
            return independently


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode',choices=('plan','run'));parser.add_argument('--config',required=True)
    parser.add_argument('--run-id',required=True);parser.add_argument('--old-graceful',type=Path,nargs='+',required=True)
    parser.add_argument('--old-rst',type=Path,nargs='+',required=True);parser.add_argument('--apply',action='store_true')
    args=parser.parse_args();cfg=base.load_config(args.config)
    if args.mode=='run' and not args.apply:parser.error('run requires --apply')
    runner=base.ShellRunner(cfg['hosts']) if args.mode=='run' else base.DryRunner()
    run=ExternalIsolationCampaign(cfg,runner,args.run_id,arms=['combined'],fixtures=['separate_ack'],config_path=args.config,
                                 old_graceful=args.old_graceful,old_rst=args.old_rst)
    return run.execute()


if __name__=='__main__':raise SystemExit(main())
