#!/usr/bin/env python3
"""Real old READ-token isolation: one install, three RST connections, no register resets.

This diagnostic is separate from >=20 READ precision qualification and from
external packet replay. The old-token population (token_window.old_token_population)
is derived from the configured workload: triggers x 2k per role, where a
control-timed build triggers the READ app for c1's READ and its SELECT. The
cleanup bound follows from that population and the configured IPGs, and c2's
pre-READ pause from the bound (token_window.plan_isolation). Every old token
drains, and IPG is restored, before c2's first READ; only quiet snapshots are
taken. Isolation is then qualified through c2/c3's traffic and written as its
own verdict (isolation_verdict.json), never as precision qualification.
"""
import argparse
import copy
import json
import re
from pathlib import Path
import sys
import threading
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import candidate_series as cs
import candidate_campaign as cc
from isolation_gate import compare_quiet_generation
from token_window import (RESTORE_ALLOWANCE_NS, ABORT_MARGIN_NS, DRAIN_BEFORE_C2_RATIONALE, TEARDOWN_RESTORES_GENERATOR, ESTIMATES, require_marker, window_proof,
                          rejection_delta, rejection_counts, full_run_rejections, operate_rejection_proof,
                          old_token_population, plan_isolation, drained, overran, cleanup_proof,
                          restore_proof, quiet_poll_proof, expected_generations, post_traffic_authority,
                          endpoint_capability, permit_conditions)
from privileged_python import authorized_python

base, ARCH=cs.base,cs.ARCH
BARRIER_DIRECTORY='/home/decps/pad58b_rearm_barrier_10s_20261012'
BARRIER_BINARY='8270132ea76123e72cb5f4d196d5726c49f5f95d2516a468fc882bed84127158'
# The opt-in 20 s isolation endpoint (rearm_01/endpoint_isolation_20s, manifest/build_manifest.json): accepted
# ONLY when cfg['endpoint'] declares its capability (max_pause_ms 20000, permit true); its own new directory.
ISOLATION_DIRECTORY='/home/decps/pad58b_isolation_20s_20261016'
ISOLATION_BINARY='c73290162d0f0b1934f13da77c1354cec110a9d29d38e4a170470432b4bae7c0'
ENDPOINT_IDENTITIES={'barrier_10s':dict(directory=BARRIER_DIRECTORY,binary=BARRIER_BINARY),
                     'isolation_20s':dict(directory=ISOLATION_DIRECTORY,binary=ISOLATION_BINARY)}
ABORT_MARGIN_S=ABORT_MARGIN_NS/1e9   # local time kept for the fail-safe abort before c2's pause deadline
ABORT_PREFLIGHT_MAX_S=0.8   # the abort path must answer within this wall time before any traffic
MARKER_READ_RETRIES=3       # consecutive failed marker reads tolerated while waiting for c2
ABORT_RETRY_S=0.5
ABORT_MAX_ATTEMPTS=240


def installed_app_ipgs(k):
    """IPG per generator app as the installer writes it (response_only/hw/t_config.pktgen_ops)."""
    import importlib.util
    hw=ARCH/'integration/core/response_only/hw'
    sys.path[:0]=[str(hw.parent),str(hw)]
    try:
        spec=importlib.util.spec_from_file_location('isolation_t_config',hw/'t_config.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        ops=[op for op in module.pktgen_ops(k,{'pktgen_return':196}) if op['kind']=='pktgen_app']
    finally:
        del sys.path[:2]
    return {op['label']:dict(op['data'])['ipg'] for op in ops}


def marker_command(path):
    script=('import json,time\nfrom pathlib import Path\np=Path(%r)\nvalue=None\nstatus="absent"\n'
            'try:\n if p.exists():\n  value=json.loads(p.read_text())\n  status="complete"\n'
            'except (OSError,ValueError):\n status="incomplete"\n'
            'print(json.dumps(dict(marker=value,marker_status=status,vision_ns=time.monotonic_ns())))') % path
    return 'python3 -c '+base.q(script)


class Watchdog:
    """Aborts c2 at a local monotonic deadline unless the IPG restore is confirmed first. The lock makes
    'fired' and 'confirmed' mutually exclusive: the timer aborts only if not confirmed, and the main thread
    confirms only if the timer has not fired."""

    def __init__(self,abort,clock=time.monotonic):
        self.abort,self.clock,self.lock=abort,clock,threading.Lock()
        self.timer,self.fired_at,self.confirmed,self.armed_at=None,None,False,None

    def _fire(self):
        with self.lock:
            if self.confirmed:
                return
            self.fired_at=self.clock()
        self.abort()

    def arm(self,at_local):
        self.cancel()
        self.armed_at=at_local
        self.timer=threading.Timer(max(0.0,at_local-self.clock()),self._fire)
        self.timer.daemon=True
        self.timer.start()

    def cancel(self):
        if self.timer is not None:
            self.timer.cancel()
            if self.timer is not threading.current_thread():
                self.timer.join()
            self.timer=None

    def confirm(self):
        """True when the restore is confirmed in time; False when the watchdog already fired (c2 aborted)."""
        with self.lock:
            if self.fired_at is not None:
                return False
            self.confirmed=True
        self.cancel()
        return True


class TokenIsolationCampaign(cs.CandidateSeriesCampaign):
    # The delayed-token plan gates activation only for campaigns that delay generator tokens; external packet
    # replay (candidate_external) inherits the class but never uses the plan, so it overrides this.
    USES_TOKEN_PLAN=True

    def __init__(self,*args,analysis_only=False,**kwargs):
        """analysis_only=True builds the campaign to analyse retained evidence only: a plan that does not fit is
        recorded instead of refused, and execute()/deploy_only() refuse. Every new activation uses the default."""
        self.analysis_only=analysis_only
        super().__init__(*args,close_mode='rst',rst_grace_ms=1000,**kwargs)
        self.window={}
        self.record['token_isolation']=self.window
        self.record['isolation_source_identity']={str(path):base.sha256_file(path) for path in
            (Path(__file__),HERE/'token_window.py',HERE/'isolation_gate.py',HERE/'candidate_series.py',
             HERE/'snapshot_lifecycle.py',HERE/'candidate_campaign.py',HERE/'privileged_python.py')}
        self.active_unit=None
        build=self.cfg['builds'][self.arms[0]['build']]
        control_timed=build.get('control_timed',False)
        if not isinstance(control_timed,bool):
            raise ValueError('isolation build control_timed must be a boolean')
        k=self.cfg.get('service',{}).get('k')
        sbo=cs.checks.sbo_count(self.cfg['traffic'])
        self.population=old_token_population(k,1,sbo,control_timed)
        self.installed_ipg=installed_app_ipgs(k)
        self.endpoint_name,self.capability=endpoint_capability(self.cfg['endpoint'])
        # candidate61 (one READ-lane batch) keeps its retained 2.5 s delay (legacy plan); a plan that does not fit
        # the selected endpoint's capability refuses every new activation (analysis_only only records it)
        self.plan=plan_isolation(self.population,self.installed_ipg['OPERATE'],
                                 self.cfg.get('isolation',{}).get('delay_ipg_ns'),legacy=not control_timed,
                                 capability=self.capability,
                                 activation=self.USES_TOKEN_PLAN and not analysis_only)
        self.delay_ipg_ns=self.plan['delay_ipg_ns']
        self.pause_ms=self.plan['pause']['pause_ms']
        _,reserve=cc.HEADROOM.workload_reserve(1,sbo,1,control_timed)
        self.generations=expected_generations(reserve['read_lane_per_connection'],reserve['operate_per_connection'],
                                              reserve['open_close_per_connection'])
        self.record['isolation_endpoint']=dict(name=self.endpoint_name,capability=self.capability,
                                               analysis_only=analysis_only)
        self.window.update(population=self.population,plan=self.plan,installed_app_ipg_ns=self.installed_ipg,
                           expected_generations=self.generations,design=DRAIN_BEFORE_C2_RATIONALE,
                           rollback=TEARDOWN_RESTORES_GENERATOR)

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
        name,_=endpoint_capability(self.cfg['endpoint'])
        identity=ENDPOINT_IDENTITIES[name]
        if self.cfg['hosts']['vision_run_dir']!=identity['directory'] or \
                self.cfg['endpoint']['binary_sha256']!=identity['binary']:
            raise ValueError('isolation requires the exact pinned pre-READ endpoint for its declared capability (%s)'
                             % name)

    def execute(self):
        if self.analysis_only:
            raise base.StepFailed('analysis-only isolation campaign: no activation')
        return super().execute()

    def deploy_only(self):
        if self.analysis_only:
            raise base.StepFailed('analysis-only isolation campaign: no activation')
        return super().deploy_only()

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
        if not self.rn.dry:
            self.abort_preflight()

    def abort_preflight(self):
        """Before any traffic: exercise the exact fail-safe path on a label no process can carry; it must answer
        'no c2 master' (exit 1) with a report, quickly. Otherwise the block is refused."""
        label='abortpreflight'+re.sub('[^A-Za-z0-9]','',self.run_id)
        started=time.monotonic()
        result=self.rn.run('vision',authorized_python(self.V+'/vision_isolation.py',['abort-c2',label]),timeout=5,
                           label='preflight: exercise the c2 abort path on an unused label')
        wall=time.monotonic()-started
        report=None
        try:
            report=json.loads(result.out.strip().splitlines()[-1])
        except (ValueError,IndexError,AttributeError):
            pass
        record=dict(label=label,rc=result.rc,wall_s=wall,report=report,err=result.err,max_wall_s=ABORT_PREFLIGHT_MAX_S)
        record['ok']=(result.rc==1 and isinstance(report,dict) and report.get('matched')==[] and
                      report.get('c2_already_exited') is True and wall<ABORT_PREFLIGHT_MAX_S)
        self.record['abort_preflight']=record
        if not record['ok']:
            raise base.StepFailed('c2 abort path preflight failed (rc %s, %.3f s, report %r): block refused'
                                  % (result.rc,wall,report))

    def deploy_switch(self):
        super().deploy_switch()
        self._copy_verify('switch',[HERE/'delay_read_tokens.py'],self.R+'/aux','isolation_switch_identity')

    def series_vision_cmd(self,label,master_port,reads,*args,**kwargs):
        if reads!=1 or any(kwargs.get(key) for key in ('connect_must_fail','drop','scenario','reconnect_port')):
            raise ValueError('isolation requires a protected one-READ tuple')
        args = [label, '--master-port', master_port, '--padding', 1,
                '--control-padding', self._control_padding(), '--image-len', self._image_len(), '--apply',
                '--pre-read-grace-ms', self.pause_ms]
        if self.endpoint_name!='barrier_10s':
            args += ['--endpoint', self.endpoint_name]
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

    def delay_command(self,record,restore=None,budget_s=None):
        unit,_,_=self.active_unit
        build=unit['arm']['build']; data=self.cfg['builds'][build]
        command=('python3 %s/aux/delay_read_tokens.py --build-out %s/out_%s '
                 '--expected-bfrt-sha256 %s --switch-tools %s/%s --record %s '
                 '--ipg-ns %d --apply') % (
            self.R,self.R,build,data['hashes']['bfrt.json'],self.R,base.HW,base.q(record),self.delay_ipg_ns)
        if restore:
            command+=' --restore '+base.q(restore)+' --old-triggers %d' % self.population['READ']['triggers']
            if budget_s is not None:
                command+=' --budget-s %.3f' % budget_s
        return self.hw_env(command)

    def snapshot(self,out_remote,name,check=True,preset=None):
        result=super().snapshot(out_remote,name,check,preset)
        if name.endswith('_before'):
            remote=self.R+'/snap/'+name+'_token_delay.json'
            self.window['delay_remote']=remote
            delayed=self.step('switch','delay fresh READ app only',self.delay_command(remote))
            if not self.rn.dry:
                # switch clock; the cleanup anchor only if c1's first READ issue is not recoverable
                self.window['delay_time']=json.loads(delayed.out.strip().splitlines()[-1])['time']
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
        dog=Watchdog(lambda:self._watchdog_abort(label))
        try:
            deadline=time.monotonic()+90
            observed=None
            misses=0
            while not done.is_set() and time.monotonic()<deadline:
                asked=time.monotonic()      # Vision samples its clock after this instant
                result=self.rn.run('vision',marker_command(marker),timeout=5,label='wait for c2 marker')
                if result.rc:
                    misses+=1
                    if misses>=MARKER_READ_RETRIES:
                        raise ValueError('c2 readiness observer failed %d consecutive times' % misses)
                    done.wait(0.1);continue
                misses=0
                observed=json.loads(result.out)
                if observed['marker'] is not None:
                    self.window['marker_observation']=observed      # c2 is paused from here: abort on any failure
                    require_marker(observed['marker'],self.pause_ms)
                    pause_deadline=observed['marker']['pre_read_ready_ns']+self.pause_ms*1_000_000
                    # local image of c2's pause deadline (early, since Vision sampled after `asked`); the watchdog
                    # is armed now so a hung poll cannot let c2 READ with the delayed IPG
                    pause_local=asked+(pause_deadline-observed['vision_ns'])/1e9
                    dog.arm(pause_local-ABORT_MARGIN_S)
                    self.window.update(pause_deadline_local=pause_local,abort_at_local=pause_local-ABORT_MARGIN_S)
                    break
                done.wait(0.1)
            else:
                raise ValueError('c2 marker did not arrive before bounded observer deadline')
            pop=self.population
            before=self.quiet_snapshot(label,'before')
            self.window['before']=before
            # after the c2-ready snapshot (it adds no latency before it): c1's recorded first READ issue, the
            # cleanup anchor, read from Vision while c2 is paused
            first=self.rn.run('vision',marker_command(self.V+'/runs/'+label+'/c1/master.json'),timeout=5,
                              label='read c1 first READ issue')
            c1=json.loads(first.out).get('marker') if not first.rc else None
            self.window['c1_first_read_issued_ns']=(c1 or {}).get('first_read_issued_ns')
            if before.get('read_app_after',{}).get('pkt_counter',pop['READ']['tokens'])>=pop['READ']['tokens']:
                raise ValueError('c2 became ready after all old tokens; isolation cannot qualify')
            ticks=self.window.setdefault('poll_vision_ns',[])
            # the last Vision tick at which a restore may start: it must finish (restore allowance) before the
            # abort point (pause deadline - abort margin)
            restore_gate=pause_deadline-RESTORE_ALLOWANCE_NS-ABORT_MARGIN_NS
            self.window['restore_gate_vision_ns']=restore_gate
            while not done.is_set():
                after=self.quiet_snapshot(label,'after_%02d' % len(self.window.setdefault('polls',[])))
                self.window['polls'].append(after)
                asked=time.monotonic()
                tick=self.rn.run('vision',marker_command(marker),timeout=5,label='observe bounded pause')
                ticks.append(json.loads(tick.out)['vision_ns'] if not tick.rc else None)
                if overran(after,pop):
                    raise ValueError('a generator counter passed the old population before it drained')
                # no restore (a pktgen disable/write/enable) unless this poll is proven early enough on Vision's
                # clock that the restore can finish before the abort point
                if tick.rc or ticks[-1] is None or ticks[-1]>=restore_gate:
                    raise ValueError('old batches did not drain with time to restore before c2 READ')
                if drained(after,pop):
                    self.window['after']=after;self.window['drained_vision_ns']=ticks[-1]
                    pause_local=min(pause_local,asked+(pause_deadline-ticks[-1])/1e9)
                    break
                done.wait(0.1)
            else:
                raise ValueError('Vision series ended before old batch completed')
            restored=self.R+'/snap/'+label+'_token_restore.json'
            abort_at=pause_local-ABORT_MARGIN_S
            dog.arm(abort_at)                                      # re-armed on the tighter restore-phase image
            remaining=abort_at-time.monotonic()
            self.window.update(restore_timeout_s=remaining,abort_margin_s=ABORT_MARGIN_S,
                               pause_deadline_local=pause_local,abort_at_local=abort_at)
            if remaining<=0 or dog.fired_at is not None:
                raise ValueError('no time left to restore the READ IPG before the abort point')
            self.step('switch','restore READ IPG after the old READ-lane batches drained',
                      self.delay_command(restored,self.window['delay_remote'],remaining),timeout=remaining)
            tick=self.step('vision','confirm IPG restore completion on Vision clock',marker_command(marker),
                           timeout=max(0.1,abort_at-time.monotonic()))
            restored_ns=json.loads(tick.out)['vision_ns']
            if restored_ns>=pause_deadline:
                raise ValueError('IPG restore confirmation missed bounded pre-READ pause')
            if not dog.confirm():
                raise ValueError('restore not confirmed before the abort point; c2 was aborted')
            self.window['restored_vision_ns']=restored_ns
            self.window['runtime_slack_ns']=restore_gate-self.window['drained_vision_ns']
            if self.capability['permit']:
                self.grant_permit(label,observed['marker'],pause_deadline,pause_local)
            for name,remote in [('delay',self.window['delay_remote']),('restore',restored)]:
                self.step('local','collect token '+name,'scp -q %s:%s %s' % (
                    self.cfg['hosts']['switch'],base.q(remote),base.q(Path(self.root)/('token_'+name+'.json'))),timeout=5)
            self.window['monitor_ok']=True
        except Exception as error:
            dog.cancel()
            self.window.update(monitor_ok=False,error=str(error))
            # fail safe: the IPG may still be delayed, so c2 must not issue its READ. Stop the c2 master on Vision
            # (no switch or generator write during traffic), and keep stopping it until the series ends, since
            # before its marker c2 may not have started yet; the series then fails and c3 never starts.
            self.abort_until_done(label,done)
        finally:
            dog.cancel()
            if dog.fired_at is not None:
                self.window['watchdog_fired_local']=dog.fired_at
            (Path(self.root)/'token_window_observer.json').write_text(json.dumps(self.window,indent=2)+'\n')

    def grant_permit(self,label,marker,pause_deadline,pause_local):
        """isolation_20s only: grant c2's endpoint-local permit after the harness-side conditions hold. The Vision
        helper re-checks the marker binding and that Vision's monotonic clock is before c2's scheduled READ
        (pause_deadline = ready + pause, Vision clock). Any failure raises; the endpoint then exits without a
        READ at scheduled + PERMIT_GRACE_MS, and the caller's abort path stops c2 as well."""
        failures=permit_conditions(self.window['before'],self.window.get('polls'),self.population,
                                   self.window.get('drained_vision_ns'),self.window.get('restored_vision_ns'),
                                   pause_deadline)
        self.window['permit_conditions']=dict(ok=not failures,failures=failures)
        if failures:
            raise ValueError('c2 permit withheld: '+'; '.join(failures))
        remaining=pause_local-time.monotonic()
        if remaining<=0:
            raise ValueError('no time left to grant the c2 permit before its scheduled READ')
        result=self.rn.run('vision',authorized_python(self.V+'/vision_isolation.py',
                           ['grant-permit',label,'--ready-ns',marker['pre_read_ready_ns'],'--opens',marker['opens'],
                            '--deadline-ns',pause_deadline]),timeout=remaining,
                           label='grant c2 pre-READ permit on the Vision clock')
        report=None
        try:
            report=json.loads(result.out.strip().splitlines()[-1])
        except (ValueError,IndexError,AttributeError):
            pass
        self.window['permit']=dict(rc=result.rc,report=report,err=result.err)
        if result.rc!=0 or not isinstance(report,dict) or report.get('written') is not True or \
                type(report.get('granted_ns')) is not int or \
                not marker['pre_read_ready_ns']<report['granted_ns']<pause_deadline:
            raise ValueError('c2 permit not granted (rc %s, %s)' % (result.rc,(report or {}).get('reason',result.err)))
        self.window['permit_granted_vision_ns']=report['granted_ns']

    def _watchdog_abort(self,label):
        self.out('[isolation] watchdog: restore not confirmed before the abort point; aborting c2')
        self.abort_c2(label)

    def abort_until_done(self,label,done):
        attempts=[]
        while len(attempts)<ABORT_MAX_ATTEMPTS:
            attempts.append(self.abort_c2(label))
            if done.wait(ABORT_RETRY_S):
                break
        self.window['c2_abort_attempts']=len(attempts)
        # sticky: a kill confirmed by the restore watchdog or any earlier attempt counts
        self.window['c2_abort_confirmed']=bool(self.window.get('c2_abort_confirmed')) or \
            any(item['aborted'] for item in attempts)
        if not self.window['c2_abort_confirmed']:
            self.window['c2_abort']['note']=('ABORT NOT CONFIRMED in %d attempts: sudo refused, a c2 master remained, '
                                             'or no c2 master was ever found' % len(attempts))

    def abort_c2(self,label):
        """Kill the c2 master through the permitted sudo Python entry point (vision_isolation.py abort-c2: exact
        stop-path argv match over /proc, SIGKILL, rescan with the same privilege)."""
        result=self.rn.run('vision',authorized_python(self.V+'/vision_isolation.py',['abort-c2',label]),timeout=5,
                           label='fail-safe: stop the c2 master before its first READ')
        report=None
        try:
            report=json.loads(result.out.strip().splitlines()[-1])
        except (ValueError,IndexError,AttributeError):
            pass
        refused=result.rc!=0 and report is None and 'sudo:' in (result.err or '')
        if refused:
            meaning='sudo refused the permitted helper'
        elif report is None:
            meaning='helper failed (no report)'
        else:
            meaning={0:'c2 master matched, killed, none remains',1:'no c2 master process matched',
                     3:'a c2 master remains or a kill failed'}.get(result.rc,'helper failed')
        record=dict(rc=result.rc,meaning=meaning,err=result.err,report=report,sudo_refused=refused,
                    c2_already_exited=bool(report and report.get('c2_already_exited')),
                    aborted=result.rc==0 and bool(report) and bool(report.get('matched'))
                    and report.get('remaining')==[] and not refused)
        if not record['aborted']:
            record['note']='ABORT NOT CONFIRMED: '+meaning
        self.window['c2_abort']=record
        self.out('[isolation] c2 abort: rc %s, %s' % (result.rc,meaning))
        self.window.setdefault('c2_abort_history',[]).append(dict(rc=record['rc'],aborted=record['aborted'],
                                                                   meaning=meaning))
        if record['aborted']:
            self.window['c2_abort_confirmed']=True
        return record

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
            script_fail=[]
            for script,filename in (('wire_check.py','wire.json'),('clrt_check.py','timing.json')):
                result=self.step('local','independent '+cn+' '+script,'%s %s %s %s --json %s' %
                    (base.runner.PY,base.q(ARCH/'protocol/hw_vepa'/script),base.q(root/'out.pcap'),
                     base.q(root/'in.pcap'),base.q(root/filename)),check=False)
                self.save(str(root),script+'.log',result)
                if result.rc:script_fail.append(script+' failed rc'+str(result.rc))
            ev=self._connection_evidence(dest,cn)
            cfail=script_fail+cs.checks.application_checks(self.cfg['expectations'],1,1,ev,True)
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
                                     reads=1,pre_read_grace_ms=self.pause_ms if cn=='c2' else 0,
                                     control_padding=self._control_padding(),image_len=self._image_len()))
            outstation = ev.get('outstation') or {}
            cfail.extend(self.validate_standards_file(
                str(root), trial, arm,
                {'out': {'path': str(root/'out.pcap')}, 'in': {'path': str(root/'in.pcap')}},
                self.standards_observed(
                    ev, list(cfail), transport_ok=(not any(f.startswith('wire_check.py failed rc') for f in cfail)),
                    select_ok=outstation.get('select_real') == 1,
                    operate_ok=outstation.get('operate_real') == 1,
                    aggregate_ok=not cfail, precision_required=False,
                    precision_reason='isolation: stale_source_characterization, never precision qualification',
                    checker_result=self.run_standards_checker(str(root), trial, arm, cn)),
                connection_id=cn))
            connections[cn]=dict(ok=not cfail,failures=cfail,fresh_mapping=fresh)
            failures.extend(cn+': '+failure for failure in cfail)
        series_ok=not v.rc and scenario.get('ok') is True
        if not series_ok:
            failures.append('Vision isolation series failed')
        plan=[leg.get('pre_read_grace_ms') for leg in scenario.get('plan') or []]
        isolation_failures=[f for f in failures if f.startswith(('collected Vision scenario source pins',
                                                                   'collected isolation scenario'))]
        if self.capability['permit']:
            c2_plan=(scenario.get('plan') or [{}, {}])[1] if len(scenario.get('plan') or [])==3 else {}
            if scenario.get('endpoint')!=self.endpoint_name or c2_plan.get('permit_run')!=label+'_c2':
                isolation_failures.append('collected Vision scenario did not run c2 behind the endpoint permit')
            accepted=(cs._load_json(Path(dest)/'c2/master.json') or {}).get('pre_read_permit') or {}
            if type(self.window.get('permit_granted_vision_ns')) is not int or \
                    accepted.get('granted_ns')!=self.window['permit_granted_vision_ns']:
                isolation_failures.append('c2 did not READ under the permit this monitor granted')
        if plan!=[0,self.pause_ms,0]:
            isolation_failures.append('collected Vision plan pauses %r differ from the derived c2 pause %d ms'
                                      % (plan,self.pause_ms))
        # c1-c3 delivery and timing belong to the isolation verdict, not only to the trial
        isolation_failures.extend(cn+': '+f for cn in ('c1','c2','c3') for f in connections[cn]['failures'])
        if not series_ok:
            isolation_failures.append('Vision isolation series failed')
        pop=self.population
        bank,window=dict(ok=False,failures=['missing quiet snapshots']),dict(ok=False,failures=['missing token window'])
        cleanup,restore=dict(ok=False,failures=['missing cleanup proof']),dict(ok=False,failures=['missing restore proof'])
        quiet=dict(ok=False,failures=['missing poll series'])
        if self.window.get('monitor_ok') is True and connections['c2']['fresh_mapping']:
            marker=self.window['marker_observation']['marker']
            master=cs._load_json(Path(dest)/'c2/master.json') or {}
            drain_tick=self.window.get('drained_vision_ns')
            if type(self.window.get('c1_first_read_issued_ns')) is int:
                cleanup=cleanup_proof(self.window['c1_first_read_issued_ns'],drain_tick,self.plan['bound'])
            else:
                delay,done=self.window.get('delay_time'),self.window['after'].get('completed_time')
                cleanup=cleanup_proof(int(delay*1e9) if type(delay) is float else None,
                                      int(done*1e9) if type(done) is float else None,self.plan['bound'],
                                      anchor='switch: delay record (c1 first READ issue was not recorded)')
            restore=restore_proof(drain_tick,self.window.get('restored_vision_ns'))
            quiet=quiet_poll_proof(self.window['before'],self.window.get('polls'),self.window.get('poll_vision_ns'),
                                   master.get('first_read_issued_ns'),self.generations['at_c2_ready'])
            if self.window['before'].get('operate_app_after',{}).get('ipg')!=self.installed_ipg['OPERATE']:
                isolation_failures.append('OPERATE app IPG differs from the configured installer IPG')
            bank=compare_quiet_generation(self.window['before'],self.window['after'],2,
                                           connections['c2']['fresh_mapping']['server_isn'])
            window=window_proof(marker,master,self.window['before'],self.window['after'],self.window['restored_vision_ns'],
                                population=pop,cleanup=cleanup,delay_ipg_ns=self.delay_ipg_ns,pause_ms=self.pause_ms)
        isolation_failures.extend('banks: '+f for f in bank['failures'])
        isolation_failures.extend('window: '+f for f in window['failures'])
        isolation_failures.extend('restore: '+f for f in restore['failures'])
        isolation_failures.extend('quiet: '+f for f in quiet['failures'])
        rejection_delta_value=None
        quiet_rejections=None
        if window.get('ok'):
            try:
                quiet_rejections=rejection_counts(self.window['before'],self.window['after'])
                rejection_delta_value=rejection_delta(self.window['before'],self.window['after'])
                if rejection_delta_value!=window['old_packets_during_pause']:
                    isolation_failures.append('old READ token rejections do not match generated packets during pause')
            except (KeyError,TypeError,ValueError) as error:
                isolation_failures.append('missing old-token rejection hardware evidence: '+str(error))
        snapdir=Path(dest)/'snapshots'
        snapshots=cs.checks.load_evidence_files(before=str(snapdir/(label+'_before.json')),
                                                after=str(snapdir/(label+'_after.json')))
        # Qualification stays strict0. This diagnostic permits only the exact
        # independently proven prefix while the old batches drain before c2 READ.
        diagnostic_cfg=copy.deepcopy(self.cfg)
        sobs={}
        try:
            prefix=full_run_rejections(snapshots['before'],snapshots['after'],self.window['after'],pop)
            sobs['operate_cohort']=operate_rejection_proof(self.window['before'],self.window['after'],snapshots['before'],
                                                           pop)
            diagnostic_cfg['builds'][arm['build']]['max_token_stale']=prefix['strict_stale_total']
            sobs.update(prefix)
        except (KeyError,TypeError,ValueError) as error:
            isolation_failures.append('missing full-run rejection evidence: '+str(error))
        lifecycle=cs._load_json(snapdir/(label+'_after_lifecycle.json')) or {}
        lifecycle_before=cs._load_json(snapdir/(label+'_before_lifecycle.json')) or {}
        authority=post_traffic_authority(lifecycle_before,lifecycle,self.generations['after_c3'])
        isolation_failures.extend('authority: '+f for f in authority['failures'])
        failures.extend([f for f in isolation_failures if f not in failures])
        sfail,switch_observed=cs.series_switch_gate(diagnostic_cfg,arm,1,snapshots,lifecycle)
        sobs.update(switch_observed)
        failures.extend('switch: '+failure for failure in sfail)
        lfail,lobs=cs.lifecycle_gate(lifecycle,'rst')
        failures.extend('lifecycle: '+failure for failure in lfail)
        isolation_failures.extend('lifecycle: '+failure for failure in lfail)
        if self.window.get('error'):
            failures.append(self.window['error'])
            isolation_failures.append(self.window['error'])
        abort=self.window.get('c2_abort')
        if abort and self.window.get('c2_abort_confirmed') is not True and abort.get('aborted') is not True:
            failures.append('c2 fail-safe abort not confirmed: '+abort.get('note',''))
            isolation_failures.append('c2 fail-safe abort not confirmed: '+abort.get('note',''))
        isolation_failures.extend('switch: '+f for f in sfail)
        isolation=dict(ok=not isolation_failures,failures=isolation_failures,separate_from_precision=True,
                       precision_qualified=False,design=DRAIN_BEFORE_C2_RATIONALE,rollback=TEARDOWN_RESTORES_GENERATOR,
                       c2_abort=self.window.get('c2_abort'),c2_abort_attempts=self.window.get('c2_abort_attempts'),
                       runtime_slack_ns=self.window.get('runtime_slack_ns'),
                       planned_slack_ns=self.plan['pause'].get('planned_slack_ns'),
                       estimates=ESTIMATES,population=pop,plan=self.plan,
                       installed_app_ipg_ns=self.installed_ipg,expected_generations=self.generations,
                       connections={cn:dict(ok=c['ok'],failures=c['failures']) for cn,c in connections.items()},
                       vision_series_ok=series_ok,cleanup=cleanup,restore=restore,quiet_polls=quiet,
                       bank_isolation=bank,old_token_window=window,old_rejection_delta=rejection_delta_value,
                       quiet_rejections=quiet_rejections,full_run=sobs,post_traffic_authority=authority)
        (Path(dest)/'isolation_verdict.json').write_text(json.dumps(isolation,indent=2)+'\n')
        trial.update(ok=not failures,failures=failures,scenario=dict(policy='real_old_token_isolation',connections=connections),
                     observed=dict(bank_isolation=bank,old_token_window=window,old_rejection_delta=rejection_delta_value,
                                   quiet_rejections=quiet_rejections,isolation_verdict=isolation,
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
