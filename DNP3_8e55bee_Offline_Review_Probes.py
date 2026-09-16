"""Offline review probes. Uses only test doubles; never accesses a host or switch."""
from pathlib import Path
import sys, json, time, threading, argparse

ap = argparse.ArgumentParser(description=__doc__)
ap.add_argument('--repo', type=Path, required=True, help='Checkout of DNP3_obf at 8e55bee')
ap.add_argument('--output', type=Path, help='Optional JSON results path; otherwise print only')
args = ap.parse_args()
ROOT = args.repo.resolve()
for p in ['defense4/timing/active_control/tests', 'defense4/timing/active_probe/tests']:
    sys.path.insert(0, str(ROOT / p))
import test_delay_admission as da
import test_timing_only_profile as tp
import test_rto_probe_plan as rp
import timing_only_profile as top
import rto_probe_plan as probe

results = {}
for label, admission in [('empty_verdict', {}), ('unknown_verdict', {'verdict':'banana'}),
                          ('provisional', {'verdict':'provisional'})]:
    dev=tp.RecordingDevice()
    r=top.activate(top.TimingOnlyProfile(),dev,mock=False,admission=admission)
    results['activation_'+label]={'status':r['status'],'writes':len(dev.writes)}

small=da.evaluate(da.inputs(d_a_ms=5,policy_cap_ms=10))
dev=tp.RecordingDevice()
large=top.activate(top.TimingOnlyProfile(d_a_ms=20),dev,mock=False,admission=small)
results['different_policy_activated']={'admitted_d_a_ms':5,'admitted_cap_ms':10,
    'activated_d_a_ms':20,'status':large['status'],'admission_verdict':small['verdict']}

opposite=da.Applicability(connection_id='conn-1',build_id='frozen-7ce30494',
    direction='outstation_to_master',timer='outstation_rto')
v=da.evaluate(da.inputs(master_rto_ms=da.b('master_rto_ms',3000,applies_to=opposite)))
results['wrong_timer_applicability']={'verdict':v['verdict'],
    'inputs_not_authoritative':v['inputs_not_authoritative']}
v=da.evaluate(da.inputs(context=da.PolicyContext()))
results['empty_policy_context']={'verdict':v['verdict']}
v=da.evaluate(da.inputs(master_rto_ms=da.b('application_deadline_ms',200,
    da.Provenance.OPERATOR_SUPPLIED)))
results['role_name_spoof']={'verdict':v['verdict']}

for native in [20,1]:
    v=da.evaluate(da.inputs(clrt_original_ms=da.b('clrt_original_ms',native),
        native_request_to_response_ms=da.b('native_request_to_response_ms',25),
        outstation_rto_ms=da.b('outstation_rto_ms',10)))
    results['native_interval_'+str(native)]={'verdict':v['verdict'],
        'response_hold_ms':v['response_hold_ms'],
        'outstation':da.check(v,'outstation')['consumed_ms']}

results['empty_queue_plan_errors']=top.validate(top.TimingOnlyProfile(
    queue_plan_rrc=(),queue_plan_bor=()))
results['wrong_qid_plan_errors']=top.validate(top.TimingOnlyProfile(
    queue_plan_rrc=(('ACK_BLOCK',27,7),('ACK_HOLD',26,6),('RESP_BLOCK',25,5),('RESP_HOLD',24,4))))
class FinalFailure(tp.RecordingDevice):
    def read(self,table):
        if table=='tbl_params' and self.state['pktgen.app_cfg'].get('app_enable'):
            raise OSError('readback failed after pktgen enable')
        return super().read(table)
dev=FinalFailure()
try:
    top.activate(top.TimingOnlyProfile(),dev,mock=True)
except Exception as e:
    results['activation_final_failure']={'exception':type(e).__name__,
        'has_record':hasattr(e,'record'),'pktgen_still_enabled':dev.state['pktgen.app_cfg']['app_enable']}

rec,_=rp.run(probe.plan(rp.conn(),rp.ctx(),40),rp.Runner(),workload=lambda _:None)
results['early_workload']={'status':rec['status'],'elapsed_seconds':rec['elapsed_seconds'],
    'requested_hold_seconds':rec['requested_hold_seconds']}
for label,kw,runner in [('workload_exception',{'workload':lambda _:(_ for _ in ()).throw(OSError('workload failed'))},rp.Runner()),
                       ('cleanup_exception',{},rp.Runner(raise_on='-D'))]:
    try: rp.run(probe.plan(rp.conn(),rp.ctx(),.01),runner,**kw)
    except Exception as e:
        results[label]={'exception':type(e).__name__,'has_record':hasattr(e,'record'),
            'rule_still_installed':runner.installed}

p=probe.plan(rp.conn(),rp.ctx(),.01);p['watchdog_seconds']=.02
runner=rp.Runner();release=threading.Event();started=threading.Event();thread_result={}
def workload(_):
    started.set();release.wait(.5)
def run_thread():
    try: probe.run_steps(p,runner,workload=workload)
    except Exception as e:thread_result['after_release_exception']=type(e).__name__
t=threading.Thread(target=run_thread,daemon=True);t.start();started.wait(.1);time.sleep(.06)
results['watchdog_during_blocking_workload']={'watchdog_seconds':.02,
    'observed_after_seconds':.06,'worker_alive':t.is_alive(),'rule_still_installed':runner.installed}
release.set();t.join(1)
results['watchdog_during_blocking_workload'].update(thread_result)

p=probe.plan(rp.conn(),rp.ctx(),float('nan'))
rec,_=rp.run(p,rp.Runner())
results['nan_hold']={'status':rec['status'],'elapsed_seconds':rec['elapsed_seconds']}
results['network_selector_accepted']=probe.plan(rp.conn(src_ip='192.168.10.0/24'),rp.ctx(),1)['commands']['install']

rendered = json.dumps(results, indent=2) + '\n'
if args.output:
    args.output.write_text(rendered)
print(rendered)
