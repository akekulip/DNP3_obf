#!/usr/bin/env python3
"""Matched DA grid using the existing seven-stage binary and guarded runner."""
import argparse
from dataclasses import asdict
import json
from pathlib import Path
import subprocess
import time

try:
    from . import focused_campaign as focused
except ImportError:
    import focused_campaign as focused

rc=focused.rc
HERE=Path(__file__).resolve().parent
DELAYS=(5,10,15,20)
SEED=20260927


def names():
    return [f'da{d}_gap1_joint_amp0p5' for d in DELAYS]


def protocol():
    return dict(version=1,study='matched_delay_grid',delays_ms=list(DELAYS),policy_names=names(),
        center_gap_ms=1.,amplitude_ms=.5,mode='joint',j_set_ms=[.25,.5,1.],
        rounds=100,count_per_operation=100,primary_exchanges=240000,
        training_rounds=list(range(40)),test_rounds=list(range(40,100)),seed=SEED,
        gap_ms=400,timeout_ms=500,immediate_select_operate=True,
        tasks=focused.protocol()['tasks'],models=focused.protocol()['models'],
        features=focused.protocol()['features'],pools=[1,5,20],
        tuning='Five grouped folds within training rounds only; models frozen before test scoring',
        primary_features=['clrt','ack_clrt'],level_aware_features=['clrt','ack_clrt'],
        level_aware='Nearest public timing-level subtraction; actual selected offsets excluded from features',
        criterion='ACK/CLRT fixed, adaptive and level-aware attacks; request-spacing results reported separately',
        chance_margin=.05,confidence_per_task=.975,bootstrap_resamples=5000,
        uncertainty='Shared paired-round bootstrap; maximum centered deviation across all policies and protected attacks',
        selection='Smallest worst-operation added pooled median; tie by worst-operation p99 then smaller DA',
        coverage='Master-facing Timing OFF availability proxy, averaging joint ACK/response inequalities over 16 equally likely quantized selections; no direct switch-arrival claim',
        coverage_hard_threshold=None,
        stop_rule='100 rounds; no outcome-dependent extension or policy changes')


def pairing(schedule):
    pairs=[]
    if len(schedule)%2: raise ValueError('Unpaired block')
    seen=set()
    for protected,native in zip(schedule[::2],schedule[1::2]):
        if protected.kind!='random_policy' or native.kind!='off_reference' or protected.replicate!=native.replicate:
            raise ValueError('Expected protected block followed by same-round OFF block')
        name=protected.random_plan_path.stem
        key=(protected.replicate,name)
        if key in seen: raise ValueError('Duplicate policy/round pair')
        seen.add(key)
        pairs.append(dict(round=protected.replicate,policy=name,protected=protected.label,native=native.label))
    return pairs


def snapshot_live():
    script='''import json,sys
sys.path.insert(0,"/home/decps/dnp3_latency_20260926")
import configure
from randomized import bfrt_random_table as rt
gc,interface,info,target=rt.open_bfrt(client_id=117)
try:
    plan=configure._read_live_plan(info.table_get(configure.CODEBOOK_TABLE),info.table_get(configure.PARAMS_TABLE),info.table_get(configure.BOR_PARAMS_TABLE),target)
    table=info.table_get(rt.TABLE_NAME)
    random_entries=rt.readback_table(table,target)
    default=rt.verify_default_noaction(table,target)
    ports=[dict(key=k.to_dict(),data=d.to_dict()) for d,k in info.table_get('$PORT').entry_get(target,flags={'from_hw':True})]
    print(json.dumps(dict(restore=configure.plan_to_dict(plan),random_entries=random_entries,random_default=default,ports=ports)))
finally:
    interface.tear_down_stream()
'''
    command='PYTHONPATH='+rc.SDE+'/lib/python3.8/site-packages/tofino python3 -'
    result=rc.remote.ssh(rc.remote.SWITCH,command,input=script,text=True,stdout=subprocess.PIPE,timeout=45)
    return rc._json_from_stdout(result.stdout,'grid preflight')


def verify_snapshot(doc):
    if doc['random_entries']: raise ValueError('Random table is not empty; preserve unexpected live state')
    ports={int(p['key']['$DEV_PORT']['value']):p['data'] for p in doc['ports']}
    for port in (8,9,10,64):
        if not ports.get(port,{}).get('$PORT_UP') or not ports[port].get('$PORT_ENABLE'):
            raise ValueError('Required port down: '+str(port))
    for port in (8,10):
        if ports[port]['$LOOPBACK_MODE']!='BF_LPBK_MAC_NEAR':raise ValueError('Loopback configuration changed')


def prepare():
    root=HERE/'evidence/delay_grid'
    preflight=root/('preflight_'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime()))
    preflight.mkdir(parents=True,exist_ok=False)
    snapshot=snapshot_live();verify_snapshot(snapshot)
    rc.write_json(preflight/'snapshot.json',snapshot)
    rc.write_json(preflight/'restore.json',snapshot['restore'])
    plans=[]
    for delay,name in zip(DELAYS,names()):
        plan=rc.policy_planner.build_plan(center_da_ms=float(delay),center_gap_ms=1.,amplitude_ms=.5,mode='joint')
        path=preflight/(name+'.json');rc.write_json(path,rc.policy_planner.plan_to_dict(plan));plans.append(path)
    evidence=HERE/'evidence'
    run=rc.prepare_run(random_plan_paths=plans,
        fixed_config_plan=evidence/'random_policies_20260926/fixed_config.json',
        off_config_plan=evidence/'random_policies_20260926/off_config.json',
        restore_config_plan=preflight/'restore.json',
        identity_file=evidence/'random_screen_plan_20260926/program_identity.json',
        output_root=root,phase='screen',count=100,repeats=100,seed=SEED,off_every=1,
        transport=focused.OfflineTransport())
    focused.identity_snapshot(run,None,'live_identity_preparation.json')
    rc.write_json(run.run_dir/'preflight_snapshot.json',snapshot)
    rc.write_json(run.run_dir/'protocol.json',protocol())
    rc.write_json(run.run_dir/'pairing.json',pairing(run.schedule))
    frozen=[p for p in run.run_dir.iterdir() if p.is_file()]+list((run.run_dir/'plans').glob('*.json'))
    rc.write_json(run.run_dir/'frozen_inputs.json',{str(p.relative_to(run.run_dir)):rc.sha256_file(p) for p in frozen})
    return run


def load_run(directory):
    directory=Path(directory).resolve()
    for name,h in rc._load_json(directory/'frozen_inputs.json').items():
        if rc.sha256_file(directory/name)!=h:raise ValueError('Frozen input changed: '+name)
    if rc._load_json(directory/'protocol.json')!=protocol():raise ValueError('Grid protocol changed')
    rows=rc._load_json(directory/'schedule.json')['schedule'];blocks=[]
    for row in rows:
        row=dict(row)
        if row['random_plan_path'] is not None:row['random_plan_path']=directory/'plans'/Path(row['random_plan_path']).name
        blocks.append(rc.BlockSpec(**row))
    expected=rc.build_schedule(random_plan_paths=[directory/'plans'/(n+'.json') for n in names()],
        repeats=100,seed=SEED,off_every=1,phase='screen',count=100,run_name=directory.name)
    if tuple(blocks)!=expected or rc._load_json(directory/'pairing.json')!=pairing(expected):
        raise ValueError('Schedule/pairing differs from frozen 100-round grid')
    return rc.PreparedRun(directory,'screen',100,100,SEED,tuple(blocks),
        'fixed_config.json','off_config.json','restore_config.json',directory/'program_identity.json')


def execute(run):
    rc._require_authorized()
    snapshot=snapshot_live();verify_snapshot(snapshot)
    saved=rc._load_json(run.run_dir/'restore_config.json')
    for field in ('codebook_entries','params_default','bor_params_default'):
        if snapshot['restore'][field]!=saved[field]:raise ValueError('Live configuration changed since preparation: '+field)
    # Same tested stop/failure/restore path; no P4 loading or compilation.
    focused.execute(run)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    g=parser.add_mutually_exclusive_group(required=True)
    g.add_argument('--prepare',action='store_true');g.add_argument('--run',type=Path)
    args=parser.parse_args()
    if args.prepare:print(prepare().run_dir)
    else:execute(load_run(args.run))
