#!/usr/bin/env python3
"""Repeat the existing 5/1 ms policy; no P4 compilation or pipeline loading."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import signal
import subprocess

try:
    from . import random_campaign as rc
except ImportError:
    import random_campaign as rc

HERE = Path(__file__).resolve().parent
POLICY = 'da5_gap1_joint_amp0p5'


class OfflineTransport:
    def deploy(self): pass
    def upload_switch(self, files): pass
    def upload_vision(self, files): pass


def protocol():
    return dict(version=1, policy_name=POLICY, count_per_operation=100,
        repetitions=100, primary_exchanges=60000, safety_polls_per_block=2,
        training_repetitions=list(range(40)), test_repetitions=list(range(40, 100)),
        gap_ms=400, timeout_ms=500, immediate_select_operate=True,
        seed=20260926, pools=[1, 5, 20],
        tasks={'three_class':['READ','SELECT','OPERATE'], 'read_select':['READ','SELECT']},
        features=['clrt','ack_clrt','request_gap','ack_clrt_gap'],
        models={'rf':{'min_samples_leaf':[1,3,10]},
                'logistic':{'C':[0.1,1,10]}, 'rbf_svm':{'C':[0.1,1,10]}},
        tuning='Five grouped folds within the first 40 paired repetitions only',
        fixed_training_arm='native', adaptive_training_arm='obfuscated',
        level_aware='Supplemental adaptive attack using nearest public levels; no digest values as features',
        bootstrap_resamples=5000, confidence_per_task=0.975,
        chance_margin=0.05, late_response_threshold_ms=1.0,
        inference_scope='One SEL-751; transaction classes; approximate paired-block uncertainty',
        pooling_assumption='Attacker can group known-same-operation exchanges; never cross blocks or partitions',
        stop_rule='100 complete paired repetitions; no outcome-dependent extension or policy changes')


def prepare():
    evidence = HERE/'evidence'
    source = evidence/'random_screen_plan_20260926'
    run = rc.prepare_run(random_plan_paths=[source/(POLICY+'.json')],
        fixed_config_plan=evidence/'random_policies_20260926/fixed_config.json',
        off_config_plan=evidence/'random_policies_20260926/off_config.json',
        restore_config_plan=evidence/'random_preflight_20260926/restore.json',
        identity_file=source/'program_identity.json',
        output_root=evidence/'focused', phase='screen', count=100, repeats=100,
        off_every=1, transport=OfflineTransport())
    rc.write_json(run.run_dir/'protocol.json', protocol())
    frozen = [run.run_dir/n for n in ('protocol.json','schedule.json','provenance.json',
              'fixed_config.json','off_config.json','restore_config.json','program_identity.json')]
    frozen += list((run.run_dir/'plans').glob('*.json'))
    rc.write_json(run.run_dir/'frozen_inputs.json', {str(p.relative_to(run.run_dir)):rc.sha256_file(p) for p in frozen})
    return run


def load_run(directory):
    directory = Path(directory).resolve()
    for name, expected in rc._load_json(directory/'frozen_inputs.json').items():
        if rc.sha256_file(directory/name) != expected:
            raise ValueError('Frozen input changed: '+name)
    if rc._load_json(directory/'protocol.json') != protocol():
        raise ValueError('Focused protocol differs from the frozen implementation')
    schedule = rc._load_json(directory/'schedule.json')
    blocks = []
    for row in schedule['schedule']:
        row = dict(row)
        if row['random_plan_path'] is not None:
            row['random_plan_path'] = directory/'plans'/Path(row['random_plan_path']).name
        blocks.append(rc.BlockSpec(**row))
    expected = rc.build_schedule(random_plan_paths=[directory/'plans'/(POLICY+'.json')],
        repeats=100,seed=20260926,off_every=1,phase='screen',count=100,run_name=directory.name)
    if tuple(blocks) != expected:
        raise ValueError('Focused schedule differs from 100 protected/OFF pairs')
    return rc.PreparedRun(directory,'screen',100,100,20260926,tuple(blocks),
        'fixed_config.json','off_config.json','restore_config.json',directory/'program_identity.json')


def identity_snapshot(run, transport, name):
    script = HERE/'evidence/random_preflight_20260926/inspect_program.py'
    result = rc.remote.ssh(rc.remote.SWITCH, 'python3 -', input=script.read_text(),
                           stdout=subprocess.PIPE, text=True, timeout=30)
    observed = json.loads(result.stdout)
    expected = rc._load_json(run.identity_file)
    # The manifest embeds the exact deployable artifact identity.
    expected_hashes = expected.get('artifact_sha256') or expected.get('artifact_hashes')
    if expected_hashes is None:
        raise ValueError('Missing deployed artifact hashes in identity manifest')
    if observed['program'] != rc.PROGRAM_NAME or observed['artifact_sha256'] != expected_hashes:
        raise ValueError('Live program differs from frozen seven-stage binary')
    rc.write_json(run.run_dir/name, observed)


def execute(run, transport=None):
    rc._require_authorized()
    if (run.run_dir/'started.json').exists():
        raise RuntimeError('Refusing automatic restart/replay of a started hardware run')
    rc.validate_program_identity(rc._load_json(run.identity_file))
    transport = transport or rc.RemoteTransport()
    identity_snapshot(run, transport, 'live_identity_before.json')
    transport.deploy()
    transport.upload_switch(rc._base_upload_files(run))
    transport.upload_vision([(HERE/n,n) for n in ('run_block.py','stop_block.py')])
    rc.write_json(run.run_dir/'started.json', {'protocol_sha256':rc.sha256_file(run.run_dir/'protocol.json')})
    completed, error, stopped = [], None, False
    def interrupted(signum, frame):
        raise KeyboardInterrupt('Focused run interrupted; stop owned traffic and restore')
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        for block in run.schedule:
            if (run.run_dir/'STOP_AFTER_BLOCK').exists():
                stopped = True
                break
            print('START',block.label,flush=True)
            completed.append(rc.run_block(block,run,transport=transport))
            rc.write_json(run.run_dir/'progress.json', completed)
            print('CAPTURED',block.label,flush=True)
    except BaseException as exc:
        error = repr(exc)
        rc.write_json(run.run_dir/'failure.json', {'error':error,'completed_blocks':len(completed)})
        raise
    finally:
        try:
            rc._restore(run,transport)
            identity_snapshot(run,transport,'live_identity_after.json')
            rc.write_json(run.run_dir/'final_status.json',dict(completed_blocks=len(completed),
                error=error, configuration_restored=True, stopped_after_block=stopped))
        except BaseException as exc:
            rc.write_json(run.run_dir/'restoration_failure.json', {'error':repr(exc)})
            raise
        finally:
            signal.signal(signal.SIGTERM,previous)


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare',action='store_true')
    group.add_argument('--run',type=Path)
    args=parser.parse_args()
    if args.prepare:
        print(prepare().run_dir)
    else:
        execute(load_run(args.run))
