#!/usr/bin/env python3
"""Sequential, captured latency-policy acquisition with restoration in finally."""
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import random
import shlex
import signal
import subprocess
import time

import configure
import policy
from remote import HERE, REMOTE, SWITCH, VISION, ssh, upload, collect, deploy

SDE = '/home/decps/Downloads/bf-sde-9.13.2/install'


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def switch_apply(filename, log, readback):
    args = ['python3', REMOTE + '/configure.py', 'apply', '--policy', REMOTE + '/' + filename,
            '--control-dir', REMOTE + '/control', '--readback-output', REMOTE + '/' + readback]
    command = 'DEFENSE4_HW_AUTHORIZED=1 PYTHONPATH=' + SDE + '/lib/python3.8/site-packages/tofino ' + shlex.join(args)
    with log.open('wb') as stream:
        ssh(SWITCH, command, stdout=stream, stderr=subprocess.STDOUT, timeout=60)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--phase', choices=['pilot', 'screen'], required=True)
    parser.add_argument('--replicates', type=int)
    parser.add_argument('--names', nargs='*')
    args = parser.parse_args()
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        raise SystemExit('REFUSED: DEFENSE4_HW_AUTHORIZED=1 required')
    count = 10 if args.phase == 'pilot' else 100
    repeats = args.replicates or (1 if args.phase == 'pilot' else 5)
    selected = list(policy.build_search_plan())
    if args.names:
        selected = [p for p in selected if p.name in args.names]
        if set(args.names) != {p.name for p in selected}:
            raise ValueError('Unknown policy name')
    run = HERE / 'evidence' / (args.phase + '_' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()))
    run.mkdir(parents=True, exist_ok=False)
    plans = []
    for p in selected:
        name = 'plan_' + p.name + '.json'
        configure.write_plan(run / name, configure.build_policy_plan(p))
        plans.append((run / name, name))
    original = configure.load_snapshot(HERE / 'evidence/preflight/switch.json')
    configure.write_plan(run / 'restore.json', configure.restore_plan_from_snapshot(original))
    plans.append((run / 'restore.json', 'restore.json'))
    seed = 20260926
    rng = random.Random(seed)
    schedule = []
    for rep in range(repeats):
        shuffled = list(selected)
        rng.shuffle(shuffled)
        for p in shuffled:
            schedule.append((rep, p))
    write_json(run / 'schedule.json', {'seed': seed, 'phase': args.phase, 'count_per_class': count,
        'schedule': [{'replicate': r, 'policy': asdict(p)} for r,p in schedule]})
    deploy()
    upload(SWITCH, plans)
    failed = None
    active_label = None
    results = []
    def interrupted(sig, frame):
        raise KeyboardInterrupt('Campaign interrupted; restoring policy')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        for rep, p in schedule:
            label = run.name + '_r%02d_' % rep + p.name
            print('START', label, flush=True)
            log = run / (label + '_configure.log')
            rb = label + '_readback.json'
            switch_apply('plan_' + p.name + '.json', log, rb)
            raw = ssh(SWITCH, 'cat ' + shlex.quote(REMOTE + '/' + rb), stdout=subprocess.PIPE, timeout=20)
            readback = json.loads(raw.stdout)
            cmd = ['python3', REMOTE + '/run_block.py', label, '--reads', str(count), '--sbo', str(count)]
            try:
                active_label = label
                with (run / (label + '_runner.log')).open('wb') as stream:
                    ssh(VISION, 'DEFENSE4_HW_AUTHORIZED=1 ' + shlex.join(cmd),
                        stdout=stream, stderr=subprocess.STDOUT, timeout=count*2.4+60)
                active_label = None
            finally:
                if active_label:
                    ssh(VISION, shlex.join(['python3', REMOTE + '/stop_block.py', active_label]), timeout=30)
                    active_label = None
                collect(label, HERE / 'evidence/blocks')
                block = HERE / 'evidence/blocks' / label
                write_json(block / 'policy.json', dict(asdict(p), da_ms=p.da.realized_ms,
                    new_clrt_ms=p.gap.realized_ms, arm='native' if p.mode == 'OFF' else 'obfuscated',
                    session='replicate_%02d' % rep, block=label, phase=args.phase))
                write_json(block / 'configuration_readback.json', readback)
            results.append({'label': label, 'status': 'captured'})
            write_json(run / 'progress.json', results)
            print('CAPTURED', label, flush=True)
    except BaseException as exc:
        failed = repr(exc)
        write_json(run / 'failure.json', {'error': failed, 'completed': len(results)})
        raise
    finally:
        if active_label:
            raise RuntimeError('Cannot confirm stopped runner ' + active_label + '; policy restoration withheld')
        switch_apply('restore.json', run / 'restore.log', 'restored_readback.json')
        raw = ssh(SWITCH, 'cat ' + REMOTE + '/restored_readback.json', stdout=subprocess.PIPE, timeout=20)
        (run / 'restored_readback.json').write_bytes(raw.stdout)
        print('RESTORED starting policy; completed', len(results), 'error', failed, flush=True)


if __name__ == '__main__':
    main()
