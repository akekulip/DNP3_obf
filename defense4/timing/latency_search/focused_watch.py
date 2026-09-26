#!/usr/bin/env python3
"""Observe acquisition; fit on the frozen training split, then audit and score.

This process never transmits traffic, configures the switch, or retries acquisition.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import focused_campaign as campaign
import evaluate_focused as attacks
import summarize_random
import audit_tcp


def training_snapshot(run, out):
    """Copy only the 80 immutable completed blocks; never read an active capture."""
    progress=json.loads((run/'progress.json').read_text())
    labels=[b['label'] for b in progress if int(b['replicate'])<40]
    if len(labels)!=80:
        raise ValueError('Training snapshot requires all 40 complete pairs')
    blocks=out/'training_blocks'
    blocks.mkdir(parents=True,exist_ok=True)
    for label in labels:
        target=blocks/label
        if not target.exists():
            temporary=blocks/(label+'.copying')
            if temporary.exists(): shutil.rmtree(temporary)
            shutil.copytree(run/'collected_blocks'/label,temporary)
            temporary.rename(target)
    summarize_random.summarize_run(run,blocks_root=blocks,out_dir=out/'training',allow_partial=True)


def watch(run,out,workers):
    campaign.load_run(run)  # Verify frozen inputs before observing anything.
    out.mkdir(parents=True,exist_ok=True)
    last=-1;last_change=time.monotonic();fitted=False
    while True:
        progress=json.loads((run/'progress.json').read_text()) if (run/'progress.json').exists() else []
        n=len(progress)
        if n!=last:
            print('PROGRESS',n,'/200 blocks;',n*300,'primary exchanges',flush=True)
            last=n;last_change=time.monotonic()
        if (run/'failure.json').exists() or (run/'restoration_failure.json').exists():
            raise RuntimeError('Acquisition/restoration failed; evidence retained; no automatic retry')
        if n>=80 and not fitted:
            training_snapshot(run,out)
            rows,protocol,levels=attacks.load(out/'training/measurements.json',
                out/'training/primarytransactions.csv',run/'protocol.json')
            attacks.train(rows,protocol,levels,out/'models',workers)
            fitted=True
            print('TRAINING FROZEN: all 180 models fitted without held-out data',flush=True)
            last_change=time.monotonic()
        if (run/'final_status.json').exists():
            final=json.loads((run/'final_status.json').read_text())
            if final.get('error') is not None or final.get('completed_blocks')!=200 or not final.get('configuration_restored'):
                raise RuntimeError('Focused acquisition ended without 200 restored blocks')
            if not fitted: raise RuntimeError('No frozen models')
            summarize_random.summarize_run(run,out_dir=out/'final')
            audit_tcp.audit(out/'final/measurements.json',out/'final/tcp_audit.json')
            rows,protocol,levels=attacks.load(out/'final/measurements.json',
                out/'final/primarytransactions.csv',run/'protocol.json',complete=True)
            attacks.score(rows,protocol,levels,out/'models',out/'final',workers)
            subprocess.run([sys.executable,str(HERE/'focused_report.py'),'--results',str(out/'final'),
                            '--protocol',str(run/'protocol.json')],check=True)
            campaign.rc.write_json(out/'analysis_status.json',dict(status='complete',
                note='Acquisition, audit, held-out evaluation and figure generation finished; manuscript integration still requires review.'))
            print('COMPLETE: focused results and figures ready for review',flush=True)
            return
        if time.monotonic()-last_change>900:
            raise RuntimeError('No completed block for 15 minutes; inspect acquisition, do not restart automatically')
        time.sleep(30)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--jobs',type=int,default=8)
    args=parser.parse_args()
    try:
        watch(args.run.resolve(),args.out.resolve(),args.jobs)
    except BaseException as exc:
        campaign.rc.write_json(args.out/'analysis_status.json',dict(status='failed',error=repr(exc)))
        raise
