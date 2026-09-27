#!/usr/bin/env python3
"""Observe the matched grid; freeze training, audit final captures, and score.

This process never configures hardware, transmits traffic, or retries acquisition.
"""
import argparse
import json
from pathlib import Path
import shutil
import time

import grid_analysis as analysis
import grid_report
import summarize_random
import audit_tcp

campaign = analysis.campaign


def read_progress(run):
    path = run / 'progress.json'
    if not path.exists():
        return []
    # Acquisition writes this small status file in place. Retry an overlapping read.
    for attempt in range(5):
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            if attempt == 4:
                raise
            time.sleep(.2)


def training_labels(run, progress):
    protocol = json.loads((run / 'protocol.json').read_text())
    pairs = json.loads((run / 'pairing.json').read_text())
    expected = {p[k] for p in pairs if p['round'] in protocol['training_rounds']
                for k in ('protected', 'native')}
    completed = [b['label'] for b in progress]
    if len(completed) != len(set(completed)):
        raise ValueError('Duplicate completed block')
    if not expected.issubset(completed):
        raise ValueError('Training snapshot requires all 40 complete grid rounds')
    return sorted(expected)


def training_snapshot(run, out, progress):
    labels = training_labels(run, progress)
    blocks = out / 'training_blocks'
    blocks.mkdir(parents=True, exist_ok=True)
    for label in labels:
        target = blocks / label
        if not target.exists():
            temporary = blocks / (label + '.copying')
            if temporary.exists():
                shutil.rmtree(temporary)
            shutil.copytree(run / 'collected_blocks' / label, temporary)
            temporary.rename(target)
    summarize_random.summarize_run(run, blocks_root=blocks,
                                  out_dir=out / 'training', allow_partial=True)


def verify_final(final, expected):
    if (final.get('error') is not None or final.get('completed_blocks') != expected
            or not final.get('configuration_restored')):
        raise RuntimeError('Grid acquisition ended without all blocks and verified restoration')


def watch(run, out, workers):
    prepared = campaign.load_run(run)
    protocol = json.loads((run / 'protocol.json').read_text())
    expected = len(prepared.schedule)
    training_count = len(protocol['training_rounds']) * len(protocol['policy_names']) * 2
    out.mkdir(parents=True, exist_ok=True)
    last = -1
    last_change = time.monotonic()
    fitted = False
    while True:
        progress = read_progress(run)
        n = len(progress)
        if n != last:
            print('PROGRESS', n, '/', expected, 'blocks;', n * 300, 'primary exchanges', flush=True)
            last = n
            last_change = time.monotonic()
        if (run / 'failure.json').exists() or (run / 'restoration_failure.json').exists():
            raise RuntimeError('Acquisition/restoration failed; evidence retained; no automatic retry')
        if n >= training_count and not fitted:
            training_snapshot(run, out, progress)
            analysis.fit(run, out / 'training/measurements.json',
                         out / 'training/primarytransactions.csv', out, workers)
            fitted = True
            print('TRAINING FROZEN: four policies fitted using rounds 0–39 only', flush=True)
            last_change = time.monotonic()
        if (run / 'final_status.json').exists():
            verify_final(json.loads((run / 'final_status.json').read_text()), expected)
            if not fitted:
                raise RuntimeError('No frozen models')
            summarize_random.summarize_run(run, out_dir=out / 'final')
            audit_tcp.audit(out / 'final/measurements.json', out / 'final/tcp_audit.json')
            analysis.score(run, out / 'final/measurements.json',
                           out / 'final/primarytransactions.csv', out, workers)
            grid_report.generate(run, out)
            campaign.rc.write_json(out / 'analysis_status.json', dict(status='complete',
                note='Acquisition, audit, held-out evaluation and figures finished; manuscript integration still requires review.'))
            print('COMPLETE: grid results and figures ready for review', flush=True)
            return
        if time.monotonic() - last_change > 900:
            raise RuntimeError('No completed block for 15 minutes; inspect acquisition, do not restart automatically')
        time.sleep(30)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--jobs', type=int, default=8)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('jobs must be positive')
    try:
        watch(args.run.resolve(), args.out.resolve(), args.jobs)
    except BaseException as exc:
        campaign.rc.write_json(args.out / 'analysis_status.json', dict(status='failed', error=repr(exc)))
        raise
