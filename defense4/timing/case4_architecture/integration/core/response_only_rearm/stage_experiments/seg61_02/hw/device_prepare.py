#!/usr/bin/env python3
"""Frozen collection order and offline hooks for the m11_09 device-classification study.

Protocol: seg61_02/evaluation/DEVICE_STUDY_PROTOCOL.md (pre-registered 2026-10-19). The binary, the
common envelope, the shaping and the supervision are those of eval_m11_09_20261018_02; only the
emulated device (netem delay, jitter and distribution of the outstation's READ responses) and the
schedule differ. No command here touches hardware: the detached evaluation_campaign controller runs
run_block_frozen.sh for each block, and these hooks only prepare, check and analyse.
"""
import argparse
import csv
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import evaluation_prepare as ep  # noqa: E402

SEG = ep.SEG
ARMS = ('off', 'combined')
CONDITION = ep.CONDITIONS[1]                    # D10_J2p4, the primary setting
# (name, netem delay ms, jitter ms, distribution); netem tables bound a sample to delay + 4 x jitter
DEVICES = (('dev_const5', 5, 0, None), ('dev_sel', 2, 2, 'paretonormal'), ('dev_slow', 9, 1, 'normal'))
PILOT_READS, MAIN_READS, ROUNDS = 64, 512, 16
CAMPAIGN = SEG / 'evidence/evaluation_campaigns/eval_m11_09_20261018_02'
ENVELOPE = CAMPAIGN / 'common_envelope.json'


def collection_order(campaign_id):
    ep.collection_order(campaign_id)            # reuses its campaign-ID validation
    out = []
    def add(phase, label, device, number, arms, reads, split=None):
        name, delay, jitter, distribution = device
        out.append(dict(id=campaign_id + '_' + label, phase=phase, collection_index=len(out),
                        condition_id=CONDITION[0], D_ns=CONDITION[1], J_ns=CONDITION[2], round=number,
                        split=split, arms=list(arms), reads=reads, sbo=0, device=name, delay_ms=delay,
                        jitter_ms=jitter, distribution=distribution, expected_exchanges=len(arms) * reads,
                        tool='candidate_campaign', arguments=[]))
    for device in DEVICES:
        add('pilot', 'pilot_' + device[0], device, 0, ARMS, PILOT_READS)
    for r in range(1, ROUNDS + 1):
        k = (r - 1) % len(DEVICES)
        arms = ARMS if r % 2 else tuple(reversed(ARMS))
        for device in DEVICES[k:] + DEVICES[:k]:
            add('main', 'r%02d_%s' % (r, device[0]), device, r, arms, MAIN_READS,
                'training' if r <= 8 else 'testing')
    return out


def device_config(template, block, envelope, order_sha):
    cfg = ep.evaluation_config(template, block, envelope, order_sha)
    cfg['fixture'].update(modes=['separate_ack'], delay_ms=block['delay_ms'], jitter_ms=block['jitter_ms'])
    if block['jitter_ms']:
        cfg['fixture']['distribution'] = block['distribution']
    cfg['evaluation'].update(purpose='timing_precision_characterization', study='device_classification',
                             device=block['device'], protocol='DEVICE_STUDY_PROTOCOL.md')
    return cfg


def prepare(root, campaign_id):
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=False)
    if ep.sha(ep.BUILD / 'response_only.p4') != ep.SOURCE:
        raise ValueError('selected source changed')
    envelope = ep.load(ENVELOPE)
    order = collection_order(campaign_id)
    ep.write_new(root / 'collection_order.json', order)
    order_sha = ep.sha(root / 'collection_order.json')
    main = [b for b in order if b['phase'] == 'main']
    ep.write_new(root / 'definition.json', dict(schema_version=1, campaign_id=campaign_id, study='device_classification',
        collection_order_sha256=order_sha, hardware_blocks=len(order), main_blocks=len(main),
        main_exchanges=sum(b['expected_exchanges'] for b in main), evidence_kind='hardware', source_sha256=ep.SOURCE,
        build=str(ep.BUILD), no_replacement=True, envelope_source=str(ENVELOPE), envelope_sha256=ep.sha(ENVELOPE),
        devices=[dict(device=d, delay_ms=a, jitter_ms=j, distribution=s) for d, a, j, s in DEVICES]))
    ep.write_new(root / 'common_envelope.json', envelope)
    template = ep.load(ep.BUILD / 'configs/part2_m11_09_ref_r30_b1.json')
    for block in order:
        cfg = device_config(template, block, envelope, order_sha)
        cfg['evidence_dir'] = str(root / 'blocks')
        ep.write_new(ep.config_path(root, block), cfg)
    steps = []
    def hook(name):
        steps.append(dict(id=name, kind='hook', argv=['/usr/bin/python3', str(Path(__file__).resolve()), name, str(root)]))
    for i, block in enumerate(order):
        if i == len(DEVICES):
            hook('qualify')
        if block['phase'] == 'main' and block['round'] == 9 and order[i-1]['round'] == 8:
            hook('fit')
        steps.append(dict(id=block['id'], kind='block', run_root=str(ep.run_root(root, block)),
                          argv=['/bin/bash', str(ep.HW / 'run_block_frozen.sh'), str(root / 'freeze_device.json'),
                                block['tool'], str(ep.config_path(root, block)), block['id']] + block['arguments'],
                          postcheck_argv=['/usr/bin/python3', str(Path(__file__).resolve()), 'postcheck', str(root),
                                          '--block', block['id']]))
    hook('export')
    ep.write_new(root / 'controller_manifest.json', dict(campaign_id=campaign_id, evidence_kind='hardware', steps=steps))
    return root


def qualify(root):
    """Stop rule: every pilot block passed its postcheck (which already requires zero fallbacks, complete
    exchanges and a verified restore). Device CLRT profiles are recorded descriptively, never tuned on."""
    root = Path(root).resolve()
    definition, order = ep.frozen_order(root)
    pilots = [b for b in order if b['phase'] == 'pilot']
    ep.qualified(root, pilots)
    if any(ep.run_root(root, b).exists() for b in order if b['phase'] == 'main'):
        raise ValueError('main evidence predates pilot qualification')
    profiles = {}
    for block in pilots:
        ledger = ep.load(ep.run_root(root, block) / 'publication_ledger.json')
        for arm in ARMS:
            values = sorted(r['clrt_ns'] / ep.MS for r in ledger['records']
                            if r['record_type'] == 'captured_exchange' and r['txn_class'] == 'READ'
                            and r['arm'] == ('baseline' if arm == 'off' else arm) and ep.number(r.get('clrt_ns')))
            profiles['%s/%s' % (block['device'], arm)] = dict(
                n=len(values), median_ms=values[len(values)//2] if values else None,
                p95_ms=values[int(.95*(len(values)-1))] if values else None, max_ms=values[-1] if values else None)
    ep.write_new(root / 'device_qualification.json', dict(ok=True, collection_order_sha256=definition['collection_order_sha256'],
        postchecks={b['id']: ep.sha(ep.run_root(root, b) / 'evaluation_postcheck.json') for b in pilots},
        device_clrt_profiles=profiles, scope='descriptive; not used for training, testing or tuning'))


def rows(root, split):
    """Analysis rows of the qualified main blocks of one split, from their publication ledgers."""
    _, order = ep.frozen_order(root)
    blocks = [b for b in order if b['phase'] == 'main' and b['split'] == split]
    ep.qualified(root, blocks)
    out = []
    for block in blocks:
        for record in ep.load(ep.run_root(root, block) / 'publication_ledger.json')['records']:
            if record['record_type'] != 'captured_exchange' or record['txn_class'] != 'READ':
                continue
            out.append(dict(example_id=record['exchange_id'], block_id=block['id'], device=block['device'],
                            condition_id=block['condition_id'], round=block['round'], split=split,
                            arm='off' if record['arm'] == 'baseline' else record['arm'], operation='READ',
                            connection_id=record.get('connection_id'), session_id=record.get('session_id'),
                            sequence=record.get('sequence'), observed_at_ms=record.get('observed_at_ms'),
                            clrt_ms=record['clrt_ns'] / ep.MS if ep.number(record.get('clrt_ns')) else None))
    return out


def write_rows(path, values):
    with open(path, 'x', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=sorted({k for r in values for k in r}))
        writer.writeheader()
        writer.writerows(values)


def fit(root):
    root = Path(root).resolve()
    _, order = ep.frozen_order(root)
    if any(ep.run_root(root, b).exists() for b in order if b.get('split') == 'testing'):
        raise ValueError('test hardware already exists; refusing post-test training lock')
    write_rows(root / 'rows_training.csv', rows(root, 'training'))
    subprocess.run([str(ep.ANALYSIS_PYTHON), str(SEG / 'analysis/device_analysis.py'), 'fit',
                    str(root / 'rows_training.csv'), str(root / 'device_model_lock.json')], check=True)


def export(root):
    root = Path(root).resolve()
    write_rows(root / 'rows_testing.csv', rows(root, 'testing'))
    subprocess.run([str(ep.ANALYSIS_PYTHON), str(SEG / 'analysis/device_analysis.py'), 'evaluate',
                    str(root / 'rows_training.csv'), str(root / 'rows_testing.csv'),
                    str(root / 'device_model_lock.json'), str(root / 'results')], check=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('prepare', 'postcheck', 'qualify', 'fit', 'export'))
    parser.add_argument('root', type=Path)
    parser.add_argument('--campaign-id')
    parser.add_argument('--block')
    args = parser.parse_args(argv)
    if args.command == 'prepare':
        root = prepare(args.root, args.campaign_id)
        ep.freeze(root, 'freeze_device.json', [ep.config_path(root, b) for b in ep.frozen_order(root)[1]])
        print(root)
    elif args.command == 'postcheck':
        ep.postcheck(args.root, args.block)
    else:
        globals()[args.command](args.root)


if __name__ == '__main__':
    main()
