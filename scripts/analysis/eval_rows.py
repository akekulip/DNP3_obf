#!/usr/bin/env python3
"""One row per captured exchange of an evaluation campaign, with every input bound by SHA-256.

Rows come from each trial's relay_wire.json, which is the campaign's own parse of the master-NIC PCAPs
(scripts/checks/relay_check.analyze), and from master.json. A trial is refused, not repaired, when its
relay_wire artifact hashes no longer match its PCAPs or master record, when its exchanges do not match the
master's records one for one, or when it lacks the planned per-class counts.

  python3 scripts/analysis/eval_rows.py CAMPAIGN_DIR --output OUT_DIR
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = 'c72-eval-rows-v1'
EXPECTED = {'READ': 65, 'SELECT': 64, 'OPERATE': 64}
TRAIN_REPETITIONS = range(1, 9)
FIELDS = ('campaign', 'block_id', 'block_index', 'd_ms', 'repetition', 'split', 'arm', 'arm_position', 'trial',
          'seq', 'operation', 'read_class', 'clrt_ms', 'ack_ms', 'rt_ms', 'req_len', 'resp_len', 'resp_segments',
          'piggyback', 'outcome', 'iin', 'app_ok', 'crob', 'observed_at_ns', 'retx_out', 'retx_in', 'kernel_drops')
ARTIFACTS = ('out.pcap', 'in.pcap', 'master.json', 'result.json')


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def block_identity(block_id):
    """(D in ms, repetition, split) of an evaluation block ID eNN_dD_rRR; Nones for any other block."""
    match = re.fullmatch(r'e\d+_d(\d+)_r(\d+)', block_id)
    if not match:
        return None, None, None
    repetition = int(match.group(2))
    return int(match.group(1)), repetition, 'train' if repetition in TRAIN_REPETITIONS else 'test'


def trial_rows(trial, context, expected=None):
    """Rows, problems and the {path: sha256} of every input used for one trial directory."""
    trial = Path(trial)
    needed = ('relay_wire.json',) + ARTIFACTS
    missing = [name for name in needed if not (trial / name).is_file()]
    if missing:
        return [], ['%s: missing %s' % (trial.name, ', '.join(missing))], {}
    inputs = {str(trial / name): sha(trial / name) for name in needed}
    wire = json.loads((trial / 'relay_wire.json').read_text())
    master = json.loads((trial / 'master.json').read_text())
    problems = []
    if wire.get('ok') is not True or wire.get('failures'):
        problems.append('%s: relay_wire.json reports failure: %s' % (trial.name, (wire.get('failures') or [])[:3]))
    for direction, stats in sorted((wire.get('capture_drops') or {}).items()):
        if (stats or {}).get('dropped_kernel') != 0 or (stats or {}).get('dropped_interface', 0) != 0:
            problems.append('%s: capture drops %s %s' % (trial.name, direction, stats))
    for name in ARTIFACTS:
        if wire.get('artifacts', {}).get(name) != inputs[str(trial / name)]:
            problems.append('%s: %s differs from the bytes relay_wire.json analysed' % (trial.name, name))
    exchanges, records = wire.get('exchanges', []), master.get('records', [])
    if len(exchanges) != len(records):
        problems.append('%s: %d exchanges for %d master records' % (trial.name, len(exchanges), len(records)))
    retransmissions = wire.get('retransmissions') or {}
    drops = sum(int((stats or {}).get('dropped_kernel') or 0) + int((stats or {}).get('dropped_interface') or 0)
                for stats in (wire.get('capture_drops') or {}).values())
    counts = {}
    rows = []
    for seq, (exchange, record) in enumerate(zip(exchanges, records)):
        operation = exchange.get('operation')
        counts[operation] = counts.get(operation, 0) + 1
        if operation != record.get('operation'):
            problems.append('%s: exchange %d is %s, master record is %s' % (trial.name, seq, operation,
                                                                          record.get('operation')))
            continue
        request, response = exchange.get('request'), exchange.get('response')
        if not request or not response or exchange.get('ack_timestamp_ns') is None:
            problems.append('%s: exchange %d has no complete request/ACK/response span' % (trial.name, seq))
            continue
        start, ack, done = (request['first_timestamp_ns'], exchange['ack_timestamp_ns'],
                            response['complete_timestamp_ns'])
        application = exchange.get('application') or {}
        if application.get('ok') is not True:
            problems.append('%s: exchange %d application check failed: %s' % (
                trial.name, seq, (application.get('failures') or [])[:2]))
        rows.append(dict(context, trial=trial.name, seq=seq, operation=operation,
                         read_class=exchange.get('workload') or '',
                         clrt_ms=(done - ack) / 1e6, ack_ms=(ack - start) / 1e6, rt_ms=(done - start) / 1e6,
                         req_len=sum(request['actual_payload_lengths']),
                         resp_len=sum(response['actual_payload_lengths']),
                         resp_segments=len(response['actual_payload_lengths']),
                         piggyback=int(bool(exchange.get('piggyback'))), outcome=record.get('outcome'),
                         iin=record.get('iin'), app_ok=int(application.get('ok') is True),
                         crob=';'.join('%d:%s' % tuple(point) for point in application.get('points') or []),
                         observed_at_ns=start, retx_out=retransmissions.get('out'),
                         retx_in=retransmissions.get('in'), kernel_drops=drops))
    if expected and counts != expected:
        problems.append('%s: exchanges per class %s, planned %s' % (trial.name, counts, expected))
    return rows, problems, inputs


def manifest_problems(run_root, inputs):
    """Every trial input must match the block's retained artifact_manifest.json (hashed at block end)."""
    path = Path(run_root) / 'artifact_manifest.json'
    if not path.is_file():
        return ['%s: artifact_manifest.json missing' % Path(run_root).name]
    files = json.loads(path.read_text()).get('files', {})
    problems = []
    for name, digest in sorted(inputs.items()):
        relative = str(Path(name).resolve().relative_to(Path(run_root).resolve()))
        if (files.get(relative) or {}).get('sha256') != digest:
            problems.append('%s: %s differs from the retained artifact manifest' % (Path(run_root).name, relative))
    return problems


def campaign_rows(campaign):
    """Rows of every completed block, in manifest order, plus per-block status and problems."""
    campaign = Path(campaign).resolve()
    manifest = json.loads((campaign / 'manifest.json').read_text())
    rows, problems, inputs, blocks = [], [], {str(campaign / 'manifest.json'): sha(campaign / 'manifest.json')}, []
    for index, step in enumerate(manifest['steps']):
        terminal_path = campaign / 'steps' / step['id'] / 'terminal.json'
        terminal = json.loads(terminal_path.read_text()) if terminal_path.is_file() else {}
        status = terminal.get('status', 'unexecuted')
        blocks.append(dict(id=step['id'], status=status, reason=terminal.get('reason')))
        if status != 'completed':
            continue
        inputs[str(terminal_path)] = sha(terminal_path)
        config_path = Path(step['argv'][4])
        config = json.loads(config_path.read_text())
        inputs[str(config_path)] = sha(config_path)
        d_ms, repetition, split = block_identity(step['id'])
        d_ms = d_ms if d_ms is not None else config['timing_params_ns']['gap'] // 1000000
        order = [arm['name'] for arm in config['arms']]
        run_root = Path(step['run_root'])
        trials = sorted(path.parent for path in run_root.glob('*/*/*/relay_wire.json'))
        if sorted(path.parent.name for path in trials) != sorted(order):
            problems.append('%s: trial arms %s, planned %s' % (step['id'], [p.parent.name for p in trials], order))
        for trial in trials:
            arm = trial.parent.name
            context = dict(campaign=manifest['campaign_id'], block_id=step['id'], block_index=index, d_ms=d_ms,
                           repetition=repetition, split=split, arm=arm,
                           arm_position=order.index(arm) if arm in order else None)
            got, trial_problems, trial_inputs = trial_rows(trial, context, EXPECTED)
            rows.extend(got)
            problems.extend('%s: %s' % (step['id'], p) for p in trial_problems)
            problems.extend(manifest_problems(run_root, trial_inputs))
            inputs.update(trial_inputs)
    return rows, problems, inputs, blocks


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('campaign', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    rows, problems, inputs, blocks = campaign_rows(args.campaign)
    args.output.mkdir(parents=True, exist_ok=True)
    with (args.output / 'rows.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    record = dict(schema=SCHEMA, campaign=str(args.campaign.resolve()), rows=len(rows),
                  rows_sha256=sha(args.output / 'rows.csv'), extractor_sha256=sha(__file__),
                  blocks=blocks, problems=problems, inputs=inputs)
    (args.output / 'rows_manifest.json').write_text(json.dumps(record, indent=1) + '\n')
    excluded = [b for b in blocks if b['status'] != 'completed']
    print(json.dumps(dict(rows=len(rows), completed_blocks=sum(b['status'] == 'completed' for b in blocks),
                          excluded_blocks={b['id']: b['status'] for b in excluded if b['status'] != 'unexecuted'},
                          unexecuted_blocks=sum(b['status'] == 'unexecuted' for b in excluded),
                          problems=problems[:20], problem_count=len(problems)), indent=1))
    return 1 if problems else 0


if __name__ == '__main__':
    raise SystemExit(main())
