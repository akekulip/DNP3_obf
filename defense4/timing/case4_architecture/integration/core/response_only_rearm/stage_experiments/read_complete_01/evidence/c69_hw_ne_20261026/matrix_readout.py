#!/usr/bin/env python3
"""Read-only readout of the c69 SEL-751 matrix from the retained block evidence.

  python3 matrix_readout.py --out matrix_readout.json --md matrix_readout.md

Per block: campaign terminal rc and restoration, planned versus observed exchanges (master records), the trial
dimension verdicts (application, switch, receiver-visible standards; loss target where present) and failures, the
response sizes seen per class, and the visible CLRT per class at the master NIC (first ACK of the request -> complete
response; piggybacked ACKs counted apart). CLRT is reported data, never a criterion. Nothing here is recomputed into a
verdict: verdicts are the retained trial records'.
"""
import argparse
import json
import statistics
from pathlib import Path

HERE = Path(__file__).resolve().parent
RC = HERE.parents[1]
BLOCKS = [('01', 'smoke', 5, 4), ('11', 'smoke', 5, 4), ('12', 'reference', 5, 772),
          ('13', 'reference_rest', 10, 386), ('14', 'reference_rest', 15, 386), ('15', 'reference_rest', 20, 386),
          ('16', 'persistence_graceful_950', 20, 66), ('17', 'persistence_rst_950', 20, 66),
          ('18', 'reconnect_950', 20, 66), ('19', 'loss_mixed_950', 20, 154), ('20', 'loss_full_950', 20, 154)]
CLASSES = ('READ mixed', 'READ integrity', 'SELECT', 'OPERATE')


def connections(trial_dir):
    subs = [d for d in sorted(trial_dir.iterdir()) if d.is_dir() and (d / 'master.json').is_file()]
    return subs or [trial_dir]


def class_of(record):
    return 'READ ' + record.get('workload', '?') if record.get('operation') == 'READ' else record.get('operation')


def block(number, name, d_ms, planned):
    run = 'rc01_hw_c69_20261026_%s_%s' % (number, name)
    root = RC / 'evidence/hw_blocks' / run
    terminal = json.loads((RC / 'evidence/hw_campaigns' / ('rc01_hw_c69_20261026_' + number) / 'steps' / run /
                           'terminal.json').read_text())
    restore = json.loads((root / 'restore_verify.json').read_text())
    out = {'run_id': run, 'D_ms': d_ms, 'planned_exchanges': planned, 'block_rc': terminal.get('rc'),
           'restoration_ok': restore.get('ok'), 'arms': {}}
    observed_total, ok_total = 0, 0
    for trial_json in sorted(root.glob('physical_relay/*/*/trial.json')):
        trial_dir, arm = trial_json.parent, trial_json.parent.parent.name
        trial = json.loads(trial_json.read_text())
        clrt, sizes, counts = {c: [] for c in CLASSES}, {c: set() for c in CLASSES}, {c: 0 for c in CLASSES}
        piggy, outcomes = {c: 0 for c in CLASSES}, {}
        for conn in connections(trial_dir):
            master = json.loads((conn / 'master.json').read_text())
            for rec in master.get('records', []):
                c = class_of(rec)
                counts[c] = counts.get(c, 0) + 1
                outcomes[rec.get('outcome')] = outcomes.get(rec.get('outcome'), 0) + 1
                sizes.setdefault(c, set()).add(len(bytes.fromhex(rec.get('response_wire_hex') or '')))
            wire = json.loads((conn / 'relay_wire.json').read_text()) if (conn / 'relay_wire.json').is_file() else {}
            for row in wire.get('exchanges', []):
                c = 'READ ' + str(row.get('workload')) if row['operation'] == 'READ' else row['operation']
                if row.get('piggyback'):
                    piggy[c] += 1
                elif row.get('complete_clrt_us') is not None:
                    clrt[c].append(row['complete_clrt_us'] / 1000)
        n = sum(counts.values())
        observed_total += n
        ok_total += outcomes.get('OK', 0)
        key = trial_dir.name.rsplit('_', 1)[-1]
        out['arms'].setdefault(arm, {})[key] = {
            'ok': trial.get('ok'), 'dimension_verdicts': trial.get('dimension_verdicts'),
            'failures': trial.get('failures'), 'exchanges': n, 'outcomes': outcomes,
            'counts': {c: v for c, v in counts.items() if v},
            'response_bytes': {c: sorted(s) for c, s in sizes.items() if s},
            'visible_clrt_ms': {c: {'n': len(v), 'piggyback': piggy[c],
                                    'min': round(min(v), 3) if v else None,
                                    'median': round(statistics.median(v), 3) if v else None,
                                    'max': round(max(v), 3) if v else None}
                                for c, v in clrt.items() if v or piggy[c]}}
    out.update(observed_exchanges=observed_total, ok_outcomes=ok_total,
               all_trials_ok=all(t['ok'] for a in out['arms'].values() for t in a.values()))
    return out


def markdown(blocks):
    lines = ['| run | D ms | planned | observed | OK outcomes | block rc | restored | all trials ok |',
             '|---|---:|---:|---:|---:|---:|---|---|']
    for b in blocks:
        lines.append('| %s | %s | %d | %d | %d | %s | %s | %s |' % (
            b['run_id'], b['D_ms'], b['planned_exchanges'], b['observed_exchanges'], b['ok_outcomes'],
            b['block_rc'], b['restoration_ok'], b['all_trials_ok']))
    lines += ['', '| run | arm | class | n | piggyback | min ms | median ms | max ms | response bytes |',
              '|---|---|---|---:|---:|---:|---:|---:|---|']
    for b in blocks:
        for arm, trials in b['arms'].items():
            merged = {}
            for t in trials.values():
                for c, v in t['visible_clrt_ms'].items():
                    merged.setdefault(c, []).append((v, t['response_bytes'].get(c)))
            for c in CLASSES:
                for v, size in merged.get(c, []):
                    lines.append('| %s | %s | %s | %d | %d | %s | %s | %s | %s |' % (
                        b['run_id'].split('_20261026_')[1], arm, c, v['n'], v['piggyback'], v['min'], v['median'],
                        v['max'], size))
    return '\n'.join(lines) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--md', type=Path, required=True)
    args = parser.parse_args()
    blocks = [block(*b) for b in BLOCKS]
    args.out.write_text(json.dumps({'observation': 'master NIC; CLRT = first ACK of the request -> complete response; '
                                                   'reported, never gated', 'blocks': blocks}, indent=1) + '\n')
    args.md.write_text(markdown(blocks))
    print(markdown(blocks).split('\n\n')[0])


if __name__ == '__main__':
    main()
