#!/usr/bin/env python3
"""Derive the candidate57s repeated four-arm evaluation (directive f813bc089 §6) from candidate57s_fourarm_smoke.

Three independent blocks; each is one campaign run of the four arms (off, timing_only, size_only, combined),
one cold bring-up per arm, 500 completed READs per arm plus one software-handler SBO. Order is balanced by
rotating the arm sequence per block (Latin square over three blocks); the processing-fixture delay, the
seed for the start phase, and the start-delay bound vary per block within a bounded matrix. The separate-ACK
fixture is emulated (vision_run.py casea), as in every candidate run.
  python3 make_candidate57s_eval.py     (writes candidate57s_eval_b1..b3.json)
"""
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORDERS = (('off', 'timing_only', 'size_only', 'combined'),
          ('combined', 'off', 'timing_only', 'size_only'),
          ('size_only', 'combined', 'off', 'timing_only'))
BLOCKS = ({'delay_ms': 5, 'rng_seed': 57101, 'start_delay_ms': 50},
          {'delay_ms': 3, 'rng_seed': 57202, 'start_delay_ms': 50},
          {'delay_ms': 8, 'rng_seed': 57303, 'start_delay_ms': 50})
READS = 500


def derive(base, b):
    cfg = json.loads(json.dumps(base))
    arms = {a['name']: a for a in cfg['arms']}
    cfg['arms'] = [arms[n] for n in ORDERS[b]]
    cfg['trials'].update(reads_per_trial=READS, trials_per_arm=1)
    cfg['fixture']['delay_ms'] = BLOCKS[b]['delay_ms']
    cfg['seeds']['rng_seed'] = BLOCKS[b]['rng_seed']
    cfg['traffic']['start_delay_ms'] = BLOCKS[b]['start_delay_ms']
    cfg['evaluation'] = dict(cfg.get('evaluation', {}), purpose='timing_precision_characterization', block=b + 1,
                             arm_order=list(ORDERS[b]))
    cfg['_notes'] = ['candidate57s repeated evaluation block %d of 3 (make_candidate57s_eval.py): arms %s, '
                     'fixture delay %d ms, %d READs per arm. Emulated separate-ACK fixture; software-handler SBO. Every hard gate applies; only the provisional 100 us p99 READ-precision threshold may fail without stopping the block (timing_precision_characterization).'
                     % (b + 1, ', '.join(ORDERS[b]), BLOCKS[b]['delay_ms'], READS)] + cfg.get('_notes', [])
    readiness_ms = cfg['timing_params_ns']['readiness'] / 1e6 if 'readiness' in cfg.get('timing_params_ns', {}) else None
    if readiness_ms is not None:
        assert readiness_ms > BLOCKS[b]['delay_ms'] + cfg['fixture'].get('readiness_margin_ms', 0), 'readiness'
    return cfg


def dup_hold(base):
    """candidate57s_dup_hold_500: the strict graceful same-tuple series with the OPERATE hold op_j raised to 500 ms,
    above the master's kernel RTO (~200 ms). The outstation cannot acknowledge a held OPERATE, so the master's TCP
    itself retransmits it while the original is held: a genuine early duplicate on silicon. Expected with
    dup_hold_01: the copy is dropped (OUT_OP_DUP_DROP +1 per connection), the original is released once at the
    deadline, exactly one real OPERATE callback per connection."""
    cfg = json.loads(json.dumps(base))
    cfg['timing_params_ns']['op_j'] = 500000000
    cfg['_notes'] = ['candidate57s_dup_hold_500 (make_candidate57s_eval.py): graceful series with op_j 500 ms > RTO, '
                     'so the master retransmits the held OPERATE; tests dup_hold_01 on silicon.'] + cfg.get('_notes', [])
    return cfg


if __name__ == '__main__':
    graceful = json.loads((HERE / 'candidate57s_graceful_800.json').read_text())
    (HERE / 'candidate57s_dup_hold_500.json').write_text(json.dumps(dup_hold(graceful), indent=2) + '\n')
    print('wrote candidate57s_dup_hold_500.json')
    base = json.loads((HERE / 'candidate57s_fourarm_smoke.json').read_text())
    for b in range(3):
        name = 'candidate57s_eval_b%d.json' % (b + 1)
        (HERE / name).write_text(json.dumps(derive(base, b), indent=2) + '\n')
        print('wrote', name)
