"""Combine c52 reference blocks 24 (off, timing_only) and 31 (size_only, combined) into one 772-exchange ledger.
Copies verdicts as recorded; recomputes nothing."""
import glob, hashlib, json, sys
from pathlib import Path
RC = Path('/home/philip/Projects/DNP3/defense4/timing/case4_architecture/integration/core/response_only_rearm/stage_experiments/read_complete_01')
BLOCKS = {'rc01_hw_c52_20261024_24_reference': ['off', 'timing_only', 'size_only', 'combined'],
          'rc01_hw_c52_20261024_31_reference_rest': ['size_only', 'combined']}
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
arms, blocks = {}, {}
for block, planned_arms in BLOCKS.items():
    root = RC / 'evidence/hw_blocks' / block
    run = json.loads((root / 'campaign_run.json').read_text())
    fc = json.loads((root / 'freeze_check.json').read_text())
    blocks[block] = dict(campaign_run_sha256=sha(root / 'campaign_run.json'), config_sha256=fc.get('config_sha256'),
                         freeze=fc.get('freeze'), block_ok=run.get('ok'), restore_ok=all(s['ok'] for s in run.get('restore', [])), restore_verify_errors=json.loads((root / 'restore_verify_postrun.json').read_text())['errors'],
                         arms_planned=planned_arms, arms_run=sorted(p.name for p in (root / 'physical_relay').iterdir()))
    for arm in planned_arms:
        trials = sorted(glob.glob(str(root / 'physical_relay' / arm / '*/trial.json')))
        if arm in arms:
            continue  # first block that ran the arm owns it
        if not trials:
            continue
        t = json.loads(Path(trials[0]).read_text())
        prec = t['observed']['connections']['single']['precision']
        arms[arm] = dict(block=block, trial_sha256=sha(trials[0]), ok=t['ok'], dimension_verdicts=t['dimension_verdicts'],
                         failures=t['failures'], switch_outcomes=t['observed']['switch']['outcomes'],
                         per_operation={op: dict(planned=v['planned'], eligible=v['eligible'],
                                                 p99_abs_error_us=v['p99_nearest_rank_abs_error_us'],
                                                 max_abs_error_us=v['max_abs_error_us'], pass_100us=v['pass_'])
                                        for op, v in prec.items()})
order = ['off', 'timing_only', 'size_only', 'combined']
planned = sum(v['planned'] for a in arms.values() for v in a['per_operation'].values())
ledger = dict(candidate='m12p_c52_sdk9132', criterion_us=100, blocks=blocks,
              arms={a: arms[a] for a in order if a in arms}, missing_arms=[a for a in order if a not in arms],
              planned_exchanges=planned, full_denominator=772, denominator_complete=planned == 772 and len(arms) == 4,
              timing_verdict='fails the 100 us criterion in every timing arm' if all(
                  not v['pass_100us'] for a in ('timing_only', 'combined') if a in arms for v in arms[a]['per_operation'].values()) else 'see arms',
              operate_j='unproven: no relay-side observation',
              note='Verdicts copied from each trial.json; nothing recomputed. Block 24 stopped after timing_only on its '
                   'switch gate (one ACK/RESP fallback on the first READ); block 31 ran the remaining arms under freeze_v3_ref2.')
out = RC / 'evidence/c52_reference_ledger_20261024.json'
with out.open('x') as s:
    json.dump(ledger, s, indent=1); s.write('\n')
print(json.dumps(dict(planned=planned, complete=ledger['denominator_complete'], missing=ledger['missing_arms'],
                      arms={a: (v['ok'], v['dimension_verdicts']) for a, v in ledger['arms'].items()}), indent=1))
