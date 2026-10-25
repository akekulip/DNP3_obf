"""Offline replay of the c67 physical reference blocks with the campaign checker (relay_check.py).

Not an independent checker validation: it reruns protocol/hw_vepa/relay_check.analyze and .precision exactly as
campaign.py relay_verdict does, on the retained captures and master records, with the frozen config's gap, SBO count
and read schedule and each trial's own master port and READ count. It never calls relay_check.main (that writes
relay_wire.json into the evidence) and writes only the new ledger beside this script, refusing to overwrite it.
"""
import glob
import hashlib
import json
import sys
from pathlib import Path

ARCH = Path(__file__).resolve().parents[6]
RC = Path(__file__).resolve().parents[1]
REPO = ARCH.parents[2]
sys.path[:0] = [str(ARCH / 'protocol/hw_vepa')]
import checks  # noqa: E402
import relay_check  # noqa: E402

BLOCKS = ['rc01_hw_c67_20261025_03_reference', 'rc01_hw_c67_20261025_04_reference_rest',
          'rc01_hw_c67_20261025_05_reference_rest', 'rc01_hw_c67_20261025_06_reference_rest']
sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()

blocks, cells, disagreements = {}, [], []
for block in BLOCKS:
    root = RC / 'evidence/hw_blocks' / block
    frozen = json.loads((root / 'freeze_check.json').read_text())
    config_path = REPO / frozen['config']
    assert sha(config_path) == frozen['config_sha256'], config_path
    cfg = json.loads(config_path.read_text())
    gap_ns, sbo = cfg['timing_params_ns']['gap'], checks.sbo_count(cfg['traffic'])
    schedule = cfg['traffic']['read_schedule']
    blocks[block] = dict(config=frozen['config'], config_sha256=frozen['config_sha256'], freeze=frozen['freeze'],
                         D_ns=gap_ns, sbo=sbo, read_schedule=schedule)
    for trial_path in sorted(glob.glob(str(root / 'physical_relay/*/*/trial.json'))):
        directory = Path(trial_path).parent
        arm = directory.parent.name
        trial = json.loads(Path(trial_path).read_text())
        report = relay_check.analyze(directory, trial['master_port'], dict(READ=trial['reads'], SELECT=sbo, OPERATE=sbo),
                                     schedule)
        mixed = (trial['reads'] + 1) // 2 if schedule == 'mixed_full' else trial['reads'] if schedule == 'mixed' else 0
        planned = {'READ mixed': mixed, 'READ integrity': trial['reads'] - mixed, 'SELECT': sbo, 'OPERATE': sbo}
        replayed = relay_check.precision(report, gap_ns, split_reads=True, planned=planned)
        recorded = trial['observed']['connections']['single']['precision']
        retained = json.loads((directory / 'relay_wire.json').read_text())
        same_clrt = [e['complete_clrt_us'] for e in report['exchanges']] == \
                    [e['complete_clrt_us'] for e in retained['exchanges']]
        if replayed != recorded or not same_clrt:
            disagreements.append(dict(block=block, arm=arm, precision_equal=replayed == recorded,
                                      complete_clrt_equal=same_clrt))
        timed = bool(trial['observed']['connections']['single']['timing_gated'])
        for workload, v in replayed.items():
            cells.append(dict(block=block, D_ms=gap_ns / 1e6, arm=arm, workload=workload, timing_gated=timed,
                              planned=v['planned'], observed=v['observed'], eligible=v['eligible'],
                              complete_clrt_us=v['complete_clrt_us'],
                              p99_nearest_rank_abs_error_us=v['p99_nearest_rank_abs_error_us'],
                              max_abs_error_us=v['max_abs_error_us'], pass_100us=v['pass_']))
        blocks[block].setdefault('trials', {})[arm] = dict(
            trial=str(Path(trial_path).relative_to(REPO)), trial_sha256=sha(trial_path),
            inputs_sha256={name: sha(directory / name) for name in ('out.pcap', 'in.pcap', 'master.json', 'result.json')},
            replay_checker_ok=report['ok'], replay_checker_failures=report['failures'])

timed = [c for c in cells if c['timing_gated']]
errors = [c['p99_nearest_rank_abs_error_us'] for c in timed]
ledger = dict(
    candidate='m12p_c67_sdk9132', criterion_us=100,
    method='offline replay with the campaign checker (protocol/hw_vepa/relay_check.py analyze + precision, '
           'split_reads, planned denominators); not an independent checker validation',
    checker_sha256=sha(ARCH / 'protocol/hw_vepa/relay_check.py'), blocks=blocks, cells=cells,
    planned_exchanges=sum(c['planned'] for c in cells),
    observed_exchanges=sum(c['observed'] for c in cells), eligible_exchanges=sum(c['eligible'] for c in cells),
    timed_cells=len(timed), timed_cells_passing=sum(c['pass_100us'] for c in timed),
    timed_p99_abs_error_us_range=[min(errors), max(errors)] if errors else None,
    disagreements_with_recorded=disagreements,
    note='Error is |complete CLRT - D| at the master NIC; CLRT itself is the latency. Only the master NIC is observed.')
out = RC / 'evidence/c67_reference_replay_20261025.json'
with out.open('x') as stream:
    json.dump(ledger, stream, indent=1)
    stream.write('\n')
print(json.dumps({k: ledger[k] for k in ('planned_exchanges', 'observed_exchanges', 'eligible_exchanges', 'timed_cells',
                                         'timed_cells_passing', 'timed_p99_abs_error_us_range',
                                         'disagreements_with_recorded')}, indent=1))
