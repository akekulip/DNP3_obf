#!/usr/bin/env python3
"""Compiler-reported resources of each m9 efficiency probe against m9_01, per compile and per pipe.

  python3 efficiency_probes_m9/compare_resources.py      # writes efficiency_probes_m9/resource_comparison.json

Read from each compile's own reports only: stages per role (resource_review.json), the MAU 'Totals' row of
p0/p1 logs/mau.resources.log, and 'Overall PHV Usage' of the final logs/phv_allocation_summary_*.log. A probe is
an improvement only where a reported number falls with every other number and both SDKs agreeing; fewer source
lines or tables are not evidence.
"""
import json
import re
from pathlib import Path

CT = Path(__file__).resolve().parents[1]
BUILDS = ('m9_01', 'probe_n_zero_unused_timestamp_m9_01', 'probe_t_single_child_m9_01', 'probe_n_bank_diffs_m9_01')
COMPILES = ('compile_local', 'compile_switch_9132')
COLUMNS = ('Exact Match Input xbar', 'Ternary Match Input xbar', 'Hash Bit', 'Hash Dist Unit', 'Gateway', 'SRAM',
           'Map RAM', 'TCAM', 'VLIW Instr', 'Meter ALU', 'Stats ALU', 'Logical TableID')


def mau_totals(log):
    lines = log.read_text().splitlines()
    header = next(l for l in lines if l.startswith('| Stage Number'))
    names = [c.strip() for c in header.strip('|').split('|')]
    totals = next(l for l in lines if l.strip().startswith('|') and 'Totals' in l)
    values = [c.strip() for c in totals.strip('|').split('|')]
    row = dict(zip(names, values))
    return {k: int(row[k]) for k in COLUMNS if row.get(k, '').isdigit()}


def phv_overall(logs):
    final = sorted(logs.glob('phv_allocation_summary_*.log'), key=lambda p: int(re.findall(r'\d+', p.name)[-1]))[-1]
    line = next(l for l in final.read_text().splitlines() if 'Overall PHV Usage' in l)
    return [int(x) for x in re.findall(r'\|\s*(\d+) \(', line)]


def main():
    out = {}
    for build in BUILDS:
        review = json.loads((CT / 'evidence' / build / 'resource_review.json').read_text())
        for comp in COMPILES:
            o = CT / 'evidence' / build / comp / 'out'
            out.setdefault(build, {})[comp] = dict(
                stages=review['compiles'][comp]['stages'], mirror_guard=review['compiles'][comp]['mirror_guard'][:4],
                mau={pipe: mau_totals(o / pipe / 'logs/mau.resources.log') for pipe in ('p0', 'p1')},
                phv_overall_used={pipe: phv_overall(o / pipe / 'logs') for pipe in ('p0', 'p1')})
    delta = {}
    for build in BUILDS[1:]:
        for comp in COMPILES:
            base, probe = out['m9_01'][comp], out[build][comp]
            d = {pipe: {k: probe['mau'][pipe].get(k, 0) - base['mau'][pipe].get(k, 0) for k in COLUMNS
                        if probe['mau'][pipe].get(k, 0) != base['mau'][pipe].get(k, 0)} for pipe in ('p0', 'p1')}
            phv = {pipe: [a - b for a, b in zip(probe['phv_overall_used'][pipe], base['phv_overall_used'][pipe])]
                   for pipe in ('p0', 'p1')}
            stages = {r: probe['stages'][r] - base['stages'][r] for r in base['stages']}
            delta.setdefault(build, {})[comp] = dict(stages=stages, mau=d, phv_overall_used=phv)
    result = dict(baseline='m9_01', builds=out, delta_vs_m9=delta)
    (CT / 'efficiency_probes_m9/resource_comparison.json').write_text(json.dumps(result, indent=1) + '\n')
    for build, comps in delta.items():
        for comp, d in comps.items():
            print(build, comp, 'stages', d['stages'], 'mau', d['mau'], 'phv', d['phv_overall_used'])


if __name__ == '__main__':
    main()
