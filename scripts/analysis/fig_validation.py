#!/usr/bin/env python3
"""Validation figure (question 2, communication survives): E3 recovery and E2 connection-start drops.

    $RESEARCH_PYTHON scripts/analysis/fig_validation.py [--out results/analysis/validation/figures]

(a) E3: when the relay acknowledged the recovered OPERATE (ms after the SELECT request), per trial, by condition;
    filled = CROB SUCCESS, open = TIMEOUT. Sources: results/analysis/recovery_e3/e3_trials.json and the retained
    qualification block 10 t3.
(b) E2: the master frame the switch did not forward at connection start, over the mirror-on fresh connections of
    the diagnostic build, from the retained trial captures and switch counters (results/hardware/blocks/).
"""
import argparse
import json
import sys
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import diag_mirror_capture as cap  # noqa: E402
import diag_mirror_d3 as d3  # noqa: E402
import fig_style as fs  # noqa: E402
import recovery_e3  # noqa: E402

BLOCKS = ROOT / 'results/hardware/blocks'
QUAL_T3 = BLOCKS / ('rc01_hw_c72_20261027_02_10_d20_loss_full/physical_relay/combined/'
                    'rc01_hw_c72_20261027_02_10_d20_loss_full_physical_relay_combined_t3')
CONDITIONS = (('r1_d20_combined', 'D=20, T+S'), ('r2_d20_size_only', 'D=20, S'), ('r3_d5_combined', 'D=5, T+S'),
              ('qualification', 'Qual. t3'))
MIRROR_ON = ('rc01_hw_c72diag_d3on_20261028_01_d3_mirror_on_d20', 'rc01_hw_c72diag_e2_20261028_01_e2_first_request_d20')


def e3_points():
    rows = json.loads((ROOT / 'results/analysis/recovery_e3/e3_trials.json').read_text())['rows']
    rows = rows + [dict(recovery_e3.trial(QUAL_T3), condition='qualification')]
    points = []
    for row in rows:
        condition = row.get('condition') or next(c for c, _ in CONDITIONS[:3] if c in row['trial'])
        ok = all(status == 'SUCCESS' for _, status in row['operate_points'])
        points.append((condition, row['ms_from_select_request']['relay_ack_of_operate'], ok))
    return points


def e2_counts():
    """Per mirror-on fresh connection: which master frame the switch received and did not emit (no egress copy and
    dev9 RX - dev64 TX covers it): the final handshake ACK, the first request, or none."""
    counts = dict(none=0, handshake_ack=0, first_request=0)
    for block in MIRROR_ON:
        for path in sorted((BLOCKS / block / 'physical_relay').glob('*/*_t*')):
            trial = cap.load(path)
            copies = {(s['seq'], s['ack'], s['flags'], s['frame'][18:20]) for s in trial['mirror']['to_relay']}
            missing = [s for s in trial['master']['to_relay'][:3]
                       if (s['seq'], s['ack'], s['flags'], s['frame'][18:20]) not in copies]
            cnt, _ = d3.counters(trial)
            dropped = missing and cnt and cnt['dev9']['rx'] - cnt['dev64']['tx'] >= len(missing)
            if not dropped:
                counts['none'] += 1
            elif missing[0]['len']:
                counts['first_request'] += 1
            else:
                counts['handshake_ack'] += 1
    return counts


def figure(out):
    fs.setup()
    fig, (a, b) = fs.pair()
    points = e3_points()
    for x, (condition, _) in enumerate(CONDITIONS):
        for k, (c, y, ok) in enumerate(p for p in points if p[0] == condition):
            a.plot(x + (k - 2.5) * 0.06, y, marker='o', ms=4.5, ls='none', markeredgecolor=fs.EDGE,
                   markeredgewidth=0.7, color=fs.ARM_COLOR['combined'] if ok else 'white', zorder=3)
    a.axhline(1000, **fs.CHANCE)
    a.set_xticks(range(len(CONDITIONS)), [label for _, label in CONDITIONS])
    a.set_ylabel('Relay ACK of OPERATE (ms)')
    counts = e2_counts()
    labels = ('No frame lost', 'Handshake ACK\nnot forwarded', 'First request\nnot forwarded')
    values = (counts['none'], counts['handshake_ack'], counts['first_request'])
    b.bar(range(3), values, color=[fs.ARM_COLOR['off'], fs.ARM_COLOR['timing_only'], fs.ARM_COLOR['combined']],
          edgecolor=fs.EDGE, linewidth=0.6, width=0.6)
    b.set_xticks(range(3), labels)
    b.set_ylabel('Fresh connections (of %d)' % sum(values))
    fs.panel_titles((a, b), ('E3 SELECT-response loss', 'E2 connection start (diagnostic)'))
    handles = [plt.Line2D([], [], marker='o', ls='none', color=fs.ARM_COLOR['combined'], markeredgecolor=fs.EDGE,
                          label='OPERATE SUCCESS'),
               plt.Line2D([], [], marker='o', ls='none', color='white', markeredgecolor=fs.EDGE,
                          label='OPERATE TIMEOUT'),
               plt.Line2D([], [], label='1.0 s (manual default select timeout)',
                          **{k: v for k, v in fs.CHANCE.items() if k != 'zorder'})]
    fs.legend_below(fig, handles)
    fs.save(fig, out, 'fig_validation_recovery')
    return dict(e3=points, e2=counts)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    parser.add_argument('--out', type=Path, default=ROOT / 'results/analysis/validation/figures')
    data = figure(parser.parse_args(argv).out)
    print(json.dumps(dict(e3_trials=len(data['e3']), e2=data['e2'])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
