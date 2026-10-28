#!/usr/bin/env python3
"""Evaluation figures and tables from rows.csv and formby_results.json.

Figures follow the P4USE (IEEE TDSC 2026) and in-network ML survey (IEEE COMST 2024) style set out in fig_style.py:
one message per figure and at most two panels. main/ holds fig01-fig08 (no obfuscation against Timing+Size, D on the
x-axis of every trend, D = 5 ms for the distribution figures); supplementary/ holds S01-S12, one file per D where D
matters. Tables T1-T4, the sufficiency gate and the verdicts come from eval_tables.py and are written next to them.
figure_notes.json records every number a caption cites and the number of data panels per figure. Request->ACK and
request->response are descriptive only (outside the D contract).

  $RESEARCH_PYTHON scripts/analysis/eval_figures.py ROWS_CSV FORMBY_JSON --output OUT_DIR
"""
import argparse
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import fig_style  # noqa: E402
import figs_main  # noqa: E402
import figs_supp  # noqa: E402
import formby_eval  # noqa: E402
from eval_tables import (DS, ARMS, CLASSES, size_verdict, stats, sufficiency, tables,  # noqa: E402,F401
                         timing_verdict)

__all__ = ['main', 'setup', 'save', 'render_figures', 'stats', 'sufficiency', 'tables', 'size_verdict',
           'timing_verdict', 'DS', 'ARMS', 'CLASSES']   # tables and verdicts live in eval_tables

setup, save = fig_style.setup, fig_style.save


def render_figures(rows, results, out, comparisons=()):
    """Write main/ and supplementary/ figures under out; return the caption notes (incl. panels per figure)."""
    notes = {}
    fig_style.AXES_PER_FIGURE.clear()
    clean = [r for r in rows if not r['piggyback']]   # descriptive figures; piggyback reported in T3
    verdict = timing_verdict(rows, list(comparisons))
    figs_main.render(clean, results, out, notes, verdict)
    figs_supp.render(clean, results, out, notes)
    notes['axes_per_figure'] = dict(sorted(fig_style.AXES_PER_FIGURE.items()))
    return notes


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('rows', type=Path)
    parser.add_argument('formby', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    setup()
    rows = formby_eval.load_rows(args.rows)
    for row in rows:
        for field in ('retx_out', 'retx_in', 'kernel_drops', 'app_ok', 'observed_at_ns'):
            row[field] = int(row[field])
    formby = json.loads(args.formby.read_text())
    results = formby['results']
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    notes = render_figures(rows, results, out, formby.get('comparisons', []))
    tables(rows, results, out)
    gate = sufficiency(rows)
    (out / 'sufficiency.json').write_text(json.dumps(gate, indent=1) + '\n')
    verdicts = dict(size=size_verdict(rows), timing=timing_verdict(rows, formby.get('comparisons', [])),
                    sufficiency_gate_passed=gate['gate_passed'])
    (out / 'verdicts.json').write_text(json.dumps(verdicts, indent=1, default=float) + '\n')
    (out / 'figure_notes.json').write_text(json.dumps(notes, indent=1, default=float) + '\n')
    print('figures and tables written to', out, '| sufficiency gate', 'PASS' if gate['gate_passed'] else 'FAIL')
    return 0 if gate['gate_passed'] else 3


if __name__ == '__main__':
    raise SystemExit(main())
