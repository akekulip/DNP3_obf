import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'scripts/analysis'), str(ROOT / 'tests/analysis')]
pytest.importorskip('sklearn')
pytest.importorskip('matplotlib')
import eval_figures  # noqa: E402
from test_formby_eval import synthetic  # noqa: E402


def rows_for_all_arms(blocks=16):
    rows = []
    for index, arm in enumerate(eval_figures.ARMS):
        for row in synthetic(arm == 'off', d_ms=5, arm=arm, blocks=blocks, seed=index):
            row.update(block_index=row['repetition'], trial=arm, req_len=25 if row['operation'] == 'READ' else 45,
                       rt_ms=row['clrt_ms'] + 2.0, ack_ms=2.0, outcome='OK', app_ok=1, iin=128,
                       crob='' if row['operation'] == 'READ' else '1:SUCCESS;3:SUCCESS',
                       observed_at_ns=row['repetition'] * 10 ** 10 + row['seq'] * 30 * 10 ** 6,
                       retx_out=0, retx_in=0, kernel_drops=0, read_class='mixed' if row['operation'] == 'READ' else '')
            rows.append(row)
    return rows


def test_sufficiency_gate_counts_test_blocks_and_windows():
    rows = rows_for_all_arms()
    report = eval_figures.sufficiency(rows)
    cell = report['cells']['D5/off/SELECT']
    assert cell == dict(train_blocks=8, test_blocks=8, test_windows_K8=64, test_windows_K64=8)
    assert report['gate_passed'] is False          # D10-D20 cells are empty in this fixture
    assert report['cells']['D10/off/READ']['test_blocks'] == 0


def test_tables_and_figures_render_from_rows_and_results(tmp_path):
    rows = rows_for_all_arms(blocks=4)
    for row in rows:
        row['split'] = 'train' if row['repetition'] <= 2 else 'test'
    eval_figures.setup()
    eval_figures.f2_size_hist(rows, tmp_path)
    eval_figures.f10_overhead(rows, tmp_path)
    eval_figures.tables(rows, [], tmp_path)
    assert (tmp_path / 'F2_response_size_histograms.pdf').stat().st_size > 1000
    assert (tmp_path / 'F10_overhead_small_multiples.pdf').stat().st_size > 1000
    delivery = (tmp_path / 'T3_delivery.csv').read_text().splitlines()
    assert delivery[0].startswith('d_ms,arm,blocks,exchanges')
    assert len(delivery) == 1 + 4
    t1 = (tmp_path / 'T1_distribution_stats.csv').read_text()
    assert 'clrt_ms' in t1 and 'resp_len' in t1 and 'ack_ms' in t1
    assert json.loads(json.dumps(eval_figures.stats([1.0, 2.0, 3.0])))['median'] == 2.0


def test_gate_also_requires_training_blocks_and_clean_captures():
    rows = rows_for_all_arms()
    assert eval_figures.sufficiency(rows)['cells']['D5/off/READ']['train_blocks'] == 8
    rows[0]['kernel_drops'] = 1
    report = eval_figures.sufficiency(rows)
    assert report['capture_clean'] is False and report['gate_passed'] is False


def test_descriptive_tables_exclude_piggybacked_exchanges(tmp_path):
    rows = rows_for_all_arms(blocks=2)
    target = next(r for r in rows if r['arm'] == 'combined' and r['operation'] == 'SELECT')
    target.update(piggyback=1, clrt_ms=0.0)
    eval_figures.tables(rows, [], tmp_path)
    import csv as _csv
    t1 = [r for r in _csv.DictReader((tmp_path / 'T1_distribution_stats.csv').open())
          if r['arm'] == 'combined' and r['operation'] == 'SELECT' and r['field'] == 'clrt_ms']
    assert float(t1[0]['min']) > 0 and int(t1[0]['n']) == 2 * 64 - 1
    t3 = [r for r in _csv.DictReader((tmp_path / 'T3_delivery.csv').open()) if r['arm'] == 'combined']
    assert int(t3[0]['piggyback']) == 1


def test_size_verdict_flags_any_padded_response_off_its_class_image():
    rows = rows_for_all_arms(blocks=2)
    for r in rows:
        image = {'READ': 141, 'SELECT': 60, 'OPERATE': 60} if r['arm'] in ('size_only', 'combined') else \
            {'READ': 91, 'SELECT': 49, 'OPERATE': 49}
        r['resp_len'] = image[r['operation']]
    assert eval_figures.size_verdict(rows)['falsified'] is False
    next(r for r in rows if r['arm'] == 'combined').update(resp_len=91)
    verdict = eval_figures.size_verdict(rows)
    assert verdict['falsified'] is True and verdict['violations'] == 1


def test_timing_verdict_compares_timed_class_median_spread_with_off_spread():
    rows = rows_for_all_arms(blocks=2)   # off separable (2/6/12 ms), other arms all at D
    verdict = eval_figures.timing_verdict(rows, [])
    cell = verdict['cells']['D5/combined']
    assert cell['median_spread_ms'] < cell['off_median_spread_ms'] and cell['spread_falsified'] is False


def test_saved_figures_are_byte_stable_and_carry_no_tool_metadata(tmp_path):
    import matplotlib.pyplot as plt
    hashes = []
    for run in ('a', 'b'):
        out = tmp_path / run
        out.mkdir()
        fig, ax = plt.subplots(figsize=(3.5, 2.0))
        ax.plot([0, 1], [0, 1])
        eval_figures.save(fig, out, 'probe')
        hashes.append(((out / 'probe.pdf').read_bytes(), (out / 'probe.svg').read_bytes()))
    assert hashes[0] == hashes[1]
    pdf, svg = hashes[0]
    for marker in (b'/CreationDate', b'/Producer', b'/Creator', b'matplotlib'):
        assert marker not in pdf
    assert b'<dc:date>' not in svg and b'matplotlib.org' not in svg   # element ids may still say matplotlib
    assert b'Software' not in (tmp_path / 'a' / 'preview' / 'probe.png').read_bytes()
