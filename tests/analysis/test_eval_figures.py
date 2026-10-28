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


MAIN_FIGURES = ('fig01_clrt_histogram_D5', 'fig02_median_spread_vs_D', 'fig03_response_size',
                'fig04_classifier_vs_D', 'fig05_confusion_D5', 'fig06_added_latency_vs_D', 'fig07_rate_vs_D',
                'fig08_first_request_retransmissions')
SUPPLEMENTARY_D5 = ('S01_clrt_histogram_D5', 'S02_clrt_histogram_D5_timing_size', 'S03_clrt_cdf_D5',
                    'S04_formby_signature_D5', 'S05_mean_variance_D5', 'S06_confusion_D5', 'S07_block_stability_D5',
                    'S08_classifier_clrt_nb', 'S09_classifier_joint_ann_gmm', 'S10_classifier_vs_K_size',
                    'S11_request_sizes', 'S12_request_to_ack_vs_D')


def fake_results():
    """Classifier entries shaped like formby_results.json (FF-ANN has no block interval)."""
    results = []
    for d in eval_figures.DS:
        for arm in eval_figures.ARMS:
            for feature in ('clrt', 'size', 'joint'):
                for k in (8, 32, 64):
                    for attacker in ('retrained', 'pre_deployment'):
                        model = dict(balanced_accuracy=0.5, ci=dict(estimate=0.5, lower=0.4, upper=0.6),
                                     confusion=[[6, 1, 1], [1, 6, 1], [1, 1, 6]], min_recall=0.4)
                        results.append(dict(d_ms=d, arm=arm, feature=feature, k=k, attacker=attacker, nb=model,
                                            gmm=model, ff_ann=dict(model, ci=None)))
    return results


def rendered(tmp_path):
    rows = rows_for_all_arms(blocks=4)
    for row in rows:
        row['split'] = 'train' if row['repetition'] <= 2 else 'test'
    eval_figures.setup()
    return eval_figures.render_figures(rows, fake_results(), tmp_path)


def test_main_and_supplementary_figures_render_with_at_most_two_panels(tmp_path):
    notes = rendered(tmp_path)
    for name in MAIN_FIGURES:
        assert (tmp_path / 'main' / (name + '.pdf')).stat().st_size > 1000, name
    for name in SUPPLEMENTARY_D5:
        assert (tmp_path / 'supplementary' / (name + '.pdf')).stat().st_size > 1000, name
    panels = notes['axes_per_figure']
    assert set(MAIN_FIGURES) | set(SUPPLEMENTARY_D5) <= set(panels)
    assert max(panels.values()) <= 2


def test_trend_figures_use_the_p4use_arm_palette(tmp_path):
    rendered(tmp_path)
    svg = (tmp_path / 'main' / 'fig07_rate_vs_D.svg').read_text().lower()
    for colour in ('#4472c4', '#ed7d31', '#a5a5a5', '#ffc000'):
        assert colour in svg


def test_figures_draw_no_shaded_bands():
    for name in ('fig_style.py', 'figs_main.py', 'figs_supp.py', 'eval_figures.py'):
        assert 'fill_between' not in (ROOT / 'scripts/analysis' / name).read_text(), name


def test_tables_render_from_rows_and_results(tmp_path):
    rows = rows_for_all_arms(blocks=4)
    for row in rows:
        row['split'] = 'train' if row['repetition'] <= 2 else 'test'
    eval_figures.tables(rows, [], tmp_path)
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


def write_rows_csv(path, rows):
    import csv
    fields = sorted({k for r in rows for k in r})
    with path.open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def test_figures_refuse_a_classifier_artifact_bound_to_other_rows(tmp_path):
    rows = rows_for_all_arms(blocks=16)
    for row in rows:
        row.setdefault('block_index', row['repetition'])
    write_rows_csv(tmp_path / 'rows.csv', rows)
    formby = tmp_path / 'formby.json'
    formby.write_text(json.dumps(dict(schema='c72-formby-eval-v1', rows_sha256='0' * 64, results=[],
                                      comparisons=[])))
    out = tmp_path / 'figures'
    assert eval_figures.main([str(tmp_path / 'rows.csv'), str(formby), '--output', str(out)]) == 4
    assert not out.exists()


def test_input_check_flags_schema_class_and_split_disagreements(tmp_path):
    rows = rows_for_all_arms(blocks=16)
    path = tmp_path / 'rows.csv'
    write_rows_csv(path, rows)
    import hashlib
    good = dict(schema='c72-formby-eval-v1', rows_sha256=hashlib.sha256(path.read_bytes()).hexdigest(), results=[])
    assert eval_figures.input_problems(path, rows, good) == []
    assert any('schema' in p for p in eval_figures.input_problems(path, rows, dict(good, schema='other')))
    bad_split = [dict(r) for r in rows]
    bad_split[0]['split'] = 'test' if bad_split[0]['split'] == 'train' else 'train'
    assert any('split' in p for p in eval_figures.input_problems(path, bad_split, good))
    bad_class = [dict(r) for r in rows if r['operation'] != 'OPERATE']
    assert any('class' in p for p in eval_figures.input_problems(path, bad_class, good))


def test_statuses_keep_sufficiency_construction_and_hypothesis_apart():
    status = eval_figures.statuses(dict(gate_passed=True), dict(falsified=False),
                                   dict(cells={'D5/combined': dict(spread_falsified=False,
                                                                   classifier_by_k={64: dict(falsified=True)})}))
    assert set(status) == {'data_sufficient', 'transformation_correct', 'hypothesis_supported'}
    assert status['data_sufficient'] is True and status['transformation_correct'] is True
    assert status['hypothesis_supported']['classifier_cells_falsified'] == 1
