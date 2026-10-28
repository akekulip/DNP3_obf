import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
import eval_report  # noqa: E402


def test_report_numbers_are_read_from_pipeline_outputs(tmp_path):
    (tmp_path / 'rows').mkdir()
    (tmp_path / 'figures').mkdir()
    (tmp_path / 'rows/rows_manifest.json').write_text(json.dumps(dict(
        campaign='c', rows=10, rows_sha256='ab', problems=[],
        blocks=[dict(id='e01', status='completed'), dict(id='e02', status='failed', reason='block_failed'),
                dict(id='e03', status='unexecuted')])))
    (tmp_path / 'figures/sufficiency.json').write_text(json.dumps(dict(
        gate_passed=False, capture_clean=True, rule='r',
        cells={'D5/off/READ': dict(train_blocks=8, test_blocks=7, test_windows_K8=56, test_windows_K64=7)})))
    cell = dict(median_spread_ms=0.1, off_median_spread_ms=0.4, spread_falsified=False,
                classifier_by_k={'64': dict(off_minus_arm=0.2, lower=0.1, upper=0.3, falsified=False)})
    (tmp_path / 'figures/verdicts.json').write_text(json.dumps(dict(
        size=dict(rule='s', falsified=False, violations=0), timing=dict(rule='t  x', cells={'D5/combined': cell}))))
    for name, header in (('T2_classifier_metrics', 'd_ms,arm,feature,k,attacker,classifier,ba_pooled,ba_block_mean,'
                                                   'ci_lower,ci_upper'),
                         ('T3_delivery', 'd_ms,arm,blocks,exchanges,outcome_ok,application_ok,crob_success,sbo,'
                                         'retransmitted_segments,kernel_drops,piggyback'),
                         ('T4_overhead', 'd_ms,arm,pad_READ_B,pad_SELECT_B,pad_OPERATE_B,bytes_per_txn_pct,'
                                         'added_p50_ms,added_p50_ci,added_p95_ms,added_p95_ci,txn_per_s')):
        (tmp_path / 'figures' / (name + '.csv')).write_text(header + '\n')
    (tmp_path / 'figures/T2_classifier_metrics.csv').write_text(
        'd_ms,arm,feature,k,attacker,classifier,ba_pooled,ba_block_mean,ci_lower,ci_upper\n'
        '5,combined,clrt,64,retrained,nb,0.4,0.35,0.3,0.41\n')
    text = eval_report.build(tmp_path).read_text()
    assert 'Blocks completed: 1 of 3; unexecuted: 1; failed or excluded: e02 (failed: block_failed)' in text
    assert '**FAIL**' in text and 'D5/off/READ' in text
    assert '0.350 [0.300, 0.410]' in text and '0.200 [0.100, 0.300] ok' in text and 'Timing falsifier: t x' in text
