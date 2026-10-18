"""four_arm_transactions.py: the attacker's table from four-arm block outputs (Part 2, 2026-10-18)."""
import csv
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fat', HERE / 'analysis' / 'four_arm_transactions.py')
fat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fat)


def block(root, name, exchanges_by_arm):
    records = []
    reads = sum(e['kind'] == 'READ' for e in next(iter(exchanges_by_arm.values())))
    for arm, ex in exchanges_by_arm.items():
        t = root / name / 'separate_ack' / arm / ('%s_separate_ack_%s_t0' % (name, arm))
        t.mkdir(parents=True)
        capture = {key: hashlib.sha256(('%s/%s/%s' % (name, arm, key)).encode()).hexdigest()
                   for key in ('out', 'in')}
        for i, row in enumerate(ex):
            row.update(exchange_id=str(i), request_key={'flow': [['m', 1], ['o', 2]], 'inc': 0, 'seq': i, 'func': 1},
                       request_packet_index=i, response_packet_index=i)
        (t / 'timing.json').write_text(json.dumps({'exchanges': ex, 'capture_sha256': capture,
                                                 'extractor_sha256': 'e' * 64}))
        records.append({'arm': arm, 'fixture': 'separate_ack', 'build': 'candidate', 'trials': [
            {'label': t.name, 'reads': reads,
             'conditions': {'delay_ms': 5, 'gap_ms': 0, 'start_delay_ms': 50}}]})
    (root / name / 'campaign_run.json').write_text(json.dumps({
        'effective': {'timing_params_ns': {'pb': 4_000_000}, 'fixture': {'delay_ms': 5}, 'k': 2,
                      'shaping_requested': {'preset': 'same'}, 'trials': {'trials_per_arm': 1, 'reads_per_trial': reads},
                      'endpoint_identity': {'binary_sha256': 'a' * 64},
                      'traffic': {'run_sbo': True, 'sbo_cycles': 1, 'gap_ms': 0, 'start_delay_ms': 50}},
        'source_identity': {'build_sources': {'candidate': {'source_sha256': 's' * 64}}},
        'builds': {'candidate': {'bfrt.json': 'b' * 64}}, 'arms': records}))
    return root / name


def ex(kind='READ', ack=200, clrt=950, complete=True):
    return dict(kind=kind, complete=complete, ack_lat_us=ack, clrt_us=clrt, rt_us=None if clrt is None else ack + clrt, resp_len=61,
                retransmitted=False, piggyback=False)


def test_rows_counts_and_arm_names(tmp_path):
    b = block(tmp_path, 'blk_b1_01', {'off': [ex(), ex('SELECT'), ex(complete=False)], 'combined': [ex(clrt=None)],
                                      'size_only': [ex('OPERATE')], 'timing_only': [ex(kind='NULL')]})
    out = tmp_path / 't.csv'
    rows, counts = fat.block_rows(b)
    assert {r['arm'] for r in rows} == {'baseline', 'size_only'} and len(rows) == 3
    assert rows[0]['run'] == 'blk_b1_01' and float(rows[0]['clrt_ms']) == 0.95
    assert {k: counts['baseline'][k] for k in ('written', 'incomplete', 'missing_interval', 'other_kind')} == dict(
        written=2, incomplete=1, missing_interval=0, other_kind=0)
    assert counts['combined']['missing_interval'] == 1 and counts['timing_only']['other_kind'] == 1


def test_an_unknown_arm_directory_or_empty_block_is_refused(tmp_path):
    with pytest.raises(ValueError):
        fat.block_rows(block(tmp_path, 'b1', {'defended': [ex()]}))
    (tmp_path / 'empty').mkdir()
    with pytest.raises(ValueError):
        fat.block_rows(tmp_path / 'empty')


def test_output_feeds_the_four_arm_attacker(tmp_path):
    spec2 = importlib.util.spec_from_file_location('lfa', HERE / 'analysis' / 'leakage_four_arm.py')
    lfa = importlib.util.module_from_spec(spec2)
    spec2.loader.exec_module(lfa)
    blocks = [block(tmp_path, 'b%d' % i, {a: [ex(k) for k in fat.CLASSES]
              for a in ('off', 'size_only', 'timing_only', 'combined')}) for i in range(3)]
    out = tmp_path / 't.csv'
    fat.main(['x', str(out)] + [str(b) for b in blocks])
    runs, arms, cls, X = lfa.load(out)
    assert sorted(set(arms)) == sorted(lfa.ARMS) and X.shape == (36, 3)


@pytest.mark.parametrize('fault', ['duplicate_block', 'partial', 'duplicate_exchange', 'reused_capture',
                                  'reused_out_capture', 'missing_trial', 'mixed_condition', 'mixed_trial_condition', 'mixed_build',
                                  'missing_identity', 'missing_response_index', 'nan', 'bad_size'])
def test_main_refuses_invalid_pairs_and_keeps_counts(tmp_path, fault):
    blocks = [block(tmp_path, 'b%d' % i, {a: [ex(k) for k in fat.CLASSES]
              for a in ('off', 'size_only', 'timing_only', 'combined')}) for i in range(3)]
    if fault == 'duplicate_block':
        blocks[2] = blocks[0]
    elif fault == 'partial':
        blocks = blocks[:2]
    elif fault in ('mixed_condition', 'mixed_trial_condition', 'mixed_build', 'missing_trial'):
        p = blocks[2] / 'campaign_run.json'; d = json.loads(p.read_text())
        if fault == 'mixed_condition': d['effective']['timing_params_ns']['pb'] = 1
        elif fault == 'mixed_trial_condition': d['arms'][0]['trials'][0]['conditions']['delay_ms'] = 8
        elif fault == 'mixed_build': d['source_identity']['build_sources']['candidate']['source_sha256'] = 'other'
        else: d['effective']['trials']['trials_per_arm'] = 2
        p.write_text(json.dumps(d))
        if fault == 'missing_trial':
            for b in blocks[:2]:
                p = b / 'campaign_run.json'; d = json.loads(p.read_text())
                d['effective']['trials']['trials_per_arm'] = 2; p.write_text(json.dumps(d))
    else:
        p = next((blocks[0] / 'separate_ack' / 'off').glob('*/timing.json'))
        d = json.loads(p.read_text())
        if fault == 'duplicate_exchange': d['exchanges'].append(d['exchanges'][0])
        elif fault in ('reused_capture', 'reused_out_capture'):
            other = next((blocks[1] / 'separate_ack' / 'off').glob('*/timing.json'))
            od = json.loads(other.read_text())
            if fault == 'reused_capture': od['capture_sha256'] = d['capture_sha256']
            else: od['capture_sha256']['out'] = d['capture_sha256']['out']
            other.write_text(json.dumps(od))
        elif fault == 'missing_identity': d['exchanges'][0].pop('exchange_id')
        elif fault == 'missing_response_index': d['exchanges'][0].pop('response_packet_index')
        elif fault == 'nan': d['exchanges'][0]['ack_lat_us'] = float('nan')
        else: d['exchanges'][0]['resp_len'] = 49.5
        p.write_text(json.dumps(d))
    out = tmp_path / 'table.csv'
    with pytest.raises(ValueError): fat.main(['x', str(out)] + [str(b) for b in blocks])
    assert Path(str(out) + '.counts.json').exists()
    assert not out.exists()


@pytest.mark.parametrize('mutation', ['endpoint', 'start_delay', 'executed_start_delay', 'declared_reads'])
def test_effective_endpoint_and_declared_workload_must_match_execution(tmp_path, mutation):
    blocks = [block(tmp_path, 'b%d' % i, {a: [ex('READ')] + [ex(k) for k in fat.CLASSES]
              for a in ('off', 'size_only', 'timing_only', 'combined')}) for i in range(3)]
    p = blocks[0] / 'campaign_run.json'; record = json.loads(p.read_text())
    if mutation == 'endpoint': record['effective']['endpoint_identity']['binary_sha256'] = 'changed'
    elif mutation == 'start_delay':
        record['effective']['traffic']['start_delay_ms'] = 999
        for arm in record['arms']: arm['trials'][0]['conditions']['start_delay_ms'] = 999
    elif mutation == 'executed_start_delay': record['arms'][0]['trials'][0]['conditions']['start_delay_ms'] = 999
    else:
        record['arms'][0]['trials'][0]['reads'] = 1
        timing = next((blocks[0] / 'separate_ack' / 'off').glob('*/timing.json'))
        report = json.loads(timing.read_text()); report['exchanges'].pop(0); timing.write_text(json.dumps(report))
    p.write_text(json.dumps(record))
    with pytest.raises(ValueError): fat.main(['x', str(tmp_path / 'table.csv')] + list(map(str, blocks)))


@pytest.mark.parametrize('mutation', ['missing_counts', 'truncated', 'changed_value', 'changed_counts', 'changed_identity'])
def test_attacker_requires_the_complete_bound_extraction_table(tmp_path, mutation):
    spec = importlib.util.spec_from_file_location('bound_leakage', HERE / 'analysis/leakage_four_arm.py')
    lfa = importlib.util.module_from_spec(spec); spec.loader.exec_module(lfa)
    blocks = [block(tmp_path, 'b%d' % i, {a: [ex('READ')] + [ex(k) for k in fat.CLASSES]
              for a in ('off', 'size_only', 'timing_only', 'combined')}) for i in range(3)]
    table = tmp_path / 'table.csv'; fat.main(['x', str(table)] + list(map(str, blocks)))
    counts = Path(str(table) + '.counts.json'); data = json.loads(counts.read_text())
    rows = list(csv.DictReader(table.open()))
    assert len(rows) == 48
    if mutation == 'missing_counts': counts.unlink()
    elif mutation == 'changed_counts':
        data['b0']['baseline']['classes']['READ']['written'] = 1; counts.write_text(json.dumps(data))
    else:
        if mutation == 'truncated': rows.pop(0)
        elif mutation == 'changed_value': rows[0]['clrt_ms'] = '123.0'
        else: rows[0]['exchange_id'] = 'changed'
        with table.open('w', newline='') as stream:
            writer = csv.DictWriter(stream, fieldnames=fat.FIELDS); writer.writeheader(); writer.writerows(rows)
        if mutation == 'changed_identity' and '_table' in data:
            data['_table']['sha256'] = hashlib.sha256(table.read_bytes()).hexdigest()
            counts.write_text(json.dumps(data))
    with pytest.raises(ValueError): lfa.load(table)
