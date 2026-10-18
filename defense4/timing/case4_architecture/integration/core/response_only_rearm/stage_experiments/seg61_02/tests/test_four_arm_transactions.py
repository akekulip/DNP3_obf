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


def test_publication_ledger_reconciles_subset_and_retains_incomplete_and_count_gaps(tmp_path):
    b = block(tmp_path, 'b0', {'off': [ex(), ex(complete=False)]})
    trial = next(b.glob('*/*/*/timing.json')).parent
    (trial / 'master.json').write_text(json.dumps(dict(
        issued_ns=123456789, completed_ns=123456999, reads_requested=3,
        reads=[dict(completed=True), dict(completed=False)])))
    ledger = fat.publication_ledger(b, dict(condition='frozen', round=2, split='heldout'))
    captured = [r for r in ledger['records'] if r['record_type'] == 'captured_exchange']
    issued = [r for r in ledger['records'] if r['record_type'] == 'endpoint_issued_task']
    assert len(captured) == 2 and len(issued) == 1
    assert sum(r['legacy_feature_eligible'] for r in captured) == 1
    assert any(r['status'] == 'incomplete' for r in captured)
    assert all(r['condition'] == 'frozen' and r['round'] == 2 and r['split'] == 'heldout' for r in captured)
    assert issued[0]['captured_exchange_ids'] is None
    assert ledger['counts']['trials'][0]['requested_read_capture_gap'] == 1
    assert ledger['counts']['trials'][0]['endpoint_read_records'] == 2
    assert captured[0]['request_timestamp_ns'] is None
    assert ledger['bindings']['legacy_exchange_ids_sha256'] == fat.identity([
        r['exchange_id'] for r in captured if r['legacy_feature_eligible']])
    json.dumps(ledger, allow_nan=False)


def test_endpoint_only_partial_trial_is_retained_without_synthetic_requests(tmp_path):
    b = tmp_path / 'partial'
    trial = b / 'separate_ack' / 'off' / 'timeout'
    trial.mkdir(parents=True)
    (trial / 'master.json').write_text('{"reads": [')
    ledger = fat.publication_ledger(b)
    assert ledger['records'] == []
    assert ledger['legacy_validation']['status'] == 'error'
    assert ledger['counts']['trials'][0]['captured_exchanges'] is None
    assert ledger['counts']['trials'][0]['endpoint_read_records'] is None
    assert any(s.get('reason') == 'partial_or_invalid_json' for s in ledger['sources'])


def test_publication_export_binds_content_and_preserves_explicit_fallback(tmp_path):
    b = block(tmp_path, 'b0', {'off': [ex()]})
    trial = next(b.glob('*/*/*/timing.json')).parent
    (trial / 'result.json').write_text(json.dumps(dict(fallback=True, master_timeout=True)))
    output = tmp_path / 'ledger.json'
    fat.export_publication_ledger(output, [b], labels={'b0': dict(round=4, split='test')})
    value = json.loads(output.read_text())
    assert value['content_sha256'] == fat.identity(value['blocks'])
    row = value['blocks'][0]['records'][0]
    assert row['status'] == 'fallback' and row['fallback'] is True
    assert row['master_timeout'] is True
    assert row['round'] == 4 and row['split'] == 'test'


def test_out_only_capture_retains_observed_requests_attempts_and_hash(tmp_path):
    import sys
    architecture = next(p for p in HERE.parents if (p / 'protocol/hw_vepa/tests/pcaptk.py').exists())
    sys.path.insert(0, str(architecture / 'protocol/hw_vepa/tests'))
    import pcaptk as tk
    b = tmp_path / 'partial'
    trial = b / 'fixture/off/trial'
    trial.mkdir(parents=True)
    req = tk.frame('192.168.10.61', '192.168.10.62', 40000, 20000, 1001, 5001, tk.PSH | tk.ACK, tk.read_request())
    tk.write_pcap(trial / 'out.pcap', [(100, req), (200, req)])
    (trial / 'master.json').write_text('{"reads_requested":1}')
    ledger = fat.publication_ledger(b)
    captured = [r for r in ledger['records'] if r['record_type'] == 'captured_exchange']
    assert len(captured) == 1 and captured[0]['attempts'] == 2
    assert captured[0]['request_timestamp_ns'] == 100000
    assert captured[0]['response_timestamp_ns'] is None
    assert captured[0]['in_request_packet_count'] is None
    assert captured[0]['capture_out_sha256'] == hashlib.sha256((trial / 'out.pcap').read_bytes()).hexdigest()
    assert any(s.get('sha256') == captured[0]['capture_out_sha256'] for s in ledger['sources'])
    assert ledger['counts']['trials'][0]['captured_reads'] == 1
    assert ledger['counts']['trials'][0]['captured_attempts'] == 2
    assert ledger['counts']['trials'][0]['capture_availability']['in']['status'] == 'unavailable'


@pytest.mark.parametrize('artifact', ['in.pcap', 'result.json'])
def test_other_partial_evidence_is_discovered_with_unknown_request_counts(tmp_path, artifact):
    b = tmp_path / 'partial'
    trial = b / 'fixture/off/trial'
    trial.mkdir(parents=True)
    (trial / artifact).write_bytes(b'' if artifact == 'in.pcap' else b'{"master_timeout":true}')
    ledger = fat.publication_ledger(b)
    assert len(ledger['counts']['trials']) == 1
    assert ledger['counts']['trials'][0]['captured_exchanges'] is None
    assert ledger['counts']['trials'][0]['captured_attempts'] is None
    assert any(s['path'].endswith(artifact) and s.get('sha256') for s in ledger['sources'])


def test_partial_session_identity_includes_arm_and_missing_condition_stays_null(tmp_path):
    b = tmp_path / 'partial'
    for index, arm in enumerate(('off', 'size_only')):
        trial = b / 'fixture' / arm / 'trial_001'
        trial.mkdir(parents=True)
        (trial / 'master.json').write_text(json.dumps(dict(issued_ns=100 + index)))
        (trial / 'timing.json').write_text('{"exchanges":[]}')
    ledger = fat.publication_ledger(b)
    assert len({r['session_id'] for r in ledger['records']}) == 2
    assert all(r['condition'] is None for r in ledger['records'])
    assert all('condition' in r['audit_null_reasons'] for r in ledger['records'])


def test_retained_smoke_replay_preserves_all_legacy_numbers_and_packets():
    b = HERE / 'evidence/hw_campaigns/candidate61_fourarm_smoke_03'
    ledger = fat.publication_ledger(b)
    captured = [r for r in ledger['records'] if r['record_type'] == 'captured_exchange']
    assert len(captured) == 88
    # This historical fixture predates identity/provenance fields; replay does not silently
    # upgrade its legacy CSV qualification or mutate any retained evidence.
    assert ledger['legacy_validation']['status'] == 'error'
    for timing in b.glob('*/*/*/timing.json'):
        original = json.loads(timing.read_text())
        replay = fat._replay_capture(timing.parent / 'out.pcap', timing.parent / 'in.pcap')
        assert original['summary'] == replay['summary']
        assert len(original['exchanges']) == len(replay['exchanges'])
        for old, new in zip(original['exchanges'], replay['exchanges']):
            assert old == {key: new[key] for key in old}
    assert all(r['observation']['request']['frame_sha256'] for r in captured)
    assert all(type(r['request_timestamp_ns']) is int for r in captured)
    assert all(r['response_availability_ns'] is not None for r in captured)
    assert all(r['operate_hold_ns'] == r['request_delivery_ns'] for r in captured if r['txn_class'] == 'OPERATE')
    assert all(r['round'] is None and r['split'] is None for r in captured)
    assert ledger['counts']['endpoint_issued_tasks'] == 4
