import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
import eval_rows  # noqa: E402

BLOCK = ROOT / 'results/hardware/blocks/rc01_hw_c72_20261027_02_02_d5_reference/physical_relay'
needs_block = pytest.mark.skipif(not BLOCK.is_dir(), reason='qualification block 02 evidence not present')


def trial(arm):
    return next((BLOCK / arm).iterdir())


def context(arm):
    return dict(campaign='q', block_id='02_d5_reference', block_index=0, d_ms=5, repetition=None, arm=arm,
                arm_position=0, split=None)


@needs_block
@pytest.mark.parametrize('arm, sizes', [('off', {91, 134, 49}), ('combined', {141, 158, 60})])
def test_real_trial_yields_one_row_per_exchange_with_class_sizes(arm, sizes):
    rows, problems, inputs = eval_rows.trial_rows(trial(arm), context(arm), eval_rows.EXPECTED)
    assert problems == []
    assert len(rows) == 193
    assert {r['operation'] for r in rows} == {'READ', 'SELECT', 'OPERATE'}
    assert {r['resp_len'] for r in rows} == sizes
    assert all(r['clrt_ms'] > 0 and r['rt_ms'] >= r['ack_ms'] >= 0 for r in rows)
    assert all(abs(r['rt_ms'] - r['ack_ms'] - r['clrt_ms']) < 1e-6 for r in rows)
    assert {r['crob'] for r in rows if r['operation'] != 'READ'} == {'1:SUCCESS;3:SUCCESS'}
    assert set(inputs) >= {str(trial(arm) / name) for name in ('relay_wire.json', 'master.json', 'out.pcap', 'in.pcap')}


@needs_block
def test_timed_arm_clrt_sits_near_d_and_off_does_not():
    off, _, _ = eval_rows.trial_rows(trial('off'), context('off'), eval_rows.EXPECTED)
    timed, _, _ = eval_rows.trial_rows(trial('combined'), context('combined'), eval_rows.EXPECTED)
    median = lambda rows: sorted(r['clrt_ms'] for r in rows)[len(rows) // 2]
    # measured on block 02: timed medians ~5.0 ms at D=5; native SEL-751 CLRT is broad (median ~2.5, max ~27 ms)
    assert abs(median(timed) - 5) < 0.5
    assert abs(median(off) - 5) > 1.0
    assert max(r['clrt_ms'] for r in off) > max(r['clrt_ms'] for r in timed)


@needs_block
def test_tampered_pcap_or_master_record_is_refused(tmp_path):
    copy = tmp_path / 'trial'
    shutil.copytree(trial('off'), copy)
    with open(copy / 'in.pcap', 'ab') as stream:
        stream.write(b'\0')
    _, problems, _ = eval_rows.trial_rows(copy, context('off'), eval_rows.EXPECTED)
    assert any('in.pcap' in p for p in problems)
    shutil.copy(trial('off') / 'in.pcap', copy / 'in.pcap')
    master = json.loads((copy / 'master.json').read_text())
    master['records'].pop()
    (copy / 'master.json').write_text(json.dumps(master))
    _, problems, _ = eval_rows.trial_rows(copy, context('off'), eval_rows.EXPECTED)
    assert any('master.json' in p for p in problems)


@needs_block
def test_partial_connection_is_reported_against_the_planned_counts(tmp_path):
    copy = tmp_path / 'trial'
    shutil.copytree(trial('off'), copy)
    wire = json.loads((copy / 'relay_wire.json').read_text())
    wire['exchanges'].pop()
    (copy / 'relay_wire.json').write_text(json.dumps(wire))
    _, problems, _ = eval_rows.trial_rows(copy, context('off'), eval_rows.EXPECTED)
    assert any('exchanges' in p for p in problems)


def test_missing_trial_files_are_refused(tmp_path):
    _, problems, _ = eval_rows.trial_rows(tmp_path, context('off'), eval_rows.EXPECTED)
    assert problems and 'missing' in problems[0]


def test_block_identity_parses_evaluation_ids_and_split():
    assert eval_rows.block_identity('e07_d15_r02') == (15, 2, 'train')
    assert eval_rows.block_identity('e40_d20_r10') == (20, 10, 'test')
    assert eval_rows.block_identity('02_d5_reference') == (None, None, None)


@needs_block
def test_watchdog_passes_clean_qualification_block_and_flags_each_injected_anomaly():
    import copy
    import eval_watchdog
    rows = []
    for arm in ('off', 'timing_only', 'size_only', 'combined'):
        got, problems, _ = eval_rows.trial_rows(trial(arm), dict(context(arm), arm=arm), eval_rows.EXPECTED)
        assert problems == []
        rows.extend(got)
    assert eval_watchdog.block_anomalies(rows, 5) == []
    assert eval_watchdog.capture_anomalies(BLOCK.parent) == []
    for change, needle in ((dict(resp_len=91), 'sizes'), (dict(outcome='TIMEOUT'), 'not OK'),
                           (dict(iin=132), 'IIN'), (dict(piggyback=1), 'piggybacked')):
        bad = copy.deepcopy(rows)
        target = next(r for r in bad if r['arm'] == 'combined' and r['operation'] == 'SELECT')
        target.update(change)
        assert any(needle in a for a in eval_watchdog.block_anomalies(bad, 5)), change
    assert any('CLRT median' in a for a in eval_watchdog.block_anomalies(rows, 15))


@needs_block
def test_rows_carry_trial_retransmission_and_capture_drop_counts():
    rows, _, _ = eval_rows.trial_rows(trial('off'), context('off'), eval_rows.EXPECTED)
    assert {(r['retx_out'], r['retx_in'], r['kernel_drops']) for r in rows} == {(0, 0, 0)}
    assert set(eval_rows.FIELDS) >= set(rows[0])


def test_watchdog_names_the_exchange_whose_bytes_were_sent_twice():
    import eval_watchdog
    request = lambda seq: dict(sequence_start=seq, sequence_end=seq + 25)
    wire = dict(exchanges=[dict(request=request(100), response=dict(sequence_start=9, sequence_end=100)),
                           dict(request=request(125), response=dict(sequence_start=100, sequence_end=160))],
                packets=dict(out=[dict(seq=100, payload_hex='aa', payload_len=25)] * 2 +
                             [dict(seq=125, payload_hex='bb', payload_len=25)],
                             **{'in': [dict(seq=9, payload_hex='cc', payload_len=91),
                                       dict(seq=100, payload_hex='dd', payload_len=60),
                                       dict(seq=100, payload_hex='dd', payload_len=60)]}))
    assert eval_watchdog.retransmitted_exchanges(wire) == [0, 1]


@needs_block
@pytest.mark.parametrize('change, needle', [
    (lambda w: w.update(ok=False, failures=['captured DNP3 application cannot be decoded']), 'reports failure'),
    (lambda w: w['capture_drops']['in'].update(dropped_interface=7), 'capture drops'),
    (lambda w: w['exchanges'][3]['application'].update(ok=False), 'application check failed'),
])
def test_trial_whose_relay_wire_reports_a_failure_is_refused(tmp_path, change, needle):
    copy = tmp_path / 'trial'
    shutil.copytree(trial('off'), copy)
    wire = json.loads((copy / 'relay_wire.json').read_text())
    change(wire)
    (copy / 'relay_wire.json').write_text(json.dumps(wire))
    _, problems, _ = eval_rows.trial_rows(copy, context('off'), eval_rows.EXPECTED)
    assert any(needle in p for p in problems), problems


def test_retained_artifact_manifest_must_match_every_input(tmp_path):
    run = tmp_path / 'run'
    (run / 'physical_relay/off/t').mkdir(parents=True)
    target = run / 'physical_relay/off/t/relay_wire.json'
    target.write_text('{}')
    manifest = {'files': {'physical_relay/off/t/relay_wire.json': {'sha256': eval_rows.sha(target)}}}
    (run / 'artifact_manifest.json').write_text(json.dumps(manifest))
    assert eval_rows.manifest_problems(run, {str(target): eval_rows.sha(target)}) == []
    target.write_text('{"regenerated": true}')
    assert eval_rows.manifest_problems(run, {str(target): eval_rows.sha(target)})
    (run / 'artifact_manifest.json').unlink()
    assert 'artifact_manifest.json missing' in eval_rows.manifest_problems(run, {})[0]


def test_mixed_relay_wire_schemas_are_reported():
    assert eval_rows.mixed_schema_problems({'sel751-wire-v2'}) == []
    problems = eval_rows.mixed_schema_problems({'sel751-wire-v2', 'sel751-wire-v3'})
    assert len(problems) == 1 and 'sel751-wire-v2' in problems[0] and 'sel751-wire-v3' in problems[0]
