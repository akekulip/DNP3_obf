"""Tests for c52_timing_diag.py (Python >= 3.10, research venv).

Fixture: the retained c52 block 24 timing_only trial. Every case that changes evidence works on a COPY in
tmp_path; the original block is only read.
"""
import importlib.util
import json
import math
import shutil
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
TOOL = ROOT / 'analysis/c52_timing_diag.py'
BLOCK = ROOT / 'evidence/hw_blocks/rc01_hw_c52_20261024_24_reference'
ARM = 'physical_relay/timing_only'
TRIAL = 'rc01_hw_c52_20261024_24_reference_physical_relay_timing_only_t0'


def load_tool():
    spec = importlib.util.spec_from_file_location('c52_timing_diag', TOOL)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy_block(tmp_path):
    """Copy only the timing_only trial and the block's campaign_run.json (timing parameters)."""
    block = tmp_path / BLOCK.name
    shutil.copytree(BLOCK / ARM / TRIAL, block / ARM / TRIAL)
    shutil.copy(BLOCK / 'campaign_run.json', block / 'campaign_run.json')
    return block, block / ARM / TRIAL


def run_cli(*args):
    return subprocess.run([sys.executable, str(TOOL), *map(str, args)], capture_output=True, text=True)


def fixture_rows():
    diag = load_tool()
    block = diag.analyze_block(BLOCK)
    return [row for row in block['transactions'] if row['arm'] == 'timing_only']


def test_fixture_has_193_transactions_by_function_code():
    rows = fixture_rows()
    assert len(rows) == 193
    counts = {op: sum(r['operation'] == op for r in rows) for op in ('READ', 'SELECT', 'OPERATE')}
    assert counts == {'READ': 65, 'SELECT': 64, 'OPERATE': 64}
    assert {r['function_code'] for r in rows} == {1, 3, 4}


def test_first_read_is_a_slow_fallback_trial_first_transaction():
    rows = fixture_rows()
    first = rows[0]
    assert first['operation'] == 'READ' and first['first_on_connection'] is True
    assert abs(first['response_complete_after_request_us'] / 1000 - 98.3) <= 0.5
    assert first['trial_fallback'] is True
    assert first['fallback_trial_first_transaction'] is True
    assert first['t_on'] is True
    assert 'T t0 unobserved' in first['t_interval']['label']
    assert not any(r['first_on_connection'] for r in rows[1:])


def test_clrt_reproduces_relay_check_and_the_retained_verdict():
    rows = fixture_rows()
    reads = sorted(abs(r['clrt_error_us']) for r in rows if r['operation'] == 'READ' and not r['piggyback'])
    p99 = reads[max(0, math.ceil(.99 * len(reads)) - 1)]
    assert abs(p99 - 64389) <= 1
    retained = json.loads((BLOCK / ARM / TRIAL / 'trial.json').read_text())
    precision = retained['observed']['connections']['single']['precision']
    diag = load_tool()
    summary = diag.precision_like_relay_check(rows, 950000)
    for op in ('READ', 'SELECT', 'OPERATE'):
        assert abs(summary[op]['p99_us'] - precision[op]['p99_nearest_rank_abs_error_us']) <= 1


def _pcap_records(path):
    data = path.read_bytes()
    out, pos = [], 24
    while pos + 16 <= len(data):
        incl = struct.unpack_from('<I', data, pos + 8)[0]
        out.append(data[pos:pos + 16 + incl])
        pos += 16 + incl
    return data[:24], out


def _tcp_payload_len(frame):
    ihl = (frame[14] & 15) * 4
    return int.from_bytes(frame[16:18], 'big') - ihl - (frame[14 + ihl + 12] >> 4) * 4


def test_a_duplicate_seq_request_is_detected_as_a_retransmission(tmp_path):
    block, trial = copy_block(tmp_path)
    head, recs = _pcap_records(trial / 'out.pcap')
    first_data = next(r for r in recs if _tcp_payload_len(r[16:]) > 0)
    ts_s, ts_f = struct.unpack_from('<II', first_data, 0)
    dup = bytearray(first_data)
    struct.pack_into('<I', dup, 0, ts_s + (ts_f + 211000 >= 1_000_000))
    struct.pack_into('<I', dup, 4, (ts_f + 211000) % 1_000_000)  # +211 ms (microsecond pcap)
    (trial / 'out.pcap').write_bytes(head + b''.join(recs) + bytes(dup))
    diag = load_tool()
    rows = diag.analyze_block(block)['transactions']
    first = rows[0]
    assert first['request_retransmissions'] == 1
    assert abs(first['request_retransmit_after_first_tx_us'][0] - 211000) <= 1
    assert all(r['request_retransmissions'] == 0 for r in rows[1:])


def test_a_trial_missing_in_pcap_fails_loudly(tmp_path):
    block, trial = copy_block(tmp_path)
    (trial / 'in.pcap').unlink()
    result = run_cli(block, '--out', tmp_path / 'out')
    assert result.returncode != 0
    assert 'in.pcap' in result.stderr
    assert not (tmp_path / 'out' / 'diagnosis.json').exists()


def test_cli_writes_json_and_markdown(tmp_path):
    block, _ = copy_block(tmp_path)
    result = run_cli(block, '--out', tmp_path / 'out')
    assert result.returncode == 0, result.stderr
    data = json.loads((tmp_path / 'out' / 'diagnosis.json').read_text())
    assert len(data['transactions']) == 193
    md = (tmp_path / 'out' / 'DIAGNOSIS.md').read_text()
    assert 'Undecidable from master-only data' in md
    assert 'readiness' in md and "T's t0" in md
