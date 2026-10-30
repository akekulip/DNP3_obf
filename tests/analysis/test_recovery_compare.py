"""recovery_compare on the retained E3 blocks: c72 (16/18) against c74 (13/18), relay-side evidence included."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
import recovery_compare as rc  # noqa: E402

BLOCKS = ROOT / 'results/hardware/blocks'
C72 = sorted(BLOCKS.glob('rc01_hw_c72_recovery_r?_20261028_01_*'))
C74 = sorted(BLOCKS.glob('rc01_hw_c74_recovery_r?_20261030_02_*'))
needs = pytest.mark.skipif(len(C72) != 3 or len(C74) != 3, reason='retained E3 blocks absent')


@pytest.fixture(scope='module')
def out():
    return rc.compare({'c72': C72, 'c74': C74})


def rows(out, build):
    return {(r['condition'], r['trial'][-2:]): r for r in out['rows'] if r['build'] == build}


@needs
def test_outcomes_match_the_retained_counts(out):
    assert out['builds']['c72']['success'] == dict(n=16, of=18)
    assert out['builds']['c74']['success'] == dict(n=13, of=18)
    timeouts = sorted(k for k, r in rows(out, 'c74').items() if r['outcome'] == 'TIMEOUT')
    assert timeouts == [('r1', 't3'), ('r1', 't5'), ('r2', 't4'), ('r3', 't2'), ('r3', 't4')]


@needs
def test_relay_timestamps_tick_in_30_ms_and_the_operate_arrives_34_ticks_after_the_select(out):
    assert out['relay_tsval']['all_multiples_of_30'] is True
    ticks = {(b, k): r['relay_ticks_select_to_operate'] for b in ('c72', 'c74') for k, r in rows(out, b).items()}
    assert sum(t == 34 for t in ticks.values()) == 34
    assert ticks[('c72', ('r2', 't2'))] == 35 and ticks[('c72', ('r1', 't3'))] == 41


@needs
def test_the_two_known_exceptions_are_found(out):
    c72, c74 = rows(out, 'c72'), rows(out, 'c74')
    assert [k for k, r in c72.items() if r['operate_copies'] != 1] == [('r1', 't3')]
    assert all(r['operate_copies'] == 1 for r in c74.values())
    extra = [(b, k) for b in ('c72', 'c74') for k, r in rows(out, b).items() if r['extra_relay_pure_acks']]
    assert extra == [('c74', ('r2', 't4'))]


@needs
def test_application_bytes_are_the_same_in_every_trial(out):
    for r in out['rows']:
        assert r['iin'] == ['8000', '8000'] and r['app_control'] == ['c4', 'c5']
        assert r['operate_objects_equal_select'] is True and r['relay_ip_id_gaps'] == 0


@needs
def test_no_captured_feature_separates_timeout_from_success(out):
    assert out['separating_features'] == []
    assert 'relay_ticks_select_to_operate' in out['features_checked']


def test_tcp_fields_parse_window_ip_id_and_timestamps():
    ip = bytes([0x45, 0, 0, 52, 0x12, 0x34, 0x40, 0, 64, 6, 0, 0, 192, 168, 10, 7, 192, 168, 10, 1])
    tcp = (bytes([0x4e, 0x20, 0xea, 0x60]) + (1).to_bytes(4, 'big') + (2).to_bytes(4, 'big') +
           bytes([0x80, 0x10]) + (8103).to_bytes(2, 'big') + bytes(4) +
           bytes([1, 1, 8, 10]) + (3600).to_bytes(4, 'big') + (77).to_bytes(4, 'big'))
    frame = bytes(12) + b'\x08\x00' + ip + tcp
    assert rc.tcp_fields(frame) == dict(ip_id=0x1234, window=8103, tsval=3600, tsecr=77)
