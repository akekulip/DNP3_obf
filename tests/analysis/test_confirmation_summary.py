"""confirmation_summary on the retained c72 baselines (2026-10-30): strict workload and combined-arm connection starts."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts/analysis'))
import confirmation_summary as cs  # noqa: E402

BLOCKS = ROOT / 'results/hardware/blocks'
SC20 = sorted((BLOCKS / 'rc01_hw_c72_sc20_20261030_01_strict_cycle_d20_combined/physical_relay').glob('*/*_t*'))
SC5 = sorted((BLOCKS / 'rc01_hw_c72_sc5_20261030_01_strict_cycle_d5_combined/physical_relay').glob('*/*_t*'))
E2C = sorted((BLOCKS / 'rc01_hw_c72diag_e2c_20261030_01_e2_combined_first_request_d20/physical_relay').glob('*/*_t*'))
DIAG_SHA = 'a46cc55a73a77dfa5691e292451d18d4ec663a04fb5f07b39c6e91915010d437'

needs_evidence = pytest.mark.skipif(not (SC20 and SC5 and E2C), reason='retained c72 baseline blocks not present')


@needs_evidence
def test_strict_d20_baseline():
    out = cs.strict(SC20)
    assert out['trials'] == dict(n=4, of=4) and out['order_ok'] == dict(n=4, of=4)
    assert out['sizes_equal_image'] == dict(n=512, of=512) and out['crob_success'] == dict(n=256, of=256)
    assert out['retransmissions'] == dict(out=1, **{'in': 0})
    assert [t['retransmissions']['out'] for t in out['per_trial']] == [0, 0, 0, 1]
    assert out['clrt_us']['READ mixed']['n'] == 128 and 18000 < out['clrt_us']['READ mixed']['median'] < 22000


@needs_evidence
def test_strict_d5_baseline():
    out = cs.strict(SC5)
    assert out['trials'] == dict(n=4, of=4) and out['order_ok'] == dict(n=4, of=4)
    assert out['retransmissions'] == dict(out=0, **{'in': 0})
    assert all(3000 < c['median'] < 7000 for c in out['clrt_us'].values())


@needs_evidence
def test_strict_order_failure_is_caught(tmp_path):
    """Swapping two exchanges in a copy of one trial must fail the order check, not the counts."""
    src = SC20[0]
    dst = tmp_path / src.name
    dst.mkdir()
    for name in ('trial.json', 'standards_verdict.json'):
        (dst / name).write_text((src / name).read_text())
    wire = json.loads((src / 'relay_wire.json').read_text())
    ex = wire['exchanges']
    ex[1], ex[2] = ex[2], ex[1]
    (dst / 'relay_wire.json').write_text(json.dumps(wire))
    out = cs.strict([dst])
    assert out['order_ok'] == dict(n=0, of=1) and out['crob_success'] == dict(n=64, of=64)


@needs_evidence
def test_combined_starts_baseline():
    out = cs.starts(E2C, 'c72_diag_mirror', DIAG_SHA)
    assert out['connections'] == 32
    assert out['not_forwarded'] == dict(none=27, syn=0, suppressed_obsolete_ack=3, lost_valid_ack=0,
                                         first_request=2, unexplained_missing_copy=0)
    lost = {r['trial'].rsplit('_', 1)[1]: r['frame'] for r in out['per_trial'] if r['frame'] != 'none'}
    assert lost == dict(t0='first_request', t17='suppressed_obsolete_ack', t18='suppressed_obsolete_ack',
                        t19='suppressed_obsolete_ack', t30='first_request')
    assert out['first_request_retransmitted'] == dict(n=2, of=32)


def test_starts_refuses_a_wrong_build_identity():
    with pytest.raises(SystemExit):
        cs.main(['starts', '--build-label', 'c72_diag_mirror', '--source-sha256', '0' * 64, '--out',
                 '/dev/null', str(ROOT)])


@needs_evidence
def test_starts_reply_observable_baseline():
    """c72 never forwards a late handshake ACK: one relay ACK and one master ACK precede every first response."""
    out = cs.starts(E2C, 'c72_diag_mirror', DIAG_SHA)
    assert out['late_handshake_ack_forwarded'] == dict(n=0, of=32)
    assert out['pure_acks_before_first_response'] == dict(relay={'1': 32}, master={'1': 32})
    assert all(r['first_clrt_us'] for r in out['per_trial'])


@needs_evidence
def test_dropped_syn_is_not_a_handshake_ack(monkeypatch):
    trial = cs.cap.load(E2C[0])
    syn = trial['master']['to_relay'][0]
    assert syn['flags'] & cs.SYN
    trial['mirror']['to_relay'] = [s for s in trial['mirror']['to_relay'] if s['seq'] != syn['seq'] or s['len']]
    monkeypatch.setattr(cs.d3, 'counters', lambda t: ({'dev9': dict(rx=9, tx=0), 'dev64': dict(rx=0, tx=7)}, None))
    monkeypatch.setattr(cs.d3, 'completeness', lambda t: dict(ok=True))
    assert cs.start_row(trial)['frame'] == 'syn'



def seg(seq, ack, window, tsval, flags=0x10, length=0):
    return dict(seq=seq, ack=ack, window=window, tsval=tsval, flags=flags, len=length)


def test_an_ack_is_obsolete_only_when_a_forwarded_later_segment_covers_every_field():
    ack = seg(101, 501, 502, 7000)
    request = seg(101, 501, 502, 7001, flags=0x18, length=25)
    assert cs.obsolete(ack, request) is True
    assert cs.obsolete(ack, dict(request, ack=500)) is False          # acknowledgment not covered
    assert cs.obsolete(ack, dict(request, window=600)) is False       # a window change is new information
    assert cs.obsolete(ack, dict(request, tsval=6999)) is False       # the ACK carries the newer timestamp
    assert cs.obsolete(ack, dict(request, seq=100)) is False          # the later segment does not reach the ACK
    assert cs.obsolete(ack, None) is False                            # nothing later was forwarded


@needs_evidence
def test_c72_off_arm_handshake_ack_losses_are_suppressed_obsolete_acks():
    off = sorted((BLOCKS / 'rc01_hw_c72diag_e2_20261028_01_e2_first_request_d20/physical_relay').glob('*/*_t*'))
    out = cs.starts(off, 'c72_diag_mirror', DIAG_SHA)
    assert out['not_forwarded']['suppressed_obsolete_ack'] == 3 and out['not_forwarded']['lost_valid_ack'] == 0
