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
    assert out['not_forwarded'] == dict(none=27, syn=0, handshake_ack=3, first_request=2,
                                         unexplained_missing_copy=0)
    lost = {r['trial'].rsplit('_', 1)[1]: r['frame'] for r in out['per_trial'] if r['frame'] != 'none'}
    assert lost == dict(t0='first_request', t17='handshake_ack', t18='handshake_ack', t19='handshake_ack',
                        t30='first_request')
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
