"""T's readiness test across its clock range: the pre-m7 T arithmetic aliases, m7's does not (directive ba50eac69,
C1).

The arithmetic tested here is shared by every T build before m7 (32-bit ns values compared by the sign of
now - readiness - t0); these tests reproduce it on m6, they do not show that m6 introduced it. Measurements on earlier
builds stay as recorded; their exposure (any exchange resolved more than readiness + 2^31 ns after its anchor) is
assessed separately. The retained model failure (evidence/model_contention_m6_07_01/TRACE_sweep_SELECT_000ms.md) had
the outstation ACK 4.1375 s and the response 4.216 s after the request anchor, readiness 2 s: the response read as
"not ready" until the difference wrapped modulo 2^32 (released 2.08 s late), and an exchange 4.5 s past its anchor
aliased to a fresh one and committed. m7's T counts in 256 ns units on a 512 ns grid (generate.transform_t_m7; signed
horizon about 9.16 minutes, see test_t_phase_sweep.py): both cases fall back at once. Inside the profile both commit.
"""
import importlib.util
import os
import tempfile
from pathlib import Path

import pytest

import contention_source as cs
import test_m6_lifecycle as lc

READINESS_NS = 2_000_000_000          # the contention model driver's readiness


def _generated(milestone):
    spec = importlib.util.spec_from_file_location('t_time_base_generate', lc.EVIDENCE.parent / 'generate.py')
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    path = Path(tempfile.mkdtemp(prefix='%s_generated_' % milestone)) / 'response_only.p4'
    path.write_text(gen.full_source(milestone))
    return path


M7 = Path(os.environ['M7_TIME_SOURCE']) if os.environ.get('M7_TIME_SOURCE') else _generated('m7')


def exchange(source, ack_ns, response_ns):
    p = cs.LapPipeline(source, readiness=READINESS_NS).handshake()
    request, ack, response = cs.transaction('SELECT')
    before, seen = cs.outcomes(p), len(p.to_master())
    t0 = p.now + 100_000
    p.at(t0, request, master=True)
    p.at(t0 + ack_ns, ack)
    p.at(t0 + response_ns, response)
    p.now = t0
    p.settle(horizon=9_000_000_000)
    after = cs.outcomes(p)
    frames = [((t - t0) / 1e6, len(raw)) for t, raw in p.to_master()[seen:]]
    return frames, {k: after[k] - before[k] for k in cs.OUTCOMES}


@pytest.mark.parametrize('ack_ns,response_ns', ((200_000, 400_000), (1_500_000_000, 1_550_000_000)))
def test_inside_readiness_both_builds_commit(ack_ns, response_ns):
    for source in (lc.M6, M7):
        frames, out = exchange(source, ack_ns, response_ns)
        assert [n for _t, n in frames] == [cs.ACK_LEN, cs.RESPONSE_LEN]
        assert out['ACK_COMMIT'] == out['RESP_RELEASE'] == 1 and out['ACK_FALLBACK'] == out['RESP_FALLBACK'] == 0


def test_the_retained_model_timing_falls_back_at_once_on_m7():
    """ACK 4.1375 s and response 4.21625 s after the anchor (the m6_07 model run): the response leaves within 1 ms of
    its arrival by fallback on m7."""
    frames, out = exchange(M7, 4_137_500_000, 4_216_250_000)
    assert [n for _t, n in frames] == [cs.ACK_LEN, cs.RESPONSE_LEN]
    assert frames[0][0] - 4137.5 < 1.0 and frames[1][0] - 4216.25 < 1.0
    assert out['ACK_FALLBACK'] == out['RESP_FALLBACK'] == 1 and out['ACK_COMMIT'] == out['RESP_RELEASE'] == 0


def test_m6_characterization_holds_the_response_until_the_32_bit_wrap():
    """Inherited defect kept as a record: the same timing on m6 holds the response about 2.08 s (released when
    now - t0 wraps past 2^32 ns), the model's sweep_SELECT_000ms failure."""
    frames, out = exchange(lc.M6, 4_137_500_000, 4_216_250_000)
    assert frames[1][0] - 4216.25 > 2000.0 and out['RESP_FALLBACK'] == 1


def test_past_2_32_ns_m7_falls_back_where_m6_aliases_to_a_commit():
    frames7, out7 = exchange(M7, 4_500_000_000, 4_550_000_000)
    assert out7['ACK_COMMIT'] == out7['RESP_RELEASE'] == 0 and out7['ACK_FALLBACK'] == out7['RESP_FALLBACK'] == 1
    assert [n for _t, n in frames7] == [cs.ACK_LEN, cs.RESPONSE_LEN]
    _frames6, out6 = exchange(lc.M6, 4_500_000_000, 4_550_000_000)
    assert out6['ACK_COMMIT'] == out6['RESP_RELEASE'] == 1          # m6: aliased false commit (characterization)
