"""A bounded fallback past readiness, inside and outside T's committed profile (source pipeline).

Inside the profile the exchange commits and releases; with the ACK 1 ms past readiness the original response still
reaches the master once, by T's bounded fallback, never vanishing. This does not reproduce the m6_07 model failure,
which needs anchors past readiness + 2^31 ns (see test_t_time_base.py and test_t_phase_sweep.py). Each case runs with
the response 0, 1 and 3 laps after the ACK (3, 2 and 0 retry laps of N's work cell), on m5, m6 and m7.
"""
import pytest

import contention_source as cs
import test_m6_lifecycle as lifecycle
import test_t_time_base as time_base

SOURCES = {'m5_10': lifecycle.M5, 'm6': lifecycle.M6, 'm7': time_base.M7}
IN_PROFILE_NS = 200_000                          # cs.REQ_TO_ACK_NS: well inside readiness
LATE_NS = cs.qs.READINESS + 1_000_000           # 1 ms past readiness


def exchange(source, kind, ack_after_ns, offset_laps):
    p = cs.LapPipeline(source).handshake()
    request, ack, response = cs.transaction(kind)
    before, busy0, seen = cs.outcomes(p), [p.busy(i) for i in range(5)], len(p.to_master())
    t0 = p.now + 100_000
    p.at(t0, request, master=True)
    p.at(t0 + ack_after_ns, ack)
    p.at(t0 + ack_after_ns + offset_laps * 1000 + 1, response)
    p.now = t0
    p.settle(horizon=50_000_000)
    after = cs.outcomes(p)
    return ([len(raw) for _t, raw in p.to_master()[seen:]], [p.busy(i) - busy0[i] for i in range(5)],
            {k: after[k] - before[k] for k in cs.OUTCOMES})


@pytest.mark.parametrize('source', sorted(SOURCES))
@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
@pytest.mark.parametrize('offset_laps,retries', ((0, 3), (1, 2), (3, 0)))
def test_inside_the_profile_commits_and_releases(source, kind, offset_laps, retries):
    lens, busy, out = exchange(SOURCES[source], kind, IN_PROFILE_NS, offset_laps)
    assert lens == [cs.ACK_LEN, cs.RESPONSE_LEN]
    assert busy[cs.RETRY] == retries and busy[cs.BUSY_DROP] == busy[cs.EXHAUSTED] == busy[cs.STALE] == 0
    assert out['ACK_COMMIT'] == out['RESP_RELEASE'] == 1 and out['ACK_FALLBACK'] == out['RESP_FALLBACK'] == 0


@pytest.mark.parametrize('source', sorted(SOURCES))
@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
@pytest.mark.parametrize('offset_laps', (0, 1, 3))
def test_a_late_ack_still_delivers_the_original_once_by_bounded_fallback(source, kind, offset_laps):
    """ACK past readiness: the original response is released by T's fallback, once, after the ACK; nothing
    vanishes and nothing is busy-dropped, exhausted or stale."""
    lens, busy, out = exchange(SOURCES[source], kind, LATE_NS, offset_laps)
    assert lens == [cs.ACK_LEN, cs.RESPONSE_LEN]
    assert busy[cs.BUSY_DROP] == busy[cs.EXHAUSTED] == busy[cs.STALE] == 0
    assert out['ACK_COMMIT'] + out['ACK_FALLBACK'] == 1
    assert out['RESP_RELEASE'] == 0 and out['RESP_FALLBACK'] == 1
