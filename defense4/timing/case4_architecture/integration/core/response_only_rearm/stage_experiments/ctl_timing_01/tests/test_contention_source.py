"""N's ACK/response work-cell contention at lap granularity, source level (PLAN_m5.md S1).

The outstation's bare ACK holds N's single work cell for four passes; its response arriving during those laps
found the cell busy and m4 busy-dropped it (count_busy[0]); T then released the ACK by its readiness fallback and
the response reached the master only through the outstation's TCP retransmission. The m4 cases keep that
original race as a regression; every successor build must deliver at every offset.
"""
from pathlib import Path

import pytest

import contention_source as cs

EVIDENCE = Path(__file__).resolve().parent.parent / 'evidence'
M4 = EVIDENCE / 'm4_01/response_only.p4'
SUCCESSORS = [p for p in (EVIDENCE / 'm5_01/response_only.p4',) if p.is_file()]
IDS = [p.parent.name for p in SUCCESSORS]
KINDS = ('READ', 'SELECT', 'OPERATE')
OFFSETS = range(5)
M4_BUSY_OFFSETS = {0, 1, 2}        # the ACK's passes 1-3 still hold the cell; its 4th pass frees it


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('offset', OFFSETS)
def test_m4_keeps_the_original_race(kind, offset):
    r = cs.contended(M4, kind, offset)
    if offset in M4_BUSY_OFFSETS:
        # the busy-dropped response never reaches the master; the ACK leaves by T's readiness fallback
        assert r['busy'][cs.BUSY_DROP] == 1
        assert [len(raw) for _, raw in r['master']] == [cs.ACK_LEN]
        assert r['outcomes']['ACK_FALLBACK'] == 1 and r['outcomes']['RESP_RELEASE'] == 0
        assert not cs.delivered_once_after_ack(r)
    else:
        assert cs.delivered_once_after_ack(r), r['outcomes']


@pytest.mark.parametrize('source', SUCCESSORS, ids=IDS)
@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('offset', OFFSETS)
def test_successor_delivers_at_every_offset(source, kind, offset):
    r = cs.contended(source, kind, offset)
    assert cs.delivered_once_after_ack(r), (r['busy'], r['outcomes'], [len(x) for _, x in r['master']])
    ack_at, rsp_at = (stamp for stamp, _ in r['master'])
    assert ack_at < rsp_at
