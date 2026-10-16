"""m8 (m7 + E reset): an outstation abort while T holds the response completes at the master (directive ba50eac69, section 2).

m6 closes N and flushes the held response, but E drops the outstation's RST as OUT_DROP_AHEAD (front_ret 49 for READ,
37 for control): the RST's SEQ follows response bytes the master never received, so the master's connection stays
open. Linux 5.15 resets only on an RST at its RCV.NXT and answers an in-window RST ahead of it with a challenge ACK
(measured 2026-10-16). m8's one E exception (generate.transform_e_m8) places such an RST at the frontier. The master's
RCV.NXT here is the SYN-ACK's SEQ + 1 (901) for READ and SELECT, and 962 for OPERATE (after the 61-octet SELECT image);
after a released response it is that value + 61.
"""
import importlib.util
import os
import struct
import tempfile
from pathlib import Path

import pytest

import contention_source as cs
import test_m6_lifecycle as lc

V = cs.vectors
OUT_RST = dict(lc.OUT_RST, OPERATE=(975, 171))     # outstation SEQ after its 37-octet OPERATE response / ACK
RCV_NXT = {'READ': 901, 'SELECT': 901, 'OPERATE': 962}


def _generated(milestone):
    spec = importlib.util.spec_from_file_location('m8_abort_generate', lc.EVIDENCE.parent / 'generate.py')
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    path = Path(tempfile.mkdtemp(prefix='%s_generated_' % milestone)) / 'response_only.p4'
    path.write_text(gen.full_source(milestone))
    return path


M8 = Path(os.environ['M8_ABORT_SOURCE']) if os.environ.get('M8_ABORT_SOURCE') else _generated('m8')


def resets_to_master(p):
    return [struct.unpack('!II', raw[38:46]) + (raw[47],) for _t, raw in p.to_master() if raw[47] & 0x04]


def responses_to_master(p):
    return [raw for _t, raw in p.to_master() if len(raw) == cs.RESPONSE_LEN]


@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
@pytest.mark.parametrize('rst_laps', (0, 1, 5))
def test_outstation_abort_while_held_resets_the_master_exactly(kind, rst_laps):
    """The held response is discarded (never reaches the master) and the master receives exactly one RST at its
    RCV.NXT, the reset Linux accepts; N closes and a fresh connection then completes a READ."""
    p, _frames, _ = lc.held(M8, kind, extra=[(rst_laps * 1000 + 2, V.packet(20, *OUT_RST[kind], reverse=True), False)])
    assert lc.owner_state(p) == 0x200
    before_response = len(responses_to_master(p))
    assert [r[0] for r in resets_to_master(p)] == [RCV_NXT[kind]]
    assert all(r[2] == 0x14 for r in resets_to_master(p))
    assert before_response == (1 if kind == 'OPERATE' else 0)        # OPERATE: only the earlier SELECT's image
    assert p.busy(cs.BUSY_DROP) == p.busy(cs.EXHAUSTED) == p.busy(cs.STALE) == 0
    assert lc.new_incarnation_read_completes(p)


@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
def test_m6_characterization_closes_n_but_never_resets_the_master(kind):
    """Inherited defect kept as a record: on m6 the same abort closes N and reaches nobody (E OUT_DROP_AHEAD)."""
    p, _frames, _ = lc.held(lc.M6, kind, extra=[(5 * 1000 + 2, V.packet(20, *OUT_RST[kind], reverse=True), False)])
    assert lc.owner_state(p) == 0x200 and resets_to_master(p) == []


@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
def test_abort_after_release_is_unchanged_at_the_released_frontier(kind):
    """After T released the response the frontier has advanced: the RST is translated as before (m6 = m8), at
    RCV.NXT + 61."""
    out = {}
    for name, source in (('m6', lc.M6), ('m8', M8)):
        p, _f, _ = lc.held(source, kind, extra=[(5000 * 1000 + 2, V.packet(20, *OUT_RST[kind], reverse=True), False)])
        out[name] = ([r[0] for r in resets_to_master(p)], len(responses_to_master(p)))
    assert out['m6'] == out['m8'] == ([RCV_NXT[kind] + 61], 1)


@pytest.mark.parametrize('delta', (-1, 1, 12, 61))
def test_other_ahead_or_off_frontier_resets_are_not_moved(delta):
    """Only an RST exactly one held response ahead is placed at the frontier; an outstation RST at any other offset
    is refused by N (wrong SEQ) or, if it reached E, dropped as before: the master is never reset by it."""
    seq, ack = OUT_RST['READ']
    p, _f, _ = lc.held(M8, 'READ', extra=[(5 * 1000 + 2, V.packet(20, seq + delta, ack, reverse=True), False)])
    assert resets_to_master(p) == []
    assert lc.owner_state(p) != 0x200
