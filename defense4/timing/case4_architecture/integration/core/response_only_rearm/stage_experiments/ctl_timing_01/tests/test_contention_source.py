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
import importlib.util
import os
import tempfile


def _generated(milestone='m5'):
    """The source as the generator produces it now, so the successor cases always run in the suite."""
    spec = importlib.util.spec_from_file_location('contention_generate', EVIDENCE.parent / 'generate.py')
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    path = Path(tempfile.mkdtemp(prefix='%s_generated_' % milestone)) / 'response_only.p4'
    path.write_text(gen.full_source(milestone))
    return path


SUCCESSORS = [_generated('m5')] + [p for p in (EVIDENCE / 'm5_10/response_only.p4',) if p.is_file()] + \
    [Path(x) for x in os.environ.get('CONTENTION_EXTRA_SOURCES', '').split(':') if x]
IDS = ['generated_m5'] + [p.parent.name for p in SUCCESSORS[1:]]
# m6 (DESIGN.md m6): the generated source; CONTENTION_M6_SOURCES (':'-separated) replaces it, e.g. with a retained
# build, to show which m6 expectations pin a fix
M6S = [Path(x) for x in os.environ.get('CONTENTION_M6_SOURCES', '').split(':') if x] or [_generated('m6')]
M6_IDS = ['generated_m6' if 'm6_generated_' in str(p) else p.parent.name for p in M6S]
ALL = SUCCESSORS + M6S
ALL_IDS = IDS + M6_IDS
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


@pytest.mark.parametrize('source', ALL, ids=ALL_IDS)
@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('offset', OFFSETS)
def test_successor_delivers_at_every_offset(source, kind, offset):
    r = cs.contended(source, kind, offset)
    assert cs.delivered_once_after_ack(r), (r['busy'], r['outcomes'], [len(x) for _, x in r['master']])
    ack_at, rsp_at = (stamp for stamp, _ in r['master'])
    assert ack_at < rsp_at


# ---- m5 edge cases (PLAN_m5.md S2: amendments 1-5) ------------------------------------------------
def _busy_retry(source):
    """A READ whose response arrives one lap after the ACK, so it retries at least once."""
    return cs.contended(source, 'READ', 0)


@pytest.mark.parametrize('source', ALL, ids=ALL_IDS)
def test_retry_allocates_no_generation_and_touches_nothing_else(source):
    contended, clean = _busy_retry(source), cs.contended(source, 'READ', 6)
    assert contended['busy'][cs.RETRY] >= 1 and clean['busy'][cs.RETRY] == 0
    a, b = contended['pipeline'], clean['pipeline']
    # the same N generations, N registers and E mapper state as the uncontended exchange (amendments 1, 5)
    assert cs.n_state(a) == cs.n_state(b)
    assert a.e.cells == b.e.cells
    assert all(destination != cs.RETURN_PORT for kind, _t, destination, *_ in a.trace if kind == 'E')
    assert [raw for _t, raw in contended['master']] == [raw for _t, raw in clean['master']]


def _duplicate(source, first_laps, second_laps, kind='READ'):
    p = cs.LapPipeline(source).handshake()
    request, ack, response = cs.transaction(kind)
    seen, t = len(p.to_master()), p.now + 100_000
    t_ack = t + cs.REQ_TO_ACK_NS
    p.at(t, request, master=True)
    p.at(t_ack, ack)
    p.at(t_ack + first_laps * p.lap_ns + 1, response)
    p.at(t_ack + second_laps * p.lap_ns + 2, response)
    p.now = t
    p.settle()
    return p, [(stamp - t_ack, len(raw)) for stamp, raw in p.to_master()[seen:]]


def test_m4_forwards_a_duplicate_response_untimed_once_the_original_was_admitted():
    """Pre-existing m4 behaviour, recorded so m5 is held to it (not a property m5 introduces): an outstation
    retransmission of a response N already admitted is forwarded natively at once, ahead of T's timed release
    of the original; a copy that lands while the original's lifecycle holds the cell is busy-dropped instead."""
    p, frames = _duplicate(M4, 5, 12)
    assert [n for _t, n in frames] == [cs.RESPONSE_LEN, cs.ACK_LEN, cs.RESPONSE_LEN] and frames[0][0] < frames[1][0]
    p, frames = _duplicate(M4, 5, 6)
    assert [n for _t, n in frames] == [cs.ACK_LEN, cs.RESPONSE_LEN] and p.busy(cs.BUSY_DROP) == 1


@pytest.mark.parametrize('source', SUCCESSORS, ids=IDS)
@pytest.mark.parametrize('first, second', [(0, 0), (1, 1), (5, 6)])
def test_retried_duplicate_is_dropped_and_counted_never_forwarded(source, first, second):
    """A copy that waits in retry and is then classed as a retransmission (forward_original) aborts instead of
    leaving untimed ahead of the timed original: the master sees exactly the ACK and one response, both timed."""
    p, frames = _duplicate(source, first, second)
    o = cs.outcomes(p)
    assert (o['ACK_COMMIT'], o['RESP_RELEASE'], o['ACK_FALLBACK'], o['RESP_FALLBACK']) == (1, 1, 0, 0)
    assert [n for _t, n in frames] == [cs.ACK_LEN, cs.RESPONSE_LEN] and frames[0][0] < frames[1][0]
    assert p.retried_duplicates() == 1
    assert p.busy(cs.BUSY_DROP) == 0 and p.busy(cs.EXHAUSTED) == 0 and p.busy(cs.STALE) == 0
    assert p.n.state()['work']['phase'] == 4                  # the aborted copy returned the cell


@pytest.mark.parametrize('source', SUCCESSORS, ids=IDS)
def test_post_lifecycle_native_duplicate_keeps_m4_behaviour(source):
    """Outside this correction: a copy arriving natively after the original's lifecycle is m4's path, unchanged
    (forwarded untimed; open item in DESIGN.md m5)."""
    _p, frames = _duplicate(source, 5, 12)
    _p4, m4_frames = _duplicate(M4, 5, 12)
    assert [n for _t, n in frames] == [n for _t, n in m4_frames]


@pytest.mark.parametrize('source', M6S, ids=M6_IDS)
@pytest.mark.parametrize('kind, owner', [('READ', 0x5), ('SELECT', 0xa)])
@pytest.mark.parametrize('first, second', [(0, 0), (1, 1), (5, 6)])
def test_m6_retried_duplicate_is_dropped_by_t(source, kind, owner, first, second):
    """m6 (DESIGN.md m6 D): the copy is no longer aborted as a retried duplicate in N (count_term[0] stays 0); in
    owner states 5 and 0xa it becomes event 0x0119 and T's release gate drops it while the original is held. The
    master still sees exactly the ACK and one response, both timed."""
    p, frames = _duplicate(source, first, second, kind)
    o = cs.outcomes(p)
    assert (o['ACK_COMMIT'], o['RESP_RELEASE'], o['ACK_FALLBACK'], o['RESP_FALLBACK']) == (1, 1, 0, 0)
    assert [n for _t, n in frames] == [cs.ACK_LEN, cs.RESPONSE_LEN] and frames[0][0] < frames[1][0]
    assert o['RESP_DUP_DROP'] == 1 and p.retried_duplicates() == 0
    assert p.busy(cs.BUSY_DROP) == 0 and p.busy(cs.EXHAUSTED) == 0 and p.busy(cs.STALE) == 0
    assert p.n.state()['owner'] >> 16 == owner and p.n.state()['work']['phase'] == 4


@pytest.mark.parametrize('source', M6S, ids=M6_IDS)
def test_m6_post_lifecycle_duplicate_goes_through_t(source):
    """m6 corrects m4/m5's native path here: a copy arriving after the original's lifecycle, while T still holds
    the original, is dropped by T instead of leaving untimed ahead of the ACK."""
    p, frames = _duplicate(source, 5, 12)
    _p4, m4_frames = _duplicate(M4, 5, 12)
    assert [n for _t, n in m4_frames] == [cs.RESPONSE_LEN, cs.ACK_LEN, cs.RESPONSE_LEN]
    assert [n for _t, n in frames] == [cs.ACK_LEN, cs.RESPONSE_LEN]
    assert cs.outcomes(p)['RESP_DUP_DROP'] == 1 and p.retried_duplicates() == 0


def _waiting_retry(source, kind='READ'):
    """A pipeline right after a genuine retry frame was produced, and that frame."""
    r = cs.contended(source, kind, 0)
    frames = cs.retry_frames(r['pipeline'])
    assert frames, 'no retry frame was produced'
    return r['pipeline'], frames[0]


def _inject(p, port, raw):
    before, busy0 = cs.n_state(p), [p.busy(i) for i in range(8)]
    seen, passes = len(p.wire), len(p.passes)
    p.ingress(p.now + 1000, port, raw)
    p.settle()
    p.injected_passes = len(p.passes) - passes
    return before, cs.n_state(p), [p.busy(i) - busy0[i] for i in range(8)], p.wire[seen:]


@pytest.mark.parametrize('source', ALL, ids=ALL_IDS)
def test_genuine_retry_form_claims_when_current(source):
    """Positive control for the mutation cases: the captured retry frame, replayed while its connection is still
    current and the cell free, is accepted (it claims and runs a lifecycle), so a refusal below is meaningful."""
    p, frame = _waiting_retry(source)
    before, after, busy, _wire = _inject(p, cs.RETURN_PORT, frame)
    assert busy[cs.STALE] == 0 and after['work']['generation'] == int.from_bytes(frame[4:8], 'big')


@pytest.mark.parametrize('source', ALL, ids=ALL_IDS)
@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
@pytest.mark.parametrize('mutation, stale', [
    (dict(event=0x0401), False), (dict(event=0x0500), False), (dict(event=0x0c00), False),
    (dict(reserved=1), False), (dict(budget=0), True), (dict(budget=33), True), (dict(budget=0xffffffff), True),
    (dict(epoch='+1'), True), (dict(generation=0), False)])
def test_mutated_retry_form_never_claims(source, kind, mutation, stale):
    p, frame = _waiting_retry(source, kind)
    if mutation.get('epoch') == '+1':
        mutation = dict(epoch=int.from_bytes(frame[0:4], 'big') + 1)
    before, after, busy, wire = _inject(p, cs.RETURN_PORT, cs.envelope(frame, **mutation))
    assert after == before                       # no claim, no generation, no register write
    assert busy[cs.STALE] == (1 if stale else 0) and sum(busy) == busy[cs.STALE]
    assert not wire and p.injected_passes == 1   # dropped on its single pass: no recirculation


@pytest.mark.parametrize('source', ALL, ids=ALL_IDS)
def test_retry_form_on_another_connection_or_port_never_claims(source):
    p, frame = _waiting_retry(source)
    tcp = 16 + 14 + 20
    # a corrupted retry (TCP checksum no longer valid) fails N's network check: denied on its single pass
    broken = bytearray(frame)
    broken[tcp + 2:tcp + 4] = (cs.vectors.CLIENT_PORT + 1).to_bytes(2, 'big')
    before, after, busy, wire = _inject(p, cs.RETURN_PORT, bytes(broken))
    assert after == before and sum(busy) == 0 and not wire and p.injected_passes == 1
    # identity: the same retry re-addressed to a tuple N has no connection row, checksum recomputed (direction 0)
    other = bytearray(broken)
    other[tcp + 16:tcp + 18] = b'\0\0'
    ip = other[16 + 14:16 + 34]
    pseudo = ip[12:20] + bytes((0, 6)) + (len(other) - tcp).to_bytes(2, 'big')
    other[tcp + 16:tcp + 18] = cs.vectors.checksum(bytes(pseudo) + bytes(other[tcp:])).to_bytes(2, 'big')
    before, after, busy, wire = _inject(p, cs.RETURN_PORT, bytes(other))
    assert after == before and busy[cs.STALE] == 1 and not wire and p.injected_passes == 1
    # arrival port: the retry form from a front port is not a retry (no claim, no count)
    for port in (cs.RELAY_PORT, cs.MASTER_PORT):
        before, after, busy, _wire = _inject(p, port, frame)
        assert after == before and busy[cs.STALE] == 0


@pytest.mark.parametrize('source', ALL, ids=ALL_IDS)
def test_retry_from_a_reset_or_reconnected_connection_is_refused_before_claiming(source):
    p, frame = _waiting_retry(source)
    p.send(cs.vectors.packet(20, 121, 962))            # master RST: retry_epoch cleared
    p.settle()
    assert cs.n_state(p)['retry_epoch'] == 0
    before, after, busy, wire = _inject(p, cs.RETURN_PORT, frame)
    assert after == before and busy[cs.STALE] == 1 and not wire
    p.handshake(4000, 7000)                            # same tuple, new incarnation
    assert cs.n_state(p)['retry_epoch'] == p.n.state()['epoch'] != int.from_bytes(frame[0:4], 'big')
    before, after, busy, wire = _inject(p, cs.RETURN_PORT, frame)
    assert after == before and busy[cs.STALE] == 1 and not wire


@pytest.mark.parametrize('source', ALL, ids=ALL_IDS)
def test_exhausted_budget_is_a_counted_drop(source):
    """The work cell held by a lifecycle that never returns (forced): the response retries exactly the budget,
    then is dropped and counted, and never reaches the master."""
    p = cs.LapPipeline(source).handshake()
    request, ack, response = cs.transaction('READ')
    t = p.now + 100_000
    p.at(t, request, master=True)
    p.now = t
    p.run(t + cs.REQ_TO_ACK_NS)
    seen = len(p.to_master())
    p.n.src.cells[('work', 'work')][0] = {'generation': 0x7ffffff0, 'phase': 1}
    p.at(p.now + 1, response)
    p.settle()
    budget = int(cs.re.search(r'n_RETRY_BUDGET=(\d+);', source.read_text())[1])
    assert p.busy(cs.RETRY) == budget and p.busy(cs.EXHAUSTED) == 1 and p.busy(cs.BUSY_DROP) == 0
    assert not p.to_master()[seen:]


@pytest.mark.parametrize('source', ALL, ids=ALL_IDS)
@pytest.mark.parametrize('kind, table', [('READ', 'connection'), ('READ', 'read_connection'),
                                         ('SELECT', 'connection'), ('SELECT', 'data_connection')])
def test_retry_whose_connection_rows_were_removed_is_counted_on_one_pass(source, kind, table):
    """A retry in flight while the control plane removes the rows that validated it (teardown or restore): it
    passes the epoch check but no longer matches go_retry, so it is stale -- dropped and counted on its single
    pass, never recirculated (review H1: go_stale left m.retry at 1 and the frame looped on RETURN_PORT)."""
    p, frame = _waiting_retry(source, kind)
    cs.rs.drop_runtime(p.n, table)
    before, after, busy, wire = _inject(p, cs.RETURN_PORT, frame)
    assert after == before and not wire and p.injected_passes == 1 and busy[cs.STALE] == 1


@pytest.mark.parametrize('source', ALL, ids=ALL_IDS)
def test_waiting_retry_keeps_its_own_epoch_across_a_new_incarnation(source):
    """A retry keeps the epoch it was created with on every lap. If the connection's epoch and retry_epoch both move
    to a new incarnation while it waits (forced here; the m5_09 review's window), it is refused as stale when the
    cell frees -- it is never re-stamped into the new incarnation (m5_09 re-stamped it with m.epoch)."""
    p = cs.LapPipeline(source).handshake()
    request, ack, response = cs.transaction('READ')
    t = p.now + 100_000
    p.at(t, request, master=True)
    p.now = t
    p.run(t + cs.REQ_TO_ACK_NS)
    old_epoch, seen = p.n.state()['epoch'], len(p.to_master())
    p.n.src.cells[('work', 'work')][0] = {'generation': 0x7ffffff0, 'phase': 1}        # cell held
    p.at(p.now + 1, response)
    p.run(p.now + 5 * p.lap_ns)
    assert p.busy(cs.RETRY) >= 2 and p.busy(cs.STALE) == 0
    # the window: the epoch register has moved (a SYN's stage-1 pass) while retry_epoch has not yet (its stage-2
    # pass); busy laps in between must not take the new epoch, which retry_epoch then names
    p.n.src.cells[('', 'epoch')][0] = old_epoch + 100
    p.run(p.now + 3 * p.lap_ns)
    p.n.src.cells[('', 'retry_epoch')][0] = old_epoch + 100
    p.n.src.cells[('work', 'work')][0] = {'generation': 0x7ffffff0, 'phase': 4}        # cell free
    p.settle()
    assert p.busy(cs.STALE) == 1 and not p.to_master()[seen:]
    assert p.n.state()['work']['generation'] == 0x7ffffff0                              # never claimed
    assert all(int.from_bytes(f[0:4], 'big') == old_epoch for f in cs.retry_frames(p))


def _rst_after_response(source, response_laps, rst_laps):
    """READ: ACK, response `response_laps` laps later, then the master's RST acking only the pre-response sequence
    (what a master that has not yet received the held response sends), `rst_laps` laps after the response."""
    p = cs.LapPipeline(source).handshake()
    request, ack, response = cs.transaction('READ')
    t = p.now + 100_000
    t_ack = t + cs.REQ_TO_ACK_NS
    p.at(t, request, master=True)
    p.at(t_ack, ack)
    p.at(t_ack + response_laps * p.lap_ns + 1, response)
    p.at(t_ack + (response_laps + rst_laps) * p.lap_ns + 2, cs.vectors.packet(20, 121, 901), master=True)
    p.now = t
    p.settle()
    return p.n.state()['owner'] >> 16, [len(raw) for _t, raw in p.to_master()]


@pytest.mark.parametrize('source', SUCCESSORS, ids=IDS)
@pytest.mark.parametrize('rst_laps', (1, 5, 40))
def test_rst_after_a_contended_response_matches_m4_uncontended(source, rst_laps):
    """Pre-existing m4 behaviour, not changed by m5: once N has admitted a response, an RST that does not ack it is
    refused (owner stays 5) and the response is still delivered. m4 escaped it on the contended path only by
    busy-dropping the response; m5's contended path now equals m4's uncontended one (DESIGN.md m5 limitation)."""
    m4 = _rst_after_response(M4, 6, rst_laps)
    m5 = _rst_after_response(source, 0, rst_laps)
    assert m4[0] == m5[0] == 5
    assert m4[1][-2:] == m5[1][-2:] == [cs.ACK_LEN, cs.RESPONSE_LEN]
    m4_contended = _rst_after_response(M4, 0, rst_laps)
    assert m4_contended[0] == 0x200 and cs.RESPONSE_LEN not in m4_contended[1]      # dropped, then reset


@pytest.mark.parametrize('source', M6S, ids=M6_IDS)
@pytest.mark.parametrize('rst_laps', (1, 5, 40))
def test_m6_rst_after_a_contended_response_resets(source, rst_laps):
    """m6 (DESIGN.md m6 R): the RST acking only the pre-response sequence now resets the connection whether or not
    the response was contended, and the held response is never released -- the outcome m4 reached on its contended
    path only by busy-dropping the response."""
    for response_laps in (0, 6):
        owner, lens = _rst_after_response(source, response_laps, rst_laps)
        assert owner == 0x200 and lens == [58]       # the master saw only the SYN-ACK: neither ACK nor response
    m4_contended = _rst_after_response(M4, 0, rst_laps)
    assert m4_contended[0] == 0x200 and cs.RESPONSE_LEN not in m4_contended[1]
