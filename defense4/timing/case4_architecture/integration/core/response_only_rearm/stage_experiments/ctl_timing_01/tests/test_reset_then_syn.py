"""A same-tuple SYN that reaches N while the master's RST is still closing the previous connection (source pipeline).

The m8_02 contention attempt 02 (evidence/model_contention_m8_02_02/FAILURE_20261016.md) took the model about 0.7 s to
process the dup_READ master RST. It was processed directly before the dup_SELECT SYN:
- the RST's first pass ran first_close;
- the SYN's pass ran go_new and claimed N's work cell;
- the RST's continuation found no work (go_ret_nowork), so close_owner/emit_reset never ran;
- neither N nor E ever stored the new connection, and every later same-tuple connection drew no frames.

Here the SYN follows the RST by a fixed number of laps. Required on m9 (transform_n_m9): the old connection's reset
reaches the outstation exactly once; the new handshake then completes on the same tuple; and a READ on it commits
and releases once. m8 is pinned failing at one lap, which is the defect m9 corrects.
"""
import pytest

import contention_source as cs
import test_m6_lifecycle as lifecycle

V = cs.vectors
M8 = lifecycle._generated('m8')
M9 = lifecycle._generated('m9')
SOURCES = {'m9': M9}


def reset_then_syn(source, syn_laps):
    p = cs.LapPipeline(source).handshake()
    lens, _outcome, _busy, _retries = lifecycle.read_exchange(p, 101, 901, 901)
    assert lens == [cs.ACK_LEN, cs.RESPONSE_LEN]
    t = p.now + 100_000
    relay0 = len([1 for _t, port, _raw in p.wire if port == cs.RELAY_PORT])
    p.at(t, V.packet(20, 121, 901 + 49 + 12), master=True)               # RST|ACK at the master's RCV.NXT
    p.at(t + syn_laps * p.lap_ns, V.packet(2, 4000, mss=1460), master=True)
    p.now = t
    p.settle()
    relayed = [raw for _t, port, raw in p.wire if port == cs.RELAY_PORT][relay0:]
    resets = [raw for raw in relayed if raw[47] & 0x04]
    syns = [raw for raw in relayed if raw[47] & 0x02]
    return p, resets, syns


@pytest.mark.parametrize('source', sorted(SOURCES))
@pytest.mark.parametrize('syn_laps', (1, 2, 3, 4, 6, 10))
def test_reset_reaches_the_outstation_once_and_the_tuple_reconnects(source, syn_laps):
    p, resets, syns = reset_then_syn(SOURCES[source], syn_laps)
    assert len(resets) == 1, 'old connection reset relayed %d times' % len(resets)
    # the SYN may be relayed now or refused and retransmitted by the master; either way the tuple must reconnect
    if not syns:
        p.send(V.packet(2, 4000, mss=1460))
    p.send(V.packet(18, 7000, 4001, reverse=True, mss=1460), master=False)
    p.send(V.packet(16, 4001, 7001))
    assert lifecycle.owner_state(p) == 5, p.n.state()
    lens, outcome, busy, _retries = lifecycle.read_exchange(p, 4001, 7001, 7001)
    assert lifecycle.committed_once(lens, outcome), (lens, outcome)
    assert busy[cs.BUSY_DROP] == busy[cs.STALE] == 0


def test_m8_loses_the_reset_when_a_syn_claims_the_cell_one_lap_later():
    """The defect: the RST is dropped at stage 1 (terminal_abort), nothing reaches the outstation, and N keeps the
    old connection established (owner state 5), so the master's SYN retransmission is denied as well."""
    p, resets, syns = reset_then_syn(M8, 1)
    assert resets == [] and syns == [] and lifecycle.owner_state(p) == 5
    seen = len(p.wire)
    p.send(V.packet(2, 4000, mss=1460))
    assert not [1 for _t, port, _raw in p.wire[seen:] if port == cs.RELAY_PORT]


@pytest.mark.parametrize('source', sorted(SOURCES))
def test_a_reset_with_no_following_syn_still_closes_once(source):
    p = cs.LapPipeline(SOURCES[source]).handshake()
    lifecycle.read_exchange(p, 101, 901, 901)
    seen = len(p.wire)
    p.send(V.packet(20, 121, 901 + 49 + 12))
    resets = [raw for _t, port, raw in p.wire[seen:] if port == cs.RELAY_PORT and raw[47] & 0x04]
    assert len(resets) == 1 and lifecycle.owner_state(p) != 5


def test_m9_reset_wait_is_bounded_by_the_retry_budget():
    """A close that keeps finding the cell busy waits at most n_RETRY_BUDGET (32) laps, then aborts as m8 did; it
    never recirculates without end. The cell is held claimed (phase 1) from the RST's stage-1 pass on (forced)."""
    p = cs.LapPipeline(M9).handshake()
    lifecycle.read_exchange(p, 101, 901, 901)
    seen, passes = len(p.wire), len(p.passes)
    p.ingress(p.now + 1000, cs.MASTER_PORT, V.packet(20, 121, 901 + 49 + 12))
    cell = p.n.src.cells[('work', 'work')]
    while p.heap:
        time, _o, port, raw = p.heap[0]
        if port == cs.RETURN_PORT and int.from_bytes(raw[12:14], 'big') == 0x0104:
            cell[0] = dict(cell[0], phase=1)                       # another event holds the cell
        p.run(time)
    p.settle()
    waits = [raw for _t, port, raw, *_ in p.passes[passes:]
             if port == cs.RETURN_PORT and int.from_bytes(raw[12:14], 'big') == 0x0104]
    assert len(waits) == 33                                          # first stage-1 pass + 32 waits, then abort
    assert not [1 for _t, port, raw in p.wire[seen:] if port == cs.RELAY_PORT and raw[47] & 0x04]
    assert lifecycle.owner_state(p) == 5


def stage1_resets(p, since=0):
    """The RST's stage-1 passes (event 0x0104) and the wait count each carried (event.reserved)."""
    return [int.from_bytes(raw[14:16], 'big') for _t, port, raw, *_ in p.passes[since:]
            if port == cs.RETURN_PORT and int.from_bytes(raw[12:14], 'big') == 0x0104]


def test_m9_one_lap_contention_actually_takes_the_wait_path():
    p, resets, _syns = reset_then_syn(M9, 1)
    waits = stage1_resets(p)
    assert len(resets) == 1 and max(waits) >= 1, waits


@pytest.mark.parametrize('busy_laps', (5, 12, 31))
def test_m9_a_cell_busy_longer_than_a_lifecycle_then_free_still_closes(busy_laps):
    """The cell is held claimed (forced) for busy_laps stage-1 passes of the RST, then released: the RST closes once."""
    p = cs.LapPipeline(M9).handshake()
    lifecycle.read_exchange(p, 101, 901, 901)
    seen, passes = len(p.wire), len(p.passes)
    p.ingress(p.now + 1000, cs.MASTER_PORT, V.packet(20, 121, 901 + 49 + 12))
    cell, held = p.n.src.cells[('work', 'work')], 0
    while p.heap:
        time, _o, port, raw = p.heap[0]
        if port == cs.RETURN_PORT and int.from_bytes(raw[12:14], 'big') == 0x0104:
            held += 1
            cell[0] = dict(cell[0], phase=1 if held <= busy_laps else 4)
        p.run(time)
    p.settle()
    assert max(stage1_resets(p, passes)) == busy_laps
    assert len([1 for _t, port, raw in p.wire[seen:] if port == cs.RELAY_PORT and raw[47] & 0x04]) == 1
    assert lifecycle.owner_state(p) != 5


def test_m9_a_duplicate_rst_during_the_wait_resets_once():
    p = cs.LapPipeline(M9).handshake()
    lifecycle.read_exchange(p, 101, 901, 901)
    t = p.now + 100_000
    seen = len(p.wire)
    rst = V.packet(20, 121, 901 + 49 + 12)
    p.at(t, rst, master=True)
    p.at(t + p.lap_ns, V.packet(2, 4000, mss=1460), master=True)
    p.at(t + 2 * p.lap_ns, rst, master=True)
    p.now = t
    p.settle()
    assert len([1 for _t, port, raw in p.wire[seen:] if port == cs.RELAY_PORT and raw[47] & 0x04]) == 1
    assert lifecycle.owner_state(p) != 5


def test_m9_open_limitation_an_owner_changing_event_still_loses_the_reset():
    """Open limitation (review of m9): the wait applies only while the owner is unchanged. A master READ one lap after
    its own RST claims the owner, so the waiting RST aborts as on m8. A compliant master sends nothing after its RST;
    this pins the behaviour so a change to it is noticed."""
    p = cs.LapPipeline(M9).handshake()
    lifecycle.read_exchange(p, 101, 901, 901)
    t = p.now + 100_000
    seen = len(p.wire)
    p.at(t, V.packet(20, 121, 901 + 49 + 12), master=True)
    p.at(t + p.lap_ns, cs.rs.request_packet(seq=121, ack=962), master=True)
    p.now = t
    p.settle()
    assert not [1 for _t, port, raw in p.wire[seen:] if port == cs.RELAY_PORT and raw[47] & 0x04]
