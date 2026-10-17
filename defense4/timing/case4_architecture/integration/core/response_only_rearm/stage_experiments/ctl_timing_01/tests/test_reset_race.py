"""m10: a validated master RST survives a same-incarnation owner change (review of af7bd434, finding 1).

The review's reset_race_probe.py swept the master RST from -4 to +4 laps around the outstation's response. On m9 the
RST at -3 laps is lost for READ and SELECT. It waits at stage 1 while the response holds N's work cell; the response
then moves the owner word (READ 5 -> 15 -> 5, SELECT 5 -> 10), the stage-1 pass no longer matches its stage-0
snapshot, and reset_boundary's default terminal_abort drops it. m10 restarts such an RST at stage 0, where it is
validated again against the current owner; a changed epoch (a replacement connection) still aborts.

Pinned here, on m9_01 (failing at -3) and on the generated m10 (every offset):
- the first RST is relayed to the outstation exactly once, the old incarnation closes (owner state 0x200), no
  response reaches the master after the RST, and a same-tuple reconnect then completes a READ;
- on m10 the -3 case is the restart path (count_busy[5] > 0), so the new path is exercised, not assumed;
- negatives: an RST with a wrong SEQ or ACK is refused; an old-incarnation RST replayed after the reconnect closes
  nothing; a duplicate RST is not relayed twice.
"""
import os
from pathlib import Path

import pytest

import contention_source as cs
import test_m6_lifecycle as l

EVIDENCE = Path(__file__).resolve().parent.parent / 'evidence'
M9 = EVIDENCE / 'm9_01/response_only.p4'
M10 = Path(os.environ['M10_SOURCE']) if os.environ.get('M10_SOURCE') else l._generated('m10')
RESTART = 5                     # count_busy cell m10 uses for a stage-1 restart
LAPS = range(-4, 5)


def relayed_resets(p, since=0):
    """RST-bearing frames N sent towards the outstation, from wire index `since` on."""
    return [x for x in p.wire[since:] if x[1] == cs.RELAY_PORT and len(x[2]) >= 48 and x[2][47] & 4]


def responses_after(p):
    """Response-length frames the master saw after the first relayed reset."""
    first = relayed_resets(p)
    if not first:
        return []
    return [raw for t, raw in p.to_master() if t >= first[0][0] and len(raw) == cs.RESPONSE_LEN]


def closes_cleanly(source, kind, lap):
    p, frames, _rsp = l.held(source, kind, rst=l.RST[kind], rst_laps=lap)
    return p, (len(relayed_resets(p)) == 1 and l.owner_state(p) == 0x200 and not responses_after(p))


def test_m9_loses_the_first_reset_at_minus_three_laps():
    for kind in ('READ', 'SELECT'):
        p, ok = closes_cleanly(M9, kind, -3)
        assert not ok and relayed_resets(p) == [] and l.owner_state(p) == {'READ': 5, 'SELECT': 10}[kind]


@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
@pytest.mark.parametrize('lap', LAPS)
def test_m10_relays_the_first_reset_once_closes_and_reconnects(kind, lap):
    p, ok = closes_cleanly(M10, kind, lap)
    assert ok
    assert p.busy(cs.BUSY_DROP) == p.busy(cs.EXHAUSTED) == 0
    assert l.new_incarnation_read_completes(p)


def test_m9_also_loses_an_operate_reset_at_minus_three_and_m10_does_not():
    _p, m9_ok = closes_cleanly(M9, 'OPERATE', -3)
    p, ok = closes_cleanly(M10, 'OPERATE', -3)
    assert not m9_ok and ok and p.busy(RESTART) >= 1


@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
def test_m10_minus_three_takes_the_restart_path(kind):
    p, ok = closes_cleanly(M10, kind, -3)
    assert ok and p.busy(RESTART) >= 1


@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
@pytest.mark.parametrize('lap', [x for x in LAPS if x != -3])
def test_m10_counts_no_restart_where_m9_already_closed(kind, lap):
    """The restart is taken only on the owner-change interleaving; every other offset closes as on m9."""
    _p, m9_ok = closes_cleanly(M9, kind, lap)
    q, ok = closes_cleanly(M10, kind, lap)
    assert m9_ok
    assert ok and q.busy(RESTART) == 0


@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
@pytest.mark.parametrize('bad', ('seq+1', 'seq-1', 'ack-1', 'ack+1'))
def test_m10_refuses_a_reset_with_wrong_seq_or_ack_at_minus_three(kind, bad):
    seq, ack = l.RST[kind]
    rst = {'seq+1': (seq + 1, ack), 'seq-1': (seq - 1, ack), 'ack-1': (seq, ack - 1), 'ack+1': (seq, ack + 1)}[bad]
    p, frames, _rsp = l.held(M10, kind, rst=rst, rst_laps=-3)
    assert relayed_resets(p) == [] and l.owner_state(p) != 0x200


@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
def test_m10_old_incarnation_reset_after_reconnect_closes_nothing(kind):
    p, ok = closes_cleanly(M10, kind, -3)
    assert ok and l.new_incarnation_read_completes(p)
    epoch, sent = p.n.state()['epoch'], len(p.wire)
    p.send(cs.vectors.packet(20, *l.RST[kind]), master=True)       # the old incarnation's RST, replayed
    assert relayed_resets(p, sent) == [] and l.owner_state(p) == 5 and p.n.state()['epoch'] == epoch
    # the next READ: client 4001 + 20, native server 7001 + 49; the master acks the 61-octet image, 7001 + 61
    lens, outcome, _busy, _retries = l.read_exchange(p, 4021, 7050, 7062)
    assert l.committed_once(lens, outcome)


@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
def test_m10_duplicate_reset_is_relayed_once(kind):
    p, ta, _rp = l._schedule(M10, kind)
    for offset in (3000 + 2, 3000 + 400):                 # the -3 lap RST and a copy 0.4 laps later
        p.at(ta + offset, cs.vectors.packet(20, *l.RST[kind]), master=True)
    p.settle()
    assert len(relayed_resets(p)) == 1 and l.owner_state(p) == 0x200


def test_m10_reset_does_not_restart_when_the_owner_generation_changed():
    """The owner's generation half moves under the close (forced): that is another owner, so the RST aborts and the
    connection stays open, as on m6; only a state-half change restarts."""
    p = cs.LapPipeline(M10).handshake()
    p.send(cs.rs.request_packet(seq=101, ack=901))
    p.settle()
    p.ingress(p.now + 1000, cs.MASTER_PORT, cs.vectors.packet(20, 121, 901))
    stage1 = None
    while p.heap:
        time, _o, port, raw = p.heap[0]
        if port == cs.RETURN_PORT and int.from_bytes(raw[12:14], 'big') == 0x0104:
            stage1 = True
            p.n.src.cells[('', 'owner')][0] ^= 0x1                 # the generation half changes
        p.run(time)
        if stage1:
            break
    p.settle()
    assert stage1 and l.owner_state(p) != 0x200 and relayed_resets(p) == [] and p.busy(RESTART) == 0


# ---- forced owner changes under the close (register mutation between passes) ------------------------------------
def run_forcing(p, change, until_frames=None):
    """Run p to quiescence. Before each stage-1 close pass (a 0x0104 frame on RETURN_PORT) apply change(p, n, 'before')
    and after it change(p, n, 'after'), n counting those passes from 1."""
    count = 0
    while p.heap:
        time, _o, port, raw = p.heap[0]
        stage1 = port == cs.RETURN_PORT and int.from_bytes(raw[12:14], 'big') == 0x0104
        if stage1:
            count += 1
            change(p, count, 'before')
        p.run(time)
        if stage1:
            change(p, count, 'after')
    p.settle()
    return count


def owner_cell(p):
    return p.n.src.cells[('', 'owner')]


def test_m10_bounds_restarts_at_the_shared_budget():
    """The state half moves under every stage-1 pass: 32 restarts, then the RST aborts; nothing is relayed."""
    p = cs.LapPipeline(M10).handshake()
    p.send(cs.rs.request_packet(seq=101, ack=901))
    p.settle()
    p.ingress(p.now + 1000, cs.MASTER_PORT, cs.vectors.packet(20, 121, 901))

    def flap(q, n, when):
        if when == 'before':
            owner_cell(q)[0] ^= 0x10000                 # state half only: same generation
    passes = run_forcing(p, flap)
    assert p.busy(RESTART) == 32 and passes == 33 and relayed_resets(p) == []
    assert max(int.from_bytes(raw[14:16], 'big') for _t, port, raw, *_ in p.passes
               if port == cs.RETURN_PORT and int.from_bytes(raw[12:14], 'big') in (0x0104, 0x0800)) <= 32


def _outstation_close(source, change):
    p, ta, _rp = l._schedule(source, 'READ')
    p.settle()                                           # the READ completes; then the outstation resets
    p.ingress(p.now + 1000, cs.RELAY_PORT, l._outstation_rst('READ'))
    run_forcing(p, change)
    return p


def test_m10_outstation_reset_restart_ends_like_an_undisturbed_close():
    """reset_restart_out: the state half moves under the first stage-1 pass and is put back after it. The RST
    restarts once, and the end state and the master's frames equal those of the undisturbed close."""
    saved = {}

    def bump(q, n, when):
        if n != 1:
            return
        if when == 'before':
            saved['v'] = owner_cell(q)[0]
            owner_cell(q)[0] ^= 0x10000
        else:
            owner_cell(q)[0] = saved['v']
    plain = _outstation_close(M10, lambda *a: None)
    forced = _outstation_close(M10, bump)
    assert plain.busy(RESTART) == 0 and forced.busy(RESTART) == 1
    assert l.owner_state(forced) == l.owner_state(plain)
    assert [len(raw) for _t, raw in forced.to_master()] == [len(raw) for _t, raw in plain.to_master()]


def test_m10_fin_ack_does_not_restart():
    """Only RST-bearing segments restart: a FIN|ACK whose owner state moves under its close aborts as on m9."""
    for source in (M9, M10):
        p = cs.LapPipeline(source).handshake()
        p.send(cs.rs.request_packet(seq=101, ack=901))
        p.settle()
        p.ingress(p.now + 1000, cs.MASTER_PORT, cs.vectors.packet(17, 121, 901))

        def once_flip(q, n, when):
            if n == 1 and when == 'before':
                owner_cell(q)[0] ^= 0x10000
        run_forcing(p, once_flip)
        assert p.busy(RESTART) == 0 and l.owner_state(p) != 0x200


@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
def test_m10_restart_frame_replayed_after_reconnect_is_stale(kind):
    """A restart frame (0x0800, reserved > 0) of the old incarnation, injected after a same-tuple reconnect, closes
    nothing: retry_epoch_check refuses it on the retry pass."""
    p, ok = closes_cleanly(M10, kind, -3)
    restart = [raw for _t, port, raw, *_ in p.passes
               if port == cs.RETURN_PORT and int.from_bytes(raw[12:14], 'big') == 0x0800
               and int.from_bytes(raw[14:16], 'big') > 0]
    assert ok and restart
    assert l.new_incarnation_read_completes(p)
    epoch, sent = p.n.state()['epoch'], len(p.wire)
    p.ingress(p.now + 1000, cs.RETURN_PORT, restart[0])
    p.settle()
    assert relayed_resets(p, sent) == [] and l.owner_state(p) == 5 and p.n.state()['epoch'] == epoch
    lens, outcome, _busy, _retries = l.read_exchange(p, 4021, 7050, 7062)
    assert l.committed_once(lens, outcome)


def test_m10_open_limitation_a_master_sending_after_its_own_reset():
    """Kept limitation (as m9, test_reset_then_syn.py): a master READ one lap after its own RST advances the client
    sequence. m10 restarts the RST once; its stage-0 pass then refuses it on SEQ, so it is still not relayed. A
    compliant master sends nothing after its RST, so this is not the response race m10 corrects."""
    p = cs.LapPipeline(M10).handshake()
    l.read_exchange(p, 101, 901, 901)
    t = p.now + 100_000
    seen = len(p.wire)
    p.at(t, cs.vectors.packet(20, 121, 901 + 49 + 12), master=True)
    p.at(t + p.lap_ns, cs.rs.request_packet(seq=121, ack=962), master=True)
    p.now = t
    p.settle()
    assert relayed_resets(p, seen) == [] and p.busy(RESTART) == 1


# ---- known defect: the N-to-T reset propagation window, present on m9_01 and m10 as tested (failure analysis) -----
@pytest.mark.parametrize('source', (M9, M10), ids=('m9_01', 'm10'))
@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
def test_known_defect_reset_propagation_window(source, kind):
    """N cancels the connection at its stage-1 owner CAS. T learns of it only after N's stage-2 pass and the
    hand-off, so a held response whose release deadline falls in that window is released after the cancellation.
    Pinned as a defect (evidence/m10_03/failure_analysis_20261017): a master RST arriving 1-5 laps before the
    scheduled release lets the response reach the master; 8 or more laps before, it never does. If this test starts
    failing, the window changed: update the analysis, not this expectation."""
    p0, _f, _r = l.held(source, kind)
    t_rel = [t for t, raw in p0.to_master() if len(raw) == cs.RESPONSE_LEN][0]

    def leaks(back):
        p, _ta, _rp = l._schedule(source, kind)
        p.at(t_rel - back * 1000 + 2, cs.vectors.packet(20, *l.RST[kind]), master=True)
        p.settle()
        assert l.owner_state(p) == 0x200                       # the connection still closes
        return any(len(raw) == cs.RESPONSE_LEN for _t, raw in p.to_master())
    assert any(leaks(back) for back in range(1, 6))
    assert not any(leaks(back) for back in range(8, 14))
