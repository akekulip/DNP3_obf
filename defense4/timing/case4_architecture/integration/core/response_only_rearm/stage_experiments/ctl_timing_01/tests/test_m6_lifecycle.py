"""m6 lifecycle corrections, source level (PLAN_m5.md "m6 continuation"; DESIGN.md m6).

Each case runs on m5_10 (the retained record, which keeps the defect) and on the generated m6 (which corrects it):
  R  a master RST acking only the data it has received, while T still holds an admitted response, resets the
     connection: the held response is never released, a fresh handshake then works; RSTs with a wrong SEQ or an
     ACK other than the pre- or post-response sequence are still refused; an RST that finds N's work cell busy
     retries instead of being denied.
  E  retry_epoch is cleared only once a close is proven (the stage-2 pass after the owner CAS): a close whose CAS
     fails keeps live retry authority.
  D  a retransmitted response arriving while T holds the original goes through T's release gate (dropped as a
     duplicate); after release it is delivered (recovery from loss beyond the switch); with a newer transaction open
     (owner 0xe) it keeps m4/m5's native path.
"""
import copy
import importlib.util
import os
from pathlib import Path

import pytest

import contention_source as cs

EVIDENCE = Path(__file__).resolve().parent.parent / 'evidence'
M5 = EVIDENCE / 'm5_10/response_only.p4'


def _generated(milestone):
    spec = importlib.util.spec_from_file_location('m6_lifecycle_generate', EVIDENCE.parent / 'generate.py')
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    import tempfile
    path = Path(tempfile.mkdtemp(prefix='%s_generated_' % milestone)) / 'response_only.p4'
    path.write_text(gen.full_source(milestone))
    return path


# M6_LIFECYCLE_SOURCE replaces the generated m6 (e.g. with evidence/m6_01 or m5_10) to show which cases pin a fix
M6 = Path(os.environ['M6_LIFECYCLE_SOURCE']) if os.environ.get('M6_LIFECYCLE_SOURCE') else _generated('m6')
V = cs.vectors
RST = {'READ': (121, 901), 'SELECT': (136, 901), 'OPERATE': (171, 962)}   # master SEQ / pre-response ACK
OUT_RST = {'READ': (950, 121), 'SELECT': (938, 136)}   # outstation SEQ (after its response) / ACK, native
T_IN = 197                    # N's READ_HANDOFF_PORT -> T, as the harness remaps it (contention_source.role)
RST_RETRY_EVENT = 0x0800      # m6: an RST that found N's work cell busy, on its retry lap


def _schedule(source, kind):
    """A fresh connection with `kind`'s request, ACK and response queued (response 6 laps + 1 ns after the ACK, so
    uncontended); returns the pipeline (now = request time) and the ACK time."""
    p = cs.LapPipeline(source).handshake()
    if kind == 'OPERATE':
        rq, ak, rp = cs.transaction('SELECT')
        t = p.now + 100_000
        p.at(t, rq, master=True)
        p.at(t + 200_000, ak)
        p.at(t + 400_000, rp)
        p.now = t
        p.settle()
    rq, ak, rp = cs.transaction(kind)
    t = p.now + 100_000
    ta = t + (5 if kind == 'OPERATE' else 1) * 200_000
    p.at(t, rq, master=True)
    p.at(ta, ak)
    p.at(ta + 6000 + 1, rp)
    p.now = t
    return p, ta, rp


def held(source, kind, rst=None, rst_laps=5, dup_at=None, extra=None):
    """`extra`: (ns after ACK + 6 laps, frame, from_master) arrivals; the response itself arrives at +1."""
    p, ta, rp = _schedule(source, kind)
    t = p.now
    if rst is not None:
        p.at(ta + (6 + rst_laps) * 1000 + 2, V.packet(20, *rst), master=True)
    if dup_at is not None:
        p.at(ta + 6000 + dup_at, rp)
    for offset, frame, master in extra or ():
        p.at(ta + 6000 + offset, frame, master=master)
    p.now = t
    seen = len(p.to_master())
    p.settle()
    return p, [(stamp - ta, raw) for stamp, raw in p.to_master()[seen:]], rp


def owner_state(p):
    return p.n.state()['owner'] >> 16


def loop_frames(p, event, since=0):
    """Frames that entered N on RETURN_PORT carrying `event`, from pass `since` on."""
    return [raw for _t, port, raw, *_ in p.passes[since:]
            if port == cs.RETURN_PORT and int.from_bytes(raw[12:14], 'big') == event]


def deltas(p, before):
    """Outcome deltas since `before` (an cs.outcomes snapshot), non-zero only."""
    after = cs.outcomes(p)
    return {k: after[k] - before[k] for k in after if after[k] != before[k]}


def read_exchange(p, client, server, master_ack, response_laps=None, request=True):
    """One READ on p's current connection: request (client SEQ, master-visible ACK), then the outstation's ACK and
    response at native `server`. response_laps None: the response follows REQ_TO_ACK_NS after the ACK
    (uncontended); a number: it follows that many laps + 1 ns after the ACK (contended). request False: the request
    was already sent. Returns the frame lengths
    the master saw, the outcome deltas, the count_busy deltas and the number of response retry frames (0x0400)."""
    before, busy0, seen, passes = cs.outcomes(p), [p.busy(i) for i in range(5)], len(p.to_master()), len(p.passes)
    t = p.now + 100_000
    t_ack = t + cs.REQ_TO_ACK_NS
    if request:
        p.at(t, cs.rs.request_packet(seq=client, ack=master_ack), master=True)
    p.at(t_ack, cs.rs.ack_packet(seq=server, ack=client + 20))
    p.at(t_ack + (cs.REQ_TO_ACK_NS if response_laps is None else response_laps * p.lap_ns + 1),
         cs.rs.response_packet(seq=server, ack=client + 20))
    p.now = t
    p.settle()
    return ([len(raw) for _t, raw in p.to_master()[seen:]], deltas(p, before),
            [p.busy(i) - busy0[i] for i in range(5)], len(loop_frames(p, cs.RETRY_EVENT, passes)))


def committed_once(lens, outcome):
    return (lens == [cs.ACK_LEN, cs.RESPONSE_LEN] and outcome.get('ACK_COMMIT') == 1
            and outcome.get('RESP_RELEASE') == 1 and 'ACK_FALLBACK' not in outcome and 'RESP_FALLBACK' not in outcome)


def new_incarnation_read_completes(p):
    """A fresh handshake on the same tuple, then a READ through the timed path with no stale release."""
    old_epoch = p.n.state()['epoch']
    p.handshake(4000, 7000)
    assert owner_state(p) == 5 and p.n.state()['epoch'] > old_epoch
    assert cs.n_state(p)['retry_epoch'] == p.n.state()['epoch']
    lens, outcome, busy, _retries = read_exchange(p, 4001, 7001, 7001)
    return committed_once(lens, outcome) and busy[cs.BUSY_DROP] == busy[cs.STALE] == 0


# ---- R: reset while a response is held -----------------------------------------------------------------------
@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
@pytest.mark.parametrize('rst_laps', (0, 1, 5, 40))
def test_m5_refuses_a_reset_that_acks_only_received_data(kind, rst_laps):
    """The retained m5_10 record: the RST is refused and the held response is still released (rst_laps 0: the
    RST also finds the cell busy)."""
    p, frames, _rsp = held(M5, kind, rst=RST[kind], rst_laps=rst_laps)
    assert owner_state(p) != 0x200
    assert cs.RESPONSE_LEN in [len(raw) for _t, raw in frames]


@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
@pytest.mark.parametrize('rst_laps', (0, 1, 5, 40))
def test_m6_reset_while_held_aborts_and_a_fresh_handshake_works(kind, rst_laps):
    p, frames, _rsp = held(M6, kind, rst=RST[kind], rst_laps=rst_laps)
    assert owner_state(p) == 0x200                                   # the old incarnation is closed
    assert cs.RESPONSE_LEN not in [len(raw) for _t, raw in frames]   # the held response is never released
    assert cs.n_state(p)['retry_epoch'] == 0
    assert p.busy(cs.BUSY_DROP) == p.busy(cs.EXHAUSTED) == p.busy(cs.STALE) == 0
    if rst_laps == 0:
        # the RST lands one ns after the response, on the response's first pass: the cell is busy and the RST
        # retried (count_busy[2], event 0x0800) instead of being denied
        assert p.busy(cs.RETRY) > 0 and loop_frames(p, RST_RETRY_EVENT)
    # a READ on the new incarnation completes through the timed path, with no stale release from the old one
    assert new_incarnation_read_completes(p)


@pytest.mark.parametrize('source', (M5, M6), ids=('m5_10', 'm6'))
@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
@pytest.mark.parametrize('bad', ('seq+1', 'seq-1', 'ack-1', 'ack+1'))
def test_reset_with_wrong_seq_or_ack_is_refused(source, kind, bad):
    seq, ack = RST[kind]
    rst = {'seq+1': (seq + 1, ack), 'seq-1': (seq - 1, ack), 'ack-1': (seq, ack - 1), 'ack+1': (seq, ack + 1)}[bad]
    p, frames, _rsp = held(source, kind, rst=rst)
    assert owner_state(p) != 0x200
    assert [len(raw) for _t, raw in frames][-1] == cs.RESPONSE_LEN


# ---- E: retry authority survives a close that is not proven -------------------------------------------------
@pytest.mark.parametrize('source, cleared', ((M5, True), (M6, False)), ids=('m5_10', 'm6'))
def test_close_whose_owner_cas_fails_keeps_retry_authority(source, cleared):
    """An RST passes stage 0, then the owner moves before its stage-1 CAS (forced), so the close is refused.
    m5 had already cleared retry_epoch on that stage-1 pass; m6 clears it only on the stage-2 pass that follows a
    successful CAS."""
    p = cs.LapPipeline(source).handshake()
    epoch = p.n.state()['epoch']
    p.send(cs.rs.request_packet(seq=101, ack=901))
    p.settle()
    p.ingress(p.now + 1000, cs.MASTER_PORT, V.packet(20, 121, 901))
    stage1 = None
    while p.heap:
        time, _o, port, raw = p.heap[0]
        if port == cs.RETURN_PORT and int.from_bytes(raw[12:14], 'big') == 0x0104:
            stage1 = True
            p.n.src.cells[('', 'owner')][0] ^= 0x1                     # the owner moves under the close
        p.run(time)
        if stage1:
            break
    p.settle()
    assert stage1 and owner_state(p) != 0x200
    assert (cs.n_state(p)['retry_epoch'] == 0) == cleared
    if not cleared:
        assert cs.n_state(p)['retry_epoch'] == epoch
    # the connection lives on. The outstanding READ's ACK and response arrive contended (response 1 ns after the
    # ACK); the forced settle has put them >20 ms after the request, so T releases that response by its fallback.
    # A later READ, also contended, must retry and be delivered through T's committed path.
    first = read_exchange(p, 101, 901, 901, response_laps=0, request=False)[0]
    later_lens, later, busy, retries = read_exchange(p, 121, 950, 962, response_laps=0)
    if cleared:      # m5: retry authority was gone, so the busy response is refused as stale and lost
        assert first == [cs.ACK_LEN] and busy[cs.STALE] == 1 and cs.RESPONSE_LEN not in later_lens
    else:
        assert first == [cs.ACK_LEN, cs.RESPONSE_LEN]
        assert retries >= 1 and busy[cs.RETRY] >= 1 and busy[cs.STALE] == busy[cs.BUSY_DROP] == 0
        assert committed_once(later_lens, later)


# ---- D: retransmitted response and T's release gate ---------------------------------------------------------
@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
def test_m5_lets_a_held_responses_retransmission_out_untimed(kind):
    p, frames, _rsp = held(M5, kind, dup_at=40_000)
    lens = [len(raw) for _t, raw in frames]
    assert lens[0] == cs.RESPONSE_LEN and lens.count(cs.RESPONSE_LEN) == 2      # an early untimed copy


@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
def test_m6_drops_a_held_responses_retransmission_at_ts_release_gate(kind):
    p, frames, _rsp = held(M6, kind, dup_at=40_000)
    o = cs.outcomes(p)
    lens = [len(raw) for _t, raw in frames]
    assert lens == [cs.ACK_LEN, cs.RESPONSE_LEN] and o['RESP_DUP_DROP'] == 1
    assert p.retried_duplicates() == 0 and p.busy(cs.BUSY_DROP) == 0


@pytest.mark.parametrize('source, events, last_hop', ((M5, (0x0108, 0x0208, 0x0308), cs.MASTER_PORT),
                                                        (M6, (0x0119, 0x0219, 0x0319), T_IN)), ids=('m5_10', 'm6'))
@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
def test_retransmission_after_release_recovers_with_the_same_image(source, events, last_hop, kind):
    """After T released the original, the outstation's retransmission reaches the master once more with the same
    image. m5 sends it from N straight to the master (forward_original, events 0x0108-0x0308); m6 hands it to T
    (first_response_dup, events 0x0119-0x0319, last N pass to T_IN), where T's release gate passes it with no
    outcome counted. On both, N allocates one generation for the copy (counter and work generation +1)."""
    p, _frames, rsp = held(source, kind)
    before, gen0, seen, passes = cs.outcomes(p), p.n.state(), len(p.to_master()), len(p.passes)
    released = [raw for _t, raw in p.to_master() if len(raw) == cs.RESPONSE_LEN][-1]
    p.send(rsp, master=False)
    p.settle()
    assert [raw for _t, raw in p.to_master()[seen:]] == [released]           # the same 61-octet image again
    assert deltas(p, before) == {}                                           # no RESP_DUP_DROP, no new release
    copy_passes = [(int.from_bytes(raw[12:14], 'big'), egress) for _t, port, raw, _e, egress, _r in p.passes[passes:]
                   if port == cs.RETURN_PORT]
    assert copy_passes == [(events[0], cs.RETURN_PORT), (events[1], cs.RETURN_PORT), (events[2], last_hop)]
    after = p.n.state()
    assert after['counter'] == gen0['counter'] + 1 and after['work']['generation'] == gen0['work']['generation'] + 1
    assert after['owner'] == gen0['owner'] and after['work']['phase'] == 4


def test_m6_retransmission_with_a_newer_read_open_keeps_the_native_path():
    """Owner 0xe (the next READ is open): T would take an old copy as the new response, so the copy keeps
    m4/m5's native forward path; recorded, not changed by m6."""
    outs = []
    for source in (M5, M6):
        p, frames, rsp = held(source, 'READ')
        p.send(cs.rs.request_packet(seq=121, ack=962))          # the next READ (master saw 901 + 61)
        assert owner_state(p) == 0xe
        seen = len(p.to_master())
        p.send(rsp, master=False)                                # the old response again
        p.settle()
        outs.append([len(raw) for _t, raw in p.to_master()[seen:]])
    assert outs[0] == outs[1]


# ---- H1: the outstation's RST (direction 2) ------------------------------------------------------------------
def _outstation_rst(kind):
    return V.packet(20, *OUT_RST[kind], reverse=True)


@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
@pytest.mark.parametrize('rst_laps', (0, 1, 5))
def test_m6_outstation_reset_while_held_takes_effect(kind, rst_laps):
    """The outstation's RST|ACK `rst_laps` laps (+2 ns) after its own response, which T holds. At 0 and 1 laps the
    response's lifecycle still holds N's cell, so the RST retries (count_busy[2]) and then closes; m6_01 lost it
    there (the retry forced the lapped path onto a native RST) and m5 denied it, both releasing the response."""
    p, frames, _rsp = held(M6, kind, extra=[(rst_laps * 1000 + 2, _outstation_rst(kind), False)])
    assert owner_state(p) == 0x200 and cs.n_state(p)['retry_epoch'] == 0
    assert frames == []                                              # nothing reaches the master
    assert p.busy(cs.BUSY_DROP) == p.busy(cs.EXHAUSTED) == p.busy(cs.STALE) == 0
    if rst_laps in (0, 1):
        assert p.busy(cs.RETRY) > 0 and loop_frames(p, RST_RETRY_EVENT)
    else:
        assert p.busy(cs.RETRY) == 0
    assert new_incarnation_read_completes(p)


@pytest.mark.parametrize('kind', ('READ', 'SELECT'))
@pytest.mark.parametrize('rst_laps, closes', ((0, False), (1, False), (5, True)))
def test_m5_outstation_reset_while_held(kind, rst_laps, closes):
    """The retained m5_10 record: a busy-cell outstation RST is denied and the held response is released; with the
    cell free (5 laps) m5 already closes, as m6 does."""
    p, frames, _rsp = held(M5, kind, extra=[(rst_laps * 1000 + 2, _outstation_rst(kind), False)])
    assert (owner_state(p) == 0x200) == closes
    assert [len(raw) for _t, raw in frames] == ([] if closes else [cs.ACK_LEN, cs.RESPONSE_LEN])
    assert p.busy(cs.RETRY) == 0


@pytest.mark.parametrize('source', (M5, M6), ids=('m5_10', 'm6'))
def test_outstation_reset_with_the_cell_free_is_forwarded_and_closes(source):
    """After the READ completed: the outstation's RST closes the connection and reaches the master (m5 = m6)."""
    p, _frames, _rsp = held(source, 'READ')
    seen = len(p.wire)
    p.send(_outstation_rst('READ'), master=False)
    p.settle()
    assert owner_state(p) == 0x200 and p.busy(cs.RETRY) == 0
    assert [(port, len(raw)) for _t, port, raw in p.wire[seen:]] == [(cs.MASTER_PORT, cs.ACK_LEN)]
    assert new_incarnation_read_completes(p)


# ---- H2: the exact accepted RST|ACK set (master-visible ACK, exact SEQ) ----------------------------------------
# A documented decision (DESIGN.md m6 R): an RST|ACK is validated by its exact SEQ; its ACK is restricted only to
# {server, server-49, server-37} in N's native coordinates, so several master-visible ACKs pass.
RST_STATES = ('READ held', 'READ released', 'READ released, acked', 'SELECT held', 'OPERATE held')
ACCEPTED = {
    'm5': {'READ held': {950}, 'READ released': {962}, 'READ released, acked': {962},
           'SELECT held': {938}, 'OPERATE held': {999}},
    'm6': {'READ held': {901, 913, 950}, 'READ released': set(range(901, 963)),
           'READ released, acked': set(range(901, 963)), 'SELECT held': {901, 938}, 'OPERATE held': {962, 999}},
}


def _rst_base(source, state):
    """(pipeline paused where the RST lands, master SEQ, arrival time or None = after settling)."""
    kind = state.split()[0]
    if state.endswith('held'):
        p, ta, _rsp = _schedule(source, kind)
        p.run(ta + 11_000)                    # the response has passed N 5 laps ago; T holds it
        return p, RST[kind][0], ta + 11_002
    p, _frames, _rsp = held(source, kind)
    if state.endswith('acked'):
        p.send(V.packet(16, 121, 962))         # the master acks the 61-octet response it saw
        p.settle()
    return p, RST[kind][0], None


def _rst_closes(base, seq, ack):
    p, _seq, at = base
    q = copy.deepcopy(p)
    seen = len(q.to_master())
    if at is None:
        q.send(V.packet(20, seq, ack))
    else:
        q.at(at, V.packet(20, seq, ack), master=True)
    q.settle()
    return owner_state(q) == 0x200, [len(raw) for _t, raw in q.to_master()[seen:]]


@pytest.mark.parametrize('source, label', ((M5, 'm5'), (M6, 'm6')), ids=('m5_10', 'm6'))
@pytest.mark.parametrize('state', RST_STATES)
def test_reset_ack_sweep_pins_the_accepted_set(source, label, state):
    base = _rst_base(source, state)
    seq = base[1]
    pre = RST[state.split()[0]][1]
    sweep = list(range(pre - 64, pre + 128)) + [(pre + 2 ** 31) % 2 ** 32, 0, 2 ** 32 - 1]
    accepted = set()
    for ack in sweep:
        closes, lens = _rst_closes(base, seq, ack)
        if closes:
            accepted.add(ack)
            assert cs.RESPONSE_LEN not in lens                    # an accepted RST never lets a held response out
    assert accepted == ACCEPTED[label][state]
    # SEQ is exact: one off either way is refused at every accepted ACK
    for ack in sorted(accepted):
        for wrong in (seq - 1, seq + 1):
            assert not _rst_closes(base, wrong, ack)[0], (state, wrong, ack)


# ---- M2: RST retry ---------------------------------------------------------------------------------------------
def _cell_forced_busy(source):
    """A READ request open and N's cell held by a lifecycle that never returns (forced, as the m5 exhaustion test)."""
    p = cs.LapPipeline(source).handshake()
    request, _ack, _rsp = cs.transaction('READ')
    t = p.now + 100_000
    p.at(t, request, master=True)
    p.now = t
    p.run(t + cs.REQ_TO_ACK_NS)
    p.n.src.cells[('work', 'work')][0] = {'generation': 0x7ffffff0, 'phase': 1}
    return p


@pytest.mark.parametrize('direction', ('master', 'outstation'))
def test_m6_reset_retry_exhaustion_is_counted_and_never_released(direction):
    p = _cell_forced_busy(M6)
    state, seen = cs.n_state(p), len(p.wire)
    rst = V.packet(20, 121, 901) if direction == 'master' else V.packet(20, 901, 121, reverse=True)
    p.at(p.now + 1, rst, master=direction == 'master')
    p.settle()
    budget = int(cs.re.search(r'n_RETRY_BUDGET=(\d+);', M6.read_text())[1])
    assert p.busy(cs.RETRY) == budget and p.busy(cs.EXHAUSTED) == 1
    assert p.busy(cs.BUSY_DROP) == p.busy(cs.STALE) == 0
    assert len(loop_frames(p, RST_RETRY_EVENT)) == budget
    assert not p.wire[seen:]                                         # neither forwarded nor released
    assert cs.n_state(p) == state                                    # the connection is untouched (owner 0xe)


def test_m5_denies_a_busy_reset_without_retrying():
    p = _cell_forced_busy(M5)
    state, seen = cs.n_state(p), len(p.wire)
    p.at(p.now + 1, V.packet(20, 121, 901), master=True)
    p.settle()
    assert [p.busy(i) for i in range(5)] == [0] * 5 and not p.wire[seen:] and cs.n_state(p) == state


@pytest.mark.parametrize('direction', ('master', 'outstation'))
def test_m6_reset_retry_from_a_closed_or_reconnected_connection_is_stale(direction):
    """An RST retry frame captured on incarnation 1 (cell busy at the RST's arrival), replayed after that RST closed
    the connection and again after a new handshake on the same tuple: refused as stale on its single pass."""
    rst = V.packet(20, *RST['READ']) if direction == 'master' else _outstation_rst('READ')
    p, _frames, _rsp = held(M6, 'READ', extra=[(2, rst, direction == 'master')])
    frames = loop_frames(p, RST_RETRY_EVENT)
    assert frames and owner_state(p) == 0x200
    for reconnect in (False, True):
        if reconnect:
            p.handshake(4000, 7000)
        before, stale0, seen, passes = cs.n_state(p), p.busy(cs.STALE), len(p.wire), len(p.passes)
        p.ingress(p.now + 1000, cs.RETURN_PORT, frames[0])
        p.settle()
        assert cs.n_state(p) == before and p.busy(cs.STALE) == stale0 + 1
        assert not p.wire[seen:] and len(p.passes) == passes + 1


def _contended_kind(source, kind, response_laps, extra=()):
    """`kind` with its response `response_laps` laps (+1 ns) after the outstation's ACK, plus `extra` arrivals
    (ns after the ACK, frame, from_master). Returns pipeline, master frames after the ACK time, outcome deltas,
    count_busy deltas, response retry frames."""
    p = cs.LapPipeline(source).handshake()
    if kind == 'OPERATE':
        rq, ak, rp = cs.transaction('SELECT')
        t = p.now + 100_000
        p.at(t, rq, master=True)
        p.at(t + 200_000, ak)
        p.at(t + 400_000, rp)
        p.now = t
        p.settle()
    rq, ak, rp = cs.transaction(kind)
    before, busy0, seen, passes = cs.outcomes(p), [p.busy(i) for i in range(5)], len(p.to_master()), len(p.passes)
    t = p.now + 100_000
    ta = t + (5 if kind == 'OPERATE' else 1) * 200_000
    p.at(t, rq, master=True)
    p.at(ta, ak)
    p.at(ta + response_laps * 1000 + 1, rp)
    for offset, frame, master in extra:
        p.at(ta + offset, rp if frame is None else frame, master=master)
    p.now = t
    p.settle()
    return (p, [len(raw) for _t, raw in p.to_master()[seen:]], deltas(p, before),
            [p.busy(i) - busy0[i] for i in range(5)], len(loop_frames(p, cs.RETRY_EVENT, passes)))


@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
@pytest.mark.parametrize('rst_at', (1500, 2002, 3002, 4002))
def test_m6_reset_during_a_response_retry_closes_and_releases_nothing(kind, rst_at):
    """The response arrives 1 lap after the ACK and retries; the master's RST (pre-response ACK) lands while it
    waits. m6 closes and nothing of the exchange reaches the master; m5 refused the RST and released both."""
    rst = V.packet(20, *RST[kind])
    p, lens, outcome, busy, retries = _contended_kind(M6, kind, 1, extra=[(rst_at, rst, True)])
    assert retries >= 1                                              # the response did retry
    assert owner_state(p) == 0x200 and lens == []
    assert 'RESP_RELEASE' not in outcome and 'RESP_FALLBACK' not in outcome and 'ACK_COMMIT' not in outcome
    assert busy[cs.BUSY_DROP] == busy[cs.EXHAUSTED] == busy[cs.STALE] == 0
    m5 = _contended_kind(M5, kind, 1, extra=[(rst_at, rst, True)])
    assert owner_state(m5[0]) != 0x200 and m5[1] == [cs.ACK_LEN, cs.RESPONSE_LEN]


@pytest.mark.parametrize('source', (M5, M6), ids=('m5_10', 'm6'))
@pytest.mark.parametrize('ack', (901, 962))
def test_master_half_close_refused_while_held_keeps_retry_authority(source, ack):
    """A master FIN|ACK (kind 17) while T holds the READ response is refused (m5 = m6): retry_epoch is kept, the
    response is released, and a later contended READ on the same connection retries and is delivered through T's
    committed path."""
    p, frames, _rsp = held(source, 'READ', extra=[(5 * 1000 + 2, V.packet(17, 121, ack), True)])
    epoch = p.n.state()['epoch']
    assert owner_state(p) == 5 and cs.n_state(p)['retry_epoch'] == epoch
    assert [len(raw) for _t, raw in frames] == [cs.ACK_LEN, cs.RESPONSE_LEN]
    lens, outcome, busy, retries = read_exchange(p, 121, 950, 962, response_laps=0)
    assert retries >= 1 and busy[cs.RETRY] >= 1 and busy[cs.STALE] == busy[cs.BUSY_DROP] == 0
    assert committed_once(lens, outcome)


@pytest.mark.parametrize('ack', (901, 962))
def test_busy_master_fin_retries_into_the_same_outcome_as_a_free_one(ack):
    """Review of m6_06: the busy retry covers every kind-4 segment close_shape admits, FIN|ACK included (m5 denied a
    busy FIN). A FIN|ACK that finds the cell busy (2 ns after the response, 0 laps) retries as 0x0800 and ends
    exactly as the same FIN arriving with the cell free (5 laps later): owner, retry authority and frames."""
    fin = V.packet(17, 121, ack)
    busy_p, busy_frames, _ = held(M6, 'READ', extra=[(2, fin, True)])
    free_p, free_frames, _ = held(M6, 'READ', extra=[(5 * 1000 + 2, fin, True)])
    assert loop_frames(busy_p, 0x0800) and not loop_frames(free_p, 0x0800)
    assert owner_state(busy_p) == owner_state(free_p)
    assert cs.n_state(busy_p)['retry_epoch'] == cs.n_state(free_p)['retry_epoch']
    assert [len(r) for _t, r in busy_frames] == [len(r) for _t, r in free_frames]
    assert busy_p.busy(cs.BUSY_DROP) == busy_p.busy(cs.STALE) == busy_p.busy(cs.EXHAUSTED) == 0


def test_busy_master_rst_with_normalized_epoch_zero_ends_like_a_free_one(monkeypatch):
    """Review of m6_06: a master RST|ACK whose normalize lap carries epoch 0 (E's unbound slot) must end the same
    busy or free. m6_06 keyed the retry snapshot on normalized_epoch, so the busy one closed while the free one was
    denied; m6_07 keys on direction (both kept, owner 5, response released)."""
    original = cs.LapPipeline.ingress

    def ingress(self, time, port, frame):
        frame = bytes(frame)
        if port == 70 and len(frame) > 63 and frame[63] in (4, 20, 17):    # N_ACK_RETURN lap of a close segment
            frame = bytes(4) + frame[4:]
        return original(self, time, port, frame)
    monkeypatch.setattr(cs.LapPipeline, 'ingress', ingress)
    out = {}
    for label, offset in (('busy', 2), ('free', 5 * 1000 + 2)):
        p, frames, _ = held(M6, 'READ', extra=[(offset, V.packet(20, *RST['READ']), True)])
        out[label] = (owner_state(p), cs.n_state(p)['retry_epoch'], [raw for _t, raw in frames])
    assert out['busy'] == out['free']
    assert out['free'][0] == 5


# ---- M2: duplicate responses ----------------------------------------------------------------------------------
@pytest.mark.parametrize('kind', ('READ', 'SELECT', 'OPERATE'))
@pytest.mark.parametrize('dup_at', (1002, 2002, 3002, 5002, 7002))
def test_duplicate_during_the_originals_retry(kind, dup_at):
    """The response retries (1 lap after the ACK); a copy follows `dup_at` ns after the ACK. m6: T drops the copy
    (RESP_DUP_DROP), nothing is aborted as a retried duplicate (count_term[0] 0). m5: copies that waited in retry
    abort there (count_term[0] 1); a copy after the lifecycle (7002) leaves untimed ahead of the ACK."""
    p, lens, outcome, _busy, retries = _contended_kind(M6, kind, 1, extra=[(dup_at, None, False)])
    assert retries >= 1 and lens == [cs.ACK_LEN, cs.RESPONSE_LEN]
    assert outcome.get('RESP_DUP_DROP') == 1 and p.retried_duplicates() == 0
    p5, lens5, outcome5, _b, _r = _contended_kind(M5, kind, 1, extra=[(dup_at, None, False)])
    assert 'RESP_DUP_DROP' not in outcome5
    if dup_at < 7002:
        assert lens5 == [cs.ACK_LEN, cs.RESPONSE_LEN] and p5.retried_duplicates() == 1
    else:
        assert lens5 == [cs.RESPONSE_LEN, cs.ACK_LEN, cs.RESPONSE_LEN] and p5.retried_duplicates() == 0


@pytest.mark.parametrize('source', (M5, M6), ids=('m5_10', 'm6'))
def test_old_duplicate_around_the_next_read_is_dropped(source):
    """READ 1 completes; READ 2 opens (owner 0xe) and READ 1's response arrives again while T holds READ 2's, then
    once more after READ 2 completed: READ 2 is delivered once through the committed path and neither old copy
    reaches the master (m5 = m6)."""
    p = cs.LapPipeline(source).handshake()
    assert committed_once(*read_exchange(p, 101, 901, 901)[:2])
    old = cs.rs.response_packet(seq=901, ack=121)
    before, seen = cs.outcomes(p), len(p.to_master())
    t = p.now + 100_000
    p.at(t, cs.rs.request_packet(seq=121, ack=962), master=True)
    p.at(t + cs.REQ_TO_ACK_NS, cs.rs.ack_packet(seq=950, ack=141))
    p.at(t + 2 * cs.REQ_TO_ACK_NS, cs.rs.response_packet(seq=950, ack=141))
    p.at(t + 2 * cs.REQ_TO_ACK_NS + 40_000, old)
    p.now = t
    p.settle()
    assert committed_once([len(raw) for _t, raw in p.to_master()[seen:]], deltas(p, before))
    seen = len(p.to_master())
    p.send(old, master=False)
    p.settle()
    assert not p.to_master()[seen:]


@pytest.mark.parametrize('source', (M5, M6), ids=('m5_10', 'm6'))
def test_old_duplicate_after_a_reconnect_is_dropped(source):
    p = cs.LapPipeline(source).handshake()
    assert committed_once(*read_exchange(p, 101, 901, 901)[:2])
    p.send(V.packet(4, 121, 0))                                      # master bare RST
    p.settle()
    assert owner_state(p) == 0x200
    p.handshake(4000, 7000)
    seen, before = len(p.wire), cs.outcomes(p)
    p.send(cs.rs.response_packet(seq=901, ack=121), master=False)
    p.settle()
    assert not p.wire[seen:] and deltas(p, before) == {} and owner_state(p) == 5


WRAP_ISN = 2 ** 32 - 20               # server ISN: the response's 49 octets cross 2^32


@pytest.mark.parametrize('source', (M5, M6), ids=('m5_10', 'm6'))
@pytest.mark.parametrize('dup_ns, held_copy', ((40_000, True), (2_000_000, False)))
def test_duplicate_across_sequence_wrap(source, dup_ns, held_copy):
    """The same duplicate cases with the outstation's sequence wrapping inside the response. Held copy: m6 drops it
    at T (RESP_DUP_DROP), m5 lets it out untimed first. After release: delivered once more on both."""
    p = cs.LapPipeline(source).handshake(100, WRAP_ISN)
    server = (WRAP_ISN + 1) % 2 ** 32
    rsp = cs.rs.response_packet(seq=server, ack=121)
    before, seen = cs.outcomes(p), len(p.to_master())
    t = p.now + 100_000
    p.at(t, cs.rs.request_packet(seq=101, ack=server), master=True)
    p.at(t + cs.REQ_TO_ACK_NS, cs.rs.ack_packet(seq=server, ack=121))
    p.at(t + 2 * cs.REQ_TO_ACK_NS, rsp)
    p.at(t + 2 * cs.REQ_TO_ACK_NS + dup_ns, rsp)
    p.now = t
    p.settle()
    lens, outcome = [len(raw) for _t, raw in p.to_master()[seen:]], deltas(p, before)
    assert outcome.get('ACK_COMMIT') == 1 and outcome.get('RESP_RELEASE') == 1
    if not held_copy:
        assert lens == [cs.ACK_LEN, cs.RESPONSE_LEN, cs.RESPONSE_LEN] and 'RESP_DUP_DROP' not in outcome
    elif source == M6:
        assert lens == [cs.ACK_LEN, cs.RESPONSE_LEN] and outcome.get('RESP_DUP_DROP') == 1
    else:
        assert lens == [cs.RESPONSE_LEN, cs.ACK_LEN, cs.RESPONSE_LEN] and 'RESP_DUP_DROP' not in outcome


@pytest.mark.parametrize('event', [0x0104, 0x0204])
def test_delayed_close_pass_of_an_old_incarnation_keeps_the_new_retry_authority(event):
    """A close pass of the old incarnation replayed after a fresh handshake must not clear the new connection's
    retry_epoch (m6 test-matrix finding; m5 and m6_01..m6_05 cleared it and the next contended READ was refused
    as stale). The pass itself is denied on every build."""
    p, _frames, _r = held(M6, 'READ', extra=[(5002, cs.vectors.packet(4, 121, 0), True)])
    old = loop_frames(p, event)
    if not old:
        pytest.skip('this build emits no %#06x close pass' % event)
    p.handshake(4000, 7000)
    before = cs.n_state(p)
    p.ingress(p.now + 1000, cs.RETURN_PORT, old[0])
    p.settle()
    assert cs.n_state(p)['retry_epoch'] == before['retry_epoch'] != 0
    lens, lane, busy, _retries = read_exchange(p, 4001, 7001, 7001, response_laps=0)
    assert lens == [54, 115] and lane.get('ACK_COMMIT') == 1 and lane.get('RESP_RELEASE') == 1
    assert busy[4] == 0 and busy[0] == 0

