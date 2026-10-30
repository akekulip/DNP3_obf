"""Master-ACK behaviour on the compiled model, against the rule in results/analysis/ack_behaviour/DESIGN.json.
A labelled scenario, NOT a gate driver. Run with scripts/model/run_ack_behaviour.py on c72, c74 and c75.

Each case runs on a fresh connection of the same 4-tuple, for both READ classes and with T on and off. A case sends
one or more probes (master pure ACKs, window updates, keepalives) and records for each: its disposition on dev64
(with the mapped ACK, window and TSval), N state before and after, the master segments forwarded before it, the
rule classification (scripts/model/ack_rule.py), and the relay's RFC 9293 reply where one is due. It then records
the endpoint progress: the current response delivered at the class image size (T outcome counts with T on), the
next transaction admitted and delivered, and the FIN close. A progress step that fails is recorded, not raised."""
import hashlib
import json
import os
import traceback
from pathlib import Path

import model_connection_fix as cf
import model_connection_start as cs
from ack_rule import (RULE, OUTCOMES, STATE_KEYS, M32, seq_ge, covers, obsolete, covering, new_information,
                      state_unchanged, classify, relay_replies, tcp_fields, with_window, claimed_before)

__all__ = ['RULE', 'OUTCOMES', 'STATE_KEYS', 'seq_ge', 'covers', 'obsolete', 'covering', 'new_information',
           'state_unchanged', 'classify', 'relay_replies', 'tcp_fields', 'with_window', 'claimed_before', 'SCENARIOS',
           'CASES', 'CASE_FUNCTIONS', 'main']
HERE = Path(__file__).resolve().parent
CLASSES = cf.CLASSES
READ_LENGTH, OTHER = cf.READ_LENGTH, cf.OTHER
WINDOW, WINDOW_UP = 4096, 4608
ATTEMPTS = 3                                          # the wire-order overtake is a race; fresh connection each try

SCENARIOS = dict(
    late_ack_wire_order=dict(family=1, evidence_kind='forced_register'),
    late_ack_reverse_order=dict(family=1, evidence_kind='genuine_processing'),
    r1_ack_behind_read=dict(family=2, evidence_kind='genuine_processing'),
    r2_offset=dict(family=2, evidence_kind='genuine_processing', conforming=False),
    window_increase_outstanding=dict(family=3, evidence_kind='genuine_processing'),
    window_increase_idle=dict(family=3, evidence_kind='genuine_processing', control=True),
    zero_window_outstanding=dict(family=4, evidence_kind='genuine_processing'),
    keepalive_idle=dict(family=5, evidence_kind='genuine_processing'),
    keepalive_outstanding=dict(family=5, evidence_kind='genuine_processing'),
    duplicate_ack_idle=dict(family=6, evidence_kind='genuine_processing', control=True),
    response_ack_control=dict(family=6, evidence_kind='genuine_processing', control=True))


def _case(scenario, cls, timed):
    return dict(SCENARIOS[scenario], case='%s_%s_%s' % (scenario, cls, 'T' if timed else 'off'), scenario=scenario,
                read_class=cls, read_length=READ_LENGTH[cls], timed=timed)


CASES = tuple(_case(s, c, t) for c in CLASSES for t in (False, True) for s in SCENARIOS)


def action(name):
    return cf.action(name)


def n_state(m):
    """N connection/transaction state plus the generation counters (recorded, not compared)."""
    def first(value):
        return value[0] if isinstance(value, list) else value

    out = {}
    for name in ('owner', 'client', 'server', 'epoch', 'retry_epoch', 'counter'):
        values = m.register_read('p0.n_Ingress.' + name, 0, pipe=0)
        out[name] = first(next(v for k, v in values.items() if k.endswith('.f1')))
    out['application_state'] = sorted([k.rsplit('.', 1)[-1], first(v)]
                                      for k, v in m.register_read('p0.n_Ingress.application_state', 0, pipe=0).items())
    work = {k.rsplit('.', 1)[-1]: first(v) for k, v in m.register_read('p0.n_Ingress.work.work', 0, pipe=0).items()}
    out['work_phase'], out['work_generation'] = work.get('phase'), work.get('generation')
    return out


class Ctx(cf.Ctx):
    """cf.Ctx plus a ledger of the master segments forwarded in this case (arrival order) and their send order."""

    def __init__(self, gate, view, rp):
        super().__init__(gate, view, rp)
        self.ledger, self.order = [], 0
        original = gate.exchange

        def recording(name, sent, expected=None, reverse=False, allow_drop=False):
            got = original(name, sent, expected, reverse=reverse, allow_drop=allow_drop)
            if not reverse and not allow_drop:
                self.ledger.append(dict(tcp_fields(sent), order=self.next_order(), name=name))
            return got
        gate.exchange = recording

    def next_order(self):
        self.order += 1
        return self.order

    def reset(self):
        self.ledger = []

    def build(self, name, seq, ack, payload=b'', window=WINDOW, flags=None):
        """A master frame built now: its send order and TSval are fixed at build time, so a frame built before
        another is earlier in the master's send order whatever order it is sent to the switch in."""
        flags = flags if flags is not None else (24 if payload else 16)
        frame = self.run.packet(flags, seq & M32, ack & M32, payload=payload)
        if window != WINDOW:
            frame = with_window(frame, window)
        return dict(tcp_fields(frame), order=self.next_order(), name=name, frame=frame)


def want_of(item):
    return cs.seg(item['direction'], item['seq'], item['flags'], item['payload_len'])


def strip(item):
    return {k: v for k, v in item.items() if k != 'frame'}


def port64_copy(obs, label):
    rows = [r for r in obs['port64_frames'] if r['label'] == label]
    if not rows:
        return None
    fields = tcp_fields(bytes.fromhex(rows[0]['hex']))
    return {k: fields[k] for k in ('seq', 'ack', 'window', 'tsval', 'tsecr', 'payload_len')}


def evaluate(ctx, probe, obs, n_before, t_before, reference=None):
    """Disposition, state and rule classification of one probe whose observation is obs. reference: when another
    frame changed state in the same observation (the wire-order READ), the state the probe must leave in place."""
    passes = ctx.passes(obs['offset'])
    want = want_of(probe)
    forwarded = obs['port64'].count(probe['name'])
    prior = list(ctx.ledger)
    n_after = n_state(ctx.m)
    if reference is None:
        unchanged = state_unchanged(n_before, n_after)
    else:
        unchanged = n_before.get('owner') is not None and all(n_after.get(k) == v for k, v in reference.items())
    is_obsolete = obsolete(probe, prior)
    record = dict(sent=strip(probe), forwarded=forwarded > 0, port64_copies=forwarded,
                  port64=port64_copy(obs, probe['name']), port9=obs['port9'],
                  forwarded_before=[s.get('name') for s in prior], covered_by=covering(probe, prior),
                  obsolete=is_obsolete, new_information=new_information(probe, prior),
                  n_before=n_before, n_after=n_after, n_state_unchanged=unchanged, state_reference=reference,
                  generation_consumed=None if n_before.get('counter') is None or n_after.get('counter') is None
                  else (n_after['counter'] - n_before['counter']) & M32,
                  t_delta=[a - b for a, b in zip(ctx.outcomes(), t_before)],
                  passes=cf.summarize(cf.history(passes, want), ctx.t_in),
                  classification=classify(forwarded > 0, is_obsolete, unchanged))
    if forwarded:
        ctx.ledger.append(strip(probe))
    return record


def send_probe(ctx, probe, extra_sent=None, **observe):
    n_before, t_before = n_state(ctx.m), ctx.outcomes()
    sent = {probe['name']: want_of(probe)}
    sent.update(extra_sent or {})
    obs = ctx.observe([(ctx.master, probe['frame'])], sent, **observe)
    return obs, n_before, t_before


def probe_once(ctx, rec, probe, nsq, wsq, defer=False):
    """Send one probe, evaluate it, and send the relay's RFC 9293 reply when one is due."""
    obs, n_before, t_before = send_probe(ctx, probe)
    result = evaluate(ctx, probe, obs, n_before, t_before)
    reply_if_due(ctx, rec, result, probe, nsq, wsq, defer)
    rec['probes'].append(result)
    return result


def reply_if_due(ctx, rec, result, probe, nsq, wsq, defer):
    rcv_nxt = result['n_after']['client']
    if relay_replies(result['forwarded'], probe['seq'], rcv_nxt):
        result['relay_reply'] = relay_reply(ctx, rec, nsq, wsq, rcv_nxt, probe['name'], defer=defer)


def relay_reply(ctx, rec, nsq, wsq, rcv_nxt, about, defer=False):
    """<SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK> from the relay. With defer (T on, READ outstanding) it is only built:
    deliver() sends it back to back with the relay's ACK and response so T's budget measures the dataplane."""
    frame = ctx.v.packet(16, nsq, rcv_nxt, reverse=True)
    reply = dict(about=about, seq=nsq, ack=rcv_nxt, frame=frame)
    if defer:
        rec.setdefault('deferred_replies', []).append(reply)
        return dict(reply_deferred_to_response_burst=True, seq=nsq, ack=rcv_nxt)
    before = ctx.outcomes()
    obs = ctx.observe([(ctx.relay, frame)], {'relay_reply': cs.seg('r2m', nsq, 0x10, 0)})
    to_master = [r for r in obs['port9_frames'] if r['label'] == 'relay_reply']
    return dict(seq=nsq, ack=rcv_nxt, at_master=len(to_master),
                at_master_fields=[{k: f[k] for k in ('seq', 'ack', 'window')}
                                  for f in (tcp_fields(bytes.fromhex(r['hex'])) for r in to_master)],
                t_delta=[a - b for a, b in zip(ctx.outcomes(), before)], expected_wire_seq=wsq)


def deliver(ctx, rec, tag, c, nsq, wsq, native, image, timed, ack_sent=False):
    """The relay's ACK and response, preceded by any deferred relay replies; non-raising. ack_sent: the relay's ACK
    already reached the master (T off), so only the response is expected now."""
    g, v, rp, m = ctx.gate, ctx.v, ctx.rp, ctx.m
    pre = rec.pop('deferred_replies', [])
    ack = v.packet(16, nsq, c, reverse=True)
    response = v.packet(24, nsq, c, reverse=True, payload=native)
    wire_ack = rp.preserve_options(ack, v.packet(16, wsq, c, reverse=True))
    expected = rp.preserve_options(response, v.packet(24, wsq, c, reverse=True, payload=image))
    frames_in = [r['frame'] for r in pre] + ([] if ack_sent else [ack]) + [response]
    m.drain(g.ports)
    before = ctx.outcomes()
    if timed:
        for frame in frames_in:
            m.send(ctx.relay, frame)
        got = m.capture(g.ports, timeout=4, quiet=.4)
        at_master = got.get(ctx.master, [])
    else:
        at_master = []
        for frame in frames_in:
            got = m.exchange(ctx.relay, frame, g.ports, timeout=3, quiet=.15)
            at_master.extend(got.get(ctx.master, []))
    at_relay = sum(len(got.get(p, [])) for p in g.ports if p != ctx.master)
    if ack_sent:
        exact = len(at_master) == 1 and g.h.same_frame(at_master[0], expected, expected)
    else:
        exact = (len(at_master) == 2 and g.h.same_frame(at_master[0], wire_ack, wire_ack)
                 and g.h.same_frame(at_master[1], expected, expected))
    lengths = [tcp_fields(f)['payload_len'] for f in at_master]
    t_delta = [a - b for a, b in zip(ctx.outcomes(), before)]
    ok = exact and (t_delta == [1, 1, 0, 0] if timed else True)
    out = dict(step=tag, ok=ok, exact_ack_then_response=exact, frames_at_master=len(at_master),
               payload_lengths_at_master=lengths, image_len=len(image), response_at_class_size=len(image) in lengths,
               t_delta=t_delta if timed else None, pre_frames=len(pre), frames_at_relay_side=at_relay)
    rec['progress'].append(out)
    ctx.wire = wsq + len(image)
    return nsq + len(native), wsq + len(image), ok


def step(rec, name, function, *args, **kwargs):
    """A raising progress step (exact gate exchanges), recorded."""
    try:
        result = function(*args, **kwargs)
        rec['progress'].append(dict(step=name, ok=True))
        return result
    except Exception as error:      # noqa: BLE001 - a failed step is a finding, recorded with its reason
        rec['progress'].append(dict(step=name, ok=False, error='%s: %s' % (type(error).__name__, error)))
        raise


def finish(ctx, rec, tag, cls, c, nsq, wsq, timed, mapped_ack=True):
    """The master's ACK of the current response, the next transaction (the other READ class), FIN close."""
    if mapped_ack:
        step(rec, 'response_ACK', ctx.gate.exchange, tag + '_mapped_complete_ACK', ctx.v.packet(16, c, wsq),
             ctx.v.packet(16, c, nsq))
    before = wsq
    c, nsq, wsq = step(rec, 'next_transaction', ctx.actual, tag + '_NEXT', OTHER[cls], c, nsq, wsq, k=1, timed=timed)
    rec['next_image_len'] = wsq - before
    step(rec, 'FIN_close', ctx.gate.close, c, nsq, wsq, tag + '_close')
    rec['closed'] = True


def open_outstanding(ctx, case, isn, tag):
    """Handshake, then the first READ admitted (owner 0xe) and nothing from the relay yet."""
    cls = case['read_class']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    request, native, image = cf.read_frames(ctx, cls)
    ctx.gate.exchange(tag + '_READ_request', ctx.v.packet(24, c, wire, payload=request),
                      ctx.v.packet(24, c, s, payload=request))
    return c + len(request), s, wire, request, native, image


def open_idle(ctx, case, isn, tag):
    """Handshake and one complete exchange of the case's READ class: owner 5."""
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    ctx.fresh()
    request = cf.read_frames(ctx, case['read_class'])[0]
    ctx.fresh()
    c, nsq, wsq = ctx.actual(tag + '_READ', case['read_class'], c, s, wire, k=0, timed=case['timed'])
    ctx.wire = wsq
    return c, nsq, wsq, request


# ---- cases ----------------------------------------------------------------------------------------------------------
def owner_state(n):
    return None if n.get('owner') is None else n['owner'] >> 16


def case_late_ack(ctx, case, rec, isn):
    """The final handshake ACK claims after the first READ was admitted (owner 0xe, client_diff -len, server_diff 0).
    wire order: the ACK is sent first and busy-retries on a forced-held cell; the cell is released after its first
    retry and the READ is sent at once, so the READ can overtake it (a race: up to ATTEMPTS fresh connections).
    reverse order: the READ is sent and fully processed, then the ACK (built before the READ) arrives."""
    cls, tag, timed = case['read_class'], case['case'], case['timed']
    wire_order = case['scenario'] == 'late_ack_wire_order'
    rec['attempts'] = []
    for attempt in range(ATTEMPTS if wire_order else 1):
        ctx.reset()
        name = '%s_a%d' % (tag, attempt)
        c, s = ctx.open(isn[0] + 50_000 * attempt, isn[1] + 50_000 * attempt, name)
        ctx.wire = s
        request, native, image = cf.read_frames(ctx, cls)
        ack = ctx.build('final_ACK', c, s)                    # the master sends the final ACK first
        read = ctx.build('READ', c, s, payload=request)
        sent = {'final_ACK': want_of(ack), 'READ': want_of(read)}
        n_before, t_before = n_state(ctx.m), ctx.outcomes()
        if wire_order:
            ctx.force_cell(1)

            def release(_offset):
                ctx.force_cell(4)
                ctx.run.fast[ctx.master].send(read['frame'])
                return dict(cell_released_after_first_ACK_retry=True, READ_sent=True)
            try:
                obs = ctx.observe([(ctx.master, ack['frame'])], sent, pattern=action('busy_retry_ack'),
                                  on_match=release)
            finally:
                ctx.force_cell(4)
            first = obs
        else:
            first = ctx.observe([(ctx.master, read['frame'])], sent)
            if first['port64'].count('READ'):
                ctx.ledger.append(strip(read))
            n_before, t_before = n_state(ctx.m), ctx.outcomes()
            obs = ctx.observe([(ctx.master, ack['frame'])], sent)
        passes = ctx.passes(first['offset'])
        c_after = (c + len(request)) & M32
        state = cs.late_ack_state(passes, want_of(ack), expected_client=c_after)
        read_first = claimed_before(passes, want_of(read), want_of(ack))
        read_summary = cf.summarize(cf.history(passes, want_of(read)), ctx.t_in)
        rec['attempts'].append(dict(attempt=attempt, isn=[isn[0] + 50_000 * attempt, isn[1] + 50_000 * attempt],
                                    state_reached=state.get('reached') is True, read_claimed_first=read_first,
                                    read_port64=(first['port64'] + (obs['port64'] if obs is not first else [])).count('READ'),
                                    read_summary=read_summary, hook=first.get('hook')))
        if state.get('reached') is not True:
            rec['attempts'][-1]['cleanup'] = ctx.run.close(ctx.wire)
            continue
        rec['state_evidence'] = {k: v for k, v in state.items() if k != 'laps'}
        rec['state_evidence']['laps'] = state.get('laps')
        reference = None
        if wire_order:
            if read_first and first['port64'].count('READ'):
                ctx.ledger.append(strip(read))
            reference = dict(owner=(0xe << 16) | (n_before['owner'] & 0xffff), client=c_after, server=s,
                             epoch=n_before['epoch'], retry_epoch=n_before['retry_epoch'], work_phase=4)
        result = evaluate(ctx, ack, obs, n_before, t_before, reference=reference)
        result['port64_order'] = obs['port64'] if wire_order else first['port64'] + obs['port64']
        reply_if_due(ctx, rec, result, ack, s, s, defer=timed)
        rec['probes'].append(result)
        rec['state_reached'] = True
        nsq, wsq, _ok = deliver(ctx, rec, 'READ_response', c_after, s, s, native, image, timed)
        finish(ctx, rec, tag, cls, c_after, nsq, wsq, timed)
        return
    rec['state_reached'] = False


def case_r1(ctx, case, rec, isn):
    cls, tag, timed, g, v = case['read_class'], case['case'], case['timed'], ctx.gate, ctx.v
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    request, native, image = cf.read_frames(ctx, cls)
    g.exchange(tag + '_READ1_request', v.packet(24, c, wire, payload=request), v.packet(24, c, s, payload=request))
    c += len(request)
    nsq, wsq, _ok = deliver(ctx, rec, 'READ1_response', c, s, wire, native, image, timed)
    request2, native2, image2 = g.frames(cls, k=0)
    old = ctx.build('old_ACK_of_response1', c, wsq)        # sent before READ 2, arrives after it
    read2 = ctx.build('READ2', c, wsq, payload=request2)
    obs = ctx.observe([(ctx.master, read2['frame'])], {'READ2': want_of(read2)})
    rec['READ2_port64'] = obs['port64']
    if obs['port64'].count('READ2'):
        ctx.ledger.append(strip(read2))
    rec['state_reached'] = owner_state(n_state(ctx.m)) in (0xd, 0xe)
    probe_once(ctx, rec, old, nsq, wsq, defer=timed)
    c2 = c + len(request2)
    nsq, wsq, _ok = deliver(ctx, rec, 'READ2_response', c2, nsq, wsq, native2, image2, timed)
    finish(ctx, rec, tag, cls, c2, nsq, wsq, timed)


def case_r2(ctx, case, rec, isn):
    """Not produced by a conforming master: a pure ACK at the client register minus the OTHER READ length, built
    before the READ (as a stale ACK would be)."""
    cls, tag, timed, g, v = case['read_class'], case['case'], case['timed'], ctx.gate, ctx.v
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    request, native, image = cf.read_frames(ctx, cls)
    c_after = (c + len(request)) & M32
    probe = ctx.build('offset_ACK', c_after - READ_LENGTH[OTHER[cls]], wire)
    rec['offset_from_isn_plus_1'] = ((probe['seq'] - c + 0x80000000) & M32) - 0x80000000
    g.exchange(tag + '_READ_request', v.packet(24, c, wire, payload=request), v.packet(24, c, s, payload=request))
    rec['state_reached'] = owner_state(n_state(ctx.m)) in (0xd, 0xe)
    probe_once(ctx, rec, probe, s, wire, defer=timed)
    nsq, wsq, _ok = deliver(ctx, rec, 'READ_response', c_after, s, wire, native, image, timed)
    finish(ctx, rec, tag, cls, c_after, nsq, wsq, timed)


def case_window_outstanding(ctx, case, rec, isn):
    cls, tag, timed = case['read_class'], case['case'], case['timed']
    c, s, wire, request, native, image = open_outstanding(ctx, case, isn, tag)
    rec['state_reached'] = owner_state(n_state(ctx.m)) in (0xd, 0xe)
    if case['scenario'] == 'window_increase_outstanding':
        probe_once(ctx, rec, ctx.build('window_update', c, wire, window=WINDOW_UP), s, wire, defer=timed)
    else:
        probe_once(ctx, rec, ctx.build('zero_window', c, wire, window=0), s, wire, defer=timed)
        probe_once(ctx, rec, ctx.build('window_reopen', c, wire, window=WINDOW), s, wire, defer=timed)
    nsq, wsq, _ok = deliver(ctx, rec, 'READ_response', c, s, wire, native, image, timed)
    finish(ctx, rec, tag, cls, c, nsq, wsq, timed)


def case_idle(ctx, case, rec, isn):
    cls, tag, timed, scenario = case['read_class'], case['case'], case['timed'], case['scenario']
    c, nsq, wsq, request = open_idle(ctx, case, isn, tag)
    rec['state_reached'] = owner_state(n_state(ctx.m)) == 5
    if scenario == 'window_increase_idle':
        probe_once(ctx, rec, ctx.build('window_update', c, wsq, window=WINDOW_UP), nsq, wsq)
    elif scenario == 'keepalive_idle':
        probe_once(ctx, rec, ctx.build('keepalive_0', c - 1, wsq), nsq, wsq)
        probe_once(ctx, rec, ctx.build('keepalive_1', c - 1, wsq, payload=request[-1:], flags=16), nsq, wsq)
    else:                                                  # duplicate_ack_idle: the same bytes twice
        first = ctx.build('duplicate_ACK_1', c, wsq)
        probe_once(ctx, rec, first, nsq, wsq)
        probe_once(ctx, rec, dict(first, name='duplicate_ACK_2', order=ctx.next_order()), nsq, wsq)
    finish(ctx, rec, tag, cls, c, nsq, wsq, timed, mapped_ack=False)


def case_keepalive_outstanding(ctx, case, rec, isn):
    """T off: the relay's ACK of the READ reaches the master first, then the keepalives. T on: the keepalives are
    sent before the relay's ACK, because an ACK held in T while the slow model observes the probes would exceed T's
    budget and measure the harness (amendment 1 in DESIGN.json)."""
    cls, tag, timed, g, v, rp = case['read_class'], case['case'], case['timed'], ctx.gate, ctx.v, ctx.rp
    c, s, wire, request, native, image = open_outstanding(ctx, case, isn, tag)
    if not timed:
        ack = v.packet(16, s, c, reverse=True)
        step(rec, 'relay_ACK_of_READ', g.exchange, tag + '_relay_ACK', ack,
             rp.preserve_options(ack, v.packet(16, wire, c, reverse=True)), reverse=True)
    rec['state_reached'] = owner_state(n_state(ctx.m)) in (0xd, 0xe)
    probe_once(ctx, rec, ctx.build('keepalive_0', c - 1, wire), s, wire, defer=timed)
    probe_once(ctx, rec, ctx.build('keepalive_1', c - 1, wire, payload=request[-1:], flags=16), s, wire,
               defer=timed)
    nsq, wsq, _ok = deliver(ctx, rec, 'READ_response', c, s, wire, native, image, timed, ack_sent=not timed)
    finish(ctx, rec, tag, cls, c, nsq, wsq, timed)


def case_response_ack(ctx, case, rec, isn):
    cls, tag, timed = case['read_class'], case['case'], case['timed']
    c, s, wire, request, native, image = open_outstanding(ctx, case, isn, tag)
    rec['state_reached'] = owner_state(n_state(ctx.m)) in (0xd, 0xe)
    nsq, wsq, _ok = deliver(ctx, rec, 'READ_response', c, s, wire, native, image, timed)
    probe_once(ctx, rec, ctx.build('response_ACK', c, wsq), nsq, wsq)
    finish(ctx, rec, tag, cls, c, nsq, wsq, timed, mapped_ack=False)


CASE_FUNCTIONS = dict(late_ack_wire_order=case_late_ack, late_ack_reverse_order=case_late_ack, r1_ack_behind_read=case_r1,
                      r2_offset=case_r2, window_increase_outstanding=case_window_outstanding,
                      window_increase_idle=case_idle, zero_window_outstanding=case_window_outstanding,
                      keepalive_idle=case_idle, keepalive_outstanding=case_keepalive_outstanding,
                      duplicate_ack_idle=case_idle, response_ack_control=case_response_ack)


def consequence(rec):
    """One plain sentence from observed disposition and progress only."""
    parts = []
    for p in rec.get('probes', []):
        text = '%s %s the relay' % (p['sent']['name'], 'reached' if p['forwarded'] else 'did not reach')
        reply = p.get('relay_reply')
        if reply and reply.get('reply_deferred_to_response_burst'):
            text += '; the relay reply was sent ahead of the relay ACK and response'
        elif reply:
            text += '; the relay reply reached the master %d time(s)' % reply['at_master']
        parts.append(text)
    for s in rec.get('progress', []):
        if 'image_len' in s:
            parts.append('%s %s (%s octets at the master%s)' % (
                s['step'], 'delivered' if s['ok'] else 'NOT delivered as expected', s['payload_lengths_at_master'],
                '' if s['t_delta'] is None else ', T counts %s' % s['t_delta']))
        else:
            parts.append('%s %s' % (s['step'], 'completed' if s['ok'] else 'FAILED: ' + s.get('error', '')))
    return '; '.join(parts)


def isn_for(index):
    c = 1_000_000 * (index + 1) + 300
    return c, c + 700


def run_case(ctx, case, index):
    rec = dict(case, probes=[], progress=[], state_reached=None)
    isn = isn_for(index)
    rec['isn'] = dict(master=isn[0], relay=isn[1])
    ctx.set_t(case['timed'])
    ctx.fresh()
    ctx.reset()
    ctx.wire = isn[1] + 1
    try:
        CASE_FUNCTIONS[case['scenario']](ctx, case, rec, isn)
    except Exception:
        rec['error'] = traceback.format_exc()
    rec['progress_ok'] = bool(rec['progress']) and all(s['ok'] for s in rec['progress']) and 'error' not in rec
    rec['classifications'] = {p['sent']['name']: p['classification'] for p in rec['probes']}
    rec['consequence'] = consequence(rec)
    if not rec.get('closed'):
        try:
            rec['cleanup'] = ctx.run.close(ctx.wire)
            if not rec['cleanup']['rst_forwarded']:
                rec['cleanup_retry'] = ctx.run.close(n_state(ctx.m)['server'])
        except Exception:
            rec['cleanup_error'] = traceback.format_exc()
    for item in rec.get('deferred_replies', []):
        item.pop('frame', None)
    return rec


def main():
    import model_packets as mp
    from model_relay_sbo import RelayGate
    import model_log_view as view
    h = mp.load('_ab_helpers', HERE / 'model_drive_composite.py')
    cp = mp.load('_ab_cp', HERE / 'cp.py')
    out = Path(os.environ['OUT'])
    selected = [f for f in os.environ.get('ACK_CASES', '').split(',') if f]   # smoke runs only; recorded
    cases = [c for c in CASES if not selected or any(c['case'].startswith(f) for f in selected)]
    report = h.Report(os.environ['PROG'], physical=False, model_gate=False,
                      scope='master-ACK behaviour against results/analysis/ack_behaviour/DESIGN.json; labelled, not gate',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      rule_sha256=hashlib.sha256((HERE / 'ack_rule.py').read_bytes()).hexdigest(),
                      case_filter=selected or None, cases=[case['case'] for case in cases])
    gate = RelayGate(report, h.Model(ports=[], enable=False), h, cp)
    records = []
    try:
        gate.configure()
        report.record['meta']['t_params'] = dict(timed=cf.TIMED, untimed=cf.UNTIMED, note='set per case')
        ctx = Ctx(gate, view, mp.rp)
        for case in cases:
            record = run_case(ctx, case, CASES.index(case))
            records.append(record)
            (out / ('case_%s.json' % case['case'])).write_text(json.dumps(record, indent=1, sort_keys=True,
                                                                          default=str) + '\n')
            report.add(case['case'], 'completed with progress', dict(state_reached=record['state_reached'],
                       progress_ok=record['progress_ok'], classifications=record['classifications']),
                       ok=record['progress_ok'] and 'error' not in record, evidence_kind=case['evidence_kind'])
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    report.record['meta']['reflectors'] = [r.summary() for r in getattr(gate, 'reflectors', [])]
    (out / 'ack_behaviour_cases.json').write_text(json.dumps(
        [dict({k: r.get(k) for k in ('case', 'scenario', 'read_class', 'timed', 'evidence_kind', 'state_reached',
                                     'progress_ok', 'classifications', 'consequence')},
              forwarded={p['sent']['name']: p['forwarded'] for p in r['probes']},
              error=(r.get('error') or '').strip().splitlines()[-1:] or None)
         for r in records], indent=1, default=str) + '\n')
    return 0 if report.finish(out / 'ack_behaviour_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())
