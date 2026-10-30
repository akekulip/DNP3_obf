"""c74 connection-start correction: labelled regressions on the compiled model. NOT a gate driver.

c74 changes three const-entry tables of N (results/builds/c74/derive_c74.py):
  H1  READ (9), SELECT (5) and OPERATE (7) that find the single work cell held take the master-direction retry path
      (busy_retry_ack, busy_retry_rst_next, busy_exhausted at the end of n_RETRY_BUDGET) instead of busy_drop, as
      the master pure ACK (3) already did; guard go_retry(9/5/7) admits the retry pass.
  H2  a master pure ACK that finds owner 0xd/0xe, client_diff exactly -25/-27 and server_diff exactly 0 is
      forward_original (the existing old-ACK forward) instead of the default NoAction -> abort.
Every case runs on a fresh connection on the same 4-tuple and is reported with its own checks. Cases marked
'as_before' carry only build-independent structural checks; their observations are compared with the same driver's
run on c72 (results/models/c74_connection_fix/compare_c72_c74.json). Cases marked 'residual' record a known
acceptance of the H2 rows that the dataplane cannot exclude (README). Forced-register cases are labelled apart from
genuine packet processing. Run with scripts/model/run_connection_fix.py."""
import hashlib
import json
import os
import time
import traceback
from pathlib import Path

import model_connection_start as cs

HERE = Path(__file__).resolve().parent

CLASSES = ('mixed', 'integrity')
READ_LENGTH = {'mixed': 25, 'integrity': 27}
OTHER = {'mixed': 'integrity', 'integrity': 'mixed'}
RETRY_BUDGET = 32
BUSY_ACTIONS = ('busy_drop', 'busy_pass', 'busy_retry', 'busy_retry_next', 'busy_retry_rst', 'busy_retry_rst_next',
                'busy_retry_ack', 'busy_exhausted', 'retry_stale')
REQUEST_RETRY = ('busy_retry_ack', 'busy_retry_rst_next')
LOSS_ACTIONS = ('busy_drop', 'busy_exhausted', 'retry_stale')
EXHAUSTION = ['busy_retry_ack'] + ['busy_retry_rst_next'] * (RETRY_BUDGET - 1) + ['busy_exhausted']
TIMED = dict(da=1_000_000, readiness=2_000_000_000, cap=1_500_000_000, gap=50_000_000, op_j=200_000_000,
             budget=240_000, pb=1_000_000_000, enabled=1)      # model_relay_sbo's timed connection
UNTIMED = dict(TIMED, enabled=0)


def action(name):
    return r'Execute (?:Default )?Action: n_Ingress\.%s\b' % name


# scenario -> (evidence kind, expectation class, per READ class, T timed, one-line expectation on c74)
SCENARIOS = dict(
    H1=('genuine_processing', 'fix', True, True,
        'final ACK and first READ back to back: the READ retries while the ACK holds the cell, then is admitted; '
        'port 64 gets ACK then READ once each; T sees the READ once; full timed cycle follows'),
    H2=('genuine_processing', 'fix', True, False,
        'READ admitted at owner 4, then the final ACK: first_event forward_original, no abort, no N state change; '
        'port 64 gets READ then ACK once each'),
    H2r=('genuine_processing', 'fix', True, True,
         'READ and final ACK back to back: the ACK busy-retries, claims at owner 0xe, forward_original; timed cycle'),
    collision=('genuine_processing', 'fix', True, False,
               'the c72 reproduction construction (OPERATE injected while the SELECT response holds the cell, its '
               'ACK covering image octets the master has not received): the OPERATE retries instead of busy_drop, '
               'then first_event refuses it (count_refused) because its normalized ACK is 11 octets (image 60 - '
               'native 49) ahead of the relay sequence; not on port 64'),
    collision_causal=('genuine_processing', 'fix', True, False,
                      'after the SELECT image reached the master: the relay retransmits the SELECT response and the '
                      'master sends OPERATE back to back; the retransmission holds the cell, the OPERATE retries, is '
                      'admitted once by first_operate and reaches port 64 once'),
    H1prime=('forced_register', 'fix', True, True,
             'cell forced busy, READ retries; cell released after the first retry; READ admitted once; timed cycle'),
    H1_sbo=('genuine_processing', 'fix', True, True,
            'mapped ACK + SELECT and mapped ACK + OPERATE back to back after timed responses: each command retries, '
            'is admitted once and reaches port 64 once; timed padded responses; integrity/mixed READ follows'),
    exhaust=('forced_register', 'fix', True, False,
             'cell held past the budget: busy_retry_ack, 31 busy_retry_rst_next, busy_exhausted; READ never on '
             'port 64; no pass after exhaustion; the master retransmission is then delivered'),
    stale_retry=('forced_register', 'fix', True, False,
                 'a retrying READ whose epoch no longer matches retry_epoch is dropped by retry_stale once'),
    dup_during_retry=('forced_register', 'fix', True, False,
                      'a TCP retransmission of the READ arrives while the first copy retries: one admission, one '
                      'duplicate (first_request_dup), no loss action, no internal clone'),
    dup_after_admit=('genuine_processing', 'as_before', True, False,
                     'TCP retransmission of an admitted READ: first_request_dup path, as on c72'),
    stale_ack=('genuine_processing', 'fix', True, False,
               'after the first READ: ACKs with wrong seq (+1) and wrong ack (+1, -1) refused (abort, not on 64); '
               'the exact late handshake ACK forwarded; its duplicate forwarded again; N state unchanged'),
    reconnect=('genuine_processing', 'fix', True, False,
               'connection A closed by FIN; connection B on the same 4-tuple: ACK + READ back to back delivered; '
               'A\'s handshake ACK (old incarnation) refused'),
    rst_read_outstanding=('genuine_processing', 'as_before', True, False,
                          'master RST while the first READ is outstanding: RST on port 64 once'),
    fin_after_exchange=('genuine_processing', 'as_before', True, False, 'READ exchange then FIN close'),
    residual_class_mismatch=('genuine_processing', 'residual', True, False,
                             'pure ACK at client minus the OTHER READ length (seq ISN+3 or ISN-1): accepted by the '
                             'H2 rows (residual, not distinguishable without the READ length)'),
    residual_later_read=('genuine_processing', 'residual', True, False,
                         'old ACK of response 1 delayed behind READ 2: accepted by the H2 rows (residual)'),
    rst_at_start=('genuine_processing', 'as_before', False, False, 'RST after the SYN-ACK: RST on port 64 once'),
    fin_at_start=('genuine_processing', 'as_before', False, False, 'FIN close right after the handshake'),
    operate_without_select=('genuine_processing', 'as_before', False, False,
                            'OPERATE after a READ exchange, no SELECT: refused, not on port 64'),
    operate_retry_before_select_response=('forced_register', 'fix', False, False,
                                          'OPERATE retried while the SELECT is outstanding (owner 9): it claims and is '
                                          'refused by first_event, never reaches port 64'),
    operate_mismatched_crob=('genuine_processing', 'as_before', False, False,
                             'OPERATE whose CROB differs from the SELECT: refused; the matching OPERATE then admitted'),
    syn_busy=('forced_register', 'as_before', False, False,
              'SYN while the cell is held: busy_drop (SYN deliberately unchanged); its retransmission connects'))
PER_CLASS_ORDER = ('H1', 'H2', 'H2r', 'collision', 'collision_causal', 'H1prime', 'H1_sbo', 'exhaust', 'stale_retry', 'dup_during_retry',
                   'dup_after_admit', 'stale_ack', 'reconnect', 'rst_read_outstanding', 'fin_after_exchange',
                   'residual_class_mismatch', 'residual_later_read')
SINGLE_ORDER = ('rst_at_start', 'fin_at_start', 'operate_without_select', 'operate_retry_before_select_response',
                'operate_mismatched_crob', 'syn_busy')


def _case(scenario, read_class):
    kind, expectation, _per_class, timed, text = SCENARIOS[scenario]
    name = scenario if read_class is None else '%s_%s' % (scenario, read_class)
    return dict(case=name, scenario=scenario, read_class=read_class,
                read_length=READ_LENGTH.get(read_class), evidence_kind=kind, expectation=expectation,
                timed=timed, expect=text)


CASES = tuple([_case(s, c) for c in CLASSES for s in PER_CLASS_ORDER] + [_case(s, None) for s in SINGLE_ORDER])


def verdict(state_reached, checks_ok):
    """state_reached None = the case has no state precondition."""
    if state_reached is False:
        return 'state_not_reached'
    return 'pass' if checks_ok else 'fail'


class Checks:
    def __init__(self):
        self.rows = []

    def add(self, name, expect, actual, ok=None, **extra):
        ok = expect == actual if ok is None else bool(ok)
        self.rows.append(dict(name=name, expect=expect, actual=actual, ok=ok, **extra))
        return ok

    def ok(self):
        return bool(self.rows) and all(row['ok'] for row in self.rows)


# ---- pass analysis (pure) ----------------------------------------------------------------------------------------
def names(record):
    return cs.action_names(record)


def busy_action(record):
    return next((a for a in names(record) if a in BUSY_ACTIONS), None)


def history(passes, want):
    """Every ingress pass of one TCP segment: port, whether it ran the stage-0 claim, its busy_t action, its
    first_event action (if first_event ran) and all action names."""
    out = []
    for record in passes:
        if not cs.matches(record['segment'], want):
            continue
        step = cs.table_step(record, 'n_Ingress.first_event')
        out.append(dict(port=record['port'], claim=cs.salu(record, 'claim_work') is not None,
                        busy=busy_action(record),
                        first_event=None if step is None else dict(action=step['action'].rsplit('.', 1)[-1],
                                                                   default=bool(step['default'])),
                        names=names(record)))
    return out


def summarize(hist, t_in):
    busy = [h['busy'] for h in hist if h['busy']]
    first = [h['first_event']['action'] for h in hist if h['first_event']]
    return dict(busy=busy, first_event=first, loss=[b for b in busy if b in LOSS_ACTIONS],
                aborts=sum('terminal_abort' in h['names'] for h in hist),
                terminal_ack=sum('terminal_ack' in h['names'] for h in hist),
                t_ingress=sum(h['port'] == t_in for h in hist), passes=len(hist))


def request_checks(checks, prefix, summary, admit, retried=True):
    """A request that must be admitted exactly once, with no loss action and one T ingress pass."""
    busy = summary['busy']
    if retried:
        checks.add(prefix + '_first_claim_busy_retry_ack', 'busy_retry_ack', busy[0] if busy else None)
    checks.add(prefix + '_only_retry_busy_actions', True, all(b in REQUEST_RETRY for b in busy), busy=busy)
    checks.add(prefix + '_retries_within_budget', True, len(busy) <= RETRY_BUDGET, retries=len(busy))
    checks.add(prefix + '_no_loss_action', [], summary['loss'])
    checks.add(prefix + '_no_abort', 0, summary['aborts'])
    checks.add(prefix + '_admitted_once_by_' + admit, 1, summary['first_event'].count(admit),
               first_event=summary['first_event'])
    checks.add(prefix + '_T_ingress_once', 1, summary['t_ingress'])


def core_registers(regs):
    def value(name):
        cell = regs.get(name) or {}
        return cell.get('f1')
    work = regs.get('work.work') or {}
    return dict(owner=value('owner'), client=value('client'), server=value('server'), epoch=value('epoch'),
                work_phase=work.get('phase'))


# ---- model interaction ---------------------------------------------------------------------------------------
class Ctx:
    def __init__(self, gate, view, rp):
        self.gate, self.view, self.rp = gate, view, rp
        self.run = cs.Run(gate, view, rp)
        self.m, self.v = gate.m, gate.v
        self.master, self.relay = gate.master.dev_port, gate.relay.dev_port
        self.t_in = gate.h.T_IN

    def set_t(self, timed):
        self.m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', dict(TIMED if timed else UNTIMED))

    def fresh(self):
        self.gate.seqs = dict(master=0, app=0, server=0)
        self.gate.control_boundary_probed = True     # the relay_sbo boundary probe is relay_sbo's, not ours

    def handshake(self, c, s, tag):
        state = self.gate.handshake(c, s, tag + '_')
        self.gate.control_boundary_probed = True
        return state

    def observe(self, frames, sent, pattern=None, on_match=None, wait_timeout=8, fast=False):
        """Send frames back to back from pre-bound sockets. fast: short capture, no settling (a timed transaction
        must reach its relay response before T's readiness)."""
        run, view = self.run, self.view
        self.m.drain(run.ports)
        offset = view.wait_idle(run.log, quiet=0.5, timeout=20)[0]
        for port, frame in frames:
            run.fast[port].send(frame)
        line = waited = None
        if pattern:
            line, waited = view.wait_for(run.log, offset, pattern, timeout=wait_timeout)[:2]
        hook = on_match(offset) if on_match else None
        got = self.m.capture(run.ports, timeout=1.5 if fast else 4, quiet=0.3 if fast else 1.0)
        if not fast:
            view.wait_idle(run.log, quiet=0.5, timeout=20)
            for port, more in self.m.capture(run.ports, timeout=0.6, quiet=0.3).items():
                got.setdefault(port, []).extend(more)
        labelled = cs.label_frames(got, sent)
        return dict(offset=offset, decisive_line=line, decisive_wait_s=waited, hook=hook,
                    port64=[r['label'] for r in labelled.get(str(self.relay), [])],
                    port9=[r['label'] for r in labelled.get(str(self.master), [])],
                    port64_frames=labelled.get(str(self.relay), []), port9_frames=labelled.get(str(self.master), []))

    def passes(self, offset):
        return self.run.passes(offset)

    def outcomes(self):
        return [self.gate.h.scalar(self.m.register_read('p1.t_Ingress.outcomes', i, pipe=1)) for i in (2, 3, 8, 9)]

    def respond(self, tag, c, nsq, wsq, native, image, timed, mapped_ack=True):
        """The relay's ACK and response to a delivered request (model_relay_sbo actual_exchange, second half)."""
        g, v, rp = self.gate, self.v, self.rp
        ack = v.packet(16, nsq, c, reverse=True)
        response = v.packet(24, nsq, c, reverse=True, payload=native)
        wire_ack = rp.preserve_options(ack, v.packet(16, wsq, c, reverse=True))
        expected = rp.preserve_options(response, v.packet(24, wsq, c, reverse=True, payload=image))
        if timed:
            self.m.drain(g.ports)
            before = self.outcomes()
            self.m.send(self.relay, ack)
            self.m.send(self.relay, response)
            got = self.m.capture(g.ports, timeout=4, quiet=.4)
            frames = got.get(self.master, [])
            exact = len(frames) == 2 and all(g.h.same_frame(f, w, w) for f, w in zip(frames, (wire_ack, expected)))
            g.add(tag + '_timed_ACK_then_complete_response', True, exact, received=got)
            g.add(tag + '_committed_no_request_retry', [1, 1, 0, 0], [a - b for a, b in zip(self.outcomes(), before)])
            received = frames[-1]
        else:
            g.exchange(tag + '_ACK', ack, wire_ack, reverse=True)
            received = g.exchange(tag + '_complete_response', response, expected, reverse=True)
        length = len(cs_payload(received))
        g.add(tag + '_image_len', len(image), length)
        nsq, wsq = nsq + len(native), wsq + len(image)
        if mapped_ack:
            g.exchange(tag + '_mapped_complete_ACK', v.packet(16, c, wsq), v.packet(16, c, nsq))
        return nsq, wsq, length

    def tail(self, tag, cls, c, nsq, wsq, timed):
        """SELECT, OPERATE, then the other READ class: the rest of one strict cycle."""
        g = self.gate
        c, nsq, wsq = g.actual_exchange(tag + '_SELECT', 'CONTROL', c, nsq, wsq, fc=3, timed=timed)
        c, nsq, wsq = g.actual_exchange(tag + '_OPERATE', 'CONTROL', c, nsq, wsq, fc=4, timed=timed)
        return g.actual_exchange(tag + '_READ2', OTHER[cls], c, nsq, wsq, k=1, timed=timed)

    def force_cell(self, phase):
        names_ = {'n_Ingress.work.work.generation': cs.FORCED_SEED, 'n_Ingress.work.work.phase': phase}
        self.m.register_write('p0.n_Ingress.work.work', 0, names_, pipe=0)

    def retry_epoch(self, value=None):
        values = self.m.register_read('p0.n_Ingress.retry_epoch', 0, pipe=0)
        key = next(k for k in values if k.endswith('.f1'))
        if value is None:
            current = values[key]
            return current[0] if isinstance(current, list) else current
        self.m.register_write('p0.n_Ingress.retry_epoch', 0, {key: value}, pipe=0)
        return value


def cs_payload(frame):
    import model_packets as mp
    return mp.tcp_payload(frame)


def seg(direction, seq, flags, payload_len):
    return cs.seg(direction, seq, flags, payload_len)


# ---- cases -------------------------------------------------------------------------------------------------------
def read_frames(ctx, cls):
    ctx.fresh()
    request, native, image = ctx.gate.frames(cls, k=0)
    if len(request) != READ_LENGTH[cls]:
        raise ValueError('READ fixture length %d != %d' % (len(request), READ_LENGTH[cls]))
    return request, native, image


def case_H1(ctx, case, ck, rec, isn):
    cls, run, tag = case['read_class'], ctx.run, case['case']
    c, s = run.open(isn[0], isn[1], tag)
    request, native, image = read_frames(ctx, cls)
    sent = {'final_ACK': seg('m2r', c, 0x10, 0), 'READ': seg('m2r', c, 0x18, len(request))}
    obs = ctx.observe([(ctx.master, run.packet(16, c, s)), (ctx.master, run.packet(24, c, s, payload=request))],
                      sent, pattern=action('first_read_request'), fast=True)
    rec['observations'] = [obs]
    passes = ctx.passes(obs['offset'])
    state = cs.cell_held_state(passes, sent['final_ACK'], sent['READ'])
    summary = summarize(history(passes, sent['READ']), ctx.t_in)
    rec.update(state_evidence=state, read_summary=summary)
    request_checks(ck, 'READ', summary, 'first_read_request')
    ck.add('port64_order', ['final_ACK', 'READ'], obs['port64'])
    c += len(request)
    nsq, wsq, length = ctx.respond(tag + '_READ', c, s, s, native, image, timed=True)
    rec['image_len'] = {'READ': length}
    c, nsq, wsq = ctx.tail(tag, cls, c, nsq, wsq, timed=True)
    ctx.gate.close(c, nsq, wsq, tag + '_close')
    rec['closed'] = True
    ck.add('timed_cycle_completed', True, True)
    return state.get('reached') is True


def case_H2(ctx, case, ck, rec, isn):
    cls, run, tag = case['read_class'], ctx.run, case['case']
    c, s = run.open(isn[0], isn[1], tag)
    request, native, image = read_frames(ctx, cls)
    sent = {'final_ACK': seg('m2r', c, 0x10, 0), 'READ': seg('m2r', c, 0x18, len(request))}
    ack = run.packet(16, c, s)                       # built first: the master sent it before the READ
    read = run.packet(24, c, s, payload=request)
    timed = case['timed']
    if case['scenario'] == 'H2':
        obs = [ctx.observe([(ctx.master, read)], sent)]
        mid = core_registers(run.registers())
        obs.append(ctx.observe([(ctx.master, ack)], sent, pattern=action('forward_original')))
    else:
        mid = None
        obs = [ctx.observe([(ctx.master, read), (ctx.master, ack)], sent, pattern=action('forward_original'),
                           fast=timed)]
    after = core_registers(run.registers())
    rec['observations'] = obs
    passes = ctx.passes(obs[0]['offset'])
    expected_client = (c + len(request)) & 0xffffffff
    state = cs.late_ack_state(passes, sent['final_ACK'], expected_client=expected_client)
    ack_hist = history(passes, sent['final_ACK'])
    ack_summary, read_summary = summarize(ack_hist, ctx.t_in), summarize(history(passes, sent['READ']), ctx.t_in)
    rec.update(state_evidence=state, ack_summary=ack_summary, read_summary=read_summary, registers_mid=mid,
               registers_after=after)
    event = state.get('first_event') or {}
    ck.add('late_ACK_first_event', dict(action='forward_original', default=False),
           dict(action=(event.get('action') or '').rsplit('.', 1)[-1], default=event.get('default')))
    ck.add('late_ACK_no_abort', 0, ack_summary['aborts'] + sum('abort_work' in h['names'] for h in ack_hist))
    ck.add('late_ACK_terminal_ack_once', 1, ack_summary['terminal_ack'])
    if case['scenario'] == 'H2r':
        ck.add('late_ACK_was_busy_retried', 'busy_retry_ack', ack_summary['busy'][0] if ack_summary['busy'] else None)
    request_checks(ck, 'READ', read_summary, 'first_read_request', retried=False)
    ports64 = [label for item in obs for label in item['port64']]
    ck.add('port64_order', ['READ', 'final_ACK'], ports64)
    ck.add('N_state_after', dict(owner_state=0xe, client=expected_client, server=s & 0xffffffff, work_phase=4),
           dict(owner_state=None if after['owner'] is None else after['owner'] >> 16, client=after['client'],
                server=after['server'], work_phase=after['work_phase']))
    if mid is not None:
        ck.add('late_ACK_changed_no_N_state', mid, after)
    c += len(request)
    nsq, wsq, length = ctx.respond(tag + '_READ', c, s, s, native, image, timed=timed)
    rec['image_len'] = {'READ': length}
    c, nsq, wsq = ctx.tail(tag, cls, c, nsq, wsq, timed=timed)
    ctx.gate.close(c, nsq, wsq, tag + '_close')
    rec['closed'] = True
    return state.get('reached') is True


def case_collision(ctx, case, ck, rec, isn):
    """The c72 reproduction's construction, unchanged (T disabled, non-causal OPERATE)."""
    cls, run, g, tag = case['read_class'], ctx.run, ctx.gate, case['case']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    rec['progress_wire'] = wire
    c, s, wire = g.actual_exchange(tag + '_READ', cls, c, s, wire, k=0)
    rec['progress_wire'] = wire
    select, native, image = g.frames('CONTROL', fc=3)
    g.exchange(tag + '_SELECT_request', ctx.v.packet(24, c, wire, payload=select), ctx.v.packet(24, c, s, payload=select))
    c += len(select)
    ack = ctx.v.packet(16, s, c, reverse=True)
    g.exchange(tag + '_SELECT_relay_ACK', ack, ctx.rp.preserve_options(ack, ctx.v.packet(16, wire, c, reverse=True)),
               reverse=True)
    operate, op_native, op_image = g.frames('CONTROL', fc=4)
    response = run.packet(24, s, c, reverse=True, payload=native)
    operate_frame = run.packet(24, c, wire + len(image), payload=operate)
    sent = {'SELECT_response': seg('r2m', s, 0x18, len(native)), 'OPERATE': seg('m2r', c, 0x18, len(operate))}
    obs = ctx.observe([(ctx.relay, response), (ctx.master, operate_frame)], sent, pattern=action('terminal_abort'))
    rec['observations'] = [obs]
    passes = ctx.passes(obs['offset'])
    state = cs.cell_held_state(passes, sent['SELECT_response'], sent['OPERATE'])
    summary = summarize(history(passes, sent['OPERATE']), ctx.t_in)
    rec.update(state_evidence=state, operate_summary=summary)
    busy = summary['busy']
    ck.add('OPERATE_first_claim_busy_retry_ack', 'busy_retry_ack', busy[0] if busy else None)
    ck.add('OPERATE_only_retry_busy_actions', True, all(b in REQUEST_RETRY for b in busy), busy=busy)
    ck.add('OPERATE_no_loss_action', [], summary['loss'])
    ck.add('OPERATE_refused_by_first_event', ['count_refused'], summary['first_event'])
    claimed = [p for p in cs.claims(passes, sent['OPERATE']) if cs.decode_work(cs.salu(p, 'claim_work')[0])['phase'] == 4]
    server = cs.salu(claimed[0], 'load_server') if claimed else None
    ahead = None if not server else (claimed[0]['segment']['ack'] - server[0]) & 0xffffffff
    rec['noncausal_ack'] = dict(normalized_ack=claimed[0]['segment']['ack'] if claimed else None,
                                server_register=server[0] if server else None, ahead=ahead,
                                image_minus_native=len(image) - len(native))
    ck.add('OPERATE_ack_ahead_by_image_minus_native', len(image) - len(native), ahead)
    ck.add('OPERATE_not_on_port64', 0, obs['port64'].count('OPERATE'))
    images = sum(len(f) > 54 and f.find(image) >= 0 for f in [bytes.fromhex(r['hex']) for r in obs['port9_frames']])
    ck.add('SELECT_image_to_master_once', 1, images)
    rec['progress_wire'] = wire + len(image)
    return state.get('reached') is True


def case_collision_causal(ctx, case, ck, rec, isn):
    cls, run, g, tag = case['read_class'], ctx.run, ctx.gate, case['case']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    rec['progress_wire'] = wire
    c, s, wire = g.actual_exchange(tag + '_READ', cls, c, s, wire, k=0)
    rec['progress_wire'] = wire
    select, native, image = g.frames('CONTROL', fc=3)
    g.exchange(tag + '_SELECT_request', ctx.v.packet(24, c, wire, payload=select), ctx.v.packet(24, c, s, payload=select))
    c += len(select)
    nsq, wsq, length = ctx.respond(tag + '_SELECT', c, s, wire, native, image, timed=False, mapped_ack=False)
    rec['progress_wire'] = wsq
    rec['image_len'] = {'SELECT': length}
    operate, op_native, op_image = g.frames('CONTROL', fc=4)
    retransmission = run.packet(24, s, c, reverse=True, payload=native)
    sent = {'SELECT_response': seg('r2m', s, 0x18, len(native)), 'OPERATE': seg('m2r', c, 0x18, len(operate))}
    obs = ctx.observe([(ctx.relay, retransmission), (ctx.master, run.packet(24, c, wsq, payload=operate))], sent,
                      pattern=action('first_operate'))
    rec['observations'] = [obs]
    passes = ctx.passes(obs['offset'])
    state = cs.cell_held_state(passes, sent['SELECT_response'], sent['OPERATE'])
    summary = summarize(history(passes, sent['OPERATE']), ctx.t_in)
    rec.update(state_evidence=state, operate_summary=summary,
               retransmission_summary=summarize(history(passes, sent['SELECT_response']), ctx.t_in))
    request_checks(ck, 'OPERATE', summary, 'first_operate')
    ck.add('OPERATE_on_port64_once', 1, obs['port64'].count('OPERATE'))
    c += len(operate)
    nsq, wsq, length = ctx.respond(tag + '_OPERATE', c, nsq, wsq, op_native, op_image, timed=False)
    rec['image_len']['OPERATE'] = length
    g.close(c, nsq, wsq, tag + '_close')
    rec['closed'] = True
    return state.get('reached') is True


def case_H1prime(ctx, case, ck, rec, isn):
    cls, run, tag = case['read_class'], ctx.run, case['case']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    rec['progress_wire'] = wire
    request, native, image = read_frames(ctx, cls)
    sent = {'READ': seg('m2r', c, 0x18, len(request))}
    read = run.packet(24, c, wire, payload=request)
    ctx.force_cell(1)

    def release(_offset):
        ctx.force_cell(4)
        return dict(released_after_first_retry=True)
    try:
        obs = ctx.observe([(ctx.master, read)], sent, pattern=action('busy_retry_ack'), on_match=release, fast=True)
    finally:
        ctx.force_cell(4)
    rec['observations'] = [obs]
    ck.add('first_retry_seen_before_release', True, obs['decisive_line'] is not None)
    passes = ctx.passes(obs['offset'])
    state = cs.forced_state(passes, sent['READ'], cs.FORCED_SEED)
    summary = summarize(history(passes, sent['READ']), ctx.t_in)
    rec.update(state_evidence=state, read_summary=summary)
    request_checks(ck, 'READ', summary, 'first_read_request')
    ck.add('port64', ['READ'], obs['port64'])
    c += len(request)
    nsq, wsq, length = ctx.respond(tag + '_READ', c, s, wire, native, image, timed=True)
    rec['image_len'] = {'READ': length}
    c, nsq, wsq = ctx.tail(tag, cls, c, nsq, wsq, timed=True)
    ctx.gate.close(c, nsq, wsq, tag + '_close')
    rec['closed'] = True
    return state.get('reached') is True


def case_H1_sbo(ctx, case, ck, rec, isn):
    cls, run, g, tag = case['read_class'], ctx.run, ctx.gate, case['case']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    rec['progress_wire'] = wire
    request, native, image = read_frames(ctx, cls)
    g.exchange(tag + '_READ_request', ctx.v.packet(24, c, wire, payload=request), ctx.v.packet(24, c, s, payload=request))
    c += len(request)
    nsq, wsq, length = ctx.respond(tag + '_READ', c, s, wire, native, image, timed=True, mapped_ack=False)
    rec['progress_wire'] = wsq
    rec['image_len'] = {'READ': length}
    reached, observations = [], []
    for name, fc, admit in (('SELECT', 3, 'first_select'), ('OPERATE', 4, 'first_operate')):
        command, cnative, cimage = g.frames('CONTROL', fc=fc)
        sent = {'ACK': seg('m2r', c, 0x10, 0), name: seg('m2r', c, 0x18, len(command))}
        obs = ctx.observe([(ctx.master, run.packet(16, c, wsq)), (ctx.master, run.packet(24, c, wsq, payload=command))],
                          sent, pattern=action(admit), fast=True)
        observations.append(obs)
        passes = ctx.passes(obs['offset'])
        state = cs.cell_held_state(passes, sent['ACK'], sent[name])
        summary = summarize(history(passes, sent[name]), ctx.t_in)
        rec.setdefault('state_evidence', {})[name] = state
        rec.setdefault('command_summary', {})[name] = summary
        reached.append(state.get('reached') is True)
        request_checks(ck, name, summary, admit)
        ck.add(name + '_port64_order', ['ACK', name], obs['port64'])
        c += len(command)
        nsq, wsq, length = ctx.respond(tag + '_' + name, c, nsq, wsq, cnative, cimage, timed=True,
                                       mapped_ack=name == 'OPERATE')
        rec['progress_wire'] = wsq
        rec['image_len'][name] = length
    rec['observations'] = observations
    c, nsq, wsq = g.actual_exchange(tag + '_READ2', OTHER[cls], c, nsq, wsq, k=1, timed=True)
    g.close(c, nsq, wsq, tag + '_close')
    rec['closed'] = True
    return all(reached)


def forced_read_setup(ctx, case, isn):
    cls, run, tag = case['read_class'], ctx.run, case['case']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    request, native, image = read_frames(ctx, cls)
    return c, s, wire, request, native, image, {'READ': seg('m2r', c, 0x18, len(request))}


def recover(ctx, case, ck, rec, c, s, wire, request, native, image, sent):
    """The master's TCP retransmission once the cell is free: delivered once; then the exchange and a FIN close."""
    obs = ctx.observe([(ctx.master, ctx.run.packet(24, c, wire, payload=request))], sent)
    rec['recovery'] = {k: v for k, v in obs.items() if k not in ('port64_frames', 'port9_frames')}
    ck.add('retransmission_delivered_once', ['READ'], obs['port64'])
    c += len(request)
    nsq, wsq, length = ctx.respond(case['case'] + '_READ', c, s, wire, native, image, timed=False)
    ctx.gate.close(c, nsq, wsq, case['case'] + '_close')
    rec['closed'] = True


def case_exhaust(ctx, case, ck, rec, isn):
    c, s, wire, request, native, image, sent = forced_read_setup(ctx, case, isn)
    rec['progress_wire'] = wire
    ctx.force_cell(1)
    try:
        obs = ctx.observe([(ctx.master, ctx.run.packet(24, c, wire, payload=request))], sent,
                          pattern=action('busy_exhausted'), wait_timeout=60)
    finally:
        ctx.force_cell(4)
    rec['observations'] = [obs]
    passes = ctx.passes(obs['offset'])
    state = cs.forced_state(passes, sent['READ'], cs.FORCED_SEED)
    hist = history(passes, sent['READ'])
    summary = summarize(hist, ctx.t_in)
    rec.update(state_evidence=state, read_summary=summary)
    ck.add('busy_sequence_exactly_the_budget', EXHAUSTION, summary['busy'])
    ck.add('never_admitted', [], summary['first_event'])
    ck.add('READ_not_on_port64', 0, obs['port64'].count('READ'))
    ck.add('no_pass_after_exhaustion', 'busy_exhausted', hist[-1]['busy'] if hist else None)
    recover(ctx, case, ck, rec, c, s, wire, request, native, image, sent)
    return state.get('reached') is True


def case_stale_retry(ctx, case, ck, rec, isn):
    c, s, wire, request, native, image, sent = forced_read_setup(ctx, case, isn)
    rec['progress_wire'] = wire
    epoch = ctx.retry_epoch()
    rec['retry_epoch_before'] = epoch

    def poison(offset):
        ctx.retry_epoch((epoch ^ 0x5a5a5a5a) or 1)
        line, waited = ctx.view.wait_for(ctx.run.log, offset, action('retry_stale'), timeout=10)[:2]
        ctx.retry_epoch(epoch)
        ctx.force_cell(4)
        return dict(stale_line=line, stale_wait_s=waited)
    ctx.force_cell(1)
    try:
        obs = ctx.observe([(ctx.master, ctx.run.packet(24, c, wire, payload=request))], sent,
                          pattern=action('busy_retry_ack'), on_match=poison)
    finally:
        ctx.retry_epoch(epoch)
        ctx.force_cell(4)
    rec['observations'] = [obs]
    passes = ctx.passes(obs['offset'])
    state = cs.forced_state(passes, sent['READ'], cs.FORCED_SEED)
    hist = history(passes, sent['READ'])
    summary = summarize(hist, ctx.t_in)
    rec.update(state_evidence=state, read_summary=summary, retry_epoch_after=ctx.retry_epoch())
    ck.add('first_busy_retry_ack', 'busy_retry_ack', summary['busy'][0] if summary['busy'] else None)
    ck.add('retry_stale_once_and_last', (1, 'retry_stale'),
           (summary['busy'].count('retry_stale'), summary['busy'][-1] if summary['busy'] else None))
    ck.add('never_admitted', [], summary['first_event'])
    ck.add('READ_not_on_port64', 0, obs['port64'].count('READ'))
    ck.add('retry_epoch_restored', epoch, rec['retry_epoch_after'])
    recover(ctx, case, ck, rec, c, s, wire, request, native, image, sent)
    return state.get('reached') is True


def case_dup_during_retry(ctx, case, ck, rec, isn):
    c, s, wire, request, native, image, sent = forced_read_setup(ctx, case, isn)
    rec['progress_wire'] = wire
    copies = [ctx.run.packet(24, c, wire, payload=request)]

    def second_copy(offset):
        copies.append(ctx.run.packet(24, c, wire, payload=request))
        ctx.run.fast[ctx.master].send(copies[-1])
        line = ctx.view.wait_for(ctx.run.log, offset, r'Ingress Pkt from port 68', timeout=2)[0]
        time.sleep(0.2)
        ctx.force_cell(4)
        return dict(second_copy_sent=True, loop_line=line)
    ctx.force_cell(1)
    try:
        obs = ctx.observe([(ctx.master, copies[0])], sent, pattern=action('busy_retry_ack'), on_match=second_copy)
    finally:
        ctx.force_cell(4)
    rec['observations'] = [obs]
    passes = ctx.passes(obs['offset'])
    state = cs.forced_state(passes, sent['READ'], cs.FORCED_SEED)
    summary = summarize(history(passes, sent['READ']), ctx.t_in)
    rec.update(state_evidence=state, read_summary=summary)
    ck.add('both_copies_retried', 2, summary['busy'].count('busy_retry_ack'))
    ck.add('no_loss_action', [], summary['loss'])
    ck.add('one_admission', 1, summary['first_event'].count('first_read_request'))
    ck.add('one_duplicate', 1, summary['first_event'].count('first_request_dup'))
    rec['port64_READ_copies'] = obs['port64'].count('READ')
    rec['t_ingress'] = summary['t_ingress']
    c += len(request)
    ctx.respond(case['case'] + '_READ', c, s, wire, native, image, timed=False)
    return state.get('reached') is True


def case_dup_after_admit(ctx, case, ck, rec, isn):
    cls, run, g, tag = case['read_class'], ctx.run, ctx.gate, case['case']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    rec['progress_wire'] = wire
    request, native, image = read_frames(ctx, cls)
    sent = {'READ': seg('m2r', c, 0x18, len(request))}
    g.exchange(tag + '_READ_request', ctx.v.packet(24, c, wire, payload=request), ctx.v.packet(24, c, s, payload=request))
    obs = ctx.observe([(ctx.master, run.packet(24, c, wire, payload=request))], sent)
    rec['observations'] = [obs]
    summary = summarize(history(ctx.passes(obs['offset']), sent['READ']), ctx.t_in)
    rec.update(read_summary=summary, port64_READ_copies=obs['port64'].count('READ'), t_ingress=summary['t_ingress'])
    ck.add('duplicate_first_event', ['first_request_dup'], summary['first_event'])
    ck.add('no_busy_action', [], summary['busy'])
    c += len(request)
    ctx.respond(tag + '_READ', c, s, wire, native, image, timed=False)
    return None


def stale_probe(ctx, label, frame, want):
    obs = ctx.observe([(ctx.master, frame)], {label: want})
    summary = summarize(history(ctx.passes(obs['offset']), want), ctx.t_in)
    return obs, summary


def case_stale_ack(ctx, case, ck, rec, isn):
    cls, run, tag = case['read_class'], ctx.run, case['case']
    c, s = run.open(isn[0], isn[1], tag)
    request, native, image = read_frames(ctx, cls)
    read_seg = seg('m2r', c, 0x18, len(request))
    obs = ctx.observe([(ctx.master, run.packet(24, c, s, payload=request))], {'READ': read_seg})
    ck.add('READ_delivered', ['READ'], obs['port64'])
    before = core_registers(run.registers())
    rec['registers_after_READ'] = before
    probes = {}
    for label, seq, ack, expect64 in (('wrong_seq', c + 1, s, 0), ('wrong_ack_high', c, s + 1, 0),
                                      ('wrong_ack_low', c, s - 1, 0), ('late_handshake_ACK', c, s, 1),
                                      ('duplicate_late_ACK', c, s, 1)):
        obs, summary = stale_probe(ctx, label, run.packet(16, seq, ack), seg('m2r', seq, 0x10, 0))
        probes[label] = dict(seq=seq, ack=ack, port64=obs['port64'], summary=summary,
                             registers=core_registers(run.registers()))
        ck.add(label + '_on_port64', expect64, obs['port64'].count(label))
        if expect64:
            ck.add(label + '_forward_original', ['forward_original'], summary['first_event'])
        ck.add(label + '_N_state_unchanged', before, probes[label]['registers'])
    rec['probes'] = probes
    c += len(request)
    nsq, wsq, _length = ctx.respond(tag + '_READ', c, s, s, native, image, timed=False)
    rec['progress_wire'] = wsq
    return None


def case_reconnect(ctx, case, ck, rec, isn):
    cls, run, g, tag = case['read_class'], ctx.run, ctx.gate, case['case']
    ca, sa, wa = ctx.handshake(isn[0], isn[1], tag + '_A')
    ctx.fresh()
    ca, na, wa = g.actual_exchange(tag + '_A_READ', cls, ca, sa, wa, k=0)
    g.close(ca, na, wa, tag + '_A_close')
    old_ack = (isn[0] + 1, isn[1] + 1)
    c, s = run.open(isn[0] + 500_000, isn[1] + 500_000, tag + '_B')
    request, native, image = read_frames(ctx, cls)
    sent = {'final_ACK': seg('m2r', c, 0x10, 0), 'READ': seg('m2r', c, 0x18, len(request))}
    obs = ctx.observe([(ctx.master, run.packet(16, c, s)), (ctx.master, run.packet(24, c, s, payload=request))], sent)
    summary = summarize(history(ctx.passes(obs['offset']), sent['READ']), ctx.t_in)
    rec['B_read_summary'] = summary
    ck.add('B_port64_order', ['final_ACK', 'READ'], obs['port64'])
    ck.add('B_READ_no_loss_action', [], summary['loss'])
    before = core_registers(run.registers())
    probe, psum = stale_probe(ctx, 'old_incarnation_ACK', run.packet(16, *old_ack), seg('m2r', old_ack[0], 0x10, 0))
    rec['old_incarnation_probe'] = dict(port64=probe['port64'], summary=psum)
    ck.add('old_incarnation_ACK_refused', 0, probe['port64'].count('old_incarnation_ACK'))
    ck.add('old_incarnation_ACK_N_state_unchanged', before, core_registers(run.registers()))
    rec['observations'] = [obs, probe]
    c += len(request)
    nsq, wsq, _length = ctx.respond(tag + '_B_READ', c, s, s, native, image, timed=False)
    rec['progress_wire'] = wsq
    return None


def case_rst_read_outstanding(ctx, case, ck, rec, isn):
    cls, run, g, tag = case['read_class'], ctx.run, ctx.gate, case['case']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    request, native, image = read_frames(ctx, cls)
    g.exchange(tag + '_READ_request', ctx.v.packet(24, c, wire, payload=request), ctx.v.packet(24, c, s, payload=request))
    c += len(request)
    obs = ctx.observe([(ctx.master, run.packet(20, c, wire))], {'RST': dict(direction='m2r', seq=c, flags=0x14)})
    rec['observations'] = [obs]
    rec['registers_after'] = core_registers(run.registers())
    ck.add('RST_on_port64_once', 1, obs['port64'].count('RST'))
    rec['closed'] = True
    return None


def case_fin_after_exchange(ctx, case, ck, rec, isn):
    cls, g, tag = case['read_class'], ctx.gate, case['case']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    ctx.fresh()
    c, nsq, wsq = g.actual_exchange(tag + '_READ', cls, c, s, wire, k=0)
    g.close(c, nsq, wsq, tag + '_close')
    rec['closed'] = True
    rec['registers_after'] = core_registers(ctx.run.registers())
    ck.add('exchange_and_FIN_close_completed', True, True)
    return None


def residual_setup(ctx, case, isn):
    cls, run, tag = case['read_class'], ctx.run, case['case']
    c, s = run.open(isn[0], isn[1], tag)
    request, native, image = read_frames(ctx, cls)
    obs = ctx.observe([(ctx.master, run.packet(24, c, s, payload=request))], {'READ': seg('m2r', c, 0x18, len(request))})
    return c, s, request, native, image, obs


def case_residual_class_mismatch(ctx, case, ck, rec, isn):
    cls, run, tag = case['read_class'], ctx.run, case['case']
    c, s, request, native, image, obs = residual_setup(ctx, case, isn)
    ck.add('READ_delivered', ['READ'], obs['port64'])
    seq = (c + len(request) - READ_LENGTH[OTHER[cls]]) & 0xffffffff   # mixed: ISN-1; integrity: ISN+3
    probe, summary = stale_probe(ctx, 'mismatched_seq_ACK', run.packet(16, seq, s), seg('m2r', seq, 0x10, 0))
    rec['probe'] = dict(seq=seq, isn_plus_1=c, port64=probe['port64'], summary=summary)
    rec['residual_accepted'] = probe['port64'].count('mismatched_seq_ACK') == 1
    ck.add('residual_recorded', True, True)
    c += len(request)
    nsq, wsq, _length = ctx.respond(tag + '_READ', c, s, s, native, image, timed=False)
    rec['progress_wire'] = wsq
    return None


def case_residual_later_read(ctx, case, ck, rec, isn):
    cls, run, g, tag = case['read_class'], ctx.run, ctx.gate, case['case']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    request, native, image = read_frames(ctx, cls)
    g.exchange(tag + '_READ1_request', ctx.v.packet(24, c, wire, payload=request), ctx.v.packet(24, c, s, payload=request))
    c += len(request)
    nsq, wsq, _length = ctx.respond(tag + '_READ1', c, s, wire, native, image, timed=False, mapped_ack=False)
    rec['progress_wire'] = wsq
    request2, native2, image2 = g.frames(cls, k=0)
    old_ack = run.packet(16, c, wsq)                     # the ACK of response 1, sent before READ 2
    sent = {'READ2': seg('m2r', c, 0x18, len(request2)), 'old_ACK': seg('m2r', c, 0x10, 0)}
    first = ctx.observe([(ctx.master, run.packet(24, c, wsq, payload=request2))], sent)
    ck.add('READ2_delivered', ['READ2'], first['port64'])
    probe = ctx.observe([(ctx.master, old_ack)], sent)
    summary = summarize(history(ctx.passes(probe['offset']), sent['old_ACK']), ctx.t_in)
    rec['probe'] = dict(port64=probe['port64'], summary=summary)
    rec['residual_accepted'] = probe['port64'].count('old_ACK') == 1
    ck.add('residual_recorded', True, True)
    c += len(request2)
    nsq, wsq, _length = ctx.respond(tag + '_READ2', c, nsq, wsq, native2, image2, timed=False)
    rec['progress_wire'] = wsq
    return None


def case_rst_at_start(ctx, case, ck, rec, isn):
    run = ctx.run
    c, s = run.open(isn[0], isn[1], case['case'])
    obs = ctx.observe([(ctx.master, run.packet(20, c, s))], {'RST': dict(direction='m2r', seq=c, flags=0x14)})
    rec['observations'] = [obs]
    rec['registers_after'] = core_registers(run.registers())
    ck.add('RST_on_port64_once', 1, obs['port64'].count('RST'))
    rec['closed'] = True
    return None


def case_fin_at_start(ctx, case, ck, rec, isn):
    c, s, wire = ctx.handshake(isn[0], isn[1], case['case'])
    ctx.gate.close(c, s, wire, case['case'] + '_close')
    rec['closed'] = True
    rec['registers_after'] = core_registers(ctx.run.registers())
    ck.add('FIN_close_completed', True, True)
    return None


def case_operate_without_select(ctx, case, ck, rec, isn):
    g, run, tag = ctx.gate, ctx.run, case['case']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    ctx.fresh()
    c, nsq, wsq = g.actual_exchange(tag + '_READ', 'mixed', c, s, wire, k=0)
    rec['progress_wire'] = wsq
    operate = g.frames('CONTROL', fc=4)[0]
    want = seg('m2r', c, 0x18, len(operate))
    obs = ctx.observe([(ctx.master, run.packet(24, c, wsq, payload=operate))], {'OPERATE': want})
    summary = summarize(history(ctx.passes(obs['offset']), want), ctx.t_in)
    rec.update(observations=[obs], operate_summary=summary)
    ck.add('OPERATE_not_on_port64', 0, obs['port64'].count('OPERATE'))
    ck.add('OPERATE_refused_by_first_event', ['count_refused'], summary['first_event'])
    return None


def case_operate_retry_before_select_response(ctx, case, ck, rec, isn):
    g, run, tag = ctx.gate, ctx.run, case['case']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    ctx.fresh()
    select = g.frames('CONTROL', fc=3)[0]
    g.exchange(tag + '_SELECT_request', ctx.v.packet(24, c, wire, payload=select), ctx.v.packet(24, c, s, payload=select))
    c += len(select)
    rec['progress_wire'] = wire
    owner = core_registers(run.registers())['owner']
    rec['owner_before_OPERATE'] = owner
    operate = g.frames('CONTROL', fc=4)[0]
    want = seg('m2r', c, 0x18, len(operate))
    ctx.force_cell(1)

    def release(_offset):
        ctx.force_cell(4)
        return dict(released_after_first_retry=True)
    try:
        obs = ctx.observe([(ctx.master, run.packet(24, c, wire, payload=operate))], {'OPERATE': want},
                          pattern=action('busy_retry_ack'), on_match=release)
    finally:
        ctx.force_cell(4)
    passes = ctx.passes(obs['offset'])
    state = cs.forced_state(passes, want, cs.FORCED_SEED)
    summary = summarize(history(passes, want), ctx.t_in)
    rec.update(observations=[obs], state_evidence=state, operate_summary=summary)
    ck.add('SELECT_outstanding_owner_9', 9, None if owner is None else owner >> 16)
    ck.add('OPERATE_retried', 'busy_retry_ack', summary['busy'][0] if summary['busy'] else None)
    ck.add('OPERATE_refused_after_claim', ['count_refused'], summary['first_event'])
    ck.add('OPERATE_not_on_port64', 0, obs['port64'].count('OPERATE'))
    return state.get('reached') is True


def case_operate_mismatched_crob(ctx, case, ck, rec, isn):
    from relay_sbo_vectors import OBJECTS, frame
    g, run, tag = ctx.gate, ctx.run, case['case']
    c, s, wire = ctx.handshake(isn[0], isn[1], tag)
    ctx.fresh()
    c, nsq, wsq = g.actual_exchange(tag + '_SELECT', 'CONTROL', c, s, wire, fc=3)
    rec['progress_wire'] = wsq
    qseq, app = g.seqs['master'], g.seqs['app']
    objects = bytearray(OBJECTS)
    objects[7] ^= 0x01                                   # first CROB on-time 200 ms -> 201 ms
    bad = frame(bytes.fromhex('056400c400000100'), bytes([0xc0 | qseq, 0xc0 | app, 4]) + bytes(objects))
    good = g.frames('CONTROL', fc=4)[0]
    want = seg('m2r', c, 0x18, len(good))
    obs = ctx.observe([(ctx.master, run.packet(24, c, wsq, payload=bad))], {'OPERATE': want})
    summary = summarize(history(ctx.passes(obs['offset']), want), ctx.t_in)
    ck.add('mismatched_OPERATE_not_on_port64', 0, obs['port64'].count('OPERATE'))
    ok = ctx.observe([(ctx.master, run.packet(24, c, wsq, payload=good))], {'OPERATE': want})
    ok_summary = summarize(history(ctx.passes(ok['offset']), want), ctx.t_in)
    ck.add('matching_OPERATE_admitted_once', (['first_operate'], 1),
           (ok_summary['first_event'], ok['port64'].count('OPERATE')))
    rec.update(observations=[obs, ok], mismatched_summary=summary, matching_summary=ok_summary)
    return None


def case_syn_busy(ctx, case, ck, rec, isn):
    run = ctx.run
    c, s = isn
    want = seg('m2r', c, 0x02, 0)
    ctx.force_cell(1)

    def release(_offset):
        ctx.force_cell(4)
        return dict(released=True)
    try:
        obs = ctx.observe([(ctx.master, run.packet(2, c, mss=1460))], {'SYN': want},
                          pattern=action('busy_drop'), on_match=release)
    finally:
        ctx.force_cell(4)
    passes = ctx.passes(obs['offset'])
    state = cs.forced_state(passes, want, cs.FORCED_SEED)
    summary = summarize(history(passes, want), ctx.t_in)
    rec.update(observations=[obs], state_evidence=state, syn_summary=summary)
    ck.add('SYN_busy_drop', ['busy_drop'], summary['busy'])
    ck.add('SYN_not_on_port64', 0, obs['port64'].count('SYN'))
    c1, s1, wire = ctx.handshake(c, s, case['case'] + '_retransmitted')
    rec['progress_wire'] = wire
    ck.add('retransmitted_SYN_connects', True, True)
    return state.get('reached') is True


CASE_FUNCTIONS = dict(H1=case_H1, H2=case_H2, H2r=case_H2, collision=case_collision,
                      collision_causal=case_collision_causal, H1prime=case_H1prime,
                      H1_sbo=case_H1_sbo, exhaust=case_exhaust, stale_retry=case_stale_retry,
                      dup_during_retry=case_dup_during_retry, dup_after_admit=case_dup_after_admit,
                      stale_ack=case_stale_ack, reconnect=case_reconnect,
                      rst_read_outstanding=case_rst_read_outstanding, fin_after_exchange=case_fin_after_exchange,
                      residual_class_mismatch=case_residual_class_mismatch,
                      residual_later_read=case_residual_later_read, rst_at_start=case_rst_at_start,
                      fin_at_start=case_fin_at_start, operate_without_select=case_operate_without_select,
                      operate_retry_before_select_response=case_operate_retry_before_select_response,
                      operate_mismatched_crob=case_operate_mismatched_crob, syn_busy=case_syn_busy)


def isn_for(index):
    c = 1_000_000 * (index + 1) + 100
    return c, c + 800


def run_case(ctx, case, index):
    ck, rec = Checks(), dict(case)
    isn = isn_for(index)
    rec.update(isn=dict(master=isn[0], relay=isn[1]), registers_before=core_registers(ctx.run.registers()))
    ctx.set_t(case['timed'])
    ctx.fresh()
    reached = None
    try:
        reached = CASE_FUNCTIONS[case['scenario']](ctx, case, ck, rec, isn)
    except Exception:
        rec['error'] = traceback.format_exc()
        ck.add('no_exception', None, rec['error'].strip().splitlines()[-1], ok=False)
    rec['state_reached'] = reached
    rec['checks'] = ck.rows
    rec['verdict'] = verdict(reached, ck.ok())
    if not rec.get('closed'):
        try:
            rec['cleanup'] = ctx.run.close(rec.get('progress_wire', isn[1] + 1))
        except Exception:
            rec['cleanup_error'] = traceback.format_exc()
    for item in rec.get('observations') or []:
        item.pop('port64_frames', None)
        item.pop('port9_frames', None)
    return rec


def main():
    import model_packets as mp
    from model_relay_sbo import RelayGate
    import model_log_view as view
    h = mp.load('_cf_helpers', HERE / 'model_drive_composite.py')
    cp = mp.load('_cf_cp', HERE / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False, model_gate=False,
                      scope='c74 connection-start correction regressions; labelled scenario, not gate',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      cases=[case['case'] for case in CASES])
    gate = RelayGate(report, h.Model(ports=[], enable=False), h, cp)
    records = []
    try:
        gate.configure()
        report.record['meta']['t_params'] = dict(timed=TIMED, untimed=UNTIMED, note='set per case before its handshake')
        ctx = Ctx(gate, view, mp.rp)
        for index, case in enumerate(CASES):
            record = run_case(ctx, case, index)
            records.append(record)
            (out / ('case_%s.json' % case['case'])).write_text(json.dumps(record, indent=1, sort_keys=True,
                                                                          default=str) + '\n')
            report.add(case['case'], 'pass', record['verdict'], ok=record['verdict'] == 'pass',
                       evidence_kind=case['evidence_kind'], expectation=case['expectation'])
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    report.record['meta']['reflectors'] = [r.summary() for r in getattr(gate, 'reflectors', [])]
    (out / 'connection_fix_cases.json').write_text(json.dumps(
        [dict({k: r.get(k) for k in ('case', 'scenario', 'read_class', 'evidence_kind', 'expectation', 'verdict',
                                     'state_reached', 'residual_accepted', 'port64_READ_copies', 't_ingress')},
              failed=[c['name'] for c in r.get('checks', []) if not c['ok']])
         for r in records], indent=1) + '\n')
    return 0 if report.finish(out / 'connection_fix_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())
