"""N's ACK/response work-cell contention on the compiled model (PLAN_m5.md S1/S2).

Runs inside launch_model.sh. Each point uses a fresh connection (RST, then a same-tuple reconnect with higher ISNs):
the master's request, the outstation's standalone ACK, then its response `d` ms (wall) after the ACK. One N pass
takes about 8-15 ms wall on the model and the ACK holds N's single work cell for about 60 ms, so small d makes the
response arrive while the cell is busy. A point passes only if the master receives the ACK and then exactly one exact
61-octet response WITHOUT any resend from the outstation, T counts ACK_COMMIT 1 / RESP_RELEASE 1 and no fallback, and
N busy-dropped nothing (count_busy[0]). Retry count (count_busy[2]) and exhaustion (count_busy[3]) are recorded.

Sweep: d in DELAYS_MS for READ, SELECT and OPERATE. Edge cases: a duplicate response while the first waits; packets
of a second, unconfigured connection interleaved during the wait; master RST during the wait (nothing may reach the
master afterwards); RST and same-tuple reconnect during the wait (the old response never reaches the new
connection, whose READ then completes); a lost response recovered by the outstation's retransmission.

On m4 the small-d points are expected to FAIL (busy drop): that run is the recorded regression. MILESTONE selects
the T behaviour the driver expects (m3+: bounded, control-timed). Frame builders come from seg61_02/model_repeat.py.
"""
import hashlib
import importlib.util
import json
import os
import select
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('_repeat_builders', HERE.parent / 'seg61_02/model_repeat.py')
rb = importlib.util.module_from_spec(spec)
sys.modules['_repeat_builders'] = rb
spec.loader.exec_module(rb)
helpers, cp, vectors, scalar, encode61 = rb.helpers, rb.cp, rb.vectors, rb.scalar, rb.encode61
Model, Report, gc, same_frame = rb.Model, rb.Report, rb.gc, rb.same_frame
PM, MASTER, RELAY, IMAGE_LEN = rb.PM, rb.MASTER, rb.RELAY, rb.IMAGE_LEN


def tcp_payload_len(frame):
    """TCP payload octets of an IPv4 frame from its IP total length (ignores Ethernet padding)."""
    ip_len = int.from_bytes(frame[16:18], 'big')
    ihl = (frame[14] & 15) * 4
    return ip_len - ihl - (frame[14 + ihl + 12] >> 4) * 4


def img_len(kind):
    """Wire image of a response kind on this build (READ image differs from the control image on policy builds)."""
    return rb.rp.read_image_len(IMAGE_LEN) if kind == 'READ' else IMAGE_LEN
# the contract rules (failure analysis of m10_03, 2026-10-17): judged from the dataplane's own evidence, not wall time
_spec = importlib.util.spec_from_file_location('contention_rules', HERE / 'contention_rules.py')
rules = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rules)
sys.path.insert(0, str(HERE))                    # model_log_view imports reset_application_check from here
import model_log_view as view  # noqa: E402
NAMES = ('UNMATCHED', 'HELD_REWAIT', 'ACK_COMMIT', 'RESP_RELEASE', 'RESP_DUP_DROP', 'OP_RELEASE', 'TOKEN_STALE',
         'HELD_STALE_FLUSH', 'ACK_FALLBACK', 'RESP_FALLBACK', 'TOKEN_TMO', 'HELD_OFF_FLUSH', 'TOKEN_OFF',
         'REQ_BYPASS', 'OLD_EPOCH_DROP', 'GEN_EXHAUSTED', 'OP_DUP_DROP')
OUT = {name: i for i, name in enumerate(NAMES)}
LANE = ('ACK_COMMIT', 'RESP_RELEASE', 'ACK_FALLBACK', 'RESP_FALLBACK')
COMMITTED = {'ACK_COMMIT': 1, 'RESP_RELEASE': 1, 'ACK_FALLBACK': 0, 'RESP_FALLBACK': 0}
_TIMELINE = os.environ.get('CONTENTION_TIMELINE')


def timeline(event, **fields):
    """Diagnostic timeline (attempt-04 stall): one JSON line per event with monotonic and wall time. A no-op unless
    CONTENTION_TIMELINE names a file; it never changes what is sent, waited for or judged."""
    if _TIMELINE:
        with open(_TIMELINE, 'a') as out:
            out.write(json.dumps(dict(fields, event=event, mono=time.monotonic(), wall=time.time()),
                                 default=str) + '\n')
DELAYS_MS = (0, 8, 15, 22, 30, 45, 60, 90, 120)
WAIT_S, QUIET_S = 8.0, 1.5     # > T's readiness fallback in wall time (about 3 s at ~6.8e8 model ns/s)
OP_HOLD_S = 0.9                # > J (200 ms model) in wall time
# OP_HOLD_S is in effect the quiet after the relayed OPERATE: the only window a duplicate OPERATE release was watched
# for. point() OPERATE exchanges (option a, 2026-10-17) use the READ/SELECT quiet instead and watch for an
# outstation-bound copy through the response capture (<tag>_request_not_relayed_again), a longer window; the stimulus then leaves margin
# to T's readiness (evidence/m10_03/precondition_05). Other OPERATE paths keep OP_HOLD_S.
# TRACE_sweep_SELECT_000ms.md (m6_07): a point's verdict is T's own lane (commit and release required). Before m7, T's lane
# could be fooled by 32-bit readiness aliasing past 2^32 ns (_02); m7's clock moves that to 9.16 minutes. The request-
# to-ACK wall time is recorded only; model-time stimulus checks are read from the model log (trace_model_log.py).
READ_BODY = rb.READ_BODY


def abort_survivor_verdict(held, before, frames, ack, want_ack, want_rsp, deltas, e_delta, proof, same):
    """v2 abort negative after its genuine ACK. held: T had admitted the response and released nothing when the
    invalid RST was sent; before: nothing reached the master before the ACK. Then the master receives exactly the
    mapped ACK and the already-held original response; T commits the ACK once and releases the response once (the
    v2 counters have no fallback cells); E resets nothing; T's own clock shows the ACK release after both arrivals
    and the response release a full D later."""
    return (held is True and before.get('responses') == 0 and before.get('frames_to_master') == 0
            and len(frames) == 2 and same(frames[0], want_ack, ack) and same(frames[1], want_rsp, want_rsp)
            and not any(f[47] & 0x04 for f in frames)
            and deltas.get('ACK_COMMIT', 0) == 1 and deltas.get('RESP_RELEASE', 0) == 1
            and deltas.get('ACK_FALLBACK', 0) == 0 and deltas.get('RESP_FALLBACK', 0) == 0
            and e_delta == 0 and proof.get('passed') is True)


class PointInterrupted(Exception):
    """A handshake step got nothing back (harness fix 4, 2026-10-17). Attempt 06: one SYN took the model about 3.5 s,
    the 3 s step closed first, and the point's remaining cases failed in a cascade. The step's evidence is recorded
    (meta 'interrupted': times, model-log growth, whether the expected frame arrived late) and the run stops. The
    cause is not classified here: a refused or lost frame and a slow model look the same at this point."""


def main():
    from model_profile import from_env
    profile = from_env()
    ready = profile.get('timing_contract') in ('response_ready_ack_d_v2', 'response_ready_ack_d_no_j_v3')
    names = tuple('REQ_DUP_DROP' if i == 8 else 'REQ_DUP_FORWARD' if i == 9 else name
                  for i, name in enumerate(NAMES)) if ready else NAMES
    out_indices = {name: i for i, name in enumerate(names) if profile.get('timing_contract') != 'response_ready_ack_d_no_j_v3' or name not in ('OP_RELEASE','OP_DUP_DROP')}
    names = tuple(out_indices)  # Every abort/restart delta uses only the explicitly observed contract cells.
    lane_keys = ('ACK_COMMIT', 'RESP_RELEASE') if ready else LANE
    committed = {name: COMMITTED[name] for name in lane_keys}
    milestone = profile['milestone']
    if milestone not in ('m1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7', 'm8', 'm9', 'm9d', 'm10'):          # an unknown milestone would silently take older expectations
        raise SystemExit('unknown MILESTONE %r' % milestone)
    bounded = milestone not in ('m1', 'm2')
    retrying = milestone in ('m5', 'm6', 'm7', 'm8', 'm9', 'm9d', 'm10')     # m5's retry form and counters; m6 changes N's reset/duplicate handling
    report = Report(os.environ['PROG'], physical=False,
                    scope='ctl_timing_01 %s: ACK/response contention for N\'s work cell (spacing sweep, edges)'
                    % milestone, driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    timing_contract=profile.get('timing_contract'))
    points = report.record['meta'].setdefault('points', [])
    # CONTENTION_SECTIONS (comma list) runs only the named sections; model_abort.py sets it to 'abort'
    sections = [x for x in os.environ.get('CONTENTION_SECTIONS', '').split(',') if x]
    report.record['meta']['sections'] = sections or 'all'

    def section_on(name):
        return not sections or name in sections
    rb.rp.report_endpoint(report)
    try:
        m = Model(ports=[], enable=False)
        ports = sorted({MASTER.dev_port, RELAY.dev_port})
        m.enable_ports(ports + helpers.FRONT_LOOPS)
        m.enable_ports([p for p in helpers.LOOP_PORTS if p not in helpers.FRONT_LOOPS])
        reflectors = [helpers.Reflector(p) for p in helpers.FRONT_LOOPS]
        for reflector in reflectors:
            reflector.start()
        rows = cp.n_ports_rows(MASTER.dev_port, RELAY.dev_port, MASTER.ip_int, RELAY.ip_int,
                               n_ack_return=PM.n_ack_return)
        rows += cp.n_connection_rows(RELAY, MASTER, n_ack_return=PM.n_ack_return)
        rows += cp.n_read_rows(RELAY, MASTER)
        for table, key, action, data, priority in rows:
            m.add('p0.n_' + table, dict(key), 'n_' + action, dict(data), priority)
        dc = dict(zip(('index', 'code', 'repeat', 'on', 'off'), vectors.decoy_config()))
        for source, dest in ((MASTER, RELAY), (RELAY, MASTER)):
            key = {'hdr.ip.src': source.ip_int, 'hdr.ip.dst': dest.ip_int,
                   'hdr.tcp.sport': source.port, 'hdr.tcp.dport': dest.port}
            m.add('p0.n_Ingress.data_connection', key, 'n_Ingress.configure', dc)
        for table, key, action, data, priority in cp.e_conn_rows(0, RELAY, MASTER, n_ack_return=PM.n_ack_return):
            m.add('p0.r_' + table, dict(key), 'r_' + action, dict(data), priority)
        if rb.rp.POLICY:   # pipe-1 READ padder's size enable, mirroring E's fwd_conn row (cp.p1_pad_rows)
            for table, key, action, data, priority in cp.p1_pad_rows(RELAY, MASTER, True):
                m.add(table, dict(key), action, dict(data), priority)
        params = dict(da=1_000_000, readiness=2_000_000_000, cap=1_500_000_000,
                      gap=50_000_000, op_j=200_000_000, budget=240_000, enabled=1)
        if bounded:
            params['pb'] = 1_000_000_000
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        mirror = m.table('$mirror.cfg', raw=True)
        mirror.entry_add(gc.Target(device_id=0, pipe_id=0xffff),
                         [mirror.make_key([gc.KeyTuple('$sid', 7)])],
                         [mirror.make_data([gc.DataTuple('$direction', str_val='INGRESS'),
                                            gc.DataTuple('$ucast_egress_port', helpers.PKTGEN_RETURN),
                                            gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                            gc.DataTuple('$session_enable', bool_val=True)], '$normal')])

        def outcomes():
            return {k: scalar(m.register_read('p1.t_Ingress.outcomes', i, pipe=1)) for k, i in out_indices.items()}

        cells = 8 if retrying else 4          # m5 grows count_busy to 8 (2 retry, 3 exhaustion, 4 stale)

        def busy():
            row = [scalar(m.register_read('p0.n_Ingress.count_busy', i, pipe=0)) for i in range(cells)]
            if retrying:                                # count_term[0]: retried duplicates aborted
                row.append(scalar(m.register_read('p0.n_Ingress.count_term', 0, pipe=0)))
            return row

        def capture(timeout, quiet):
            socks = {m._listen(p): p for p in ports}
            timeline('driver_capture_entry', timeout=timeout, quiet=quiet, ports=sorted(socks.values()))
            got, end, last = [], time.monotonic() + timeout, None
            start = time.monotonic()
            while time.monotonic() < end:
                ready, _, _ = select.select(list(socks), [], [], 0.01)
                for s in ready:
                    try:
                        data, addr = s.recvfrom(4096)
                    except BlockingIOError:
                        continue
                    if addr[2] == 4:                                    # PACKET_OUTGOING
                        continue
                    last = time.monotonic()
                    got.append((last, socks[s], data))
                if last and time.monotonic() - last > quiet:
                    break
            timeline('driver_capture_exit', reason='quiet' if last and time.monotonic() < end else 'timeout',
                     frames=len(got), elapsed_mono=time.monotonic() - start)
            return got

        def step(name, sent, expected, master=True):
            expected = rb.rp.preserve_options(sent, expected)
            rb.rp.advance_timestamp()
            log = view.log_path()
            size0, mono0, wall0 = view.size(log), time.monotonic(), time.time()
            got = m.exchange(MASTER.dev_port if master else RELAY.dev_port, sent, ports, timeout=3, quiet=.15)
            flat = [frame for frames in got.values() for frame in frames]
            good = len(flat) == 1 and same_frame(flat[0], expected, sent)
            report.add(name, 'one exact frame', '%d frames' % len(flat), ok=good, received=got)
            if not flat:
                size1 = view.size(log)
                late = capture(WAIT_S, QUIET_S)                  # evidence only: the step's verdict stands
                evidence = dict(case=name, sent_wall=wall0, step_closed_after_s=round(time.monotonic() - mono0, 3),
                                model_log_size_at_send=size0, model_log_size_at_close=size1,
                                model_log_size_after_wait=view.size(log),
                                late_frames=[(round(t - mono0, 3), p, len(f)) for t, p, f in late],
                                expected_arrived_late=any(same_frame(f, expected, sent) for _t, _p, f in late))
                report.record['meta']['interrupted'] = evidence
                timeline('point_interrupted', **evidence)
                raise PointInterrupted('%s got 0 frames within 3 s (expected frame arrived late: %s; model log grew '
                                       'during the step: %s); the run stops here' % (
                                           name, evidence['expected_arrived_late'],
                                           None if size0 is None or size1 is None else size1 > size0))
            return good

        st = {'c': 0, 's': 0, 'growth': 0, 'seqs': None, 'isn': 20000}

        def reconnect(tag):
            st['isn'] += 10000
            c, s = st['isn'], st['isn'] + 5000
            st.update(c=c, s=s, growth=0, seqs=rb.Sequences())
            step('%s_SYN' % tag, vectors.packet(2, c, mss=1460), vectors.packet(2, c, mss=1460))
            step('%s_SYNACK' % tag, vectors.packet(18, s, c + 1, reverse=True, mss=1460),
                 vectors.packet(18, s, c + 1, reverse=True, mss=1460), master=False)
            st['c'], st['s'] = c + 1, s + 1
            step('%s_final_ACK' % tag, vectors.packet(16, c + 1, s + 1), vectors.packet(16, c + 1, s + 1))

        def rst(tag):
            c, s, g = st['c'], st['s'], st['growth']
            m.drain(ports)
            m.send(MASTER.dev_port, vectors.packet(20, c, s + g))
            got = capture(2.0, 0.5)
            report.add('%s_RST_relayed' % tag, True,
                       any(p == RELAY.dev_port and same_frame(f, vectors.packet(20, c, s), vectors.packet(20, c, s + g))
                           for _t, p, f in got))
            return got

        def request(kind, fc, objects, watch_later=False):
            """Send the request; OPERATE waits out J. Returns (app, request bytes). watch_later: the caller watches
            for a second outstation-bound copy through the response capture, so the OPERATE quiet is not needed."""
            c, s, g = st['c'], st['s'], st['growth']
            req, app = st['seqs'].request(fc, objects)
            st['seqs'].next_app()
            sent, want = vectors.packet(24, c, s + g, payload=req), vectors.packet(24, c, s, payload=req)
            m.drain(ports)
            m.send(MASTER.dev_port, sent)
            t_sent = time.monotonic()
            st['request_sent'] = sent
            got = capture(OP_HOLD_S * 3 if kind == 'OPERATE' else 1.0, rules.request_quiet(kind, watch_later, OP_HOLD_S))
            # the contract is "relayed exactly once", not "within 1 s of host time": a stalled model (model_contention_
            # m10_03_01, SELECT 60 ms: 3.3 s with no model activity while the request was in N) relays it later
            while not any(p == RELAY.dev_port for _t, p, _f in got) and time.monotonic() - t_sent < WAIT_S:
                got += capture(0.5, 0.5)
            got += capture(0.2, 0.2) if any(p == RELAY.dev_port for _t, p, _f in got) else []
            relayed = [f for _t, p, f in got if p == RELAY.dev_port]
            relay_delay = next((t for t, p, _f in got if p == RELAY.dev_port), t_sent) - t_sent
            if relay_delay > 1.0:
                report.record['meta'].setdefault('request_relay_over_1s', []).append(
                    dict(kind=kind, delay_s=round(relay_delay, 3)))
            st['t_relayed'] = next((t for t, p, _f in got if p == RELAY.dev_port), None)
            ok = len(relayed) == 1 and same_frame(relayed[0], want, sent)
            if not ok:
                report.record['meta'].setdefault('request_not_relayed', []).append(
                    dict(kind=kind, relayed=len(relayed), frames=[(round(t, 4), p, len(f)) for t, p, f in got]))
            st['c'] += len(req)
            return app, ok

        def respond(kind, app, body, d_ms, during=None, send_response=True, keep_queued=False):
            """Standalone ACK, then the response d_ms later. during(st) runs after the response is sent (or
            in its place when send_response is False). Returns the frames seen and the native response.
            keep_queued: frames already queued are read into st['queued'] instead of drained unseen."""
            c, s = st['c'], st['s']
            native = st['seqs'].response(app, body, kind)
            ack = vectors.packet(16, s, c, reverse=True)
            rb.rp.advance_timestamp()
            sent_rsp = vectors.packet(24, s, c, reverse=True, payload=native)
            if keep_queued:
                st['queued'] = capture(0.02, 0.01)
            else:
                m.drain(ports)
            st['response_log_offset'] = view.size(view.log_path())
            m.send(RELAY.dev_port, ack)
            st['t_ack_sent'] = time.monotonic()
            if d_ms:
                time.sleep(d_ms / 1000.0)
            if send_response:
                m.send(RELAY.dev_port, sent_rsp)
            if during is not None:
                during(sent_rsp)
            return capture(WAIT_S, QUIET_S), native, ack, sent_rsp

        def judge(tag, kind, native, ack, got, before, busy0, extra=None, sent_rsp=None):
            s, g, c = st['s'], st['growth'], st['c']
            image = encode61.read61(native) if kind == 'READ' else encode61.ctl61(native)
            want_ack = rb.rp.preserve_options(ack, vectors.packet(16, s + g, c, reverse=True))
            want_rsp = vectors.packet(24, s + g, c, reverse=True, payload=image)
            if sent_rsp is not None:
                want_rsp = rb.rp.preserve_options(sent_rsp, want_rsp)
            # the contended connection's frames only (a second connection's packets also reach the master port)
            to_master = [(t, f) for t, p, f in got if p == MASTER.dev_port
                         and int.from_bytes(f[36:38], 'big') == vectors.CLIENT_PORT]
            extended = False
            if not any(same_frame(f, want_rsp, want_rsp) for _t, f in to_master):
                extended = True
                # The capture stops QUIET_S after the last frame, earlier than T's bounded response fallback: keep
                # observing until T has released or fallen back on a response, or WAIT_S passes (trace finding 2)
                end = time.monotonic() + WAIT_S
                while time.monotonic() < end:
                    seen = outcomes()
                    if seen['RESP_RELEASE'] + seen.get('RESP_FALLBACK', 0) > before['RESP_RELEASE'] + before.get('RESP_FALLBACK', 0):
                        got = got + capture(QUIET_S, QUIET_S)
                        break
                    got = got + capture(0.5, 0.5)
                to_master = [(t, f) for t, p, f in got if p == MASTER.dev_port
                             and int.from_bytes(f[36:38], 'big') == vectors.CLIENT_PORT]
            after, busy1 = outcomes(), busy()
            if rb.rp.TCP_TIMESTAMPS:
                report.add('%s_timestamp_options_delivery_order' % tag, True,
                           rb.rp.timestamp_order_ok([f for _t, f in to_master]))
            lane = {k: after[k] - before[k] for k in lane_keys}
            counts = [b - a for a, b in zip(busy0, busy1)]
            stimulus = (st['t_ack_sent'] - st['t_relayed']) if st.get('t_relayed') and st.get('t_ack_sent') else None
            delivered = (len(to_master) == 2 and same_frame(to_master[0][1], want_ack, ack)
                         and same_frame(to_master[1][1], want_rsp, want_rsp))
            # m6 (directive: suppress a duplicate while its original is held; after release a copy is loss
            # recovery): a duplicate copy may follow the timed original, never precede it, and must be identical.
            # The model's laps take milliseconds, so a copy sent during the wait can reach T after the release.
            copy_after_release = (milestone in ('m6', 'm7', 'm8', 'm9', 'm9d', 'm10') and (extra or {}).get('duplicate_sent') and len(to_master) == 3
                                  and same_frame(to_master[0][1], want_ack, ack)
                                  and all(same_frame(f, want_rsp, want_rsp) for _t, f in to_master[1:]))
            # a committed release found only by the extended capture is late: it must not pass (review W3)
            ok = ((delivered or copy_after_release) and lane == committed and counts[0] == 0 and counts[3] == 0
                  and not extended)
            readiness_first, readiness_evidence = False, None
            if not ready and lane == {'ACK_COMMIT': 1, 'RESP_RELEASE': 0, 'ACK_FALLBACK': 0, 'RESP_FALLBACK': 1}:
                # the units T was actually given (model_driver records every set_params write)
                units = json.loads((Path(os.environ['OUT']) / 't_params_written.json').read_text())[-1]['written']
                t0_u = scalar(m.register_read('p1.t_Ingress.t0_reg', 0, pipe=1))
                commit_u = scalar(m.register_read('p1.t_Ingress.ack_commit_at_reg', 0, pipe=1))
                readiness_first = rules.readiness_reached_before_release(t0_u, commit_u, units['gap'], units['readiness'])
                readiness_evidence = dict(t0_units=t0_u, a_commit_units=commit_u, gap_units=units['gap'],
                                          readiness_units=units['readiness'],
                                          commit_plus_gap_minus_t0=((commit_u - t0_u) & 0xffffffff) + units['gap'])
            row = dict(tag=tag, kind=kind, delivered_without_resend=delivered, lane=lane, count_busy_delta=counts,
                       request_to_ack_wall_s=round(stimulus, 4) if stimulus is not None else None,
                       extended_capture_used=extended,

                       clrt_wall_s=(to_master[1][0] - to_master[0][0]) if len(to_master) >= 2 else None,
                       frames_to_master=len(to_master), copy_after_release=bool(copy_after_release),
                       resp_dup_drop=after['RESP_DUP_DROP'] - before['RESP_DUP_DROP'],
                       frame_log=[(round(t - to_master[0][0], 4), len(f),
                                   'ack' if same_frame(f, want_ack, ack) else
                                   'response' if same_frame(f, want_rsp, want_rsp) else 'other')
                                  for t, f in to_master], **(extra or {}))
            if not any(same_frame(f, want_rsp, want_rsp) for _t, f in to_master) and sent_rsp is not None:
                # CLEANUP ONLY, after the verdict above: the outstation's TCP retransmission, so N's sequence
                # state admits the next RST (as model_control_timing's race case does); never acceptance evidence
                m.drain(ports)
                m.send(RELAY.dev_port, sent_rsp)
                late = capture(WAIT_S, QUIET_S)
                row['cleanup_retransmission_delivered'] = any(
                    p == MASTER.dev_port and same_frame(f, want_rsp, want_rsp) for _t, p, f in late)
            if ready:
                records = view.records_since(view.log_path(), st['response_log_offset'])
                records = [r for r in records if r['pipe'] == 1 and ('%08x' % c) in r['frame']]
                def stamp(action):
                    record = next((r for r in records if any(a.split('.')[-1] == action for a in r['actions'])), None)
                    return None if record is None or record['t_units'] is None else record['t_units'] & ~1
                arrivals = {name: stamp(action) for name, action in
                            (('held_ack_units', 'hold_ack'), ('response_arrival_units', 'admit_response'),
                             ('ack_release_units', 'release_ack_commit'),
                             ('response_release_units', 'release_response_counted'))}
                written = json.loads((Path(os.environ['OUT']) / 't_params_written.json').read_text())[-1]['written']
                def after(later, earlier):
                    return later is not None and earlier is not None and ((later - earlier) & 0xffffffff) < 1 << 31
                a, r = arrivals['ack_release_units'], arrivals['response_release_units']
                valid = after(a, arrivals['held_ack_units']) and after(a, arrivals['response_arrival_units']) and \
                    after(r, a) and ((r - a) & 0xffffffff) >= written['gap']
                row['response_ready_clock_proof'] = dict(arrivals, gap_units=written['gap'], passed=valid)
                # The original committed case owns this proof; keep the finite reset case schema unchanged.
                ok = ok and valid
            row['readiness_reached_before_release'] = readiness_first
            row['readiness_evidence'] = readiness_evidence
            points.append(row)
            if readiness_first is None:
                report.add('%s_readiness_registers_valid' % tag, True, False, **row)     # invalid read: never a pass
            elif readiness_first:
                # T's own registers show a_commit + gap at or beyond t0 + readiness in model time: the fallback is the
                # contract outcome and this point did not measure the committed path (failure analysis 2026-10-17)
                report.record['meta'].setdefault('committed_path_not_measured', []).append(tag)
                report.add('%s_delivered_once_by_readiness' % tag, True, delivered and counts[0] == 0
                           and counts[3] == 0, **row)
            else:
                report.add('%s_delivered_once_committed' % tag, True, ok, **row)
            if not ok and not (extra or {}).get('duplicate_sent'):
                # a fallback or a miss fails the point above; whether the original still reached the master exactly
                # once, after the ACK (bounded fallback, never a vanish or a double) is recorded as its own check
                labels = [label for _t, _n, label in row['frame_log']]
                report.add('%s_original_delivered_once' % tag, True,
                           labels.count('response') == 1 and 'ack' in labels
                           and labels.index('ack') < labels.index('response')
                           and counts[0] == counts[3] == counts[4] == 0
                           and lane['ACK_COMMIT'] + lane.get('ACK_FALLBACK', 0) == 1
                           and lane['RESP_RELEASE'] + lane.get('RESP_FALLBACK', 0) == 1)
            st['s'] += len(native)
            st['growth'] += rb.rp.growth(native, IMAGE_LEN)
            return ok

        def select_complete(tag, on_ms):
            app, ok = request('SELECT', 3, rb.crob(on_ms))
            got, native, ack, _rsp = respond('SELECT', app, bytes(2) + rb.crob(on_ms), 120)
            s, g, c = st['s'], st['growth'], st['c']
            image = encode61.ctl61(native)
            frames = [f for _t, p, f in got if p == MASTER.dev_port]
            expected = rb.rp.preserve_options(_rsp, vectors.packet(24, s + g, c, reverse=True, payload=image))
            report.add('%s_setup_SELECT_completed' % tag, True, ok and len(frames) == 2 and same_frame(
                frames[1], expected, _rsp))
            st['s'] += len(native)
            st['growth'] += rb.rp.growth(native, IMAGE_LEN)

        def settled(tag):
            """N's work cell must be idle (phase 4) before a point starts: the previous point's lifecycle, retries and
            close have finished (trace finding: settlement was assumed from fixed wall-time quiet intervals)."""
            try:
                cell = m.register_read('p0.n_Ingress.work.work', 0, pipe=0)
                phase = scalar({k: v for k, v in cell.items() if k.endswith('.phase')})
            except Exception as error:
                phase = 'unavailable: %s' % str(error)[:120]
            report.add('%s_work_cell_idle_at_start' % tag, 4, phase)

        def point(tag, kind, d_ms, during=None, send_response=True, retransmit_after_s=None, on_ms=200):
            settled(tag)
            st['tag'] = tag
            reconnect(tag)
            fc, objects, body = (1, rb.READ_OBJECTS, READ_BODY) if kind == 'READ' else \
                (3 if kind == 'SELECT' else 4, rb.crob(on_ms), bytes(2) + rb.crob(on_ms))
            if kind == 'OPERATE':
                select_complete(tag, on_ms)
            before, busy0 = outcomes(), busy()
            watch = kind == 'OPERATE' and during is None             # nothing relay-bound is sent in the response phase
            app, ok = request(kind, fc, objects, watch_later=watch)
            report.add('%s_request_relayed' % tag, True, ok)
            got, native, ack, sent_rsp = respond(kind, app, body, d_ms, during, send_response, keep_queued=watch)
            extra = {'d_ms': d_ms, 'sent_rsp': sent_rsp}
            if retransmit_after_s is not None:
                time.sleep(retransmit_after_s)
                m.send(RELAY.dev_port, sent_rsp)                     # the outstation's own retransmission
                got += capture(WAIT_S, QUIET_S)
                extra['outstation_retransmission'] = True
            if watch:
                watched = rules.classify_watch_frames(st.pop('queued') + got, RELAY.dev_port, st['request_sent'],
                                                      RELAY.port)
                if not watched['ok']:                      # times are read times, relative to the first relay
                    report.record['meta'].setdefault('request_relayed_again', []).append(dict(
                        watched, tag=tag, request_relayed_ok=ok, t_relayed=st['t_relayed']))
                report.add('%s_request_not_relayed_again' % tag,
                           'no copy of the request and no unclassified frame after the request capture',
                           'confirmed duplicates %d, unclassified %d' % (watched['confirmed_duplicates'],
                                                                         watched['unclassified']),
                           ok=watched['ok'], master_bound=watched['master_bound'])
            return got, native, ack, before, busy0, extra

        # ---- spacing sweep -------------------------------------------------------------------------------------
        for kind in ('READ', 'SELECT', 'OPERATE') if section_on('sweep') else ():
            for d in DELAYS_MS:
                tag = 'sweep_%s_%03dms' % (kind, d)
                got, native, ack, before, busy0, extra = point(tag, kind, d)
                judge(tag, kind, native, ack, got, before, busy0, extra, sent_rsp=extra.pop('sent_rsp'))
                rst(tag)

        # ---- duplicate response while the first waits ------------------------------------------------------------
        for kind in ('READ', 'SELECT') if section_on('dup') else ():
            tag = 'dup_%s' % kind
            got, native, ack, before, busy0, extra = point(
                tag, kind, 0, during=lambda rsp: m.send(RELAY.dev_port, rsp))
            extra['duplicate_sent'] = True
            judge(tag, kind, native, ack, got, before, busy0, extra, sent_rsp=extra.pop('sent_rsp'))
            rst(tag)

        # ---- a second, unconfigured connection's packets during the wait -----------------------------------------
        other = (vectors.CLIENT, vectors.SERVER, vectors.CLIENT_PORT + 1, vectors.SERVER_PORT)

        def other_connection(_rsp):
            # the same hosts on another client port: a tuple N has no connection row for
            for flags, seq, master in ((2, 777, True), (18, 4321, False), (16, 778, True)):
                m.send(MASTER.dev_port if master else RELAY.dev_port,
                       vectors.packet(flags, seq, 0 if flags == 2 else 1, reverse=not master,
                                      mss=1460 if flags in (2, 18) else None, tuple4=other))
        for kind in ('READ', 'SELECT') if section_on('second') else ():
            tag = 'second_connection_%s' % kind
            got, native, ack, before, busy0, extra = point(tag, kind, 0, during=other_connection)
            extra['second_connection_packets'] = 3
            judge(tag, kind, native, ack, got, before, busy0, extra, sent_rsp=extra.pop('sent_rsp'))
            rst(tag)

        # ---- master RST while the response waits: nothing may reach the master afterwards -------------------------
        for kind in ('READ', 'SELECT') if section_on('reset_wait') else ():
            tag = 'reset_during_wait_%s' % kind
            reconnect(tag)
            fc, objects, body = (1, rb.READ_OBJECTS, READ_BODY) if kind == 'READ' else (3, rb.crob(200), bytes(2) + rb.crob(200))
            before, busy0 = outcomes(), busy()
            app, ok = request(kind, fc, objects)
            c, s, g = st['c'], st['s'], st['growth']

            first_rst = {}

            def master_rst(_rsp, c=c, s=s, g=g):
                m.send(MASTER.dev_port, vectors.packet(20, c, s + g))
                seen = capture(0.6, 0.6)
                first_rst['relayed'] = any(p == RELAY.dev_port and rules.outstation_bound(f, RELAY.port) and f[47] & 0x04
                                            for _t, p, f in seen)
                first_rst['seen'] = seen
            got, native, ack, _rsp = respond(kind, app, body, 0, during=master_rst)
            got = first_rst['seen'] + got
            after, busy1 = outcomes(), busy()
            fwd_rst = vectors.packet(20, c, s)
            # the relay-bound RST copy that also leaves the master port in every m3/m4 run is exempt
            # (model_control_timing.py reset case); no ACK image or response may reach the master
            # TCP payload from the IP total length: frame length alone misclassifies a timestamp-bearing
            # pure ACK (sel751_ts: 66 bytes) as payload.
            payload_to_master = [f for _t, p, f in got if p == MASTER.dev_port and tcp_payload_len(f) > 0
                                 and not same_frame(f, fwd_rst, fwd_rst)]
            row = dict(tag=tag, kind=kind, frames_to_master=sum(1 for _t, p, _f in got if p == MASTER.dev_port),
                       master_frames=[f.hex() for _t, p, f in got if p == MASTER.dev_port],
                       payload_frames_to_master=len(payload_to_master),
                       lane={k: after[k] - before[k] for k in lane_keys},
                       count_busy_delta=[b - a for a, b in zip(busy0, busy1)])
            # Two outcomes are correct and the model's slow laps decide which happens: the response claimed the cell
            # before the RST's close pass (it was admitted first, so it is released once, committed, and nothing is
            # stale), or the RST closed the connection first (the waiting retry is refused: nothing reaches the
            # master). Anything else -- a copy after a refusal, two copies, a fallback release -- fails.
            image = encode61.read61(native) if kind == 'READ' else encode61.ctl61(native)
            lane = row['lane']
            admitted = (len(payload_to_master) == 1 and payload_to_master[0].endswith(image) and lane == committed
                        and (not retrying or row['count_busy_delta'][4] == 0))
            counts = row['count_busy_delta']
            flushed = False
            if retrying:
                # admitted: nothing exhausted or stale; refused: a counted stale drop, nothing busy-dropped or exhausted
                admitted = admitted and counts[3] == 0
                refused = (not payload_to_master and lane['RESP_RELEASE'] == 0 and lane.get('RESP_FALLBACK', 0) == 0
                           and counts[4] == 1 and counts[0] == 0 and counts[3] == 0)
                # m6 only: the response was admitted and still held when the RST took effect; T flushes it, so
                # nothing reaches the master and nothing is busy-dropped, exhausted or stale
                flushed = (milestone in ('m6', 'm7', 'm8', 'm9', 'm9d', 'm10') and not payload_to_master and lane['RESP_RELEASE'] == 0
                           and lane.get('RESP_FALLBACK', 0) == 0 and counts[0] == 0 and counts[3] == 0 and counts[4] == 0)
            else:
                refused = not payload_to_master and lane['RESP_RELEASE'] == 0 and lane.get('RESP_FALLBACK', 0) == 0
            row['outcome'] = ('admitted_before_reset' if admitted else 'refused_after_reset' if refused
                              else 'flushed_by_reset' if flushed else 'other')
            row['first_rst_relayed'] = first_rst.get('relayed')
            points.append(row)
            report.add('%s_known_outcome' % tag, True, admitted or refused or flushed, **row)
            # its own verdict: the master's single RST must take effect (relayed to the outstation). An RST that meets
            # an in-flight N lifecycle is refused by N's owner-state check (m4 behaviour); a real stack never repeats it
            # The master's RST acks only what it has (the pre-response sequence). Once N has admitted the response,
            # N refuses such an RST until the master acks the response -- m4 behaviour on the uncontended path too
            # (source probe: m4, response 6 laps after the ACK, RST 1..40 laps later: refused, owner stays 5). So:
            # refused_after_reset -> the RST must take effect; admitted_before_reset -> the m4 refusal is recorded
            # as the pre-existing limitation (DESIGN.md m5), not as an m5 verdict.
            if row['outcome'] == 'admitted_before_reset' and milestone not in ('m6', 'm7', 'm8', 'm9', 'm9d', 'm10'):
                report.record['meta'].setdefault('rst_refused_after_admitted_response', []).append(
                    dict(tag=tag, first_rst_relayed=bool(first_rst.get('relayed'))))
            else:
                report.add('%s_first_RST_relayed' % tag, True, bool(first_rst.get('relayed')))
            # CLEANUP ONLY: an RST that met an in-flight lifecycle is refused (m4 behaviour); close the connection
            # so the next case's same-tuple SYN is accepted. Not part of the verdict above.
            time.sleep(0.5)
            for visible in (0, len(image)):                 # master-visible ack before / after the 61-octet image
                m.send(MASTER.dev_port, vectors.packet(20, c, s + g + visible))
                capture(0.6, 0.3)

        # ---- the outstation aborts its connection (directive ba50eac69 section 2; completion gate 2) -------------
        # m8/m9 place an outstation RST that is exactly one held response ahead of E's frontier (49 READ, 37 control)
        # at the master's RCV.NXT (E outcome 16). Each kind runs two deterministic branches, decided by construction
        # and confirmed by counters:
        #   held:     the response carries the ACK (no standalone ACK), so T holds it until t0 + pb (1 s model); T
        #             holding it is confirmed (no response release or fallback yet), then the outstation RST is sent.
        #             Required: exactly one RST to the master at s+g, valid checksums, ACK = c; no response to the
        #             master, ever (capture extended until T resolves); E-16 +1; T released nothing and discarded
        #             the held response. The discard is counted as OLD_EPOCH_DROP: N's close runs T's close_epoch, so
        #             the held response fails T's epoch check and held_verdict's last row drops it (m9 T source;
        #             model_abort_m9_01_01 showed it; a flush counter is accepted too).
        #   OPERATE:  T anchors t0 when the command is admitted and holds the command for J (200 ms) >> D (1 ms), so
        #             the OPERATE response is due on arrival and is never held: the 'held' construction must
        #             observe the response released before the RST and then meet the released-branch requirements
        #             (model_abort_m9_01_01 showed exactly this). OPERATE abort while held is therefore not a reachable
        #             state of the supported profile, on the model or on silicon (J > D there too).
        #   released: standalone ACK, then the response; once the response has reached the master the RST follows
        #             at the new frontier. Required: one response, then one RST at s+g+61; E-16 unchanged.
        # Then the same tuple must reconnect. Negatives for the new exception (held, RST 48 or 50 octets ahead, and
        # 49/37 ahead with nothing held) are recorded with their outcome; the first two must not reset the master.
        # m6/m7 drop a held-ahead RST in E (characterization only). Review 2026-10-16 (m8_02/REVIEW_GAPS).
        e_counter = m.table('p0.r_Egress.outcome')

        def e_count(code):
            for op in ('Sync', 'SyncCounters'):
                try:
                    e_counter.operations_execute(m.target, op)
                    break
                except Exception:
                    pass
            for data, _k in e_counter.entry_get(m.target, [e_counter.make_key([gc.KeyTuple('$COUNTER_INDEX', code)])],
                                                {'from_hw': True}):
                v = data.to_dict()['$COUNTER_SPEC_PKTS']
                return sum(v) if isinstance(v, list) else v
            raise ValueError('E outcome cell %d unreadable' % code)

        def tcp_ok(f):
            """IPv4 header and TCP checksums of a received frame both verify."""
            ihl, total = (f[14] & 0x0f) * 4, int.from_bytes(f[16:18], 'big')
            seg = f[14 + ihl:14 + total]
            pseudo = f[26:34] + bytes((0, 6)) + len(seg).to_bytes(2, 'big')
            return vectors.checksum(f[14:14 + ihl]) == 0 and vectors.checksum(pseudo + seg) == 0

        E_RESET_FRONT = 16
        RELEASED = ('RESP_RELEASE',) if ready else ('RESP_RELEASE', 'RESP_FALLBACK')
        FLUSHED = ('HELD_STALE_FLUSH', 'HELD_OFF_FLUSH')

        def abort_case(kind, branch, offset=None):
            """offset: octets the outstation RST lies ahead of the frontier; None = exactly one held response."""
            tag = 'abort_%s_%s%s' % (branch, kind, '' if offset is None else '_plus%d' % offset)
            settled(tag)
            log = view.log_path()
            log0 = view.size(log)
            reconnect(tag)
            fc, objects, body = (1, rb.READ_OBJECTS, READ_BODY) if kind == 'READ' else \
                (3 if kind == 'SELECT' else 4, rb.crob(200), bytes(2) + rb.crob(200))
            if kind == 'OPERATE':
                select_complete(tag, 200)
            t0, e0 = outcomes(), e_count(E_RESET_FRONT)
            app, ok = request(kind, fc, objects)
            report.add('%s_request_relayed' % tag, True, ok)
            c, s, g = st['c'], st['s'], st['growth']
            native = st['seqs'].response(app, body, kind)
            image = encode61.read61(native) if kind == 'READ' else encode61.ctl61(native)
            sent_rsp = vectors.packet(24, s, c, reverse=True, payload=native)
            m.drain(ports)
            got = []
            if branch == 'released':
                m.send(RELAY.dev_port, vectors.packet(16, s, c, reverse=True))
                m.send(RELAY.dev_port, sent_rsp)
                got += capture(WAIT_S, QUIET_S)
                held_ok = None
            else:
                # the held construction needs the RST at T while T holds the response, before t0 + pb (1 s model).
                # Attempt 06: the response reached T 607 ms after t0, and a fixed 0.3 s capture plus the register
                # reads left the RST racing the pb release. Wait instead for T's admission of the response in the
                # model log (bounded by the old 0.3 s); frames meanwhile stay queued and are read by later captures
                pos = view.size(log)
                m.send(RELAY.dev_port, sent_rsp)
                if pos is not None:
                    admitted = view.wait_for(log, pos, r'Execute Action: t_Ingress\.admit_response\b', 0.3)[:2]
                    got += capture(0.02, 0.01)
                else:                                            # no log to observe: the old fixed wait
                    admitted = (None, None)
                    got += capture(0.3, 0.3)
                held_ok = None                                   # decided by the pre-send read below
            reference = rb.rp.abort_reference_len(kind)
            ahead = len(native) + (0 if offset is None else offset - reference)
            rst = vectors.packet(20, s + ahead, c, reverse=True)
            # the order evidence, read immediately before the send (code review: a release seen only afterwards may
            # have escaped after T applied the reset, inside the N-to-T propagation window)
            pre = {k: scalar(m.register_read('p1.t_Ingress.outcomes', out_indices[k], pipe=1)) for k in RELEASED}
            released_before_send = sum(pre[k] - t0[k] for k in RELEASED) > 0
            if branch != 'released':
                # T still held the response when the RST went out: admitted to T (seen in its log; code review H2: a
                # response reaching T only after the reset is dropped as old-epoch, which is not 'held, then
                # flushed') and not released before the send
                held_ok = admitted[0] is not None and not released_before_send
                if admitted[0] is None and (ready or kind != 'OPERATE') and offset is None:
                    # the held construction was not established (no admission observed): unmeasured, not a dataplane
                    # verdict (code review); model_summary blocks it as incomplete
                    report.record['meta'].setdefault('abort_held_not_established', []).append(tag)
            m.send(RELAY.dev_port, rst)
            end = time.monotonic() + WAIT_S
            while time.monotonic() < end and sum(outcomes()[k] - t0[k] for k in RELEASED + FLUSHED) == 0:
                got += capture(0.5, 0.5)
            got += capture(QUIET_S, QUIET_S)
            t1, e1 = outcomes(), e_count(E_RESET_FRONT)
            to_master = [f for _t, p, f in got if p == MASTER.dev_port
                         and int.from_bytes(f[36:38], 'big') == vectors.CLIENT_PORT]
            rst_frames = [f for f in to_master if f[47] & 0x04]
            responses = [f for f in to_master if f.endswith(image)]
            dt = {k: t1[k] - t0[k] for k in names if t1[k] != t0[k]}
            row = dict(tag=tag, kind=kind, branch=branch, offset=offset, request_relayed=ok, held_before_rst=held_ok,
                       held_wait=(None if branch == 'released' else dict(admit_seen=admitted[0] is not None,
                                                                          waited_s=admitted[1])),
                       resets_seq=[int.from_bytes(f[38:42], 'big') for f in rst_frames],
                       rst_ack=[int.from_bytes(f[42:46], 'big') for f in rst_frames],
                       rst_checksums_ok=[tcp_ok(f) for f in rst_frames], responses=len(responses),
                       frames_to_master=len(to_master), e_reset_front_delta=e1 - e0, t_deltas=dt,
                       expected_flushed=s + g, expected_released=s + g + len(image), expected_rst_ack=c)
            points.append(row)
            released = sum(dt.get(k, 0) for k in RELEASED)
            flushed = sum(dt.get(k, 0) for k in FLUSHED)
            good_rst = row['rst_ack'] == [c] and all(row['rst_checksums_ok'])
            if offset is not None:
                # negative controls: 48/50 must not reset the master; 49/37 with nothing held is recorded only.
                # v2 (response-ready) also requires the held original to survive once its genuine ACK arrives
                negatives = (reference - 1, reference + 1) if rb.rp.SEL751 else (48, 50)
                if offset in negatives:
                    report.add('%s_no_master_reset' % tag, True, ok and rst_frames == [] and e1 - e0 == 0, **row)
                    if ready:
                        # v2 retains the response until its genuine ACK, so survival needs that ACK: send it now and
                        # require the already-held original to reach the master once, a full D after the ACK. The
                        # response is never resent and no new request is made (the claim is about the original).
                        row['before_ack'] = {k: row[k] for k in ('responses', 'frames_to_master', 't_deltas',
                                                                  'e_reset_front_delta', 'resets_seq')}
                        ack = vectors.packet(16, s, c, reverse=True)
                        want_ack = rb.rp.preserve_options(ack, vectors.packet(16, s + g, c, reverse=True))
                        want_rsp = rb.rp.preserve_options(sent_rsp, vectors.packet(24, s + g, c, reverse=True,
                                                                                   payload=image))
                        m.send(RELAY.dev_port, ack)
                        late = capture(WAIT_S, QUIET_S)
                        end = time.monotonic() + WAIT_S
                        while time.monotonic() < end and sum(outcomes()[k] - t1[k] for k in RELEASED) == 0:
                            late += capture(0.5, 0.5)
                        late += capture(QUIET_S, QUIET_S)
                        t2, e2 = outcomes(), e_count(E_RESET_FRONT)
                        after_ack = [f for _t, p, f in late if p == MASTER.dev_port
                                     and int.from_bytes(f[36:38], 'big') == vectors.CLIENT_PORT]
                        records = [r for r in (view.records_since(log, pos) if pos is not None else [])
                                   if r['pipe'] == 1 and ('%08x' % c) in r['frame']]
                        written = json.loads((Path(os.environ['OUT']) / 't_params_written.json').read_text())[-1]
                        proof = rb.repeat_clock_proof(records, written['written']['gap'])
                        dt2 = {k: t2[k] - t0[k] for k in names if t2[k] != t0[k]}
                        # the post-completion row is the one model_summary._abort_negatives reads
                        row.update(responses=len(responses) + sum(f.endswith(image) for f in after_ack),
                                   frames_to_master=len(to_master) + len(after_ack), t_deltas=dt2,
                                   e_reset_front_delta=e2 - e0,
                                   resets_seq=row['resets_seq'] + [int.from_bytes(f[38:42], 'big')
                                                                    for f in after_ack if f[47] & 0x04],
                                   genuine_ack_sent=True, response_ready_clock_proof=proof,
                                   after_ack_frame_log=[(len(f), 'ack' if same_frame(f, want_ack, ack) else
                                                         'response' if same_frame(f, want_rsp, want_rsp) else
                                                         'other') for f in after_ack])
                        report.add('%s_held_original_survives_once' % tag, True, ok and rst_frames == [] and
                                   e1 - e0 == 0 and abort_survivor_verdict(held_ok, row['before_ack'], after_ack, ack,
                                                                           want_ack, want_rsp, dt2, e2 - e0, proof,
                                                                           same_frame), **row)
                else:
                    report.record['meta'].setdefault('abort_negative_characterization', []).append(row)
            elif milestone in ('m8', 'm9', 'm9d', 'm10'):
                order = rules.abort_branch_outcome(released_before_send, released > 0 and not released_before_send)
                row['order_before_send'] = order
                if order == 'inconclusive' and milestone == 'm10':
                    # the agreed contract (Philip, 2026-10-17): did the response pass T's release decision before or
                    # after T applied the matching reset? Host send time cannot decide; T's own passes in the model
                    # log can (model_log_view; the connection's T records carry the client sequence c)
                    decision = (view.connection_order(view.records_since(log, log0), '%08x' % c, released,
                                                      len(responses)) if log0 is not None else
                                dict(verdict='unattributed', reason='no model log'))
                    row['order_model_log'] = decision
                    order = rules.abort_log_order(decision)
                    row['order_decided'] = order
                if branch == 'held' and (ready or kind != 'OPERATE') and order == 'released':
                    # T had released the response before the RST was sent, or (order_decided) before T applied the
                    # reset: the released-branch outcome is the contract one (contention_rules.abort_branch_outcome,
                    # abort_log_order)
                    exact = (ok and row['resets_seq'] == [s + g + len(image)] and good_rst and len(responses) == 1
                             and e1 - e0 == 0 and released == 1)
                    # either way the held path (a held response flushed by the reset) was not measured: incomplete
                    report.record['meta'].setdefault('abort_released_before_reset' if row.get('order_decided')
                                                     else 'abort_released_before_send', []).append(tag)
                elif branch == 'held' and (ready or kind != 'OPERATE') and order == 'released_after_reset':
                    exact = False                       # a release after T applied the reset: a dataplane defect
                    report.record['meta'].setdefault('abort_release_after_reset', []).append(tag)
                elif branch == 'held' and (ready or kind != 'OPERATE') and order == 'inconclusive':
                    exact = False                       # neither the register read nor T's passes decide: fails
                    report.record['meta'].setdefault('abort_order_inconclusive', []).append(tag)
                elif branch == 'held' and (ready or kind != 'OPERATE'):
                    exact = (ok and held_ok and row['resets_seq'] == [s + g] and good_rst and not responses
                             and e1 - e0 == 1 and released == 0 and flushed + dt.get('OLD_EPOCH_DROP', 0) >= 1)
                else:
                    # released first (the 'released' branch, and OPERATE 'held' since J > D): only when the pre-send
                    # read shows the release; a release seen only after the send is inconclusive (code review A)
                    exact = (ok and row['resets_seq'] == [s + g + len(image)] and good_rst and len(responses) == 1
                             and e1 - e0 == 0 and released == 1 and order == 'released')
                    if order == 'inconclusive':
                        report.record['meta'].setdefault('abort_order_inconclusive', []).append(tag)
                    elif order == 'released_after_reset':
                        report.record['meta'].setdefault('abort_release_after_reset', []).append(tag)
                report.add('%s_master_reset_at_rcv_nxt' % tag, True, exact, **row)
            else:
                report.record['meta'].setdefault('outstation_abort_characterization', []).append(row)
            # close N with the master's own RST if the connection survived (no-op when it was reset), then the same
            # tuple must accept a fresh connection
            m.send(MASTER.dev_port, vectors.packet(20, c, s + g))
            capture(0.6, 0.3)
            st['s'] += len(native)
            st['growth'] += rb.rp.growth(native, IMAGE_LEN)

        if section_on('abort'):
            for kind in ('READ', 'SELECT', 'OPERATE'):
                abort_case(kind, 'held')
                abort_case(kind, 'released')
            for kind in ('READ', 'SELECT'):
                negative = rb.rp.abort_reference_len(kind)
                for offset in ((negative - 1, negative + 1) if rb.rp.SEL751 else (48, 50)):
                    abort_case(kind, 'held', offset=offset)
            abort_case('READ', 'released', offset=rb.rp.abort_reference_len('READ'))
            abort_case('SELECT', 'released', offset=rb.rp.abort_reference_len('SELECT'))
            # the tuple still works afterwards: one ordinary READ through T's committed path
            tag = 'abort_followed_by_READ'
            got, native, ack, before, busy0, extra = point(tag, 'READ', 0)
            judge(tag, 'READ', native, ack, got, before, busy0, extra, sent_rsp=extra.pop('sent_rsp'))
            rst(tag)

        # ---- m9d diagnostic build only: E's egress timestamps of master-bound ACK (lo) and response (hi) -------------
        # (generate.transform_e_diag). One committed exchange per kind; the entry at the master-visible ack[13:0] must
        # hold both halves, response after ACK, and the ACK/response frames the master saw must carry that ack.
        if section_on('egress_diag') and milestone == 'm9d':
            def diag_entry(index):
                raw = m.register_read('p0.r_Egress.diag_egress_ts', index, pipe=0)
                lo = scalar({k: v for k, v in raw.items() if k.endswith('.lo')})
                hi = scalar({k: v for k, v in raw.items() if k.endswith('.hi')})
                return lo, hi
            for kind in ('READ', 'SELECT', 'OPERATE'):
                tag = 'egress_diag_%s' % kind
                got, native, ack, before, busy0, extra = point(tag, kind, 0)
                judge(tag, kind, native, ack, got, before, busy0, extra, sent_rsp=extra.pop('sent_rsp'))
                to_master = [f for _t, p_, f in got if p_ == MASTER.dev_port
                             and int.from_bytes(f[36:38], 'big') == vectors.CLIENT_PORT]
                acks = sorted({int.from_bytes(f[42:46], 'big') for f in to_master})
                lo, hi = diag_entry(st['c'] & 0x3fff)
                gap = (hi - lo) & 0xffffffff
                row = dict(tag=tag, kind=kind, master_acks=acks, expected_ack=st['c'], index=st['c'] & 0x3fff,
                           lo=lo, hi=hi, switch_gap_ns=gap)
                points.append(row)
                # both halves written at the master-visible ack, response after the ACK (the model's clock between
                # two egress passes is not ASIC time, so no duration bound is applied here); judge() has already
                # advanced the connection state
                report.add('%s_entry_recorded' % tag, True,
                           acks == [st['c']] and lo != 0 and hi != 0 and 0 < gap < 0x80000000, **row)
                rst(tag)

        # ---- RST and same-tuple reconnect while the response waits ----------------------------------------------
        for kind in ('READ', 'SELECT') if section_on('reconnect') else ():
            tag = 'reconnect_during_wait_%s' % kind
            reconnect(tag)
            fc, objects, body = (1, rb.READ_OBJECTS, READ_BODY) if kind == 'READ' else (3, rb.crob(200), bytes(2) + rb.crob(200))
            before, busy0 = outcomes(), busy()
            app, ok = request(kind, fc, objects)
            c, s, g = st['c'], st['s'], st['growth']
            new = {}

            def rst_and_reconnect(_rsp, c=c, s=s, g=g):
                # RST at once, then the handshake as ordinary spaced exchanges (back-to-back handshake packets
                # are themselves busy-dropped on the slow model); every frame seen meanwhile is kept
                m.send(MASTER.dev_port, vectors.packet(20, c, s + g))
                seen = capture(0.6, 0.6)
                new['first_rst_relayed'] = any(p == RELAY.dev_port and rules.outstation_bound(f, RELAY.port) and f[47] & 0x04
                                               for _t, p, f in seen)
                new.setdefault('seen', []).extend(seen)
                # CLEANUP ONLY (after the verdict input above): close the connection if N refused the first RST
                # (both master-visible acks: before and after the 61-octet image)
                for visible in (0, img_len(kind)):
                    m.send(MASTER.dev_port, vectors.packet(20, c, s + g + visible))
                    new['seen'].extend(capture(0.4, 0.3))
                st['isn'] += 10000
                nc, ns = st['isn'], st['isn'] + 5000
                new['syn_t'] = time.monotonic()
                for port, pkt in ((MASTER.dev_port, vectors.packet(2, nc, mss=1460)),
                                  (RELAY.dev_port, vectors.packet(18, ns, nc + 1, reverse=True, mss=1460)),
                                  (MASTER.dev_port, vectors.packet(16, nc + 1, ns + 1))):
                    m.send(port, pkt)                    # no drain: a wrongly released old response must be seen
                    new.setdefault('seen', []).extend(capture(1.0, 0.15))
                new.update(c=nc + 1, s=ns + 1)
            got, native, _ack, old_rsp = respond(kind, app, body, 0, during=rst_and_reconnect)
            got = got + new.get('seen', [])
            image = encode61.read61(native) if kind == 'READ' else encode61.ctl61(native)
            old_to_master = [(t, f) for t, p, f in got if p == MASTER.dev_port and f.endswith(image)]
            # the old response may have been admitted before the RST (slow model laps: released once, before the new
            # connection exists); it must never reach the master once the same-tuple reconnect has begun, nor twice
            late = [t for t, _f in old_to_master if t >= new['syn_t']]
            if old_to_master and milestone not in ('m6', 'm7', 'm8', 'm9', 'm9d', 'm10'):
                # admitted before the RST: N refuses an RST that does not ack it (m4 behaviour; see the reset case)
                report.record['meta'].setdefault('rst_refused_after_admitted_response', []).append(
                    dict(tag=tag, first_rst_relayed=bool(new.get('first_rst_relayed'))))
            else:
                report.add('%s_first_RST_relayed' % tag, True, bool(new.get('first_rst_relayed')))
            report.add('%s_old_response_never_on_new_connection' % tag, True,
                       len(old_to_master) <= 1 and not late, old_copies=len(old_to_master), after_new_syn=len(late))
            # the new connection's READ completes exactly
            st.update(c=new['c'], s=new['s'], growth=0, seqs=rb.Sequences())
            before2, busy2 = outcomes(), busy()
            app2, ok2 = request('READ', 1, rb.READ_OBJECTS)
            report.add('%s_new_READ_request_relayed' % tag, True, ok2)
            got2, native2, ack2, r2 = respond('READ', app2, READ_BODY, 120)
            judge('%s_new_READ' % tag, 'READ', native2, ack2, got2, before2, busy2, sent_rsp=r2)
            points.append(dict(tag=tag, kind=kind, old_response_frames_to_master=len(old_to_master),
                               old_response_after_new_syn=len(late),
                               count_busy_delta=[b - a for a, b in zip(busy0, busy())]))
            rst(tag)

        # ---- m10: a master RST that passed stage 0 survives the response claiming N's cell before its stage 1 ------
        # (review of af7bd434, finding 1; code review of m10_03: no compiled case exercised the restart). The ACK
        # settles first (120 ms), so the RST's stage-0 pass finds the cell idle; the response follows at once and,
        # the model's laps being slow, claims the cell before the RST's stage-1 pass. count_busy[5] counts restarts.
        restart_by_kind = {}
        for kind in ('READ', 'SELECT') if milestone == 'm10' and section_on('restart') else ():
            tag = 'restart_%s' % kind
            reconnect(tag)
            fc, objects, body = (1, rb.READ_OBJECTS, READ_BODY) if kind == 'READ' else (3, rb.crob(200), bytes(2) + rb.crob(200))
            busy0, out0 = busy(), outcomes()
            app, ok = request(kind, fc, objects)
            c, s, g = st['c'], st['s'], st['growth']
            new = {}

            def rst_then_response(sent_rsp, c=c, s=s, g=g):
                m.send(MASTER.dev_port, vectors.packet(20, c, s + g))
                m.send(RELAY.dev_port, sent_rsp)
                seen = capture(1.0, 0.6)
                new['resets'] = [f for _t, p, f in seen if p == RELAY.dev_port and rules.outstation_bound(f, RELAY.port)
                                 and f[47] & 0x04]
                new['seen'] = seen
                if not new['resets']:            # CLEANUP ONLY, after the verdict input: close a refused connection
                    for visible in (0, img_len(kind)):
                        m.send(MASTER.dev_port, vectors.packet(20, c, s + g + visible))
                        capture(0.4, 0.3)
            got, native, _ack, _rsp = respond(kind, app, body, 120, during=rst_then_response, send_response=False)
            got = got + new.get('seen', [])
            image = encode61.read61(native) if kind == 'READ' else encode61.ctl61(native)
            leaked = [f for _t, p, f in got if p == MASTER.dev_port and f.endswith(image)]
            restarts = busy()[5] - busy0[5]
            out1 = outcomes()
            t_deltas = {k: out1[k] - out0[k] for k in names if out1[k] != out0[k]}
            restart_by_kind[kind] = restarts
            report.add('%s_first_RST_relayed_once' % tag, True, len(new.get('resets', [])) == 1,
                       relayed=len(new.get('resets', [])))
            # the ORIGINAL contract ("no response reaches the master") is recorded, not gated: Philip scoped it on
            # 2026-10-17 to T's reset-application pass, which reset_application_check.py judges from this run's model
            # log (run_model.py retains reset_application.json; model_summary v3 requires it). At most one copy.
            report.record['meta'].setdefault('original_contract_no_response', []).append(
                dict(tag=tag, copies=len(leaked)))
            report.add('%s_response_at_most_once' % tag, True, len(leaked) <= 1, copies=len(leaked))
            reconnect('%s_new' % tag)
            before2, busy2 = outcomes(), busy()
            app2, ok2 = request('READ', 1, rb.READ_OBJECTS)
            report.add('%s_new_READ_request_relayed' % tag, True, ok2)
            got2, native2, ack2, r2 = respond('READ', app2, READ_BODY, 120)
            judge('%s_new_READ' % tag, 'READ', native2, ack2, got2, before2, busy2, sent_rsp=r2)
            points.append(dict(tag=tag, kind=kind, restarts=restarts, relayed_resets=len(new.get('resets', [])),
                               response_copies_to_master=len(leaked), t_deltas=t_deltas,
                               count_busy_delta=[b - a for a, b in zip(busy0, busy())]))
            rst('%s_new' % tag)

        # the ordinary restart points above are recovery tests (RST, response, same-tuple reconnect, READ); whether
        # one also lands in the restart window is recorded (restart_by_kind) but not required. Restart coverage is
        # the targeted section below (Philip, 2026-10-17: not left to a run landing in the window by chance).
        report.record['meta']['ordinary_restart_by_kind'] = restart_by_kind

        # ---- m10 targeted restart coverage (harness fix 3, 2026-10-17) -----------------------------------------------
        # The restart precondition: the master RST's stage-0 pass (n_Ingress.first_close) finds N's cell idle, and the
        # response claims the cell before the RST's stage-1 pass (about 30 ms later on the model). Two host sends
        # about 25 ms apart decided this by chance (attempt 06, READ: the response reached N 11 ms after the stage-1
        # pass). Here the response is sent, from a socket opened beforehand, as soon as the model log shows the RST's
        # stage-0 pass. Each try is judged in full (RST relayed once, response at most once, and the revised reset
        # contract over this run's model log); a try exercises the path only if N's restart counter (count_busy[5])
        # advanced. At most RESTART_TRIES per kind, stopping at the first that does; every try is recorded.
        RESTART_TRIES = 3
        if milestone == 'm10' and section_on('restart_targeted'):
            import socket
            sys.path.insert(0, str(HERE.parents[2]))
            from model_driver import veth_for
            fast = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            fast.bind((veth_for(RELAY.dev_port), 0))
            # the RST too (diagnostic 03): Model.send opens a socket per call (~25 ms), long enough for the model to
            # run the RST's stage-0 pass before the wait began, leaving the response late for the window
            fast_master = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            fast_master.bind((veth_for(MASTER.dev_port), 0))
            log = view.log_path()
            for kind in ('READ', 'SELECT'):
                tries = []
                for n in range(1, RESTART_TRIES + 1):
                    tag = 'restart_targeted_%s_%d' % (kind, n)
                    settled(tag)
                    reconnect(tag)
                    fc, objects, body = (1, rb.READ_OBJECTS, READ_BODY) if kind == 'READ' else \
                        (3, rb.crob(200), bytes(2) + rb.crob(200))
                    busy0, out0 = busy(), outcomes()
                    app, ok = request(kind, fc, objects)
                    report.add('%s_request_relayed' % tag, True, ok)
                    c, s, g = st['c'], st['s'], st['growth']
                    native = st['seqs'].response(app, body, kind)
                    sent_rsp = vectors.packet(24, s, c, reverse=True, payload=native)
                    m.drain(ports)
                    m.send(RELAY.dev_port, vectors.packet(16, s, c, reverse=True))      # the ACK settles first
                    time.sleep(0.12)
                    # the trigger must be this RST's own stage-0 pass: wait for the model to go idle, take the offset,
                    # then require the RST's ingress on the wire port before the first_close line (diagnostic 02: a
                    # stale first_close from the previous cleanup RST fired three tries 0.8 ms after the send)
                    pos, idle = view.wait_idle(log) if log is not None else (None, None)
                    t_rst = time.monotonic()
                    fast_master.send(vectors.packet(20, c, s + g))
                    rst_send_s = time.monotonic() - t_rst
                    line, waited = None, None
                    if pos is not None:
                        ingress, waited_in, after = view.wait_for(log, pos, r'Ingress Pkt from port %d ' % MASTER.dev_port,
                                                                  2.0)
                        if ingress is not None:
                            line, waited_close, _end = view.wait_for(log, after,
                                                                     r'Execute Action: n_Ingress\.first_close\b', 2.0)
                            waited = waited_in + waited_close
                    fast.send(sent_rsp)
                    rsp_after_rst_s = time.monotonic() - t_rst
                    timeline('targeted_response_sent', tag=tag, stage0_seen=line is not None, waited_s=waited,
                             rst_send_s=rst_send_s, rsp_after_rst_s=rsp_after_rst_s)
                    seen = capture(1.0, 0.6)
                    seen += capture(WAIT_S, QUIET_S)
                    resets = [f for _t, p, f in seen if p == RELAY.dev_port and rules.outstation_bound(f, RELAY.port)
                              and f[47] & 0x04]
                    if not resets:               # CLEANUP ONLY, after the verdict input: close a refused connection
                        for visible in (0, img_len(kind)):
                            m.send(MASTER.dev_port, vectors.packet(20, c, s + g + visible))
                            capture(0.4, 0.3)
                    image = encode61.read61(native) if kind == 'READ' else encode61.ctl61(native)
                    leaked = [f for _t, p, f in seen if p == MASTER.dev_port and f.endswith(image)]
                    restarts = busy()[5] - busy0[5]
                    out1 = outcomes()
                    t_deltas = {k: out1[k] - out0[k] for k in names if out1[k] != out0[k]}
                    report.add('%s_first_RST_relayed_once' % tag, True, len(resets) == 1, relayed=len(resets))
                    report.add('%s_response_at_most_once' % tag, True, len(leaked) <= 1, copies=len(leaked))
                    report.record['meta'].setdefault('original_contract_no_response', []).append(
                        dict(tag=tag, copies=len(leaked)))
                    # recovery after this try (code review H1): the same tuple reconnects and a READ completes
                    reconnect('%s_new' % tag)
                    before2, busy2 = outcomes(), busy()
                    app2, ok2 = request('READ', 1, rb.READ_OBJECTS)
                    report.add('%s_new_READ_request_relayed' % tag, True, ok2)
                    got2, native2, ack2, r2 = respond('READ', app2, READ_BODY, 120)
                    judge('%s_new_READ' % tag, 'READ', native2, ack2, got2, before2, busy2, sent_rsp=r2)
                    rst('%s_new' % tag)
                    row = dict(tag=tag, kind=kind, restarts=restarts, relayed_resets=len(resets),
                               response_copies_to_master=len(leaked), t_deltas=t_deltas, stage0_seen=line is not None,
                               stage0_wait_s=waited, rst_send_s=rst_send_s, rsp_after_rst_s=rsp_after_rst_s,
                               log_idle_before_rst=idle, count_busy_delta=[b - a for a, b in zip(busy0, busy())])
                    points.append(row)
                    tries.append(row)
                    if restarts >= 1 and row['stage0_seen']:
                        break
                # a try exercises the path only if it was triggered by the observed stage-0 pass and N counted the
                # restart (code review L2)
                report.add('restart_targeted_%s_path_exercised' % kind, True,
                           any(t['restarts'] >= 1 and t['stage0_seen'] for t in tries),
                           tries=len(tries), restarts=[t['restarts'] for t in tries],
                           stage0_seen=[t['stage0_seen'] for t in tries])
            fast.close()
            fast_master.close()

        # ---- m6: a duplicate of a released response (loss beyond the switch) passes, with the same image ---------
        if milestone in ('m6', 'm7', 'm8', 'm9', 'm9d', 'm10') and section_on('post_release'):
            for kind in ('READ', 'SELECT'):
                tag = 'post_release_duplicate_%s' % kind
                got, native, ack, before, busy0, extra = point(tag, kind, 120)
                s0, g0, c0 = st['s'], st['growth'], st['c']
                sent_rsp = extra.pop('sent_rsp')
                ok = judge(tag, kind, native, ack, got, before, busy0, extra, sent_rsp=sent_rsp)
                image = encode61.read61(native) if kind == 'READ' else encode61.ctl61(native)
                want = vectors.packet(24, s0 + g0, c0, reverse=True, payload=image)
                gen0, before2, busy2 = scalar(m.register_read('p0.n_Ingress.counter', 0, pipe=0)), outcomes(), busy()
                m.drain(ports)
                m.send(RELAY.dev_port, sent_rsp)
                late = capture(WAIT_S, QUIET_S)
                copies = [f for _t, p, f in late if p == MASTER.dev_port and same_frame(f, want, want)]
                after2 = outcomes()
                row = dict(tag=tag + '_resend', copies_to_master=len(copies),
                           frames_to_master=sum(1 for _t, p, _f in late if p == MASTER.dev_port),
                           generation_delta=scalar(m.register_read('p0.n_Ingress.counter', 0, pipe=0)) - gen0,
                           lane={k: after2[k] - before2[k] for k in lane_keys},
                           count_busy_delta=[b - a for a, b in zip(busy2, busy())])
                points.append(row)
                # N's go_new allocates an N generation for the copy's lifecycle, as m5's forward_original path did
                # (recorded, not gated); T allocates nothing: no release, no fallback
                report.add('%s_resend_passes_once_same_image' % tag, True,
                           ok and len(copies) == 1 and row['frames_to_master'] == 1
                           and all(v == 0 for v in row['lane'].values())
                           and row['count_busy_delta'][0] == 0, **row)
                rst(tag)

        # ---- a lost response, recovered by the outstation's retransmission ----------------------------------------
        if section_on('loss'):
            tag = 'loss_recovery_READ'
            got, native, ack, before, busy0, extra = point(tag, 'READ', 0, send_response=False, retransmit_after_s=0.3)
            extra.pop('sent_rsp')
            s, g, c = st['s'], st['growth'], st['c']
            image = encode61.read61(native)
            to_master = [f for _t, p, f in got if p == MASTER.dev_port]
            rsp = [f for f in to_master if same_frame(f, vectors.packet(24, s + g, c, reverse=True, payload=image),
                                                      vectors.packet(24, s + g, c, reverse=True, payload=image))]
            after = outcomes()
            row = dict(tag=tag, kind='READ', responses_to_master=len(rsp), frames_to_master=len(to_master),
                       lane={k: after[k] - before[k] for k in lane_keys},
                       count_busy_delta=[b - a for a, b in zip(busy0, busy())])
            points.append(row)
            report.add('%s_exactly_one_response' % tag, 1, len(rsp), **row)
            st['s'] += len(native)
            st['growth'] += rb.rp.growth(native, IMAGE_LEN)
            rst(tag)
        report.record['meta']['final_outcomes'] = outcomes()
        report.record['meta']['final_count_busy'] = busy()
        report.record['meta']['n_generation_counter'] = scalar(m.register_read('p0.n_Ingress.counter', 0, pipe=0))
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / ('%s_results.json' % sections[0] if len(sections) == 1 else 'contention_results.json'))
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
