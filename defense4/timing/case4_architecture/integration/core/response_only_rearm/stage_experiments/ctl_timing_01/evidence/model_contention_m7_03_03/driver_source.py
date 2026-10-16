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
NAMES = ('UNMATCHED', 'HELD_REWAIT', 'ACK_COMMIT', 'RESP_RELEASE', 'RESP_DUP_DROP', 'OP_RELEASE', 'TOKEN_STALE',
         'HELD_STALE_FLUSH', 'ACK_FALLBACK', 'RESP_FALLBACK', 'TOKEN_TMO', 'HELD_OFF_FLUSH', 'TOKEN_OFF',
         'REQ_BYPASS', 'OLD_EPOCH_DROP', 'GEN_EXHAUSTED', 'OP_DUP_DROP')
OUT = {name: i for i, name in enumerate(NAMES)}
LANE = ('ACK_COMMIT', 'RESP_RELEASE', 'ACK_FALLBACK', 'RESP_FALLBACK')
COMMITTED = {'ACK_COMMIT': 1, 'RESP_RELEASE': 1, 'ACK_FALLBACK': 0, 'RESP_FALLBACK': 0}
DELAYS_MS = (0, 8, 15, 22, 30, 45, 60, 90, 120)
WAIT_S, QUIET_S = 8.0, 1.5     # > T's readiness fallback in wall time (about 3 s at ~6.8e8 model ns/s)
OP_HOLD_S = 0.9                # > J (200 ms model) in wall time
# TRACE_sweep_SELECT_000ms.md (m6_07): a point's verdict is T's own lane (commit and release required). Before m7, T's lane
# could be fooled by 32-bit readiness aliasing past 2^32 ns (_02); m7's clock moves that to 9.16 minutes. The request-
# to-ACK wall time is recorded only; model-time stimulus checks are read from the model log (trace_model_log.py).
READ_BODY = bytes((0x80, 0x00)) + rb.READ_OBJECTS + bytes(range(23))


def main():
    milestone = os.environ.get('MILESTONE', 'm4')
    bounded = milestone not in ('m1', 'm2')
    retrying = milestone in ('m5', 'm6', 'm7', 'm8')     # m5's retry form and counters; m6 changes N's reset/duplicate handling
    report = Report(os.environ['PROG'], physical=False,
                    scope='ctl_timing_01 %s: ACK/response contention for N\'s work cell (spacing sweep, edges)'
                    % milestone, driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    points = report.record['meta'].setdefault('points', [])
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
            return {k: scalar(m.register_read('p1.t_Ingress.outcomes', i, pipe=1)) for k, i in OUT.items()}

        cells = 8 if retrying else 4          # m5 grows count_busy to 8 (2 retry, 3 exhaustion, 4 stale)

        def busy():
            row = [scalar(m.register_read('p0.n_Ingress.count_busy', i, pipe=0)) for i in range(cells)]
            if retrying:                                # count_term[0]: retried duplicates aborted
                row.append(scalar(m.register_read('p0.n_Ingress.count_term', 0, pipe=0)))
            return row

        def capture(timeout, quiet):
            socks = {m._listen(p): p for p in ports}
            got, end, last = [], time.monotonic() + timeout, None
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
            return got

        def step(name, sent, expected, master=True):
            got = m.exchange(MASTER.dev_port if master else RELAY.dev_port, sent, ports, timeout=3, quiet=.15)
            flat = [frame for frames in got.values() for frame in frames]
            good = len(flat) == 1 and same_frame(flat[0], expected, sent)
            report.add(name, 'one exact frame', '%d frames' % len(flat), ok=good, received=got)
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

        def request(kind, fc, objects):
            """Send the request; OPERATE waits out J. Returns (app, request bytes)."""
            c, s, g = st['c'], st['s'], st['growth']
            req, app = st['seqs'].request(fc, objects)
            st['seqs'].next_app()
            sent, want = vectors.packet(24, c, s + g, payload=req), vectors.packet(24, c, s, payload=req)
            m.drain(ports)
            m.send(MASTER.dev_port, sent)
            got = capture(OP_HOLD_S * 3 if kind == 'OPERATE' else 1.0, OP_HOLD_S if kind == 'OPERATE' else 0.2)
            relayed = [f for _t, p, f in got if p == RELAY.dev_port]
            st['t_relayed'] = next((t for t, p, _f in got if p == RELAY.dev_port), None)
            ok = len(relayed) == 1 and same_frame(relayed[0], want, sent)
            if not ok:
                report.record['meta'].setdefault('request_not_relayed', []).append(
                    dict(kind=kind, relayed=len(relayed), frames=[(round(t, 4), p, len(f)) for t, p, f in got]))
            st['c'] += len(req)
            return app, ok

        def respond(kind, app, body, d_ms, during=None, send_response=True):
            """Standalone ACK, then the response d_ms later. during(st) runs after the response is sent (or
            in its place when send_response is False). Returns the frames seen and the native response."""
            c, s = st['c'], st['s']
            native = st['seqs'].response(app, body, kind)
            ack = vectors.packet(16, s, c, reverse=True)
            sent_rsp = vectors.packet(24, s, c, reverse=True, payload=native)
            m.drain(ports)
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
            want_ack = vectors.packet(16, s + g, c, reverse=True)
            want_rsp = vectors.packet(24, s + g, c, reverse=True, payload=image)
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
                    if seen['RESP_RELEASE'] + seen['RESP_FALLBACK'] > before['RESP_RELEASE'] + before['RESP_FALLBACK']:
                        got = got + capture(QUIET_S, QUIET_S)
                        break
                    got = got + capture(0.5, 0.5)
                to_master = [(t, f) for t, p, f in got if p == MASTER.dev_port
                             and int.from_bytes(f[36:38], 'big') == vectors.CLIENT_PORT]
            after, busy1 = outcomes(), busy()
            lane = {k: after[k] - before[k] for k in LANE}
            counts = [b - a for a, b in zip(busy0, busy1)]
            stimulus = (st['t_ack_sent'] - st['t_relayed']) if st.get('t_relayed') and st.get('t_ack_sent') else None
            delivered = (len(to_master) == 2 and same_frame(to_master[0][1], want_ack, ack)
                         and same_frame(to_master[1][1], want_rsp, want_rsp))
            # m6 (directive: suppress a duplicate while its original is held; after release a copy is loss
            # recovery): a duplicate copy may follow the timed original, never precede it, and must be identical.
            # The model's laps take milliseconds, so a copy sent during the wait can reach T after the release.
            copy_after_release = (milestone in ('m6', 'm7', 'm8') and (extra or {}).get('duplicate_sent') and len(to_master) == 3
                                  and same_frame(to_master[0][1], want_ack, ack)
                                  and all(same_frame(f, want_rsp, want_rsp) for _t, f in to_master[1:]))
            # a committed release found only by the extended capture is late: it must not pass (review W3)
            ok = ((delivered or copy_after_release) and lane == COMMITTED and counts[0] == 0 and counts[3] == 0
                  and not extended)
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
            points.append(row)
            report.add('%s_delivered_once_committed' % tag, True, ok, **row)
            if not ok and not (extra or {}).get('duplicate_sent'):
                # a fallback or a miss fails the point above; whether the original still reached the master exactly
                # once, after the ACK (bounded fallback, never a vanish or a double) is recorded as its own check
                labels = [label for _t, _n, label in row['frame_log']]
                report.add('%s_original_delivered_once' % tag, True,
                           labels.count('response') == 1 and 'ack' in labels
                           and labels.index('ack') < labels.index('response')
                           and counts[0] == counts[3] == counts[4] == 0
                           and lane['ACK_COMMIT'] + lane['ACK_FALLBACK'] == 1
                           and lane['RESP_RELEASE'] + lane['RESP_FALLBACK'] == 1)
            st['s'] += len(native)
            st['growth'] += IMAGE_LEN - len(native)
            return ok

        def select_complete(tag, on_ms):
            app, ok = request('SELECT', 3, rb.crob(on_ms))
            got, native, ack, _rsp = respond('SELECT', app, bytes(2) + rb.crob(on_ms), 120)
            s, g, c = st['s'], st['growth'], st['c']
            image = encode61.ctl61(native)
            frames = [f for _t, p, f in got if p == MASTER.dev_port]
            report.add('%s_setup_SELECT_completed' % tag, True, ok and len(frames) == 2 and same_frame(
                frames[1], vectors.packet(24, s + g, c, reverse=True, payload=image),
                vectors.packet(24, s + g, c, reverse=True, payload=image)))
            st['s'] += len(native)
            st['growth'] += IMAGE_LEN - len(native)

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
            app, ok = request(kind, fc, objects)
            report.add('%s_request_relayed' % tag, True, ok)
            got, native, ack, sent_rsp = respond(kind, app, body, d_ms, during, send_response)
            extra = {'d_ms': d_ms, 'sent_rsp': sent_rsp}
            if retransmit_after_s is not None:
                time.sleep(retransmit_after_s)
                m.send(RELAY.dev_port, sent_rsp)                     # the outstation's own retransmission
                got += capture(WAIT_S, QUIET_S)
                extra['outstation_retransmission'] = True
            return got, native, ack, before, busy0, extra

        # ---- spacing sweep -------------------------------------------------------------------------------------
        for kind in ('READ', 'SELECT', 'OPERATE'):
            for d in DELAYS_MS:
                tag = 'sweep_%s_%03dms' % (kind, d)
                got, native, ack, before, busy0, extra = point(tag, kind, d)
                judge(tag, kind, native, ack, got, before, busy0, extra, sent_rsp=extra.pop('sent_rsp'))
                rst(tag)

        # ---- duplicate response while the first waits ------------------------------------------------------------
        for kind in ('READ', 'SELECT'):
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
        for kind in ('READ', 'SELECT'):
            tag = 'second_connection_%s' % kind
            got, native, ack, before, busy0, extra = point(tag, kind, 0, during=other_connection)
            extra['second_connection_packets'] = 3
            judge(tag, kind, native, ack, got, before, busy0, extra, sent_rsp=extra.pop('sent_rsp'))
            rst(tag)

        # ---- master RST while the response waits: nothing may reach the master afterwards -------------------------
        for kind in ('READ', 'SELECT'):
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
                first_rst['relayed'] = any(p == RELAY.dev_port and f[47] & 0x04 for _t, p, f in seen)
                first_rst['seen'] = seen
            got, native, ack, _rsp = respond(kind, app, body, 0, during=master_rst)
            got = first_rst['seen'] + got
            after, busy1 = outcomes(), busy()
            fwd_rst = vectors.packet(20, c, s)
            # the relay-bound RST copy that also leaves the master port in every m3/m4 run is exempt
            # (model_control_timing.py reset case); no ACK image or response may reach the master
            payload_to_master = [f for _t, p, f in got if p == MASTER.dev_port and len(f) > 60
                                 and not same_frame(f, fwd_rst, fwd_rst)]
            row = dict(tag=tag, kind=kind, frames_to_master=sum(1 for _t, p, _f in got if p == MASTER.dev_port),
                       payload_frames_to_master=len(payload_to_master),
                       lane={k: after[k] - before[k] for k in LANE},
                       count_busy_delta=[b - a for a, b in zip(busy0, busy1)])
            # Two outcomes are correct and the model's slow laps decide which happens: the response claimed the cell
            # before the RST's close pass (it was admitted first, so it is released once, committed, and nothing is
            # stale), or the RST closed the connection first (the waiting retry is refused: nothing reaches the
            # master). Anything else -- a copy after a refusal, two copies, a fallback release -- fails.
            image = encode61.read61(native) if kind == 'READ' else encode61.ctl61(native)
            lane = row['lane']
            admitted = (len(payload_to_master) == 1 and payload_to_master[0].endswith(image) and lane == COMMITTED
                        and (not retrying or row['count_busy_delta'][4] == 0))
            counts = row['count_busy_delta']
            flushed = False
            if retrying:
                # admitted: nothing exhausted or stale; refused: a counted stale drop, nothing busy-dropped or exhausted
                admitted = admitted and counts[3] == 0
                refused = (not payload_to_master and lane['RESP_RELEASE'] == 0 and lane['RESP_FALLBACK'] == 0
                           and counts[4] == 1 and counts[0] == 0 and counts[3] == 0)
                # m6 only: the response was admitted and still held when the RST took effect; T flushes it, so
                # nothing reaches the master and nothing is busy-dropped, exhausted or stale
                flushed = (milestone in ('m6', 'm7', 'm8') and not payload_to_master and lane['RESP_RELEASE'] == 0
                           and lane['RESP_FALLBACK'] == 0 and counts[0] == 0 and counts[3] == 0 and counts[4] == 0)
            else:
                refused = not payload_to_master and lane['RESP_RELEASE'] == 0 and lane['RESP_FALLBACK'] == 0
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
            if row['outcome'] == 'admitted_before_reset' and milestone not in ('m6', 'm7', 'm8'):
                report.record['meta'].setdefault('rst_refused_after_admitted_response', []).append(
                    dict(tag=tag, first_rst_relayed=bool(first_rst.get('relayed'))))
            else:
                report.add('%s_first_RST_relayed' % tag, True, bool(first_rst.get('relayed')))
            # CLEANUP ONLY: an RST that met an in-flight lifecycle is refused (m4 behaviour); close the connection
            # so the next case's same-tuple SYN is accepted. Not part of the verdict above.
            time.sleep(0.5)
            for visible in (0, IMAGE_LEN):                 # master-visible ack before / after the 61-octet image
                m.send(MASTER.dev_port, vectors.packet(20, c, s + g + visible))
                capture(0.6, 0.3)

        # ---- RST and same-tuple reconnect while the response waits ----------------------------------------------
        for kind in ('READ', 'SELECT'):
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
                new['first_rst_relayed'] = any(p == RELAY.dev_port and f[47] & 0x04 for _t, p, f in seen)
                new.setdefault('seen', []).extend(seen)
                # CLEANUP ONLY (after the verdict input above): close the connection if N refused the first RST
                # (both master-visible acks: before and after the 61-octet image)
                for visible in (0, IMAGE_LEN):
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
            if old_to_master and milestone not in ('m6', 'm7', 'm8'):
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

        # ---- m6: a duplicate of a released response (loss beyond the switch) passes, with the same image ---------
        if milestone in ('m6', 'm7', 'm8'):
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
                           lane={k: after2[k] - before2[k] for k in LANE},
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
                   lane={k: after[k] - before[k] for k in LANE},
                   count_busy_delta=[b - a for a, b in zip(busy0, busy())])
        points.append(row)
        report.add('%s_exactly_one_response' % tag, 1, len(rsp), **row)
        st['s'] += len(native)
        st['growth'] += IMAGE_LEN - len(native)
        rst(tag)
        report.record['meta']['final_outcomes'] = outcomes()
        report.record['meta']['final_count_busy'] = busy()
        report.record['meta']['n_generation_counter'] = scalar(m.register_read('p0.n_Ingress.counter', 0, pipe=0))
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / 'contention_results.json')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
