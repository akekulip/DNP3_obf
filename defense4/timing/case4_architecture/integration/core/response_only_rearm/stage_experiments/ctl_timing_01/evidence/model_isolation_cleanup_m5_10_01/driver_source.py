"""C3 (directive ba50eac69): which connection and lane generation retire blockers as stale (T outcome 6,
OUT_TOKEN_STALE, counted by stop_blocking_stale) in the quiet-isolation workload, with normal traffic.

Runs inside launch_model.sh. Three same-tuple connections c1, c2, c3, each: handshake, one READ (separate ACK then
response), one SBO (SELECT, then OPERATE held J), then the master's RST. T's outcome counters are read before and after
each connection and after a quiet interval following each RST, so every outcome-6 increment falls in a named window.
The model log then attributes each stop_blocking_stale pass to its ladder role and generation (trace_model_log.py).
This is the normal-traffic control: no generator IPG change and no pre-READ pause. Frame builders and helpers are the
contention driver's.
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
OUT.update(RAW_OPERATE_TIMER_STALE=23, RAW_READ_TIMER_STALE=24)   # T outcomes cells the isolation checker reads
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
                    scope='ctl_timing_01 %s: blocker retirement by connection in the quiet-isolation workload (C3)'
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

        WINDOWS = report.record['meta'].setdefault('windows', [])
        QUIET_AFTER_RST_S = 3.0 * params['readiness'] / 1e9 * 1.5      # well past readiness in wall time

        def window(name, before):
            after = outcomes()
            WINDOWS.append(dict(window=name, delta={k: after[k] - before[k] for k in after if after[k] != before[k]},
                                cumulative_token_stale=after['TOKEN_STALE']))
            return after

        def operate(tag, on_ms):
            app, ok = request('OPERATE', 4, rb.crob(on_ms))
            report.add('%s_OPERATE_relayed' % tag, True, ok)
            got, native, _ack, _rsp = respond('OPERATE', app, bytes(2) + rb.crob(on_ms), 120)
            st['s'] += len(native)
            st['growth'] += IMAGE_LEN - len(native)
            frames = [f for _t, p, f in got if p == MASTER.dev_port]
            report.add('%s_OPERATE_ACK_then_response' % tag, 2, len(frames))

        def read(tag):
            app, ok = request('READ', 1, rb.READ_OBJECTS)
            report.add('%s_READ_relayed' % tag, True, ok)
            got, native, _ack, _rsp = respond('READ', app, READ_BODY, 120)
            st['s'] += len(native)
            st['growth'] += IMAGE_LEN - len(native)
            report.add('%s_READ_ACK_then_response' % tag, 2, len([f for _t, p, f in got if p == MASTER.dev_port]))

        last = outcomes()
        for conn in ('c1', 'c2', 'c3'):
            reconnect(conn)
            last = window('%s_handshake' % conn, last)
            read(conn)
            last = window('%s_READ' % conn, last)
            select_complete(conn, 200)
            last = window('%s_SELECT' % conn, last)
            operate(conn, 200)
            last = window('%s_OPERATE' % conn, last)
            rst(conn)
            last = window('%s_RST' % conn, last)
            time.sleep(QUIET_AFTER_RST_S)
            last = window('%s_quiet_after_RST' % conn, last)
        report.record['meta']['final_outcomes'] = outcomes()
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / 'isolation_cleanup_results.json')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
