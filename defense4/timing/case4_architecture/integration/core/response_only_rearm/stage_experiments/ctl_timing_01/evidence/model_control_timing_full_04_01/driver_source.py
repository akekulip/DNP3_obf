"""Compiled control-timing candidate (ctl_timing_01): what T holds and releases for READ, SELECT and OPERATE.

Runs inside launch_model.sh with T enabled (model-scale parameters: da 50 ms, gap 50 ms, readiness 400 ms,
op_j 200 ms). For each transaction it sends the request, the outstation's standalone ACK, then the response, and
timestamps every frame that leaves the switch (wall clock at the capture socket, model behaviour only):
  timed lane   the ACK is held until the response is seen, then released; the 61-octet response follows at
               least `gap` later and well before `readiness` (no fallback); ACK_COMMIT and RESP_RELEASE each +1
  untimed      the ACK and response leave without lane counters moving
MILESTONE=m1 expects READ and SELECT timed and OPERATE as in candidate61 (command hold only, CLRT untimed).
Also: T disabled passes everything through; a stray outstation ACK after the SELECT response (owner state 0xa)
is forwarded at once. Frame builders come from seg61_02/model_repeat.py.
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
spec.loader.exec_module(rb)
helpers, cp, vectors, scalar, encode61 = rb.helpers, rb.cp, rb.vectors, rb.scalar, rb.encode61
Model, Report, gc, same_frame = rb.Model, rb.Report, rb.gc, rb.same_frame
PM, MASTER, RELAY, IMAGE_LEN = rb.PM, rb.MASTER, rb.RELAY, rb.IMAGE_LEN
OUT = {'ACK_COMMIT': 2, 'RESP_RELEASE': 3, 'OP_RELEASE': 5, 'ACK_FALLBACK': 8, 'RESP_FALLBACK': 9}
GAP_S, READINESS_S, OP_J_S = 0.050, 0.400, 0.200


def main():
    milestone = os.environ.get('MILESTONE', 'm1')
    timed = {'READ': True, 'SELECT': milestone in ('m1', 'm2'), 'OPERATE': milestone == 'm2'}
    report = Report(os.environ['PROG'], physical=False,
                    scope='ctl_timing_01 %s: T hold/release per transaction (READ, SELECT, OPERATE)' % milestone,
                    driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
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
        params = dict(da=50_000_000, readiness=400_000_000, cap=16_000_000,
                      gap=50_000_000, op_j=200_000_000, budget=240_000, enabled=1)
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

        def gen():
            return scalar(m.register_read('p1.t_Ingress.gen_alloc_reg', 0, pipe=1))

        def timed_capture(timeout, quiet):
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
            good = len(flat) == (0 if expected is None else 1) and (expected is None or same_frame(flat[0], expected, sent))
            report.add(name, 'drop' if expected is None else 'one exact frame',
                       'drop' if not flat else '%d frames' % len(flat), ok=good, received=got,
                       want='' if expected is None else expected.hex())
            return good

        c, s, growth = 100, 900, 0
        syn = vectors.packet(2, c, mss=1460)
        step('SYN', syn, syn)
        synack = vectors.packet(18, s, c + 1, reverse=True, mss=1460)
        step('SYNACK', synack, synack, master=False)
        c, s = c + 1, s + 1
        step('final_ACK', vectors.packet(16, c, s), vectors.packet(16, c, s))
        seqs = rb.Sequences()
        read_body = bytes((0x80, 0x00)) + rb.READ_OBJECTS + bytes(range(23))

        def transaction(kind, fc, objects, body):
            """Request, standalone ACK, response; returns the response image for later checks."""
            nonlocal c, s, growth
            tag, is_timed = kind, timed[kind]
            before, gen_before = outcomes(), gen()
            request, app = seqs.request(fc, objects)
            seqs.next_app()
            sent_req = vectors.packet(24, c, s + growth, payload=request)
            want_req = vectors.packet(24, c, s, payload=request)
            if kind == 'OPERATE':                                       # command hold J, then relay
                m.drain(ports)
                t_sent = time.monotonic()
                m.send(MASTER.dev_port, sent_req)
                got = timed_capture(OP_J_S * 3, 0.15)
                arrivals = [(t, p, f) for t, p, f in got if p == RELAY.dev_port]
                report.add('%s_request_held_J_then_relayed' % tag, True,
                           len(arrivals) == 1 and same_frame(arrivals[0][2], want_req, sent_req)
                           and arrivals[0][0] - t_sent >= OP_J_S * 0.9,
                           delay_s=[round(t - t_sent, 4) for t, _p, _f in arrivals])
            else:
                step('%s_request' % tag, sent_req, want_req)
            c += len(request)
            report.add('%s_lane_generation' % tag, gen_before + (1 if is_timed else 0), gen())
            ack, want_ack = vectors.packet(16, s, c, reverse=True), vectors.packet(16, s + growth, c, reverse=True)
            m.drain(ports)
            m.send(RELAY.dev_port, ack)
            early = timed_capture(0.12, 0.05)
            if is_timed:
                report.add('%s_ACK_held_until_response' % tag, 0, len(early))
            else:
                report.add('%s_ACK_forwarded_at_once' % tag, True,
                           len(early) == 1 and same_frame(early[0][2], want_ack, ack))
            native = seqs.response(app, body, kind)
            image = encode61.read61(native) if kind == 'READ' else encode61.ctl61(native)
            sent_rsp = vectors.packet(24, s, c, reverse=True, payload=native)
            want_rsp = vectors.packet(24, s + growth, c, reverse=True, payload=image)
            m.drain(ports)
            t_sent = time.monotonic()
            m.send(RELAY.dev_port, sent_rsp)
            got = timed_capture(READINESS_S * 1.5, 0.2)
            frames = [(t, f) for t, p, f in got if p == MASTER.dev_port]
            if is_timed:
                ok = (len(frames) == 2 and same_frame(frames[0][1], want_ack, ack)
                      and same_frame(frames[1][1], want_rsp, sent_rsp))
                clrt = frames[1][0] - frames[0][0] if len(frames) == 2 else None
                report.add('%s_ACK_then_61_response' % tag, True, ok, frames=[f.hex() for _t, f in frames])
                report.add('%s_response_after_gap_before_readiness' % tag, True,
                           clrt is not None and GAP_S * 0.8 <= clrt and frames[1][0] - t_sent < READINESS_S * 0.9,
                           clrt_s=clrt, response_after_send_s=(frames[-1][0] - t_sent) if frames else None)
                after = outcomes()
                report.add('%s_counters' % tag, {'ACK_COMMIT': 1, 'RESP_RELEASE': 1, 'ACK_FALLBACK': 0, 'RESP_FALLBACK': 0},
                           {k: after[k] - before[k] for k in ('ACK_COMMIT', 'RESP_RELEASE', 'ACK_FALLBACK', 'RESP_FALLBACK')})
            else:
                report.add('%s_61_response_untimed' % tag, True,
                           len(frames) == 1 and same_frame(frames[0][1], want_rsp, sent_rsp),
                           frames=[f.hex() for _t, f in frames])
                after = outcomes()
                report.add('%s_no_lane_counters' % tag, {'ACK_COMMIT': 0, 'RESP_RELEASE': 0},
                           {k: after[k] - before[k] for k in ('ACK_COMMIT', 'RESP_RELEASE')})
            s += len(native)
            growth += IMAGE_LEN - len(native)

        def sbo(on_ms):
            transaction('SELECT', 3, rb.crob(on_ms), bytes(2) + rb.crob(on_ms))
            # a stray outstation ACK while waiting for the OPERATE (owner state 0xa) is forwarded at once
            stray = vectors.packet(16, s, c, reverse=True)
            step('stray_ACK_state_0xa_forwarded', stray, vectors.packet(16, s + growth, c, reverse=True), master=False)
            transaction('OPERATE', 4, rb.crob(on_ms), bytes(2) + rb.crob(on_ms))

        transaction('READ', 1, rb.READ_OBJECTS, read_body)
        sbo(100)
        transaction('READ', 1, rb.READ_OBJECTS, read_body)
        sbo(101)
        transaction('READ', 1, rb.READ_OBJECTS, read_body)
        report.record['meta']['final_outcomes'] = outcomes()
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / 'control_timing_results.json')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
