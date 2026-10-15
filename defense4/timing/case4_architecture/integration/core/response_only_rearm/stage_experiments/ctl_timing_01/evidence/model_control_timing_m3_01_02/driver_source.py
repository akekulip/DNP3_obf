"""Compiled control-timing candidate (ctl_timing_01): what T holds and releases for READ, SELECT and OPERATE.

Runs inside launch_model.sh with T enabled. The model's timestamp clock does not run at wall-clock rate (a
400 ms model readiness fired within about 0.1 s wall, run model_control_timing_full_04_01), so the gates are T's
own decisions, not wall time: readiness and cap are set near the 2^31 ns limit of T's signed deltas so the
fallback cannot fire, da is 1 ms and gap 50 ms (model time). For each transaction: request, the outstation's
standalone ACK, then the response.
  timed lane   the ACK is not released before the response is seen; then the ACK and the 61-octet response leave
               in that order; ACK_COMMIT and RESP_RELEASE each +1 and no fallback counter moves
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
NAMES = ('UNMATCHED', 'HELD_REWAIT', 'ACK_COMMIT', 'RESP_RELEASE', 'RESP_DUP_DROP', 'OP_RELEASE', 'TOKEN_STALE',
         'HELD_STALE_FLUSH', 'ACK_FALLBACK', 'RESP_FALLBACK', 'TOKEN_TMO', 'HELD_OFF_FLUSH', 'TOKEN_OFF',
         'REQ_BYPASS', 'OLD_EPOCH_DROP', 'GEN_EXHAUSTED', 'OP_DUP_DROP')
OUT = {name: i for i, name in enumerate(NAMES)}
OP_J_S = 0.200                                     # J in model ns; the model clock may run faster than wall


def main():
    milestone = os.environ.get('MILESTONE', 'm1')
    timed = {'READ': True, 'SELECT': milestone in ('m1', 'm2', 'm3'), 'OPERATE': milestone in ('m2', 'm3')}
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
        params = dict(da=1_000_000, readiness=2_000_000_000, cap=1_500_000_000,
                      gap=50_000_000, op_j=200_000_000, budget=240_000, enabled=1)
        if milestone == 'm3':
            params['pb'] = 1_000_000_000                               # op_j < pb < readiness, model ns
        clock = {}                                                     # model ns per wall second, from the J hold
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

        def transaction(kind, fc, objects, body, mode='separate'):
            """Request, then (mode) 'separate': standalone ACK and response; 'slow': the ACK only after the piggyback
            bound has passed; 'piggyback': the response alone, carrying the ACK."""
            nonlocal c, s, growth
            tag, is_timed = kind if mode == 'separate' else '%s_%s' % (kind, mode), timed[kind]
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
                           len(arrivals) == 1 and same_frame(arrivals[0][2], want_req, sent_req),
                           delay_s=[round(t - t_sent, 4) for t, _p, _f in arrivals])
                report.add('%s_one_OP_RELEASE' % tag, 1, outcomes()['OP_RELEASE'] - before['OP_RELEASE'])
                if arrivals and 'ns_per_s' not in clock:
                    clock['ns_per_s'] = params['op_j'] / max(arrivals[0][0] - t_sent, 1e-6)
                    report.record['meta']['model_ns_per_wall_s'] = clock['ns_per_s']
            else:
                t_req_sent = time.monotonic()
                step('%s_request' % tag, sent_req, want_req)
            if kind == 'OPERATE':
                t_req_sent = t_sent
            c += len(request)
            report.add('%s_lane_generation' % tag, gen_before + (1 if is_timed else 0), gen())
            ack, want_ack = vectors.packet(16, s, c, reverse=True), vectors.packet(16, s + growth, c, reverse=True)
            if mode == 'slow':
                time.sleep(0.1)                                        # far beyond pb in model time
            if mode != 'piggyback':
                m.drain(ports)
                m.send(RELAY.dev_port, ack)
                early = timed_capture(0.15, 0.05)
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
            got = timed_capture(3.0, 0.3)
            frames = [(t, f) for t, p, f in got if p == MASTER.dev_port]
            if mode == 'piggyback':
                after = outcomes()
                report.add('%s_released_by_bound' % tag, True,
                           len(frames) == 1 and same_frame(frames[0][1], want_rsp, sent_rsp), frames=[f.hex() for _t, f in frames])
                # not before t0 + pb: compare the release delay with pb converted by the measured model clock
                want_s = params['pb'] / clock['ns_per_s'] if clock.get('ns_per_s') else None
                got_s = frames[0][0] - t_req_sent if frames else None
                report.add('%s_not_before_t0_plus_pb' % tag, True,
                           want_s is not None and got_s is not None and got_s >= 0.6 * want_s,
                           release_after_request_s=got_s, pb_in_wall_s=want_s)
                report.add('%s_counters' % tag, {'ACK_COMMIT': 0, 'RESP_RELEASE': 1, 'ACK_FALLBACK': 0, 'RESP_FALLBACK': 0},
                           {k: after[k] - before[k] for k in ('ACK_COMMIT', 'RESP_RELEASE', 'ACK_FALLBACK', 'RESP_FALLBACK')},
                           all_deltas={k: after[k] - before[k] for k in after if after[k] != before[k]})
            elif is_timed:
                ok = (len(frames) == 2 and same_frame(frames[0][1], want_ack, ack)
                      and same_frame(frames[1][1], want_rsp, sent_rsp))
                clrt = frames[1][0] - frames[0][0] if len(frames) == 2 else None
                report.add('%s_ACK_then_61_response' % tag, True, ok, frames=[f.hex() for _t, f in frames])
                report.record['meta'].setdefault('wall_clrt_s', {}).setdefault(tag, []).append(clrt)
                after = outcomes()
                report.add('%s_counters' % tag, {'ACK_COMMIT': 1, 'RESP_RELEASE': 1, 'ACK_FALLBACK': 0, 'RESP_FALLBACK': 0},
                           {k: after[k] - before[k] for k in ('ACK_COMMIT', 'RESP_RELEASE', 'ACK_FALLBACK', 'RESP_FALLBACK')},
                           all_deltas={k: after[k] - before[k] for k in after if after[k] != before[k]})
            else:
                report.add('%s_61_response_untimed' % tag, True,
                           len(frames) == 1 and same_frame(frames[0][1], want_rsp, sent_rsp),
                           frames=[f.hex() for _t, f in frames])
                after = outcomes()
                report.add('%s_no_lane_counters' % tag, {'ACK_COMMIT': 0, 'RESP_RELEASE': 0},
                           {k: after[k] - before[k] for k in ('ACK_COMMIT', 'RESP_RELEASE')},
                           all_deltas={k: after[k] - before[k] for k in after if after[k] != before[k]})
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
        # ACK and response back to back (microseconds apart): characterized, not asserted (design review case 5)
        before = outcomes()
        request, app = seqs.request(1, rb.READ_OBJECTS)
        seqs.next_app()
        step('race_READ_request', vectors.packet(24, c, s + growth, payload=request), vectors.packet(24, c, s, payload=request))
        c += len(request)
        native = seqs.response(app, read_body, 'READ')
        m.drain(ports)
        m.send(RELAY.dev_port, vectors.packet(16, s, c, reverse=True))
        m.send(RELAY.dev_port, vectors.packet(24, s, c, reverse=True, payload=native))
        got = timed_capture(3.0, 0.3)
        after = outcomes()
        report.add('race_ACK_and_response_back_to_back_characterized', True, True,
                   frames_to_master=sum(1 for _t, p, _f in got if p == MASTER.dev_port),
                   deltas={k: after[k] - before[k] for k in after if after[k] != before[k]})
        s += len(native)
        growth += IMAGE_LEN - len(native)
        if milestone == 'm3':
            transaction('READ', 1, rb.READ_OBJECTS, read_body, 'piggyback')
            transaction('SELECT', 3, rb.crob(102), bytes(2) + rb.crob(102), 'piggyback')
            transaction('OPERATE', 4, rb.crob(102), bytes(2) + rb.crob(102), 'piggyback')
            transaction('READ', 1, rb.READ_OBJECTS, read_body, 'slow')
            transaction('READ', 1, rb.READ_OBJECTS, read_body)
        # T disabled: everything passes through untimed and no lane state moves
        params['enabled'] = 0
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        for kind in ('READ', 'SELECT', 'OPERATE'):
            timed[kind] = False
        before_gen = gen()
        transaction('READ', 1, rb.READ_OBJECTS, read_body)
        transaction('SELECT', 3, rb.crob(103), bytes(2) + rb.crob(103))
        report.add('T_off_no_lane_generation', before_gen, gen())
        report.record['meta']['final_outcomes'] = outcomes()
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / 'control_timing_results.json')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
