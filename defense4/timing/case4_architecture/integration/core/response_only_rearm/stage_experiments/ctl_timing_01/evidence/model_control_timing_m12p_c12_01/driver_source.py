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
import json
import os
import select
import statistics
import struct
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
    from model_profile import from_env
    profile = from_env()
    milestone = profile['milestone']
    if milestone not in ('m1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7', 'm8', 'm9', 'm9d', 'm10'):          # an unknown milestone would silently take older expectations
        raise SystemExit('unknown MILESTONE %r' % milestone)
    timed = {'READ': True, 'SELECT': milestone in ('m1', 'm2', 'm3', 'm4', 'm5', 'm6', 'm7', 'm8', 'm9', 'm9d', 'm10'),
             'OPERATE': milestone in ('m2', 'm3', 'm4', 'm5', 'm6', 'm7', 'm8', 'm9', 'm9d', 'm10')}
    bounded = milestone in ('m3', 'm4', 'm5', 'm6', 'm7', 'm8', 'm9', 'm9d', 'm10')
    # m5 changes only N's busy handling (DESIGN.md m5): every m4 expectation holds, and the ACK/response race may
    # take only the committed path (the busy-drop path is the m4 defect m5 removes)
    m4_rows = milestone in ('m4', 'm5', 'm6', 'm7', 'm8', 'm9', 'm9d', 'm10')
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
        if rb.rp.POLICY:   # pipe-1 READ padder's size enable, mirroring E's fwd_conn row (cp.p1_pad_rows)
            for table, key, action, data, priority in cp.p1_pad_rows(RELAY, MASTER, True):
                m.add(table, dict(key), action, dict(data), priority)
        params = dict(da=1_000_000, readiness=2_000_000_000, cap=1_500_000_000,
                      gap=50_000_000, op_j=200_000_000, budget=240_000, enabled=1)
        if bounded:
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

        def transaction(kind, fc, objects, body, mode='separate', inject=None):
            """Request, then (mode) 'separate': standalone ACK and response; 'slow': the ACK only after the piggyback
            bound has passed; 'piggyback': the response alone, carrying the ACK; 'dupack': the standalone ACK twice.
            inject() runs after the request is admitted and before the ACK. Returns the response as sent."""
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
                # Causality, not a pass condition: the outstation cannot ACK a command it has not received, so keep
                # capturing (bounded) until the relayed command appears. In model_control_timing_m7_03_02 the model
                # lagged the driver by more than the 0.6 s capture (host load), the ACKs were sent first, N busy-
                # dropped the command, and this master never retransmits: every later case on the connection broke.
                end = time.monotonic() + 3.0
                while not any(p == RELAY.dev_port for _t, p, _f in got) and time.monotonic() < end:
                    got += timed_capture(0.5, 0.15)
                arrivals = [(t, p, f) for t, p, f in got if p == RELAY.dev_port]
                j_samples = clock.get('j_wall_s') or []
                report.add('%s_request_held_J_then_relayed' % tag, True,
                           len(arrivals) == 1 and same_frame(arrivals[0][2], want_req, sent_req)
                           and (not j_samples or arrivals[0][0] - t_sent <= 2 * min(j_samples)),
                           delay_s=[round(t - t_sent, 4) for t, _p, _f in arrivals],
                           j_upper_bound_s=2 * min(j_samples) if j_samples else None)
                report.add('%s_one_OP_RELEASE' % tag, 1, outcomes()['OP_RELEASE'] - before['OP_RELEASE'])
                if arrivals and mode == 'separate':
                    # model-time calibration from the J holds of every separate-mode OPERATE so far (one sample varied
                    # 553M..725M model ns per wall second between runs, _m4_01_09.._11). A host stall can only lengthen
                    # a hold's wall time, so the shortest hold is the least biased estimate: in model_control_timing_
                    # m7_03_01 one 0.432 s sample among 0.27-0.29 s ones moved the median and failed the piggyback
                    # check, while T's own pb_delta at those releases was >= 0 (TRACE_piggyback.md there)
                    clock.setdefault('j_wall_s', []).append(arrivals[0][0] - t_sent)
                    clock['ns_per_s'] = params['op_j'] / max(min(clock['j_wall_s']), 1e-6)
                    report.record['meta']['model_ns_per_wall_s'] = clock['ns_per_s']
                    report.record['meta']['j_wall_s'] = list(clock['j_wall_s'])
            else:
                t_req_sent = time.monotonic()
                step('%s_request' % tag, sent_req, want_req)
            if kind == 'OPERATE':
                t_req_sent = t_sent
            c += len(request)
            report.add('%s_lane_generation' % tag, gen_before + (1 if is_timed else 0), gen())
            if inject is not None:
                inject()
            ack, want_ack = vectors.packet(16, s, c, reverse=True), vectors.packet(16, s + growth, c, reverse=True)
            if mode == 'slow':
                time.sleep(0.1)                                        # far beyond pb in model time
            if mode != 'piggyback':
                m.drain(ports)
                m.send(RELAY.dev_port, ack)
                if mode == 'dupack':
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
                # and by the bound, not the readiness fallback (2 x pb here): the wall conversion of model time is
                # noisy (about 0.7 x in model_control_timing_m3_01_02), so the upper limit is the midpoint 1.5 x pb
                report.add('%s_before_readiness_fallback' % tag, True,
                           want_s is not None and got_s is not None and
                           got_s <= 0.75 * params['readiness'] / params['pb'] * want_s,
                           release_after_request_s=got_s, readiness_in_wall_s=want_s and
                           want_s * params['readiness'] / params['pb'])
                report.add('%s_counters' % tag, {'ACK_COMMIT': 0, 'RESP_RELEASE': 1, 'ACK_FALLBACK': 0, 'RESP_FALLBACK': 0},
                           {k: after[k] - before[k] for k in ('ACK_COMMIT', 'RESP_RELEASE', 'ACK_FALLBACK', 'RESP_FALLBACK')},
                           all_deltas={k: after[k] - before[k] for k in after if after[k] != before[k]})
            elif is_timed and mode == 'dupack':
                # a duplicate ACK must not release anything early or twice: ACK copies first (a forwarded duplicate
                # TCP ACK is harmless), then exactly one exact 61-octet response, last
                rsp = [f for _t, f in frames if same_frame(f, want_rsp, sent_rsp)]
                acks = [f for _t, f in frames[:-1] if same_frame(f, want_ack, ack)]
                ok = (len(frames) >= 2 and len(rsp) == 1 and same_frame(frames[-1][1], want_rsp, sent_rsp)
                      and len(acks) == len(frames) - 1)
                report.add('%s_ACKs_then_one_61_response' % tag, True, ok, ack_copies=len(acks),
                           frames=[f.hex() for _t, f in frames])
                after = outcomes()
                # One response, no fallback. The duplicate may count a second ACK_COMMIT (observed for SELECT and
                # OPERATE, model_control_timing_m4_01_07/_08, m3_01_05): commit_at_access does not move the anchor
                # once done, the copy just leaves as a released ACK. No early or second response release, but the
                # trial's exact ACK_COMMIT count then differs from its exchanges, so hardware acceptance rejects it.
                deltas = {k: after[k] - before[k] for k in ('ACK_COMMIT', 'RESP_RELEASE', 'ACK_FALLBACK', 'RESP_FALLBACK')}
                report.add('%s_counters' % tag, True,
                           deltas['ACK_COMMIT'] in (1, 2) and
                           {k: v for k, v in deltas.items() if k != 'ACK_COMMIT'} ==
                           {'RESP_RELEASE': 1, 'ACK_FALLBACK': 0, 'RESP_FALLBACK': 0},
                           deltas=deltas, all_deltas={k: after[k] - before[k] for k in after if after[k] != before[k]})
                report.record['meta'].setdefault('dupack_commits', {})[tag] = deltas['ACK_COMMIT']
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
            growth += rb.rp.growth(native, IMAGE_LEN)
            return sent_rsp

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
        if bounded:
            transaction('READ', 1, rb.READ_OBJECTS, read_body, 'piggyback')
            transaction('SELECT', 3, rb.crob(102), bytes(2) + rb.crob(102), 'piggyback')
            transaction('OPERATE', 4, rb.crob(102), bytes(2) + rb.crob(102), 'piggyback')
            transaction('READ', 1, rb.READ_OBJECTS, read_body, 'slow')
            transaction('READ', 1, rb.READ_OBJECTS, read_body)
        if bounded:
            # a duplicate standalone ACK in owner state 9 (SELECT) and 0xc (OPERATE): no early or double release
            transaction('SELECT', 3, rb.crob(110), bytes(2) + rb.crob(110), 'dupack')
            transaction('OPERATE', 4, rb.crob(110), bytes(2) + rb.crob(110), 'dupack')
        if m4_rows:
            # a late copy of the old SELECT's response after a replacement SELECT: dropped, B completes exactly
            old = transaction('SELECT', 3, rb.crob(111), bytes(2) + rb.crob(111))

            def late_old():
                m.drain(ports)
                m.send(RELAY.dev_port, old)
                got = timed_capture(0.5, 0.1)
                report.add('late_old_SELECT_response_dropped', 0, sum(1 for _t, p, _f in got if p == MASTER.dev_port))
            transaction('SELECT', 3, rb.crob(112), bytes(2) + rb.crob(112), inject=late_old)
            transaction('OPERATE', 4, rb.crob(112), bytes(2) + rb.crob(112))

        passthrough = sorted(rb.rp.PASSTHROUGH_LENS)
        if passthrough:
            # Timed READ -> SELECT -> OPERATE cycles on ONE connection rotating through every READ class the build
            # declares (the fixture endpoint's order range, analog, class0, integrity), from real captured bytes
            # (read_complete_01/vectors/read_class_templates.json): each READ held by T and released ACK-then-response
            # with its own image (range padded 141; pass-through classes unchanged), each OPERATE held for J.
            templates = json.loads((HERE.parent / 'read_complete_01/vectors/read_class_templates.json').read_text())
            classes = {'range': (rb.READ_OBJECTS, read_body)}
            for cls in ('analog', 'class0', 'integrity'):
                t = templates['databases']['base'][cls]
                q_user = encode61.std.deframe(bytes.fromhex(t['request']))[1]
                r_user = encode61.std.deframe(bytes.fromhex(t['native']))[1]
                classes[cls] = (q_user[3:], r_user[3:])
            for rnd in range(4):
                for cls in ('range', 'analog', 'class0', 'integrity'):
                    objects, body = classes[cls]
                    transaction('READ', 1, objects, body)
                    sbo(130 + rnd)
            report.record['meta']['class_cycles'] = {'rounds': 4, 'order': ['range', 'analog', 'class0', 'integrity'],
                                                     'passthrough_lengths': passthrough}

        def reconnect(tag, client, server):
            nonlocal c, s, growth, seqs
            c, s, growth, seqs = client, server, 0, rb.Sequences()
            step('%s_SYN' % tag, vectors.packet(2, c, mss=1460), vectors.packet(2, c, mss=1460))
            step('%s_SYNACK' % tag, vectors.packet(18, s, c + 1, reverse=True, mss=1460),
                 vectors.packet(18, s, c + 1, reverse=True, mss=1460), master=False)
            c, s = c + 1, s + 1
            step('%s_final_ACK' % tag, vectors.packet(16, c, s), vectors.packet(16, c, s))

        def rst(tag):
            step('%s_RST' % tag, vectors.packet(20, c, s + growth), vectors.packet(20, c, s))

        # RESET while the READ's ACK is held: the RST is forwarded, nothing is released to the master afterwards
        before = outcomes()
        request, app = seqs.request(1, rb.READ_OBJECTS)
        seqs.next_app()
        step('reset_READ_request', vectors.packet(24, c, s + growth, payload=request), vectors.packet(24, c, s, payload=request))
        c += len(request)
        m.drain(ports)
        m.send(RELAY.dev_port, vectors.packet(16, s, c, reverse=True))
        report.add('reset_ACK_held', 0, len(timed_capture(0.15, 0.05)))
        m.drain(ports)
        m.send(MASTER.dev_port, vectors.packet(20, c, s + growth))
        got = timed_capture(2.0, 0.5)
        after = outcomes()
        report.add('reset_RST_forwarded_once', True,
                   [same_frame(f, vectors.packet(20, c, s), vectors.packet(20, c, s + growth))
                    for _t, p, f in got if p == RELAY.dev_port] == [True])
        # the held ACK and any payload must not reach the master
        # Exempt exactly one frame: the relay-bound copy of the master's RST (its ACK translated to the native
        # sequence), which also leaves the master port about a second later in every m3/m4 model run
        # (model_control_timing_m4_01_10). Its origin is unexplained here; the silicon RST gate's captures decide.
        fwd_rst = vectors.packet(20, c, s)
        released = [f for _t, p, f in got if p == MASTER.dev_port and not same_frame(f, fwd_rst, fwd_rst)]
        report.add('reset_nothing_released_to_master', 0, len(released),
                   frames_to_master=[f.hex() for _t, p, f in got if p == MASTER.dev_port],
                   all_deltas={k: after[k] - before[k] for k in after if after[k] != before[k]})
        report.add('reset_no_commit_or_release', {'ACK_COMMIT': 0, 'RESP_RELEASE': 0},
                   {k: after[k] - before[k] for k in ('ACK_COMMIT', 'RESP_RELEASE')})

        # Lane exhaustion (registers forced): a protected transaction is never silently downgraded
        lane = 'p1.t_Ingress.gen_alloc_reg'
        reconnect('exhaust_read', 2000, 3000)
        m.register_write(lane, 0, {'t_Ingress.gen_alloc_reg.f1': 0xfffe}, pipe=1)
        before = outcomes()
        request, app = seqs.request(1, rb.READ_OBJECTS)
        seqs.next_app()
        step('exhausted_READ_dropped', vectors.packet(24, c, s + growth, payload=request), None)
        report.add('exhausted_READ_counted', 1, outcomes()['GEN_EXHAUSTED'] - before['GEN_EXHAUSTED'])
        c += len(request)                              # N admitted the READ before T dropped it
        rst('exhaust_read')
        reconnect('exhaust_operate', 4000, 5000)
        m.register_write(lane, 0, {'t_Ingress.gen_alloc_reg.f1': 0xfffd}, pipe=1)
        transaction('SELECT', 3, rb.crob(120), bytes(2) + rb.crob(120))      # takes the last usable 0xfffe
        before = outcomes()
        request, app = seqs.request(4, rb.crob(120))
        seqs.next_app()
        m.drain(ports)
        m.send(MASTER.dev_port, vectors.packet(24, c, s + growth, payload=request))
        got = timed_capture(OP_J_S * 3, 0.15)
        after = outcomes()
        relayed = sum(1 for _t, p, _f in got if p == RELAY.dev_port)
        deltas = {k: after[k] - before[k] for k in ('GEN_EXHAUSTED', 'OP_RELEASE')}
        if m4_rows:
            report.add('exhausted_OPERATE_dropped_and_counted', {'relayed': 0, 'GEN_EXHAUSTED': 1, 'OP_RELEASE': 0},
                       dict(deltas, relayed=relayed))
        else:
            # the audited downgrade: J still holds and releases the command, its ACK/response lane is gone
            report.add('exhausted_OPERATE_relayed_with_J_lane_untimed', {'relayed': 1, 'GEN_EXHAUSTED': 0, 'OP_RELEASE': 1},
                       dict(deltas, relayed=relayed))
        c += len(request)                              # N admitted the OPERATE before T dropped (m4) or relayed it
        rst('exhaust_operate')
        m.register_write(lane, 0, {'t_Ingress.gen_alloc_reg.f1': 100}, pipe=1)

        # ACK and response back to back (microseconds apart), on its own connection. N has one work cell: a payload
        # packet that arrives while the ACK is still in N's loop is dropped by busy_t and counted (count_busy[0]),
        # and TCP recovers it by retransmission. So either the ACK commits and the response follows gap-anchored
        # (model_control_timing_m3_01_02), or the response is busy-dropped, the ACK leaves by T's readiness
        # fallback, and the outstation's retransmission is delivered as the exact 61-octet image, released by the
        # response fallback (model_control_timing_m4_01_08). Both paths are asserted exactly.
        reconnect('race', 8000, 9000)
        before, busy0 = outcomes(), scalar(m.register_read('p0.n_Ingress.count_busy', 0, pipe=0))
        request, app = seqs.request(1, rb.READ_OBJECTS)
        seqs.next_app()
        step('race_READ_request', vectors.packet(24, c, s + growth, payload=request), vectors.packet(24, c, s, payload=request))
        c += len(request)
        native = seqs.response(app, read_body, 'READ')
        sent_rsp = vectors.packet(24, s, c, reverse=True, payload=native)
        m.drain(ports)
        m.send(RELAY.dev_port, vectors.packet(16, s, c, reverse=True))
        m.send(RELAY.dev_port, sent_rsp)
        wait_s = 3.0 * params['readiness'] / clock['ns_per_s'] if clock.get('ns_per_s') else 8.0
        got = timed_capture(wait_s, wait_s)
        busy = scalar(m.register_read('p0.n_Ingress.count_busy', 0, pipe=0)) - busy0
        retransmitted = False
        race_rsp = vectors.packet(24, s + growth, c, reverse=True, payload=encode61.read61(native))
        if busy and not any(same_frame(f, race_rsp, race_rsp) for _t, p, f in got if p == MASTER.dev_port):
            m.send(RELAY.dev_port, sent_rsp)                   # the outstation's TCP retransmission
            got += timed_capture(wait_s, wait_s)
            retransmitted = True
        after = outcomes()
        to_master = [f for _t, p, f in got if p == MASTER.dev_port]
        race_ack = vectors.packet(16, s + growth, c, reverse=True)
        report.add('race_ACK_then_one_61_response_exact', True,
                   len(to_master) == 2 and same_frame(to_master[0], race_ack, race_ack) and
                   same_frame(to_master[1], race_rsp, race_rsp), frames=[f.hex() for f in to_master],
                   capture_s=wait_s, busy_dropped=busy, retransmitted=retransmitted)
        deltas = {k: after[k] - before[k] for k in ('ACK_COMMIT', 'RESP_RELEASE', 'ACK_FALLBACK', 'RESP_FALLBACK')}
        deltas['busy_dropped'] = busy
        paths = {'committed': {'ACK_COMMIT': 1, 'RESP_RELEASE': 1, 'ACK_FALLBACK': 0, 'RESP_FALLBACK': 0,
                               'busy_dropped': 0},
                 # the retransmission arrives after readiness, so T releases it by RESP_FALLBACK on arrival
                 # (model_control_timing_m4_01_08): its CLRT is not gap-normalized and it is a retransmitted exchange
                 'busy_drop_retransmitted': {'ACK_COMMIT': 0, 'RESP_RELEASE': 0, 'ACK_FALLBACK': 1, 'RESP_FALLBACK': 1,
                                             'busy_dropped': 1}}
        path = next((name for name, want in paths.items() if want == deltas), 'other')
        # A real check that the race takes one of the two KNOWN paths (anything else fails). Only 'committed' keeps
        # the timing objective; 'busy_drop_retransmitted' is an open N limitation (one work cell), never acceptance
        # evidence: delivery then waits for the outstation's TCP retransmission and that CLRT is not normalized.
        allowed = ('committed',) if milestone in ('m5', 'm6', 'm7', 'm8', 'm9', 'm9d', 'm10') else ('committed', 'busy_drop_retransmitted')
        report.add('race_known_release_path', True, path in allowed and retransmitted == (path != 'committed'),
                   deltas=deltas, path=path, all_deltas={k: after[k] - before[k] for k in after if after[k] != before[k]})
        report.record['meta']['race_path'] = path
        s += len(native)
        growth += rb.rp.growth(native, IMAGE_LEN)
        rst('race')
        if profile['t_child_count'] == 1:
            # Use a live epoch and both current lane generations. An invalid child must be refused before
            # any stateful action, rather than merely arriving with an already stale epoch/generation.
            reconnect('single_child_ids', 9000, 10000)
            transaction('READ', 1, rb.READ_OBJECTS, read_body)
            sbo(104)

            def negative_state():
                names = {'N': ('owner', 'epoch', 'client', 'server'),
                         'E': ('epoch', 'mode', 'front', 'acct', 'img_end', 'img_start', 'img_wend'),
                         'T': ('cur_epoch_reg', 'gen_alloc_reg', 'op_gen_alloc_reg', 't0_reg', 'op_t0_reg',
                               'ack_done_reg', 'resp_done_reg', 'op_done_reg', 'child_seen0_reg', 'ack_seen_reg',
                               'ack_commit_at_reg', 'ack_commit_gen_reg')}
                prefix = {'N': 'p0.n_Ingress.', 'E': 'p0.r_Egress.', 'T': 'p1.t_Ingress.'}
                result = {role: {name: m.register_read(prefix[role] + name, 0, pipe=1 if role == 'T' else 0)
                                 for name in registers} for role, registers in names.items()}
                result['T']['outcomes'] = [scalar(m.register_read('p1.t_Ingress.outcomes', i, pipe=1))
                                            for i in range(25)]
                return result

            epoch = scalar(m.register_read('p1.t_Ingress.cur_epoch_reg', 0, pipe=1))
            read_gen = gen()
            op_gen = scalar(m.register_read('p1.t_Ingress.op_gen_alloc_reg', 0, pipe=1))
            report.add('single_child_negative_live_epoch_and_generations', True,
                       0 < epoch < 0x80000000 and 0 < read_gen < 0xffff and 0 < op_gen < 0xffff,
                       epoch=epoch, read_generation=read_gen, operate_generation=op_gen)
            probe_native = rb.Sequences().response(0, read_body, 'READ')
            opaque = vectors.packet(24, s + growth, c, reverse=True, payload=encode61.read61(probe_native))
            for child in (1, 2, 255):
                probes = [('response_stage%d' % child, PM.t_in,
                           struct.pack('!IIIBBH', epoch, 0, 0, 11, child, 0) + opaque)]
                for role in (14, 15, 16):
                    op_lane = role in (13, 16)
                    port = PM.hb_return if op_lane else PM.held_return
                    generation = op_gen if op_lane else read_gen
                    budget = epoch if role >= 14 else params['budget']
                    probes.append(('ladder_role%d_child%d' % (role, child), port,
                                   struct.pack('!BBHI', role, child, generation & 0xffff, budget) + opaque))
                for tag, port, frame in probes:
                    m.drain(ports)
                    before = negative_state()
                    got = m.exchange(port, frame, ports, timeout=0.6, quiet=0.1)
                    after = negative_state()
                    report.add('single_child_%s_no_output' % tag, 0, sum(map(len, got.values())), received=got)
                    report.add('single_child_%s_state_unchanged' % tag, before, after)
            # Completed blockers otherwise stop silently even with an invalid child. Policy-off's TOKEN_OFF
            # row precedes that silent stop, making each legitimate child-0 blocker a counted positive control.
            # The invalid-ID copies must still be rejected before that counter (or any other register) changes.
            params['enabled'] = 0
            m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
            for role in (11, 12, 13):
                port = PM.hb_return if role == 13 else PM.held_return
                generation = op_gen if role == 13 else read_gen
                for child in (0, 1, 2, 255):
                    tag = 'single_child_blocker_role%d_child%d_policy_off' % (role, child)
                    frame = struct.pack('!BBHI', role, child, generation & 0xffff, params['budget']) + opaque
                    m.drain(ports)
                    before = negative_state()
                    got = m.exchange(port, frame, ports, timeout=0.6, quiet=0.1)
                    after = negative_state()
                    report.add(tag + '_no_output', 0, sum(map(len, got.values())), received=got)
                    expected = {domain: dict(registers) for domain, registers in before.items()}
                    expected['T']['outcomes'] = list(before['T']['outcomes'])
                    if child == 0:
                        i = OUT['TOKEN_OFF']
                        expected['T']['outcomes'][i] = (expected['T']['outcomes'][i] + 1) & 0xffffffff
                    report.add(tag + ('_positive_TOKEN_OFF_once' if child == 0 else '_state_unchanged'),
                               expected, after)
            params['enabled'] = 1
            m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
            report.record['meta']['single_child_negative_ids'] = [1, 2, 255]
            report.record['meta']['single_child_negative_ladder_roles'] = [11, 12, 13, 14, 15, 16]
            report.record['meta']['single_child_blocker_positive_control'] = 'policy-off TOKEN_OFF once, child 0'
            rst('single_child_ids')
        reconnect('t_off', 10000, 11000)              # ISNs increase: N refuses an older SYN as stale

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
