"""ctl_timing m4: selection lifecycle under IEEE 1815-2012 section 4.4.4.3 Rule 4 / Table 4-9, compiled model.

Runs twice on fresh connections, first with T disabled (N authority only), then with T enabled (lane
generations and OPERATE releases counted). Each phase asserts, with exact frames:
  cancel        READ, SELECT, then a READ: the READ is forwarded unchanged and answered with the 61-octet image
                (the selection is terminated; no OPERATE release, one lane generation for the READ when timed)
  new_sbo       after the cancel, a complete SELECT/OPERATE succeeds (one OPERATE release when timed)
  replace       SELECT A, then SELECT B with a new sequence number and different octets, then OPERATE B
  retry         SELECT C, then the identical SELECT again (same application sequence, new transport segment),
                the outstation repeats its response, then OPERATE C
  stale_operate SELECT D, READ (cancels), then the old OPERATE D: dropped, no OPERATE release, no OPERATE
                generation; the connection is then retired with RST and a new SYN is admitted
The stale OPERATE ends its connection because a dropped request leaves its TCP sequence slot outstanding.
Model behavior only, not host timing or ASIC evidence.
"""
import hashlib
import importlib.util
import json
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('_repeat_builders', HERE.parent / 'seg61_02/model_repeat.py')
rep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rep)
helpers, cp, encode61 = rep.helpers, rep.cp, rep.encode61
Model, Report, gc, same_frame, vectors, scalar = (rep.Model, rep.Report, rep.gc, rep.same_frame, rep.vectors,
                                                  rep.scalar)
PM, MASTER, RELAY, IMAGE_LEN = rep.PM, rep.MASTER, rep.RELAY, rep.IMAGE_LEN
Sequences, crob, READ_OBJECTS = rep.Sequences, rep.crob, rep.READ_OBJECTS
PB = int(os.environ.get('CTL_PB', '300000000'))


def main():
    from model_profile import from_env
    profile = from_env()
    ready = profile.get('timing_contract') == 'response_ready_ack_d_v2'
    if ready:
        import model_log_view as view
        log_path = view.log_path()
    report = Report(os.environ['PROG'], physical=False,
                    scope='ctl_timing m4 compiled: Table 4-9 selection cancellation, replacement, retry and stale '
                          'OPERATE, T disabled then enabled',
                    driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    rep.rp.report_endpoint(report)
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
        if rep.rp.POLICY:   # pipe-1 READ padder's size enable, mirroring E's fwd_conn row (cp.p1_pad_rows)
            for table, key, action, data, priority in cp.p1_pad_rows(RELAY, MASTER, True):
                m.add(table, dict(key), action, dict(data), priority)
        params = dict(da=50_000_000, readiness=400_000_000, cap=16_000_000, gap=50_000_000, op_j=200_000_000,
                      budget=240_000, enabled=0, pb=PB)
        if ready:
            params = dict(gap=5_000_000, op_j=2_400_000, budget=240_000, enabled=0)
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        mirror = m.table('$mirror.cfg', raw=True)
        mirror.entry_add(gc.Target(device_id=0, pipe_id=0xffff),
                         [mirror.make_key([gc.KeyTuple('$sid', 7)])],
                         [mirror.make_data([gc.DataTuple('$direction', str_val='INGRESS'),
                                            gc.DataTuple('$ucast_egress_port', helpers.PKTGEN_RETURN),
                                            gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                            gc.DataTuple('$session_enable', bool_val=True)], '$normal')])

        def t_reg(name):
            return scalar(m.register_read('p1.t_Ingress.' + name, 0, pipe=1))

        def outcome(index):
            return scalar(m.register_read('p1.t_Ingress.outcomes', index, pipe=1))

        def owner():
            return scalar(m.register_read('p0.n_Ingress.owner', 0, pipe=0)) >> 16

        def step(name, sent, expected, master=True):
            expected = rep.rp.preserve_options(sent, expected)
            rep.rp.advance_timestamp()
            got = m.exchange(MASTER.dev_port if master else RELAY.dev_port, sent, ports, timeout=3, quiet=.15)
            flat = [frame for frames in got.values() for frame in frames]
            good = len(flat) == (0 if expected is None else 1)
            if good and expected is not None:
                good = same_frame(flat[0], expected, sent)
            report.add(name, 'drop' if expected is None else 'one exact frame',
                       'drop' if not flat else '%d frames' % len(flat), ok=good,
                       received=got, want='' if expected is None else expected.hex())
            return good

        state = {}

        def connect(tag, client, server):
            state.update(c=client, s=server, growth=0, seqs=Sequences())
            c, s = client, server
            syn = vectors.packet(2, c, mss=1460)
            step('%s_SYN' % tag, syn, syn)
            synack = vectors.packet(18, s, c + 1, reverse=True, mss=1460)
            step('%s_SYNACK' % tag, synack, synack, master=False)
            state.update(c=c + 1, s=s + 1)
            step('%s_final_ACK' % tag, vectors.packet(16, c + 1, s + 1), vectors.packet(16, c + 1, s + 1))

        def request(tag, kind, fc, objects, advance_app=True):
            seqs = state['seqs']
            frame, app = seqs.request(fc, objects)
            if advance_app:
                seqs.next_app()
            c, s, growth = state['c'], state['s'], state['growth']
            step('%s_%s_request' % (tag, kind), vectors.packet(24, c, s + growth, payload=frame),
                 vectors.packet(24, c, s, payload=frame))
            state['c'] = c + len(frame)
            return app

        def respond(tag, kind, app, body, separate_ack):
            seqs, c, s, growth = state['seqs'], state['c'], state['s'], state['growth']
            if separate_ack and not (ready and params['enabled']):
                step('%s_%s_server_ACK' % (tag, kind), vectors.packet(16, s, c, reverse=True),
                     vectors.packet(16, s + growth, c, reverse=True), master=False)
            native = seqs.response(app, body, kind)
            image = encode61.read61(native) if kind == 'READ' else encode61.ctl61(native)
            response = vectors.packet(24, s, c, reverse=True, payload=native)
            expected_response = vectors.packet(24, s + growth, c, reverse=True, payload=image)
            if ready and params['enabled']:
                ack = vectors.packet(16, s, c, reverse=True)
                expected_ack = rep.rp.preserve_options(ack, vectors.packet(16, s + growth, c, reverse=True))
                expected_response = rep.rp.preserve_options(response, expected_response)
                offset = view.size(log_path)
                got, exact = rep.response_ready_pair(m, ports, RELAY.dev_port, ack, response,
                                                     expected_ack, expected_response, same_frame)
                label = '%s_%s' % (tag, kind)
                report.add(label + '_genuine_ACK_and_complete_response', 'exact ACK then whole response',
                           sum(map(len, got.values())), ok=exact, received=got)
                records = view.records_since(log_path, offset)
                written = json.loads((Path(os.environ['OUT']) / 't_params_written.json').read_text())[-1]['written']
                proof = rep.repeat_clock_proof(records, written['gap'])
                report.add(label + '_T_clock_response_ready_ACK_then_D', True, proof['passed'],
                           response_ready_clock_proof=proof)
            else:
                step('%s_%s_response_61' % (tag, kind), response, expected_response, master=False)
            state['s'] = s + len(native)
            state['growth'] = growth + rep.rp.growth(native, IMAGE_LEN)

        read_body = rep.READ_BODY

        def control_body(on_ms):
            return bytes((0x00, 0x00)) + crob(on_ms)

        def read(tag):
            respond(tag, 'READ', request(tag, 'READ', 1, READ_OBJECTS), read_body, True)

        def select(tag, on_ms, advance_app=True, kind='SELECT'):
            app = request(tag, kind, 3, crob(on_ms), advance_app)
            respond(tag, kind, app, control_body(on_ms), False)
            return app

        def operate(tag, on_ms):
            respond(tag, 'OPERATE', request(tag, 'OPERATE', 4, crob(on_ms)), control_body(on_ms), False)

        def counted(tag, timed, body, lane, releases):
            """Run body; when timed, assert its lane generations and OPERATE releases exactly."""
            lane0, rel0 = t_reg('gen_alloc_reg'), outcome(5)
            body()
            if timed:
                report.add('%s_lane_generations' % tag, lane, t_reg('gen_alloc_reg') - lane0)
                report.add('%s_OPERATE_releases' % tag, releases, outcome(5) - rel0)

        for phase, timed, (client, server) in (('untimed', 0, (100, 900)), ('timed', 1, (20000, 30000))):
            params['enabled'] = timed
            m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
            connect(phase, client, server)
            read('%s_lead' % phase)

            def cancel(p=phase):
                select('%s_cancel' % p, 100)
                report.add('%s_cancel_selection_in_effect_owner_0xa' % p, 0xa, owner())
                read('%s_cancel_by' % p)
                report.add('%s_cancel_owner_idle' % p, 5, owner())
            counted('%s_cancel' % phase, timed, cancel, lane=2, releases=0)
            counted('%s_new_sbo' % phase, timed,
                    lambda p=phase: (select('%s_new_sbo' % p, 101), operate('%s_new_sbo' % p, 101)), lane=2, releases=1)

            def replace(p=phase):
                select('%s_replace_A' % p, 102)
                select('%s_replace_B' % p, 103)
                operate('%s_replace_B' % p, 103)
            counted('%s_replace' % phase, timed, replace, lane=3, releases=1)

            def retry(p=phase):
                seqs = state['seqs']
                app = select('%s_retry_first' % p, 104, advance_app=False)
                # identical octets after the function code: same application sequence, new transport segment
                again = select('%s_retry_again' % p, 104, advance_app=True, kind='SELECT_retry')
                report.add('%s_retry_same_application_sequence' % p, app, again)
                operate('%s_retry' % p, 104)
                return seqs
            counted('%s_retry' % phase, timed, retry, lane=3, releases=1)
            read('%s_after_retry' % phase)

            # OPERATE for the REPLACED selection (A's objects, next application sequence after B): only B may be
            # operated, so this is dropped with no release and no OPERATE generation; it retires the connection
            old_app = select('%s_old_sel_A' % phase, 106)
            select('%s_old_sel_B' % phase, 107)
            op_gen0, rel0 = t_reg('op_gen_alloc_reg'), outcome(5)
            frame, _app = state['seqs'].request(4, crob(106))
            if rep.rp.SEL751:
                head, user = rep.rp._std().deframe(frame)
                # Fixed guarded CROBs are identical for A and B. Use A's
                # stale application identity to exercise replacement authority.
                frame = rep.rp._std().frame(head, user[:1] + bytes([0xc0 | ((old_app + 1) & 15)]) + user[2:])
            got = m.exchange(MASTER.dev_port, vectors.packet(24, state['c'], state['s'] + state['growth'],
                                                             payload=frame), ports, timeout=3, quiet=.15)
            report.add('%s_replaced_selection_OPERATE_dropped' % phase, 0, sum(len(v) for v in got.values()),
                       received=got)
            report.add('%s_replaced_selection_OPERATE_no_release' % phase, rel0, outcome(5))
            report.add('%s_replaced_selection_OPERATE_no_generation' % phase, op_gen0, t_reg('op_gen_alloc_reg'))
            if rep.rp.SEL751:
                frame, _app = state['seqs'].request(4, crob(107))
                head, user = rep.rp._std().deframe(frame)
                # Current application identity, but second CROB targets point 2.
                # Refusal proves both command objects remain inside the guard.
                user = user[:19] + b'\x02' + user[20:]
                frame = rep.rp._std().frame(head, user)
                got = m.exchange(MASTER.dev_port, vectors.packet(24, state['c'], state['s'] + state['growth'],
                                                                 payload=frame), ports, timeout=3, quiet=.15)
                report.add('%s_out_of_profile_second_CROB_OPERATE_dropped' % phase, 0,
                           sum(len(v) for v in got.values()), received=got)
                report.add('%s_out_of_profile_OPERATE_no_generation' % phase, op_gen0, t_reg('op_gen_alloc_reg'))
                report.add('%s_out_of_profile_OPERATE_no_release' % phase, rel0, outcome(5))
                report.record['meta']['replacement_contract'] = (
                    'fixed guarded command; replacement changes application/TCP identity; stale application refused; '
                    'current application with out-of-profile second CROB refused; identical current OPERATE is valid')
            step('%s_replaced_RST' % phase, vectors.packet(20, state['c'], state['s'] + state['growth']),
                 vectors.packet(20, state['c'], state['s']))
            connect('%s_after_replaced' % phase, client + 5000, server + 5000)

            # stale OPERATE after cancellation: dropped, nothing released, no OPERATE generation; retire connection
            select('%s_stale' % phase, 105)
            read('%s_stale_cancel' % phase)
            op_gen0, rel0 = t_reg('op_gen_alloc_reg'), outcome(5)
            frame, _app = state['seqs'].request(4, crob(105))
            got = m.exchange(MASTER.dev_port, vectors.packet(24, state['c'], state['s'] + state['growth'],
                                                             payload=frame), ports, timeout=3, quiet=.15)
            report.add('%s_stale_OPERATE_dropped' % phase, 0, sum(len(v) for v in got.values()), received=got)
            report.add('%s_stale_OPERATE_no_release' % phase, rel0, outcome(5))
            report.add('%s_stale_OPERATE_no_generation' % phase, op_gen0, t_reg('op_gen_alloc_reg'))
            step('%s_RST' % phase, vectors.packet(20, state['c'], state['s'] + state['growth']),
                 vectors.packet(20, state['c'], state['s']))
        connect('after', 60000, 70000)
        read('after_reconnect')
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / 'select_lifecycle_results.json')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
