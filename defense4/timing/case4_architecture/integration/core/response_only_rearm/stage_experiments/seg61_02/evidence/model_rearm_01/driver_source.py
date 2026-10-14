"""Compiled candidate functional regression inside launch_model.sh's namespace.

Candidate-specific adaptation of model_drive_rearm.py. Uses the unchanged model transport/reflector helpers and the explicit E61 oracle. No register
clear, forced Work retirement, physical device, or CPU rearm is used. Queue
timing observed here is model behavior, not host timing or ASIC evidence.
"""
import copy
import hashlib
import importlib.util
import os
import struct
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parents[2]
BASE = HERE.parent / 'response_only'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


helpers = load('_retained_model_helpers', BASE / 'model_drive_composite.py')
cp = load('_protected_model_cp', HERE / 'cp.py')
Model, Report, gc, same_frame = helpers.Model, helpers.Report, helpers.gc, helpers.same_frame
vectors, rs, scalar = helpers.vectors, helpers.rs, helpers.scalar
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "seg61_01"))
import encode61
IMAGE_LEN = 61
READ_NATIVE = 49
CONTROL_NATIVE = 37
PM, MASTER, RELAY = helpers.PM, helpers.MASTER, helpers.OUTSTATION
PKTGEN_RETURN = helpers.PKTGEN_RETURN


def main():
    report = Report(os.environ['PROG'], physical=False,
                    scope='E61 compiled protected reconnect; actual N/E/T; all 61 reverse distances and stale isolation',
                    driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    try:
        m = Model(ports=[], enable=False)
        ports = sorted({MASTER.dev_port, RELAY.dev_port})
        m.enable_ports(ports + helpers.FRONT_LOOPS)
        m.enable_ports([p for p in helpers.LOOP_PORTS if p not in helpers.FRONT_LOOPS])
        reflectors = [helpers.Reflector(p) for p in helpers.FRONT_LOOPS]
        for reflector in reflectors:
            reflector.start()
        report.record['meta']['port_errors'] = m.port_errors
        report.record['meta']['port_map'] = dict(PM._asdict())
        report.record['meta']['epoch_encoding'] = {
            'N': 'bare bounded epoch, physical pipe 0',
            'E': 'raw bit31 FIRST latch; raw & 0x7fffffff epoch, physical pipe 0',
            'T': 'bare bounded epoch, physical pipe 1',
        }
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
                      gap=50_000_000, op_j=200_000_000, budget=240_000, enabled=0)
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        mirror = m.table('$mirror.cfg', raw=True)
        mirror.entry_add(gc.Target(device_id=0, pipe_id=0xffff),
                         [mirror.make_key([gc.KeyTuple('$sid', 7)])],
                         [mirror.make_data([gc.DataTuple('$direction', str_val='INGRESS'),
                                            gc.DataTuple('$ucast_egress_port', helpers.PKTGEN_RETURN),
                                            gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                            gc.DataTuple('$session_enable', bool_val=True)], '$normal')])

        def snapshot():
            registers = {'N': ('owner', 'client', 'server', 'epoch'),
                         'E': ('epoch', 'master_isn', 'mode', 'front', 'acct', 'img_end', 'img_start', 'img_wend'),
                         'T': ('cur_epoch_reg', 'quarantine_reg', 'gen_alloc_reg', 'op_gen_alloc_reg',
                               't0_reg', 'op_t0_reg', 'ack_done_reg', 'resp_done_reg', 'op_done_reg')}
            registers['T'] += ('child_seen0_reg', 'child_seen1_reg', 'child_seen2_reg',
                               'ack_commit_at_reg', 'ack_commit_gen_reg')
            prefix = {'N': 'p0.n_Ingress.', 'E': 'p0.r_Egress.', 'T': 'p1.t_Ingress.'}
            return {role: {name: m.register_read(prefix[role] + name, 0, pipe=1 if role == 'T' else 0) for name in names}
                    for role, names in registers.items()}

        def private_snapshot():
            state = snapshot()
            for name in ('work.work', 'counter', 'application', 'read_app',
                         'pair_real_links_real_tcp_src', 'pair_real_tcp_dst_real_tcp_ports',
                         'pair_real_object_real_on', 'pair_real_off_native_start',
                         'pair_native_end_server_start'):
                state['N'][name] = m.register_read('p0.n_Ingress.' + name, 0, pipe=0)
            return state

        def step(name, sent, expected, master=True):
            got = m.exchange(MASTER.dev_port if master else RELAY.dev_port, sent, ports, timeout=3, quiet=.15)
            flat = [frame for frames in got.values() for frame in frames]
            good = len(flat) == (0 if expected is None else 1)
            if good and expected is not None:
                good = same_frame(flat[0], expected, sent)
            report.add(name, 'drop' if expected is None else 'one exact frame',
                       'drop' if not flat else '%d frames' % len(flat), ok=good,
                       received=got, want='' if expected is None else expected.hex())
            return flat

        def handshake(client, server):
            syn = vectors.packet(2, client, mss=1460)
            synack = vectors.packet(18, server, client + 1, reverse=True, mss=1460)
            step('SYN_%d' % client, syn, syn)
            before = snapshot()
            step('exact_pending_SYN_retry_%d' % client, syn, syn)
            report.add('pending_SYN_retry_authority_%d' % client, before, snapshot())
            step('SYNACK_%d' % server, synack, synack, master=False)
            before = snapshot()
            # Consume the first wire SYNACK without acknowledging it, then
            # retry exactly. This must forward without another FIRST arm.
            step('exact_pending_SYNACK_retry_%d' % server, synack, synack, master=False)
            report.add('pending_SYNACK_retry_authority_%d' % server, before, snapshot())
            ack = vectors.packet(16, client + 1, server + 1)
            step('final_ACK_%d' % client, ack, ack)
            state = snapshot()
            report.add('established_%d' % client, 5, scalar(state['N']['owner']) >> 16)
            report.add('fresh_front_%d' % server, server + 1, scalar(state['E']['front']))
            report.add('epoch_agreement_%d' % client, scalar(state['N']['epoch']),
                       scalar(state['E']['epoch']) & 0x7fffffff)
            report.add('FIRST_latched_%d' % client, 1, scalar(state['E']['epoch']) >> 31)
            report.add('T_epoch_agreement_%d' % client, scalar(state['N']['epoch']),
                       scalar(state['T']['cur_epoch_reg']))
            return state

        initial = handshake(100, 900)
        initial_work = m.register_read('p0.n_Ingress.work.work', 0, pipe=0)
        old_work_generation = scalar({k: v for k, v in initial_work.items() if k.endswith('.generation')})
        request = rs.request_packet(seq=101, ack=901)
        step('READ_native', request, request)
        ack = rs.ack_packet(seq=901, ack=121)
        step('READ_server_ACK', ack, ack, master=False)
        frame = rs.response_frame()
        padded = encode61.read61(frame)
        step('READ_padded_61', rs.response_packet(seq=901, ack=121),
             vectors.packet(24, 901, 121, reverse=True, payload=padded), master=False)
        # Probe actual E's private normalization return before N qualifies the
        # ACK. These ACKs lie inside the prior image, so N will reject them and
        # cannot commit accounting. Every bounded range row is observed with
        # its computed ACK/window and independently computed checksums.
        before_inverse = copy.deepcopy(snapshot())
        for distance in range(1, IMAGE_LEN + 1):
            for window in sorted({0, distance - 1, distance, distance + 1, 65535}):
                sent = bytearray(vectors.packet(16, 121, (901 + IMAGE_LEN) - distance))
                sent[48:50] = struct.pack('!H', window)
                sent[50:52] = bytes(2)
                pseudo = sent[26:34] + bytes((0, 6)) + struct.pack('!H', len(sent) - 34)
                sent[50:52] = struct.pack('!H', vectors.checksum(pseudo + sent[34:]))
                expected = bytearray(vectors.packet(16, 121, 901))
                expected_window = 0 if window < distance else min(READ_NATIVE + window - distance, 65535)
                expected[48:50] = struct.pack('!H', expected_window)
                expected[50:52] = bytes(2)
                expected[50:52] = struct.pack('!H', vectors.checksum(pseudo + expected[34:]))
                got = m.exchange(MASTER.dev_port, bytes(sent), ports + [PM.n_ack_return],
                                 timeout=.5, quiet=.03)
                private = [raw for raw in got[PM.n_ack_return] if len(raw) >= 70 and raw[12] == 0xe1]
                name = 'inverse_distance%d_window%d' % (distance, window)
                good = len(private) == 1 and same_frame(private[0][16:], bytes(expected), bytes(sent))
                report.add(name, 'one exact normalization; no wire departure',
                           '%d normalization / %d wire' % (len(private), sum(len(got[p]) for p in ports)),
                           ok=good and not any(got[p] for p in ports),
                           received=got, want=bytes(expected).hex())
        report.add('inverse_range_batch_authority_unchanged', before_inverse, snapshot())
        # Wire coordinates acknowledge the padded READ. E normalization occurs
        # before N validates the native frontier and authorizes accounting.
        step('mapped_FIN', vectors.packet(17, 121, (901 + IMAGE_LEN)), vectors.packet(17, 121, 950))
        step('server_FIN_ACK', vectors.packet(17, 950, 122, reverse=True),
             vectors.packet(17, (901 + IMAGE_LEN), 122, reverse=True), master=False)
        step('last_FIN_ACK', vectors.packet(16, 122, (902 + IMAGE_LEN)), vectors.packet(16, 122, 951))
        report.add('bilaterally_retired', 0x10f, scalar(snapshot()['N']['owner']) >> 16)
        current = handshake(4000, 7000)
        report.add('epoch_advanced', True, scalar(current['N']['epoch']) > scalar(initial['N']['epoch']))
        # The real timer header has no epoch. CLOSE and OPEN must advance both
        # preserved allocators before the new connection's first READ, so old
        # raw tokens are rejected on the silicon clone_or_token parser path.
        params['enabled'] = 1
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        before_token = copy.deepcopy(snapshot())
        stale = scalar(m.register_read('p1.t_Ingress.outcomes', 6, pipe=1))
        for profile, allocator in ((0, 'gen_alloc_reg'), (1, 'op_gen_alloc_reg')):
            old_generation = scalar(initial['T'][allocator])
            for packet_id in (0, 1):
                raw = bytes((1 << 3 | profile, profile)) + struct.pack('!HH', old_generation, packet_id) + bytes(58)
                m.drain(ports)
                m.send(PKTGEN_RETURN, raw)
                got = m.capture(ports, timeout=.4, quiet=.1)
                name = 'old_raw_token_app%d_id%d_on196' % (profile, packet_id)
                report.add(name + '_dropped', True, not any(got.values()))
                report.add(name + '_authority_unchanged', before_token, snapshot())
        report.add('old_raw_tokens_stale_count', stale + 4,
                   scalar(m.register_read('p1.t_Ingress.outcomes', 6, pipe=1)))
        params['enabled'] = 0
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        before_private = copy.deepcopy(private_snapshot())
        old_epoch = scalar(initial['N']['epoch'])
        old_owner = scalar(initial['N']['owner'])
        for phase in (1, 2, 3):
            # Full old Work generation, expected owner and phase, including
            # READ's t0/origin headers. These never claim a replacement Work.
            prefix = struct.pack('!IIIHH', old_epoch, old_work_generation, old_owner, phase << 8 | 9, 0)
            raw = prefix + struct.pack('!III', 0, 901, old_epoch) + rs.request_packet(seq=101, ack=901)
            m.drain(ports)
            m.send(68, raw)
            got = m.capture(ports, timeout=.4, quiet=.1)
            report.add('old_Work_phase%d_dropped' % phase, True, not any(got.values()))
            report.add('old_Work_phase%d_all_banks_unchanged' % phase, before_private, private_snapshot())
        for role in range(11, 17):
            generation = scalar(initial['T']['op_gen_alloc_reg' if role in (13, 16) else 'gen_alloc_reg'])
            raw = struct.pack('!BBHI', role, 0, generation, old_epoch) + rs.response_packet(seq=901, ack=121)
            port = PM.hb_return if role in (13, 16) else PM.held_return
            m.drain(ports)
            m.send(port, raw)
            got = m.capture(ports, timeout=.4, quiet=.1)
            report.add('old_ladder_role%d_dropped_even_OFF' % role, True, not any(got.values()))
            report.add('old_ladder_role%d_all_banks_unchanged' % role, before_private, private_snapshot())
        before = copy.deepcopy(snapshot())
        for name, packet, master in (
                ('old_ACK', vectors.packet(16, 101, 901), True),
                ('old_FIN', vectors.packet(17, 121, (901 + IMAGE_LEN)), True),
                ('old_RST', vectors.packet(20, 121, (901 + IMAGE_LEN)), True),
                ('old_READ_reply', rs.response_packet(seq=901, ack=121), False)):
            step(name, packet, None, master)
            report.add(name + '_authority_unchanged', before, snapshot())
        old_reset = struct.pack('!IIIBBH', old_epoch, 0, 0, 13, 0, 0) + bytes(14)
        m.drain(ports)
        m.send(PM.t_in, old_reset)
        got = m.capture(ports, timeout=.5, quiet=.1)
        report.add('old_RESET_dropped', True, not any(got.values()))
        report.add('old_RESET_authority_unchanged', before, snapshot())
        request = rs.request_packet(seq=4001, ack=7001)
        step('new_READ_native', request, request)
        ack = rs.ack_packet(seq=7001, ack=4021)
        step('new_READ_ACK', ack, ack, master=False)
        step('new_READ_fresh_mapping_61', rs.response_packet(seq=7001, ack=4021),
             vectors.packet(24, 7001, 4021, reverse=True, payload=padded), master=False)
        step('new_READ_wire_ACK_commit', vectors.packet(16, 4021, (7001 + IMAGE_LEN)), vectors.packet(16, 4021, 7050))
        select = vectors.packet(24, 4021, (7001 + IMAGE_LEN), payload=vectors.native_select(0, 3))
        step('new_SELECT_native', select,
             vectors.packet(24, 4021, 7050, payload=vectors.native_select(0, 3)))
        response = helpers.native_response37(0, 3)
        image = encode61.ctl61(response)
        step('new_SELECT_response_61', vectors.packet(24, 7050, 4056, reverse=True, payload=response),
             vectors.packet(24, (7001 + IMAGE_LEN), 4056, reverse=True, payload=image), master=False)
        params['enabled'] = 1
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        operate = vectors.packet(24, 4056, (7001 + 2 * IMAGE_LEN), payload=vectors.native_select(1, 4))
        step('new_OPERATE_hold_native', operate,
             vectors.packet(24, 4056, 7087, payload=vectors.native_select(1, 4)))
        report.add('OPERATE_release_count', 1, scalar(m.register_read('p1.t_Ingress.outcomes', 5, pipe=1)))
        response = helpers.native_response37(1, 4)
        image = encode61.ctl61(response)
        step('new_OPERATE_response_61', vectors.packet(24, 7087, 4091, reverse=True, payload=response),
             vectors.packet(24, (7001 + 2 * IMAGE_LEN), 4091, reverse=True, payload=image), master=False)
        step('qualified_RST', vectors.packet(20, 4091, (7001 + 3 * IMAGE_LEN)), vectors.packet(20, 4091, 7124))
        report.add('RST_retired', 0x200, scalar(snapshot()['N']['owner']) >> 16)
        handshake(9000, 11000)
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / 'rearm_results.json')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
