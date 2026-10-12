"""Compiled candidate functional regression inside launch_model.sh's namespace.

Uses the unchanged model transport/reflector and padding helpers. No register
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

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE.parents[1]
BASE = CANDIDATE.parent / 'response_only'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


helpers = load('_retained_model_helpers', BASE / 'model_drive_composite.py')
cp = load('_protected_model_cp', CANDIDATE / 'cp.py')
Model, Report, gc, same_frame = helpers.Model, helpers.Report, helpers.gc, helpers.same_frame
vectors, rs, b, scalar = helpers.vectors, helpers.rs, helpers.b, helpers.scalar
PM, MASTER, RELAY = helpers.PM, helpers.MASTER, helpers.OUTSTATION
PKTGEN_RETURN = helpers.PKTGEN_RETURN


def main():
    report = Report(os.environ['PROG'], physical=False,
                    scope='compiled combined N residue11/E checkpoint55/sealed T11; full lifecycle plus eight CRC and link negatives',
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
            'T': 'raw bit31 sealed; low31 bounded epoch, physical pipe 1',
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
                         'T': ('cur_epoch_reg', 'gen_alloc_reg', 'op_gen_alloc_reg',
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

        NEGATIVE_CASES = []
        TCP_PAYLOAD_OFFSET = 54

        def fix_outer_checksums(packet):
            frame = bytearray(packet)
            if len(frame) < TCP_PAYLOAD_OFFSET:
                raise ValueError('negative packet too short for Ethernet/IP/TCP')
            ip_off = 14
            ihl = (frame[ip_off] & 0x0f) * 4
            tcp_off = ip_off + ihl
            total_len = struct.unpack('!H', frame[ip_off + 2:ip_off + 4])[0]
            if len(frame) < ip_off + total_len:
                raise ValueError('negative packet truncated before IP total length')
            frame[ip_off + 10:ip_off + 12] = bytes(2)
            frame[ip_off + 10:ip_off + 12] = struct.pack('!H', vectors.checksum(frame[ip_off:tcp_off]))
            frame[tcp_off + 16:tcp_off + 18] = bytes(2)
            pseudo = frame[ip_off + 12:ip_off + 20] + bytes((0, frame[ip_off + 9])) + struct.pack('!H', total_len - ihl)
            frame[tcp_off + 16:tcp_off + 18] = struct.pack('!H', vectors.checksum(pseudo + frame[tcp_off:ip_off + total_len]))
            return bytes(frame)

        def flip_native_crc_byte(packet, payload_crc_offset, label):
            frame = bytearray(packet)
            absolute = TCP_PAYLOAD_OFFSET + payload_crc_offset
            if absolute + 1 >= len(frame):
                raise ValueError('%s CRC offset outside packet: %d len %d' % (label, absolute, len(frame)))
            before = bytes(frame[absolute:absolute + 2])
            frame[absolute] ^= 0x01
            after = bytes(frame[absolute:absolute + 2])
            fixed = fix_outer_checksums(bytes(frame))
            return fixed, {
                'label': label,
                'payload_crc_offset': payload_crc_offset,
                'absolute_crc_offset': absolute,
                'crc_before': before.hex(),
                'crc_after': after.hex(),
                'mutated_byte_index': absolute,
                'mutated_byte_before': before[:1].hex(),
                'mutated_byte_after': after[:1].hex(),
            }

        def negative_external(name, packet, *, master=True, payload_crc_offset=None,
                              crc_label=None, extra=None):
            if payload_crc_offset is None:
                bad = fix_outer_checksums(packet)
                mutation = {'label': crc_label or name, 'crc_correct_control': True}
            else:
                bad, mutation = flip_native_crc_byte(packet, payload_crc_offset, crc_label or name)
            if extra:
                mutation.update(extra)
            before = copy.deepcopy(private_snapshot())
            m.drain(ports + [PM.n_ack_return])
            got = m.exchange(MASTER.dev_port if master else RELAY.dev_port,
                             bad, ports + [PM.n_ack_return], timeout=.7, quiet=.1)
            external_frames = sum(len(got[p]) for p in ports)
            unchanged = before == private_snapshot()
            mutation['input_port'] = MASTER.dev_port if master else RELAY.dev_port
            mutation['captured_external_frames'] = external_frames
            mutation['captured_n_ack_return_frames'] = len(got.get(PM.n_ack_return, []))
            mutation['bankscope'] = 'N private banks plus N/E/T authority snapshot'
            NEGATIVE_CASES.append(dict(name=name, mutation=mutation,
                                       drop_ok=(external_frames == 0), banks_unchanged=unchanged))
            report.add(name + '_external_drop', 'no external frame', '%d external frames' % external_frames,
                       ok=(external_frames == 0), received=got, mutation=mutation)
            report.add(name + '_all_banks_unchanged', before, private_snapshot(), ok=unchanged,
                       mutation=mutation)

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
        negative_external('bad_native_dlhead_crc_before_READ',
                          vectors.packet(24, 101, 901, payload=vectors.native_select(0, 3)),
                          payload_crc_offset=8, crc_label='DLhead')
        negative_external('bad_native_first_crc_before_READ',
                          vectors.packet(24, 101, 901, payload=vectors.native_select(0, 3)),
                          payload_crc_offset=26, crc_label='first')
        negative_external('bad_native_controltail_crc_before_READ',
                          vectors.packet(24, 101, 901, payload=vectors.native_select(1, 4)),
                          payload_crc_offset=33, crc_label='controltail')
        negative_external('bad_readrequest_crc_before_READ',
                          rs.request_packet(seq=101, ack=901),
                          payload_crc_offset=18, crc_label='readrequest')
        wrong_link = rs.request_packet(seq=101, ack=901, dst=0x2222, src=0x3333)
        negative_external('bad_readrequest_wrong_link_crc_correct_before_READ',
                          wrong_link,
                          crc_label='wrong_read_link_address',
                          extra={'link_dst_src': wrong_link[TCP_PAYLOAD_OFFSET + 4:TCP_PAYLOAD_OFFSET + 8].hex(),
                                 'dnp_crc_correct': True})
        request = rs.request_packet(seq=101, ack=901)
        step('READ_native', request, request)
        ack = rs.ack_packet(seq=901, ack=121)
        step('READ_server_ACK', ack, ack, master=False)
        negative_external('bad_readresponse_second_crc_before_response',
                          rs.response_packet(seq=901, ack=121), master=False,
                          payload_crc_offset=44, crc_label='second')
        negative_external('bad_readresponse_readtail_crc_before_response',
                          rs.response_packet(seq=901, ack=121), master=False,
                          payload_crc_offset=47, crc_label='readtail')
        frame = rs.response_frame()
        padded, _ = b.pad_read_response(frame)
        step('READ_padded_58', rs.response_packet(seq=901, ack=121),
             vectors.packet(24, 901, 121, reverse=True, payload=padded), master=False)
        # Probe actual E's private normalization return before N qualifies the
        # ACK. These ACKs lie inside the prior image, so N will reject them and
        # cannot commit accounting. Every bounded range row is observed with
        # its computed ACK/window and independently computed checksums.
        before_inverse = copy.deepcopy(snapshot())
        for distance in range(1, 59):
            for window in sorted({0, distance - 1, distance, distance + 1, 65535}):
                sent = bytearray(vectors.packet(16, 121, 959 - distance))
                sent[48:50] = struct.pack('!H', window)
                sent[50:52] = bytes(2)
                pseudo = sent[26:34] + bytes((0, 6)) + struct.pack('!H', len(sent) - 34)
                sent[50:52] = struct.pack('!H', vectors.checksum(pseudo + sent[34:]))
                expected = bytearray(vectors.packet(16, 121, 901))
                expected_window = 0 if window < distance else min(49 + window - distance, 65535)
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
        before_close = copy.deepcopy(private_snapshot())
        report.add('before_first_FIN_owner_established', 5, scalar(before_close['N']['owner']) >> 16)
        step('mapped_FIN', vectors.packet(17, 121, 959), vectors.packet(17, 121, 950))
        first_fin = copy.deepcopy(private_snapshot())
        report.add('first_FIN_owner_is_not_retired', 0x101, scalar(first_fin['N']['owner']) >> 16)
        report.add('first_FIN_seals_T_at_qualified_CLOSE',
                   scalar(before_close['N']['epoch']) | 0x80000000,
                   scalar(first_fin['T']['cur_epoch_reg']))
        for allocator in ('gen_alloc_reg', 'op_gen_alloc_reg'):
            report.add('first_FIN_bumps_' + allocator,
                       scalar(before_close['T'][allocator]) + 1, scalar(first_fin['T'][allocator]))
        step('server_FIN_ACK', vectors.packet(17, 950, 122, reverse=True),
             vectors.packet(17, 959, 122, reverse=True), master=False)
        server_fin = copy.deepcopy(private_snapshot())
        report.add('server_FIN_ACK_owner_still_not_retired', 0x10b, scalar(server_fin['N']['owner']) >> 16)
        report.add('server_FIN_duplicate_CLOSE_no_extra_T_bumps', first_fin['T'], server_fin['T'])
        step('last_FIN_ACK', vectors.packet(16, 122, 960), vectors.packet(16, 122, 951))
        report.add('bilaterally_retired', 0x10f, scalar(snapshot()['N']['owner']) >> 16)
        closed = copy.deepcopy(private_snapshot())
        old_epoch = scalar(initial['N']['epoch'])
        report.add('first_CLOSE_seals_raw_T_epoch', old_epoch | 0x80000000,
                   scalar(closed['T']['cur_epoch_reg']))
        for allocator in ('gen_alloc_reg', 'op_gen_alloc_reg'):
            report.add('first_CLOSE_bumps_' + allocator, scalar(before_close['T'][allocator]) + 1,
                       scalar(closed['T'][allocator]))

        step('duplicate_last_FIN_ACK', vectors.packet(16, 122, 960), vectors.packet(16, 122, 951))
        report.add('late_final_ACK_no_extra_T_bumps', closed['T'], snapshot()['T'])
        report.add('late_final_ACK_keeps_retired_N_owner', 0x10f, scalar(snapshot()['N']['owner']) >> 16)
        # N's diagnostic Work/counter may advance on the duplicate ACK.
        closed = copy.deepcopy(private_snapshot())

        def t_event(kind, epoch, frame=bytes(14), stage=0):
            raw = struct.pack('!IIIBBH', epoch, 0, 0, kind, stage, 0) + frame
            m.drain(ports)
            m.send(PM.t_in, raw)
            return m.capture(ports, timeout=.4, quiet=.1)

        got = t_event(13, old_epoch)
        report.add('duplicate_CLOSE_has_no_wire_departure', True, not any(got.values()))
        report.add('duplicate_CLOSE_preserves_every_raw_bank', closed, private_snapshot())
        for invalid in (0, old_epoch, 0x7fffffff, 0x80000000, 0xffffffff):
            got = t_event(14, invalid)
            report.add('sealed_invalid_OPEN_%08x_dropped' % invalid, True, not any(got.values()))
            report.add('sealed_invalid_OPEN_%08x_preserves_banks' % invalid,
                       closed, private_snapshot())
        params['enabled'] = 1
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        stale = scalar(m.register_read('p1.t_Ingress.outcomes', 6, pipe=1))
        for profile, allocator in ((0, 'gen_alloc_reg'), (1, 'op_gen_alloc_reg')):
            old_generation = scalar(initial['T'][allocator])
            for packet_id in range(4):
                raw = bytes((1 << 3 | profile, profile)) + struct.pack('!HH', old_generation, packet_id) + bytes(58)
                m.drain(ports)
                m.send(PKTGEN_RETURN, raw)
                got = m.capture(ports, timeout=.4, quiet=.1)
                name = 'sealed_old_raw_app%d_id%d_on196' % (profile, packet_id)
                report.add(name + '_dropped', True, not any(got.values()))
                report.add(name + '_all_banks_unchanged', closed, private_snapshot())
        report.add('sealed_old_raw_tokens_stale_count', stale + 8,
                   scalar(m.register_read('p1.t_Ingress.outcomes', 6, pipe=1)))
        params['enabled'] = 0
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        current = handshake(4000, 7000)
        for allocator in ('gen_alloc_reg', 'op_gen_alloc_reg'):
            report.add('fresh_OPEN_bumps_preserved_' + allocator,
                       scalar(closed['T'][allocator]) + 1, scalar(current['T'][allocator]))
        report.add('epoch_advanced', True, scalar(current['N']['epoch']) > scalar(initial['N']['epoch']))
        # The real timer header has no epoch. CLOSE and OPEN must advance both
        # preserved allocators before the new connection's first READ, so old
        # raw tokens are rejected on the silicon clone_or_token parser path.
        params['enabled'] = 1
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        before_token = copy.deepcopy(private_snapshot())
        stale = scalar(m.register_read('p1.t_Ingress.outcomes', 6, pipe=1))
        for profile, allocator in ((0, 'gen_alloc_reg'), (1, 'op_gen_alloc_reg')):
            old_generation = scalar(initial['T'][allocator])
            for packet_id in range(4):
                raw = bytes((1 << 3 | profile, profile)) + struct.pack('!HH', old_generation, packet_id) + bytes(58)
                m.drain(ports)
                m.send(PKTGEN_RETURN, raw)
                got = m.capture(ports, timeout=.4, quiet=.1)
                name = 'old_raw_token_app%d_id%d_on196' % (profile, packet_id)
                report.add(name + '_dropped', True, not any(got.values()))
                report.add(name + '_authority_unchanged', before_token, private_snapshot())
        report.add('old_raw_tokens_stale_count', stale + 8,
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
            raw = struct.pack('!BBHI', role, 0, generation, old_epoch if role >= 14 else params['budget']) + rs.response_packet(seq=901, ack=121)
            port = PM.hb_return if role in (13, 16) else PM.held_return
            m.drain(ports)
            m.send(port, raw)
            got = m.capture(ports, timeout=.4, quiet=.1)
            report.add('old_ladder_role%d_dropped_even_OFF' % role, True, not any(got.values()))
            report.add('old_ladder_role%d_all_banks_unchanged' % role, before_private, private_snapshot())
        before = copy.deepcopy(snapshot())
        for name, packet, master in (
                ('old_ACK', vectors.packet(16, 101, 901), True),
                ('old_FIN', vectors.packet(17, 121, 959), True),
                ('old_RST', vectors.packet(20, 121, 959), True),
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
        step('new_READ_fresh_mapping_58', rs.response_packet(seq=7001, ack=4021),
             vectors.packet(24, 7001, 4021, reverse=True, payload=padded), master=False)
        step('new_READ_wire_ACK_commit', vectors.packet(16, 4021, 7059), vectors.packet(16, 4021, 7050))
        select = vectors.packet(24, 4021, 7059, payload=vectors.native_select(0, 3))
        step('new_SELECT_native', select,
             vectors.packet(24, 4021, 7050, payload=vectors.native_select(0, 3)))
        negative_external('bad_control_response_responsetail_crc_before_SELECT_response',
                          vectors.packet(24, 7050, 4056, reverse=True, payload=helpers.native_response37(0, 3)),
                          master=False, payload_crc_offset=35, crc_label='responsetail')
        response = helpers.native_response37(0, 3)
        image, _ = b.pad_control_response(response, helpers.CTL_POINTS)
        step('new_SELECT_response_58', vectors.packet(24, 7050, 4056, reverse=True, payload=response),
             vectors.packet(24, 7059, 4056, reverse=True, payload=image), master=False)
        params['enabled'] = 1
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        operate = vectors.packet(24, 4056, 7117, payload=vectors.native_select(1, 4))
        step('new_OPERATE_hold_native', operate,
             vectors.packet(24, 4056, 7087, payload=vectors.native_select(1, 4)))
        report.add('OPERATE_release_count', 1, scalar(m.register_read('p1.t_Ingress.outcomes', 5, pipe=1)))
        response = helpers.native_response37(1, 4)
        image, _ = b.pad_control_response(response, helpers.CTL_POINTS)
        step('new_OPERATE_response_58', vectors.packet(24, 7087, 4091, reverse=True, payload=response),
             vectors.packet(24, 7117, 4091, reverse=True, payload=image), master=False)
        before_rst = copy.deepcopy(private_snapshot())
        step('qualified_RST', vectors.packet(20, 4091, 7175), vectors.packet(20, 4091, 7124))
        rst_closed = copy.deepcopy(private_snapshot())
        report.add('RST_retired', 0x200, scalar(rst_closed['N']['owner']) >> 16)
        rst_epoch = scalar(before_rst['N']['epoch'])
        report.add('RST_CLOSE_seals_raw_T_epoch', rst_epoch | 0x80000000,
                   scalar(rst_closed['T']['cur_epoch_reg']))
        for allocator in ('gen_alloc_reg', 'op_gen_alloc_reg'):
            report.add('RST_CLOSE_bumps_' + allocator, scalar(before_rst['T'][allocator]) + 1,
                       scalar(rst_closed['T'][allocator]))
        got = t_event(13, rst_epoch)
        report.add('RST_duplicate_CLOSE_has_no_wire_departure', True, not any(got.values()))
        report.add('RST_duplicate_CLOSE_preserves_every_raw_bank', rst_closed, private_snapshot())
        third = handshake(9000, 11000)
        for allocator in ('gen_alloc_reg', 'op_gen_alloc_reg'):
            report.add('RST_reOPEN_bumps_preserved_' + allocator,
                       scalar(rst_closed['T'][allocator]) + 1, scalar(third['T'][allocator]))
        # Positive current-owner OFF controls distinguish epoch fencing from
        # a blanket held-original drop. Keep the full current raw T bank image.
        params['enabled'] = 0
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        current_epoch = scalar(third['N']['epoch'])
        off_count = scalar(m.register_read('p1.t_Ingress.outcomes', 11, pipe=1))
        before_off_t = copy.deepcopy(snapshot()['T'])
        for role, original, expected in (
                (14, rs.ack_packet(seq=11001, ack=9001), rs.ack_packet(seq=11001, ack=9001)),
                (15, rs.response_packet(seq=11001, ack=9001),
                 vectors.packet(24, 11001, 9001, reverse=True, payload=padded)),
                (16, vectors.packet(24, 9001, 11001, payload=vectors.native_select(1, 4)),
                 vectors.packet(24, 9001, 11001, payload=vectors.native_select(1, 4)))):
            allocator = 'op_gen_alloc_reg' if role == 16 else 'gen_alloc_reg'
            generation = scalar(third['T'][allocator])
            raw = struct.pack('!BBHI', role, 0, generation, current_epoch) + original
            port = PM.hb_return if role == 16 else PM.held_return
            got = m.exchange(port, raw, ports, timeout=1, quiet=.15)
            flat = [frame for frames in got.values() for frame in frames]
            report.add('current_OFF_role%d_exact_flush' % role, 'one exact frame',
                       '%d frames' % len(flat),
                       ok=len(flat) == 1 and same_frame(flat[0], expected, original),
                       received=got, want=expected.hex())
            report.add('current_OFF_role%d_raw_T_unchanged' % role, before_off_t, snapshot()['T'])
        report.add('current_OFF_flush_count', off_count + 3,
                   scalar(m.register_read('p1.t_Ingress.outcomes', 11, pipe=1)))

        # End-of-run isolated T fixture: reach the real epoch bound through
        # OPEN, then initialize only local-model allocator cells near their
        # sentinel. No owner/Work/epoch clear or CPU rearm is performed.
        before_bound = copy.deepcopy(private_snapshot())
        t_event(14, 0x7ffffffe)
        bounded = copy.deepcopy(private_snapshot())
        report.add('max_valid_OPEN_installs_raw_epoch', 0x7ffffffe,
                   scalar(bounded['T']['cur_epoch_reg']))
        report.add('max_valid_OPEN_preserves_N', before_bound['N'], bounded['N'])
        report.add('max_valid_OPEN_preserves_E', before_bound['E'], bounded['E'])
        for allocator in ('gen_alloc_reg', 'op_gen_alloc_reg'):
            report.add('max_valid_OPEN_bumps_' + allocator,
                       scalar(before_bound['T'][allocator]) + 1, scalar(bounded['T'][allocator]))
        report.record['meta']['exhaustion_fixture'] = {
            'scope': 'private local model only, final isolated T tests',
            'registers_initialized': ['gen_alloc_reg', 'op_gen_alloc_reg'],
            'initial_value': 0xfffe,
            'owner_Work_epoch_overrides': False,
        }
        for allocator in ('gen_alloc_reg', 'op_gen_alloc_reg'):
            name = 'p1.t_Ingress.' + allocator
            fields = m.register_read(name, 0, pipe=1)
            m.register_write(name, 0, {field: 0xfffe for field, value in fields.items() if isinstance(value, list)}, pipe=1)
        params['enabled'] = 1
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        exhausted_count = scalar(m.register_read('p1.t_Ingress.outcomes', 15, pipe=1))
        for kind, allocator, anchor in ((9, 'gen_alloc_reg', 't0_reg'),
                                        (12, 'op_gen_alloc_reg', 'op_t0_reg')):
            before = copy.deepcopy(private_snapshot())
            got = t_event(kind, 0x7ffffffe, rs.request_packet(seq=9001, ack=11001))
            after = copy.deepcopy(private_snapshot())
            report.add('exhausted_%s_drop' % allocator, True, not any(got.values()))
            report.add('exhausted_%s_sentinel' % allocator, 0xffff, scalar(after['T'][allocator]))
            report.add('exhausted_%s_no_anchor_arm' % allocator, before['T'][anchor], after['T'][anchor])
            report.add('exhausted_%s_N_unchanged' % allocator, before['N'], after['N'])
            report.add('exhausted_%s_E_unchanged' % allocator, before['E'], after['E'])
        report.add('exhaustion_admission_count', exhausted_count + 2,
                   scalar(m.register_read('p1.t_Ingress.outcomes', 15, pipe=1)))
        before_sentinel_tokens = copy.deepcopy(private_snapshot())
        stale = scalar(m.register_read('p1.t_Ingress.outcomes', 6, pipe=1))
        for profile in (0, 1):
            for generation in (0xfffe, 0xffff):
                raw = bytes((1 << 3 | profile, profile)) + struct.pack('!HH', generation, 0) + bytes(58)
                got = m.exchange(PKTGEN_RETURN, raw, ports, timeout=.4, quiet=.1)
                report.add('sentinel_token_app%d_gen%04x_drop' % (profile, generation),
                           True, not any(got.values()))
                report.add('sentinel_token_app%d_gen%04x_all_banks_unchanged' % (profile, generation),
                           before_sentinel_tokens, private_snapshot())
        report.add('sentinel_tokens_stale_count', stale + 4,
                   scalar(m.register_read('p1.t_Ingress.outcomes', 6, pipe=1)))
        t_event(13, 0x7ffffffe)
        terminal = copy.deepcopy(private_snapshot())
        report.add('max_epoch_CLOSE_seals_full_raw_bank', 0xfffffffe,
                   scalar(terminal['T']['cur_epoch_reg']))
        for allocator in ('gen_alloc_reg', 'op_gen_alloc_reg'):
            report.add('max_epoch_CLOSE_preserves_sentinel_' + allocator, 0xffff,
                       scalar(terminal['T'][allocator]))
        t_event(13, 0x7ffffffe)
        report.add('terminal_duplicate_CLOSE_all_banks_unchanged', terminal, private_snapshot())
        for invalid in (0, 1, 0x7ffffffe, 0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff):
            got = t_event(14, invalid)
            report.add('terminal_OPEN_%08x_drop' % invalid, True, not any(got.values()))
            report.add('terminal_OPEN_%08x_all_banks_unchanged' % invalid,
                       terminal, private_snapshot())
        report.record['meta']['negative_crc_cases'] = NEGATIVE_CASES
        report.record['meta']['negative_crc_driver'] = {
            'source': 'corrected sealed T491 driver plus exact independent N398 negative helper/vector blocks',
            'scope': 'combined N11/E12/T11; seven captured native CRC mutations and CRC-correct wrong READ link address',
            'outer_ip_tcp': 'checksums recomputed after every native CRC mutation',
            'model_int_port_loop_required_unset': True,
        }
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / 'rearm_results.json')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
