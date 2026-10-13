"""Compiled retransmission pass-through proof inside launch_model.sh's namespace.

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
                    scope='candidate56 plus retransmission pass-through; retransmitted READ/SELECT/OPERATE copies and their responses',
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

        def stale_counts():
            return {index: scalar(m.register_read('p1.t_Ingress.outcomes', index, pipe=1))
                    for index in (6, 23, 24)}

        def aggregate_stale():
            # Preserve the original shared-counter oracle, with raw components
            # also asserted independently at each bounded replay batch.
            return sum(stale_counts().values())

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

        def authority():
            state = snapshot()
            keep = {'N': ('owner', 'client', 'server', 'epoch'), 'E': ('epoch', 'master_isn', 'mode', 'front', 'img_end', 'img_start'),
                    'T': ('cur_epoch_reg', 'gen_alloc_reg', 'op_gen_alloc_reg')}
            return {role: {k: state[role][k] for k in names} for role, names in keep.items()}

        def retx(name, sent, expected, master=True):
            before = copy.deepcopy(authority())
            frames = step(name, sent, expected, master=master)
            report.add(name + '_authority_unchanged', before, authority())
            return frames

        handshake(100, 900)
        request = rs.request_packet(seq=101, ack=901)
        step('READ_native', request, request)
        retx('READ_request_retransmission_forwarded', request, request)
        ack = rs.ack_packet(seq=901, ack=121)
        step('READ_server_ACK', ack, ack, master=False)
        padded, _ = b.pad_read_response(rs.response_frame())
        read_response = rs.response_packet(seq=901, ack=121)
        read_padded = vectors.packet(24, 901, 121, reverse=True, payload=padded)
        step('READ_padded_58', read_response, read_padded, master=False)
        retx('READ_response_retransmission_padded_identically', read_response, read_padded, master=False)
        step('READ_wire_ACK_commit', vectors.packet(16, 121, 959), vectors.packet(16, 121, 950))
        select = vectors.packet(24, 121, 959, payload=vectors.native_select(0, 3))
        select_out = vectors.packet(24, 121, 950, payload=vectors.native_select(0, 3))
        step('SELECT_native', select, select_out)
        retx('SELECT_retransmission_forwarded', select, select_out)
        response = helpers.native_response37(0, 3)
        image, _ = b.pad_control_response(response, helpers.CTL_POINTS)
        select_response = vectors.packet(24, 950, 156, reverse=True, payload=response)
        select_image = vectors.packet(24, 959, 156, reverse=True, payload=image)
        step('SELECT_response_58', select_response, select_image, master=False)
        retx('SELECT_response_retransmission_padded_identically', select_response, select_image, master=False)
        params['enabled'] = 1
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        operate = vectors.packet(24, 156, 1017, payload=vectors.native_select(1, 4))
        operate_out = vectors.packet(24, 156, 987, payload=vectors.native_select(1, 4))
        step('OPERATE_hold_native', operate, operate_out)
        retx('OPERATE_retransmission_forwarded', operate, operate_out)
        retx('SELECT_response_retransmission_after_OPERATE_stale_ack', select_response, select_image, master=False)
        response = helpers.native_response37(1, 4)
        image, _ = b.pad_control_response(response, helpers.CTL_POINTS)
        operate_response = vectors.packet(24, 987, 191, reverse=True, payload=response)
        operate_image = vectors.packet(24, 1017, 191, reverse=True, payload=image)
        step('OPERATE_response_58', operate_response, operate_image, master=False)
        retx('OPERATE_response_retransmission_padded_identically', operate_response, operate_image, master=False)
        before = copy.deepcopy(authority())
        step('OPERATE_after_its_response_still_refused', operate, None)
        report.add('OPERATE_after_response_authority_unchanged', before, authority())
        report.add('OPERATE_released_once', 1, scalar(m.register_read('p1.t_Ingress.outcomes', 5, pipe=1)))
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / 'rearm_results.json')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
