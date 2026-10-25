"""Compiled candidate functional regression inside launch_model.sh's namespace.

Candidate-specific adaptation of model_drive_rearm.py. Uses the unchanged model transport/reflector helpers and the explicit E61 oracle. No register
clear, forced Work retirement, physical device, or CPU rearm is used. Queue
timing observed here is model behavior, not host timing or ASIC evidence.
"""
import copy
import hashlib
import importlib.util
import json
import os
import select
import socket
import struct
import sys
import time
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
sealed_profile = load('_rearm_model_profile', HERE / 'hw/sealed_profile.py')
Model, Report, gc, same_frame = helpers.Model, helpers.Report, helpers.gc, helpers.same_frame
vectors, rs, scalar = helpers.vectors, helpers.rs, helpers.scalar
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "seg61_01"))
import encode61
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent))  # read_policy_expect is beside this file
import read_policy_expect as rp  # noqa: E402
rp.install(encode61)
rp.configure_helpers(helpers)
IMAGE_LEN = rp.CONTROL_IMAGE_LEN
if rp.TWO_READ:
    # A two-READ build leaves the range READ native, so the inverse-normalization probe below would see no image at
    # all. It drives the padded mixed READ instead (fixture variant 0, captured bytes re-addressed to the model
    # connection; model_policy.two_read_frames), whose 91-byte response the build pads to 141.
    import model_policy as mpol  # noqa: E402
    _t = mpol.TWO_TEMPLATES['v0']['classes']['mixed']
    READ_REQUEST = mpol.resequence(bytes.fromhex(_t['request']), 0, 0xC0, dst=0x0000, src=0x0100)
    READ_RESPONSE = mpol.resequence(bytes.fromhex(_t['native']), 0, 0xC0, dst=0x0100, src=0x0000)
else:
    READ_REQUEST, READ_RESPONSE = rs.request_frame(), rs.response_frame()
READ_NATIVE = len(READ_RESPONSE)
READ_REQ = len(READ_REQUEST)
READ_IMAGE_LEN = len(encode61.read61(READ_RESPONSE))
# explicit checks (not assert, which python -O strips): the range path keeps its old constants; the two-READ path
# must probe a genuinely padded image -- the build's declared target for the mixed native, larger than the native
if rp.TWO_READ:
    if not (READ_IMAGE_LEN == rp.SHAPES[READ_NATIVE]['target'] > READ_NATIVE):
        raise SystemExit('two-READ rearm probe is not padded: native %d image %d' % (READ_NATIVE, READ_IMAGE_LEN))
elif (READ_NATIVE, READ_REQ, READ_IMAGE_LEN) != (49, 20, rp.read_image_len(61)):
    raise SystemExit('range rearm constants changed: %r' % ((READ_NATIVE, READ_REQ, READ_IMAGE_LEN),))


def read_request_packet(seq, ack):
    return vectors.packet(24, seq, ack, payload=READ_REQUEST)


def read_response_packet(seq, ack):
    return vectors.packet(24, seq, ack, reverse=True, payload=READ_RESPONSE)
CONTROL_NATIVE = rp.CONTROL_NATIVE_LEN
PM, MASTER, RELAY = helpers.PM, helpers.MASTER, helpers.OUTSTATION
PKTGEN_RETURN = helpers.PKTGEN_RETURN



def timing_params_for_profile(profile):
    contract = profile.get('timing_contract')
    if contract == 'response_ready_ack_d_v1':
        timing = profile['timing_ns']
        return dict(gap=timing['D_release_budget'], op_j=timing['J_operate_hold'],
                    response_wait_timeout=timing['response_wait_timeout'], budget=240000, enabled=0)
    if contract is not None:
        raise ValueError('unknown rearm timing contract: %r' % contract)
    return dict(da=50_000_000, readiness=400_000_000, cap=16_000_000,
                gap=50_000_000, op_j=200_000_000, budget=240_000, enabled=0)


def response_ready_operate(send, collect, master_port, relay_port, operate, relayed_operate,
                           ack, response, complete_response, timeout=10):
    """A genuine relay-bound command causes an immediate genuine ACK/response burst.

    No counter/report/log work can consume the fixed response-wait budget between
    observing command delivery and sending its relay packets. Wall timeout only bounds I/O.
    """
    captured, relayed = [], False
    send(master_port, operate)
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        captured.extend(collect(.003))
        if any(port == relay_port and same_frame(frame, relayed_operate, operate) for port, frame in captured):
            relayed = True
            send(relay_port, ack)
            send(relay_port, response)
            break
    if relayed:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            captured.extend(collect(.003))
            if any(port == master_port and same_frame(frame, complete_response, response) for port, frame in captured):
                break
    return captured, relayed

def main():
    report = Report(os.environ['PROG'], physical=False,
                    scope='E61 compiled protected reconnect; actual N/E/T; all 61 reverse distances and stale isolation',
                    driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    rp.report_endpoint(report)
    try:
        child_regs = sealed_profile.child_registers(sealed_profile.describe(
            Path(os.environ['PORT_MAP']).parent / 'compile_local/out'))
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
        if rp.POLICY:   # pipe-1 READ padder's size enable, mirroring E's fwd_conn row (cp.p1_pad_rows)
            for table, key, action, data, priority in cp.p1_pad_rows(RELAY, MASTER, True):
                m.add(table, dict(key), action, dict(data), priority)
        inputs = json.loads(Path(os.environ['PORT_MAP']).read_text())
        timing_profile = inputs.get('supported_profile') or {}
        if timing_profile.get('timing_contract') is not None:
            timing_profiles = load('_rearm_timing_contract', Path(__file__).resolve().parent.parent / 'ctl_timing_01/model_profile.py')
            timing_profile = timing_profiles.resolve(inputs, Path(os.environ['PORT_MAP']).with_name('response_only.p4'))
        response_ready = timing_profile.get('timing_contract') == 'response_ready_ack_d_v1'
        params = timing_params_for_profile(timing_profile)
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
            registers['T'] += child_regs + ('ack_commit_at_reg', 'ack_commit_gen_reg')
            prefix = {'N': 'p0.n_Ingress.', 'E': 'p0.r_Egress.', 'T': 'p1.t_Ingress.'}
            return {role: {name: m.register_read(prefix[role] + name, 0, pipe=1 if role == 'T' else 0) for name in names}
                    for role, names in registers.items()}

        # relay_sbo replaces the object/on-time pair register with the guarded fixed command constants.
        pairs = ('pair_real_links_real_tcp_src', 'pair_real_tcp_dst_real_tcp_ports') + (
            () if 'relay_sbo' in inputs.get('transforms_applied', []) else ('pair_real_object_real_on',)) + (
            'pair_real_off_native_start', 'pair_native_end_server_start')

        def private_snapshot():
            state = snapshot()
            for name in ('work.work', 'counter', 'application', 'read_app') + pairs:
                state['N'][name] = m.register_read('p0.n_Ingress.' + name, 0, pipe=0)
            return state

        def step(name, sent, expected, master=True):
            expected = rp.preserve_options(sent, expected)
            rp.advance_timestamp()
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
        request = read_request_packet(101, 901)
        step('READ_native', request, request)
        ack = rs.ack_packet(seq=901, ack=101 + READ_REQ)
        step('READ_server_ACK', ack, ack, master=False)
        padded = encode61.read61(READ_RESPONSE)
        step('READ_padded_61', read_response_packet(901, 101 + READ_REQ),
             vectors.packet(24, 901, 101 + READ_REQ, reverse=True, payload=padded), master=False)
        # Probe actual E's private normalization return before N qualifies the
        # ACK. These ACKs lie inside the prior image, so N will reject them and
        # cannot commit accounting. Every bounded range row is observed with
        # its computed ACK/window and independently computed checksums.
        before_inverse = copy.deepcopy(snapshot())
        for distance in range(1, READ_IMAGE_LEN + 1):
            for window in sorted({0, distance - 1, distance, distance + 1, 65535}):
                sent = bytearray(vectors.packet(16, 101 + READ_REQ, (901 + READ_IMAGE_LEN) - distance))
                sent[48:50] = struct.pack('!H', window)
                sent[50:52] = bytes(2)
                pseudo = sent[26:34] + bytes((0, 6)) + struct.pack('!H', len(sent) - 34)
                sent[50:52] = struct.pack('!H', vectors.checksum(pseudo + sent[34:]))
                expected = bytearray(vectors.packet(16, 101 + READ_REQ, 901))
                expected_window = rp.reverse_window(window, distance, READ_NATIVE)
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
        c, n = 101 + READ_REQ, 901 + READ_NATIVE          # client sequence after the request; native response end
        step('mapped_FIN', vectors.packet(17, c, (901 + READ_IMAGE_LEN)), vectors.packet(17, c, n))
        step('server_FIN_ACK', vectors.packet(17, n, c + 1, reverse=True),
             vectors.packet(17, (901 + READ_IMAGE_LEN), c + 1, reverse=True), master=False)
        step('last_FIN_ACK', vectors.packet(16, c + 1, (902 + READ_IMAGE_LEN)), vectors.packet(16, c + 1, n + 1))
        report.add('bilaterally_retired', 0x10f, scalar(snapshot()['N']['owner']) >> 16)
        current = handshake(4000, 7000)
        report.add('epoch_advanced', True, scalar(current['N']['epoch']) > scalar(initial['N']['epoch']))
        # The real timer header has no epoch. CLOSE and OPEN must advance both
        # preserved allocators before the new connection's first READ, so old
        # raw tokens are rejected on the silicon clone_or_token parser path.
        params['enabled'] = 1
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        before_token = copy.deepcopy(snapshot())
        stale = {index: scalar(m.register_read('p1.t_Ingress.outcomes', index, pipe=1))
                 for index in (6, 23, 24)}
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
        for index, count in ((6, 0), (23, 2), (24, 2)):
            report.add('old_raw_tokens_stale_count_%d' % index, stale[index] + count,
                       scalar(m.register_read('p1.t_Ingress.outcomes', index, pipe=1)))
        params['enabled'] = 0
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        before_private = copy.deepcopy(private_snapshot())
        old_epoch = scalar(initial['N']['epoch'])
        old_owner = scalar(initial['N']['owner'])
        for phase in (1, 2, 3):
            # Full old Work generation, expected owner and phase, including
            # READ's t0/origin headers. These never claim a replacement Work.
            prefix = struct.pack('!IIIHH', old_epoch, old_work_generation, old_owner, phase << 8 | 9, 0)
            raw = prefix + struct.pack('!III', 0, 901, old_epoch) + read_request_packet(101, 901)
            m.drain(ports)
            m.send(68, raw)
            got = m.capture(ports, timeout=.4, quiet=.1)
            report.add('old_Work_phase%d_dropped' % phase, True, not any(got.values()))
            report.add('old_Work_phase%d_all_banks_unchanged' % phase, before_private, private_snapshot())
        for role in range(11, 17):
            generation = scalar(initial['T']['op_gen_alloc_reg' if role in (13, 16) else 'gen_alloc_reg'])
            raw = struct.pack('!BBHI', role, 0, generation, old_epoch) + read_response_packet(901, 101 + READ_REQ)
            port = PM.hb_return if role in (13, 16) else PM.held_return
            m.drain(ports)
            m.send(port, raw)
            got = m.capture(ports, timeout=.4, quiet=.1)
            report.add('old_ladder_role%d_dropped_even_OFF' % role, True, not any(got.values()))
            report.add('old_ladder_role%d_all_banks_unchanged' % role, before_private, private_snapshot())
        before = copy.deepcopy(snapshot())
        for name, packet, master in (
                ('old_ACK', vectors.packet(16, 101, 901), True),
                ('old_FIN', vectors.packet(17, 101 + READ_REQ, (901 + READ_IMAGE_LEN)), True),
                ('old_RST', vectors.packet(20, 101 + READ_REQ, (901 + READ_IMAGE_LEN)), True),
                ('old_READ_reply', read_response_packet(901, 101 + READ_REQ), False)):
            step(name, packet, None, master)
            report.add(name + '_authority_unchanged', before, snapshot())
        old_reset = struct.pack('!IIIBBH', old_epoch, 0, 0, 13, 0, 0) + bytes(14)
        m.drain(ports)
        m.send(PM.t_in, old_reset)
        got = m.capture(ports, timeout=.5, quiet=.1)
        report.add('old_RESET_dropped', True, not any(got.values()))
        report.add('old_RESET_authority_unchanged', before, snapshot())
        c, n = 4001 + READ_REQ, 7001 + READ_NATIVE       # client sequence after the request; native response end
        request = read_request_packet(4001, 7001)
        step('new_READ_native', request, request)
        ack = rs.ack_packet(seq=7001, ack=c)
        step('new_READ_ACK', ack, ack, master=False)
        step('new_READ_fresh_mapping_61', read_response_packet(7001, c),
             vectors.packet(24, 7001, c, reverse=True, payload=padded), master=False)
        step('new_READ_wire_ACK_commit', vectors.packet(16, c, (7001 + READ_IMAGE_LEN)), vectors.packet(16, c, n))
        select = vectors.packet(24, c, (7001 + READ_IMAGE_LEN), payload=vectors.native_select(0, 3))
        step('new_SELECT_native', select,
             vectors.packet(24, c, n, payload=vectors.native_select(0, 3)))
        response = helpers.native_response37(0, 3)
        image = encode61.ctl61(response)
        step('new_SELECT_response_61', vectors.packet(24, n, c + rp.CONTROL_REQUEST_LEN, reverse=True, payload=response),
             vectors.packet(24, (7001 + READ_IMAGE_LEN), c + rp.CONTROL_REQUEST_LEN, reverse=True, payload=image), master=False)
        params['enabled'] = 1
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        if response_ready:
            # Retain the same SELECT/OPERATE bytes and native/wire frontiers. The new
            # contract additionally requires a genuine relay ACK before the shaped response.
            ctl = Path(__file__).resolve().parent.parent / 'ctl_timing_01'
            sys.path.insert(0, str(ctl))
            import model_log_view as log_view
            import reset_application_check as rac
            import model_response_ready as timing_proof
            from model_driver import veth_for
            log = log_view.log_path()
            if log is None:
                raise ValueError('rearm response-ready proof requires the model T-clock log')
            written = json.loads((Path(os.environ['OUT']) / 't_params_written.json').read_text())[-1]['written']
            rp.advance_timestamp()
            operate = vectors.packet(24, c + rp.CONTROL_REQUEST_LEN, 7001 + READ_IMAGE_LEN + IMAGE_LEN,
                                     payload=vectors.native_select(1, 4))
            want_operate = rp.preserve_options(operate, vectors.packet(24, c + rp.CONTROL_REQUEST_LEN,
                n + CONTROL_NATIVE, payload=vectors.native_select(1, 4)))
            rp.advance_timestamp()
            relay_ack = vectors.packet(16, n + CONTROL_NATIVE, c + 2 * rp.CONTROL_REQUEST_LEN, reverse=True)
            want_ack = rp.preserve_options(relay_ack, vectors.packet(16, 7001 + READ_IMAGE_LEN + IMAGE_LEN,
                c + 2 * rp.CONTROL_REQUEST_LEN, reverse=True))
            rp.advance_timestamp()
            response = helpers.native_response37(1, 4)
            image = encode61.ctl61(response)
            native_packet = vectors.packet(24, n + CONTROL_NATIVE, c + 2 * rp.CONTROL_REQUEST_LEN,
                                           reverse=True, payload=response)
            want_response = rp.preserve_options(native_packet, vectors.packet(24, 7001 + READ_IMAGE_LEN + IMAGE_LEN,
                c + 2 * rp.CONTROL_REQUEST_LEN, reverse=True, payload=image))
            outcomes = lambda: {name: scalar(m.register_read('p1.t_Ingress.outcomes', index, pipe=1))
                for name, index in (('ACK_COMMIT', 2), ('RESP_RELEASE', 3), ('OP_RELEASE', 5), ('WAIT_EXPIRED', 8), ('EXPIRED_DROP', 9))}
            before_t = outcomes()
            receive = {m._listen(port): port for port in ports}
            fast = {}
            for port in ports:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
                sock.bind((veth_for(port), 0))
                fast[port] = sock

            def collect(duration):
                ready, _, _ = select.select(list(receive), [], [], duration)
                packets = []
                for sock in ready:
                    while True:
                        try:
                            frame, address = sock.recvfrom(4096)
                        except BlockingIOError:
                            break
                        if address[2] != 4:
                            packets.append((receive[sock], frame))
                return packets

            m.drain(ports)
            offset = log_view.size(log)
            try:
                captured, relayed = response_ready_operate(lambda port, frame: fast[port].send(frame), collect,
                    MASTER.dev_port, RELAY.dev_port, operate, want_operate, relay_ack, native_packet, want_response)
            finally:
                for sock in fast.values():
                    sock.close()
            tail = m.capture(ports, timeout=.6, quiet=.15)
            captured.extend((port, frame) for port, frames in tail.items() for frame in frames)
            after_t = outcomes()
            arrivals = [frame for port, frame in captured if port == RELAY.dev_port]
            master_frames = [frame for port, frame in captured if port == MASTER.dev_port]
            request_exact = relayed and len(arrivals) == 1 and same_frame(arrivals[0], want_operate, operate)
            response_exact = len(master_frames) == 2 and same_frame(master_frames[1], want_response, native_packet)
            report.add('new_OPERATE_hold_native', 'one exact frame', len(arrivals), ok=request_exact,
                       received=[frame.hex() for frame in arrivals])
            report.add('OPERATE_release_count', 1, after_t['OP_RELEASE'])
            report.add('new_OPERATE_response_61', 'one exact frame',
                       sum(same_frame(frame, want_response, native_packet) for frame in master_frames), ok=response_exact,
                       received=[frame.hex() for frame in master_frames], want=want_response.hex())
            records = rac.ingress_records(log_view.lines_since(log, offset))
            for ordinal, record in enumerate(records):
                record['ordinal'] = ordinal
                if record['t_units'] is not None:
                    record['t_units'] &= ~1
            trecs = [record for record in records if record['pipe'] == 1]
            find = lambda action: next((record for record in trecs if 't_Ingress.' + action in record['actions']), None)
            stamp = lambda action: find(action)['t_units'] if find(action) else None
            ack_record, response_record = find('hold_ack'), find('admit_response')
            point = dict(tag='new_OPERATE_response_ready', order='ack_first', t0_units=stamp('admit_t0'),
                held_ack_units=stamp('hold_ack'), response_arrival_units=stamp('admit_response'),
                ack_release_units=stamp('release_ack_commit'), response_release_units=stamp('release_response_counted'),
                ack_arrival_ordinal=ack_record['ordinal'] if ack_record else None,
                response_arrival_ordinal=response_record['ordinal'] if response_record else None,
                lane={name: after_t[name] - before_t[name] for name in ('ACK_COMMIT', 'RESP_RELEASE', 'WAIT_EXPIRED', 'EXPIRED_DROP')},
                master_frames=['ack' if same_frame(frame, want_ack, relay_ack) else
                               'response' if same_frame(frame, want_response, native_packet) else 'other' for frame in master_frames],
                operate_anchor_units=stamp('arm_operate_anchor'), operate_release_units=stamp('release_operate_counted'),
                written_units=written, native_octets=len(response), image_octets=len(image))
            problems = timing_proof.committed_problems(point, written['gap'], written['response_wait_timeout'])
            hold = timing_proof.delta(point['operate_release_units'], point['operate_anchor_units'])
            if hold is None or hold < written['op_j'] or after_t['OP_RELEASE'] - before_t['OP_RELEASE'] != 1:
                problems.append('independent OPERATE J hold/single release not proved on T clock')
            report.record['meta']['timing_contract'] = timing_profile['timing_contract']
            report.record['meta']['response_ready_operate'] = point
            report.add('new_OPERATE_genuine_ACK_full_D_and_J_on_T_clock', [], problems, point=point)
            if not request_exact or not response_exact or problems:
                raise AssertionError('timed OPERATE incomplete; do not derive a reset ACK from an undelivered image')
        else:
            operate = vectors.packet(24, c + rp.CONTROL_REQUEST_LEN, (7001 + READ_IMAGE_LEN + IMAGE_LEN), payload=vectors.native_select(1, 4))
            step('new_OPERATE_hold_native', operate,
                 vectors.packet(24, c + rp.CONTROL_REQUEST_LEN, n + CONTROL_NATIVE, payload=vectors.native_select(1, 4)))
            report.add('OPERATE_release_count', 1, scalar(m.register_read('p1.t_Ingress.outcomes', 5, pipe=1)))
            response = helpers.native_response37(1, 4)
            image = encode61.ctl61(response)
            step('new_OPERATE_response_61', vectors.packet(24, n + CONTROL_NATIVE, c + 2 * rp.CONTROL_REQUEST_LEN, reverse=True, payload=response),
                 vectors.packet(24, (7001 + READ_IMAGE_LEN + IMAGE_LEN), c + 2 * rp.CONTROL_REQUEST_LEN, reverse=True, payload=image), master=False)
        step('qualified_RST', vectors.packet(20, c + 2 * rp.CONTROL_REQUEST_LEN, (7001 + READ_IMAGE_LEN + 2 * IMAGE_LEN)),
             vectors.packet(20, c + 2 * rp.CONTROL_REQUEST_LEN, n + 2 * CONTROL_NATIVE))
        report.add('RST_retired', 0x200, scalar(snapshot()['N']['owner']) >> 16)
        handshake(9000, 11000)
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / 'rearm_results.json')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
