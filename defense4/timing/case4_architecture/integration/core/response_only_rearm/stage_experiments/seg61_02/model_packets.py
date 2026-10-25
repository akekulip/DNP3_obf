"""Extended compiled-model packet gate for the E61 candidate.

The model path reuses the smoke fixture shape but exercises the packet-level
cases that must hold before larger campaigns: transport sequence wrap, repeated
mixed traffic with 12/24-byte growth, retransmission without double growth,
TCP sequence wrap, close/rearm, and explicit admission negatives.

Run under launch_model.sh for actual model execution. Run with
``--validate-vectors`` for offline packet/oracle validation; this performs no
model, hardware, or network work.
"""
import argparse
import hashlib
import importlib.util
import json
import os
import struct
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
REARM = HERE.parents[1]
ARCH = HERE.parents[4]
sys.path[:0] = [str(HERE.parent / 'seg61_01'), str(HERE.parent / 'read_reencode_01'),
                str(ARCH / 'protocol/hw_vepa'), str(ARCH / 'protocol/hw_vepa/tests')]
import encode61
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent))  # read_policy_expect is beside this file
import read_policy_expect as rp  # noqa: E402
rp.install(encode61)
import dnp3_std as std
import wire_check
import pcaptk

IMAGE_LEN = rp.CONTROL_IMAGE_LEN
READ_NATIVE = rp.READ_NATIVE_LEN
CONTROL_NATIVE = rp.CONTROL_NATIVE_LEN
READ_REQUEST = 25 if rp.SEL751 else 20
CONTROL_REQUEST = rp.CONTROL_REQUEST_LEN
CONTROL_GROWTH = IMAGE_LEN - CONTROL_NATIVE
READ_IMAGE_LEN = rp.read_image_len(IMAGE_LEN)   # the policy READ image (141) on a policy build, else 61
READ_GROWTH = READ_IMAGE_LEN - READ_NATIVE
TCP_PAYLOAD_OFFSET = 54


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def read_user(seq, statuses, app=0xc0, iin=b'\x80\x00'):
    if len(statuses) != 23:
        raise ValueError('READ vector needs 23 status octets')
    return bytes([0xc0 | (seq & 0x3f), app, 0x81]) + iin + bytes.fromhex('0a02000016') + bytes(statuses)


def read_frame(seq, statuses, app=0xc0, iin=b'\x80\x00'):
    if rp.SEL751:
        native = rp.read_frames(seq, app & 15, variant=seq & 1)[1]
        head, user = std.deframe(native)
        return std.frame(head, user[:3] + iin + user[5:])
    return std.frame(bytes.fromhex('0564264401000000'), read_user(seq, statuses, app, iin))


def crob_object(index=1, code=1, count=1, on=100, off=100, status=0):
    return (bytes.fromhex('0c01280100') + struct.pack('<H', index) + bytes([code, count])
            + struct.pack('<I', on) + struct.pack('<I', off) + bytes([status]))


def control_request(seq=0, app=0, fc=3, index=1, code=1, count=1, on=100, off=100, status=0):
    if rp.SEL751:
        return rp.relay_control_frame(seq, app, fc, statuses=(status, status))
    user = bytes([0xc0 | (seq & 0x3f), 0xc0 | (app & 0x0f), fc]) + crob_object(index, code, count, on, off, status)
    return std.frame(bytes.fromhex('05641ac40a000100'), user)


def control_response(seq=0, app=0, fc=3, index=1, code=1, count=1, on=100, off=100,
                     status=0, iin=b'\x00\x00', con=False):
    if rp.SEL751:
        native = rp.relay_control_frame(seq, app, fc, response=True, statuses=(status, status), iin=iin)
        if con:
            head, user = std.deframe(native)
            native = std.frame(head, user[:1] + bytes([user[1] | 0x20]) + user[2:])
        return native
    app_ctrl = (0xe0 if con else 0xc0) | (app & 0x0f)
    user = (bytes([0xc0 | (seq & 0x3f), app_ctrl, 0x81]) + iin
            + crob_object(index, code, count, on, off, status))
    return std.frame(bytes.fromhex('05641c4401000a00'), user)


def tcp_payload(frame):
    total = int.from_bytes(frame[16:18], 'big')
    ihl = (frame[14] & 0x0f) * 4
    tcp = 14 + ihl
    doff = (frame[tcp + 12] >> 4) * 4
    return frame[tcp + doff:14 + total]


def tcp_seq(frame):
    return int.from_bytes(frame[38:42], 'big')


def tcp_ack(frame):
    return int.from_bytes(frame[42:46], 'big')


def tcp_flags(frame):
    return frame[47]


def fix_checksums(packet):
    frame = bytearray(packet)
    ihl = (frame[14] & 0x0f) * 4
    tcp_off = 14 + ihl
    total_len = int.from_bytes(frame[16:18], 'big')
    frame[24:26] = b'\0\0'
    frame[24:26] = struct.pack('!H', _checksum(frame[14:tcp_off]))
    frame[tcp_off + 16:tcp_off + 18] = b'\0\0'
    pseudo = frame[26:34] + bytes((0, 6)) + struct.pack('!H', total_len - ihl)
    frame[tcp_off + 16:tcp_off + 18] = struct.pack('!H', _checksum(pseudo + frame[tcp_off:14 + total_len]))
    return bytes(frame)


def _checksum(data):
    if len(data) & 1:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def mutate_payload(packet, payload):
    frame = bytearray(packet)
    total = int.from_bytes(frame[16:18], 'big')
    old_payload = tcp_payload(frame)
    if len(old_payload) != len(payload):
        raise ValueError('payload length change not supported here')
    frame[rp.tcp_payload_offset(frame):14 + total] = payload
    return fix_checksums(bytes(frame))


def assert_ip_tcp(frame):
    ip_ok, tcp_ok, _ = wire_check.ip_tcp_checksum({'frame': frame})
    if not (ip_ok and tcp_ok):
        raise AssertionError('bad IP/TCP checksum')


def validate_read_image(native, image, expected_statuses=None):
    if rp.POLICY:
        return rp.check_read_image(native, image, None if rp.SEL751 else expected_statuses)
    if len(native) != READ_NATIVE or len(image) != IMAGE_LEN:
        raise AssertionError('READ length mismatch: %d -> %d' % (len(native), len(image)))
    if not wire_check.dnp3_ok(image)[0]:
        raise AssertionError('READ image DNP3 CRC check failed')
    _, native_user = std.deframe(native)
    _, image_user = std.deframe(image)
    _, native_points = std.check_read_response(native_user)
    _, image_points = std.check_read_response(image_user, native_points)
    if image_user[:5] != native_user[:5]:
        raise AssertionError('READ application header/IIN changed')
    if expected_statuses is not None and [obj[3][0] for obj in image_points] != list(expected_statuses):
        raise AssertionError('READ statuses changed')
    return {'native_len': len(native), 'image_len': len(image), 'points': len(image_points),
            'iin': image_user[3:5].hex(), 'transport_seq': image_user[0] & 0x3f}


def validate_control_image(req, native, image, require_success=True):
    if len(native) != CONTROL_NATIVE or len(image) != IMAGE_LEN:
        raise AssertionError('control length mismatch: %d -> %d' % (len(native), len(image)))
    if not wire_check.dnp3_ok(image)[0]:
        raise AssertionError('control image DNP3 CRC check failed')
    frames = encode61.split_frames(image)
    fragments, events = std.reassemble(frames)
    _, native_user = std.deframe(native)
    _, req_user = std.deframe(req)
    if events or len(fragments) != 1:
        raise AssertionError('control transport reassembly failed: %r %r' % (fragments, events))
    if fragments[0][0] != native_user[1:]:
        raise AssertionError('control application bytes changed')
    if require_success:
        std.check_control_echo(req_user, std.fragment_user(fragments[0][0]))
    outcome = std.check_control_outcome(req_user, std.fragment_user(fragments[0][0]))
    if outcome['authorizes_or_succeeds'] != require_success:
        raise AssertionError('control success semantics failed: %r' % outcome)
    ths = [std.deframe(frame)[1][0] for frame in frames]
    return {'native_len': len(native), 'image_len': len(image), 'frame_lengths': [len(f) for f in frames],
            'transport_headers': ths, 'first_seq': ths[0] & 0x3f,
            'authorizes_or_succeeds': outcome['authorizes_or_succeeds']}


def vector_cases():
    cases = []
    if rp.SEL751:
        for seq in range(64):
            for cls in ('mixed', 'integrity'):
                request, native = rp.read_frames(seq, seq & 15, cls, seq & 1)
                cases.append(('%s_seq_%02d' % (cls, seq),
                              validate_read_image(native, encode61.read61(native))))
            request = control_request(seq, seq & 15)
            native = control_response(seq, seq & 15)
            cases.append(('SBO_seq_%02d' % seq, validate_control_image(request, native, encode61.ctl61(native))))
        for name, statuses, iin in (('first_control_status', (1, 0), b'\x00\x00'),
                                    ('second_control_status', (0, 1), b'\x00\x00'),
                                    ('both_control_statuses', (1, 2), b'\x00\x00'),
                                    ('control_iin_error', (0, 0), b'\x00\x01')):
            native = rp.relay_control_frame(response=True, statuses=statuses, iin=iin)
            image = encode61.ctl61(native)
            cases.append((name, validate_control_image(control_request(), native, image, require_success=False)))
        for name, native in (('control_con', control_response(con=True)),):
            if encode61.ctl61(native) is not None:
                raise AssertionError('%s unexpectedly encoded' % name)
            cases.append((name, {'admitted_by_oracle': False}))
        if encode61.read61(bytes(49)) is not None:
            raise AssertionError('obsolete READ49 admitted by relay oracle')
        cases.append(('obsolete_READ49', {'admitted_by_oracle': False}))
        return cases
    for seq in range(64):
        statuses = [((seq * 7 + i * 13) & 0xff) | (0x80 if i % 5 == 0 else 0) for i in range(23)]
        native = read_frame(seq, statuses, app=0xc0 | (seq & 0x0f),
                            iin=bytes([(0x80 if seq & 1 else 0), seq & 0x10]))
        image = encode61.read61(native)
        cases.append(('READ_seq_%02d' % seq, validate_read_image(native, image, statuses)))
    for seq in range(64):
        kwargs = dict(seq=seq, app=seq & 0x0f, fc=3 + (seq & 1), index=1 + seq,
                      code=1 + (seq & 0x0f), count=1, on=0x1000 + seq * 3,
                      off=0x2000 + seq * 5, status=0)
        req = control_request(**kwargs)
        native = control_response(**kwargs)
        image = encode61.ctl61(native)
        cases.append(('SBO_seq_%02d' % seq, validate_control_image(req, native, image)))
    negatives = {
        'read_wrong_shape': encode61.read61(std.frame(bytes.fromhex('0564264401000000'),
                                                     read_user(0, range(23))[:9] + b'\x17' + read_user(0, range(23))[10:])),
        'control_con': encode61.ctl61(control_response(con=True)),
        'control_status': encode61.ctl61(control_response(status=1)),
    }
    for name, result in negatives.items():
        if result is not None:
            raise AssertionError('%s unexpectedly encoded to 61' % name)
        cases.append((name, {'admitted_by_oracle': False}))
    return cases


def run_vector_validation(out=None):
    record = {'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), 'cases': []}
    ok = True
    try:
        for name, detail in vector_cases():
            record['cases'].append({'name': name, 'ok': True, 'detail': detail})
    except Exception:
        ok = False
        record['cases'].append({'name': 'exception', 'ok': False, 'detail': traceback.format_exc()})
    if out:
        out = Path(out)
        out.mkdir(parents=True, exist_ok=True)
        (out / 'packet_vector_results.json').write_text(json.dumps(record, indent=2) + '\n')
    else:
        print(json.dumps(record, indent=2))
    return 0 if ok else 1


class PacketGate:
    def __init__(self, report, model, helpers, cp):
        rp.configure_helpers(helpers)
        rp.report_endpoint(report)
        self.report, self.m, self.h, self.cp = report, model, helpers, cp
        self.v, self.rs = helpers.vectors, helpers.rs
        self.master, self.relay, self.pm = helpers.MASTER, helpers.OUTSTATION, helpers.PM
        self.ports = sorted({self.master.dev_port, self.relay.dev_port})
        self.captures = {'sent': [], 'received': []}

    def configure(self):
        h, m, cp = self.h, self.m, self.cp
        m.enable_ports(self.ports + h.FRONT_LOOPS)
        m.enable_ports([p for p in h.LOOP_PORTS if p not in h.FRONT_LOOPS])
        self.reflectors = [h.Reflector(p) for p in h.FRONT_LOOPS]
        for reflector in self.reflectors:
            reflector.start()
        rows = cp.n_ports_rows(self.master.dev_port, self.relay.dev_port, self.master.ip_int, self.relay.ip_int,
                               n_ack_return=self.pm.n_ack_return)
        rows += cp.n_connection_rows(self.relay, self.master, n_ack_return=self.pm.n_ack_return)
        rows += cp.n_read_rows(self.relay, self.master)
        for table, key, action, data, priority in rows:
            m.add('p0.n_' + table, dict(key), 'n_' + action, dict(data), priority)
        dc = dict(zip(('index', 'code', 'repeat', 'on', 'off'), self.v.decoy_config()))
        for source, dest in ((self.master, self.relay), (self.relay, self.master)):
            key = {'hdr.ip.src': source.ip_int, 'hdr.ip.dst': dest.ip_int,
                   'hdr.tcp.sport': source.port, 'hdr.tcp.dport': dest.port}
            m.add('p0.n_Ingress.data_connection', key, 'n_Ingress.configure', dc)
        for table, key, action, data, priority in cp.e_conn_rows(0, self.relay, self.master,
                                                                 n_ack_return=self.pm.n_ack_return):
            m.add('p0.r_' + table, dict(key), 'r_' + action, dict(data), priority)
        if rp.POLICY:   # pipe-1 READ padder's size enable, mirroring E's fwd_conn row (cp.p1_pad_rows)
            for table, key, action, data, priority in cp.p1_pad_rows(self.relay, self.master, True):
                m.add(table, dict(key), action, dict(data), priority)
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params',
                      dict(da=50_000_000, readiness=400_000_000, cap=16_000_000,
                           gap=50_000_000, op_j=200_000_000, budget=240_000, enabled=0))

    def add(self, name, expect, actual, ok=None, **extra):
        ok = expect == actual if ok is None else ok
        self.report.add(name, expect, actual, ok=ok, **extra)
        if not ok:
            raise AssertionError(name)

    def exchange(self, name, sent, expected=None, reverse=False, allow_drop=False):
        expected = rp.preserve_options(sent, expected)
        rp.advance_timestamp()
        self.captures['sent'].append((time.time_ns() // 1000, sent))
        got = self.m.exchange(self.relay.dev_port if reverse else self.master.dev_port,
                              sent, self.ports, timeout=3, quiet=.15)
        flat = [frame for frames in got.values() for frame in frames]
        self.captures['received'].extend((time.time_ns() // 1000, frame) for frame in flat)
        if allow_drop:
            self.add(name, 'protected flow drops excluded response', len(flat), ok=not flat,
                     sent=sent, received=got)
            return flat
        exact = len(flat) == 1 and self.h.same_frame(flat[0], expected, sent)
        self.add(name, 'one exact frame', len(flat), ok=exact, sent=sent, received=got, expected_frame=expected)
        assert_ip_tcp(flat[0])
        return flat[0]

    def handshake(self, cseq, sseq, tag=''):
        self.exchange(tag + 'SYN', self.v.packet(2, cseq, mss=1460), self.v.packet(2, cseq, mss=1460))
        self.exchange(tag + 'SYNACK', self.v.packet(18, sseq, cseq + 1, reverse=True, mss=1460),
                      self.v.packet(18, sseq, cseq + 1, reverse=True, mss=1460), reverse=True)
        self.exchange(tag + 'ACK', self.v.packet(16, cseq + 1, sseq + 1), self.v.packet(16, cseq + 1, sseq + 1))
        return cseq + 1, sseq + 1, sseq + 1

    def read_exchange(self, name, cseq, native_sseq, wire_sseq, seq=0, statuses=None, iin=b'\x80\x00',
                      expect_growth=True):
        statuses = statuses if statuses is not None else list(range(23))
        request = self.rs.request_packet(seq=cseq, ack=wire_sseq, app=0xc0 | (seq & 15))
        self.exchange(name + '_request', request, self.rs.request_packet(seq=cseq, ack=native_sseq, app=0xc0 | (seq & 15)))
        ack = self.rs.ack_packet(seq=native_sseq, ack=cseq + READ_REQUEST)
        self.exchange(name + '_server_ack', ack, self.rs.ack_packet(seq=wire_sseq, ack=cseq + READ_REQUEST), reverse=True)
        native = read_frame(seq, statuses, app=0xc0 | (seq & 0x0f), iin=iin)
        image = encode61.read61(native)
        validate_read_image(native, image, statuses)
        got = self.exchange(name + '_response61',
                            self.v.packet(24, native_sseq, cseq + READ_REQUEST, reverse=True, payload=native),
                            self.v.packet(24, wire_sseq, cseq + READ_REQUEST, reverse=True, payload=image),
                            reverse=True)
        self.add(name + '_payload_len', READ_IMAGE_LEN, len(tcp_payload(got)))
        if expect_growth:
            self.exchange(name + '_mapped_ack',
                          self.v.packet(16, cseq + READ_REQUEST, wire_sseq + READ_IMAGE_LEN),
                          self.v.packet(16, cseq + READ_REQUEST, native_sseq + READ_NATIVE))
        return cseq + READ_REQUEST, native_sseq + READ_NATIVE, wire_sseq + READ_IMAGE_LEN

    def control_exchange(self, name, cseq, native_sseq, wire_sseq, seq=0, app=0, fc=3, **kw):
        req = control_request(seq=seq, app=app, fc=fc, **kw)
        self.exchange(name + '_request', self.v.packet(24, cseq, wire_sseq, payload=req),
                      self.v.packet(24, cseq, native_sseq, payload=req))
        native = control_response(seq=seq, app=app, fc=fc, **kw)
        image = encode61.ctl61(native)
        validate_control_image(req, native, image)
        got = self.exchange(name + '_response61',
                            self.v.packet(24, native_sseq, cseq + CONTROL_REQUEST, reverse=True, payload=native),
                            self.v.packet(24, wire_sseq, cseq + CONTROL_REQUEST, reverse=True, payload=image),
                            reverse=True)
        self.add(name + '_payload_len', IMAGE_LEN, len(tcp_payload(got)))
        self.exchange(name + '_mapped_ack',
                      self.v.packet(16, cseq + CONTROL_REQUEST, wire_sseq + IMAGE_LEN),
                      self.v.packet(16, cseq + CONTROL_REQUEST, native_sseq + CONTROL_NATIVE))
        return cseq + CONTROL_REQUEST, native_sseq + CONTROL_NATIVE, wire_sseq + IMAGE_LEN

    def failed_select_case(self, name, cseq, native_sseq, wire_sseq, statuses, iin):
        """Faithful failed SELECT delivery grants no OPERATE authority; a fresh connection recovers."""
        req = control_request()
        self.exchange(name + '_SELECT_request', self.v.packet(24, cseq, wire_sseq, payload=req),
                      self.v.packet(24, cseq, native_sseq, payload=req))
        cseq += len(req)
        native = rp.relay_control_frame(response=True, statuses=statuses, iin=iin)
        image = encode61.ctl61(native)
        info = validate_control_image(req, native, image, require_success=False)
        before = self.growth()
        got = self.exchange(name + '_failed_SELECT_delivered',
                            self.v.packet(24, native_sseq, cseq, reverse=True, payload=native),
                            self.v.packet(24, wire_sseq, cseq, reverse=True, payload=image), reverse=True)
        validate_control_image(req, native, tcp_payload(got), require_success=False)
        self.add(name + '_failed_SELECT_no_success_semantics', False, info['authorizes_or_succeeds'])
        self.add(name + '_failed_SELECT_growth_once', before + CONTROL_GROWTH, self.growth())
        native_sseq += len(native)
        wire_sseq += len(image)
        self.exchange(name + '_failed_SELECT_ACK', self.v.packet(16, cseq, wire_sseq),
                      self.v.packet(16, cseq, native_sseq))
        operate = control_request(seq=1, app=1, fc=4)
        self.exchange(name + '_OPERATE_without_successful_SELECT_blocked',
                      self.v.packet(24, cseq, wire_sseq, payload=operate), allow_drop=True)
        self.add(name + '_blocked_OPERATE_no_growth', before + CONTROL_GROWTH, self.growth())
        # The dropped TCP slot is outstanding: retire it before testing recovery.
        self.exchange(name + '_reset', self.v.packet(20, cseq, wire_sseq),
                      self.v.packet(20, cseq, native_sseq))
        cseq, native_sseq, wire_sseq = self.handshake(cseq + 2000, native_sseq + 2000, name + '_recovery_')
        cseq, native_sseq, wire_sseq = self.control_exchange(name + '_fresh_SELECT', cseq, native_sseq, wire_sseq)
        cseq, native_sseq, wire_sseq = self.control_exchange(name + '_fresh_OPERATE', cseq, native_sseq, wire_sseq,
                                                            seq=1, app=1, fc=4)
        self.close(cseq, native_sseq, wire_sseq, name + '_recovery_close')
        return self.handshake(cseq + 2000, native_sseq + 2000, name + '_next_')

    def growth(self):
        acct = self.m.register_read('p0.r_Egress.acct', 0, pipe=0)
        front = self.m.register_read('p0.r_Egress.front', 0, pipe=0)
        return (self.h.scalar({k: v for k, v in acct.items() if k.endswith('.lo')}) - self.h.scalar(front)) & 0xffffffff

    def close(self, cseq, native_sseq, wire_sseq, tag):
        self.exchange(tag + '_fin', self.v.packet(17, cseq, wire_sseq), self.v.packet(17, cseq, native_sseq))
        self.exchange(tag + '_fin_ack', self.v.packet(17, native_sseq, cseq + 1, reverse=True),
                      self.v.packet(17, wire_sseq, cseq + 1, reverse=True), reverse=True)
        self.exchange(tag + '_last_ack', self.v.packet(16, cseq + 1, wire_sseq + 1),
                      self.v.packet(16, cseq + 1, native_sseq + 1))

    def run(self):
        # Start near wrap in a fresh lifetime. A near-wrap SYN after a low-ISN
        # retired lifetime is deliberately stale under the serial-number guard.
        wc, wn, ww = self.handshake(0xffffffe0, 0xfffffff0, 'wrap_')
        wc, wn, ww = self.read_exchange('wrap_read', wc, wn, ww, seq=62)
        self.close(wc, wn, ww, 'wrap_close')
        cseq, native_sseq, wire_sseq = self.handshake(100, 900, 'base_')
        expected_growth = 0
        for seq in range(64):
            statuses = [((seq * 11 + i * 17) & 0xff) | (0x80 if i in (0, 7, 22) else 0) for i in range(23)]
            cseq, native_sseq, wire_sseq = self.read_exchange('read_seq_%02d' % seq, cseq, native_sseq, wire_sseq,
                                                              seq=seq, statuses=statuses,
                                                              iin=bytes([0x80 if seq & 1 else 0, seq & 0x10]))
            expected_growth += READ_GROWTH
        for seq in range(64):
            fc = 3 + (seq & 1)
            cseq, native_sseq, wire_sseq = self.control_exchange(
                'sbo_seq_%02d' % seq, cseq, native_sseq, wire_sseq, seq=seq, app=seq & 0x0f, fc=fc,
                index=1 + seq // 2, code=1 + ((seq // 2) & 0x0f), on=0x1000 + (seq // 2) * 3, off=0x2000 + (seq // 2) * 5)
            expected_growth += CONTROL_GROWTH
        self.add('mixed_persistent_growth', expected_growth, self.growth())

        # Consistent retransmission: replay the same response before its ACK; ACK maps once.
        request = self.rs.request_packet(seq=cseq, ack=wire_sseq)
        self.exchange('retx_request', request, self.rs.request_packet(seq=cseq, ack=native_sseq))
        ack = self.rs.ack_packet(seq=native_sseq, ack=cseq + READ_REQUEST)
        self.exchange('retx_server_ack', ack, self.rs.ack_packet(seq=wire_sseq, ack=cseq + READ_REQUEST), reverse=True)
        before = self.growth()
        native = read_frame(7, [0x55] * 23)
        image = encode61.read61(native)
        first = self.exchange('retx_response_first',
                              self.v.packet(24, native_sseq, cseq + READ_REQUEST, reverse=True, payload=native),
                              self.v.packet(24, wire_sseq, cseq + READ_REQUEST, reverse=True, payload=image), reverse=True)
        second = self.exchange('retx_response_second',
                               self.v.packet(24, native_sseq, cseq + READ_REQUEST, reverse=True, payload=native),
                               self.v.packet(24, wire_sseq, cseq + READ_REQUEST, reverse=True, payload=image), reverse=True)
        self.add('retx_identical_image',
                 tcp_payload(first).hex() if rp.TCP_TIMESTAMPS else first.hex(),
                 tcp_payload(second).hex() if rp.TCP_TIMESTAMPS else second.hex())
        if rp.TCP_TIMESTAMPS:
            self.add('retx_new_timestamp_preserved', True, rp.timestamp_values(second)[0] > rp.timestamp_values(first)[0])
        self.add('retx_no_doublegrowth_before_ack', before + READ_GROWTH, self.growth())
        self.exchange('retx_ack_maps_once', self.v.packet(16, cseq + READ_REQUEST, wire_sseq + READ_IMAGE_LEN),
                      self.v.packet(16, cseq + READ_REQUEST, native_sseq + READ_NATIVE))
        cseq += READ_REQUEST
        native_sseq += READ_NATIVE
        wire_sseq += READ_IMAGE_LEN

        # Excluded responses are tested with a real outstanding request. A
        # subsequent legal response must still complete that same transaction.
        request = self.rs.request_packet(seq=cseq, ack=wire_sseq)
        self.exchange('neg_read_request', request, self.rs.request_packet(seq=cseq, ack=native_sseq))
        self.exchange('neg_read_ack', self.rs.ack_packet(seq=native_sseq, ack=cseq + READ_REQUEST),
                      self.rs.ack_packet(seq=wire_sseq, ack=cseq + READ_REQUEST), reverse=True)
        good = read_frame(0, range(23))
        head, user = std.deframe(good)
        bad_user = user[:5] + b'\xff' + user[6:] if rp.SEL751 else user[:9] + b'\x17' + user[10:]
        bad_read = std.frame(head, bad_user)
        con_read = std.frame(head, user[:1] + b'\xe0' + user[2:])
        before = self.growth()
        for name, native in (('neg_read_wrongshape', bad_read), ('neg_read_CON', con_read)):
            self.exchange(name, self.v.packet(24, native_sseq, cseq + READ_REQUEST, reverse=True, payload=native),
                          allow_drop=True, reverse=True)
        self.add('neg_read_no_growth', before, self.growth())
        self.exchange('neg_read_recovery', self.v.packet(24, native_sseq, cseq + READ_REQUEST, reverse=True, payload=good),
                      self.v.packet(24, wire_sseq, cseq + READ_REQUEST, reverse=True, payload=encode61.read61(good)), reverse=True)
        cseq, native_sseq, wire_sseq = cseq + READ_REQUEST, native_sseq + READ_NATIVE, wire_sseq + READ_IMAGE_LEN
        self.exchange('neg_read_recovery_ack', self.v.packet(16, cseq, wire_sseq), self.v.packet(16, cseq, native_sseq))
        req = control_request()
        self.exchange('neg_control_request', self.v.packet(24, cseq, wire_sseq, payload=req),
                      self.v.packet(24, cseq, native_sseq, payload=req))
        before = self.growth()
        excluded = [('neg_control_con', control_response(con=True))]
        if not rp.SEL751:
            excluded += [('neg_control_status', control_response(status=1)),
                         ('neg_control_iin_error', control_response(iin=b'\x00\x01'))]
        for name, native in excluded:
            self.exchange(name, self.v.packet(24, native_sseq, cseq + CONTROL_REQUEST, reverse=True, payload=native),
                          allow_drop=True, reverse=True)
        self.add('neg_control_no_growth', before, self.growth())
        good = control_response()
        self.exchange('neg_control_recovery', self.v.packet(24, native_sseq, cseq + CONTROL_REQUEST, reverse=True, payload=good),
                      self.v.packet(24, wire_sseq, cseq + CONTROL_REQUEST, reverse=True, payload=encode61.ctl61(good)), reverse=True)
        cseq, native_sseq, wire_sseq = cseq + CONTROL_REQUEST, native_sseq + CONTROL_NATIVE, wire_sseq + IMAGE_LEN
        self.exchange('neg_control_recovery_ack', self.v.packet(16, cseq, wire_sseq), self.v.packet(16, cseq, native_sseq))
        cseq, native_sseq, wire_sseq = self.control_exchange('neg_recovered_operate', cseq, native_sseq, wire_sseq,
                                                            app=1, fc=4)
        self.close(cseq, native_sseq, wire_sseq, 'close')
        state = self.handshake(cseq + 1000, native_sseq + 1000, 'fresh_rearm_')
        if rp.SEL751:
            for tag, statuses, iin in (('first_status', (1, 0), b'\x00\x00'),
                                        ('second_status', (0, 1), b'\x00\x00'),
                                        ('both_statuses', (1, 2), b'\x00\x00'),
                                        ('iin_error', (0, 0), b'\x00\x01')):
                state = self.failed_select_case('failed_SELECT_' + tag, *state, statuses=statuses, iin=iin)
        if rp.SEL751:
            state = self.half_closed_rst(*state)
            if state is None:
                self.report.add('relay_fpa_close', 'run', 'not run: the half-closed RST case did not reconnect', ok=False)
            else:
                self.relay_fpa_close(*state)
        if rp.TCP_TIMESTAMPS:
            self.add('timestamp_options_receive_order', True,
                     rp.timestamp_order_ok([frame for _time, frame in self.captures['received']]))
        self.report.record['meta']['reflections'] = {r.port: r.summary() for r in self.reflectors}

    def n_state(self):
        m, h = self.m, self.h
        state = {n: m.register_read('p0.n_Ingress.' + n, 0, pipe=0)
                 for n in ('epoch', 'retry_epoch', 'owner', 'work.work')}
        state['busy'] = [h.scalar(m.register_read('p0.n_Ingress.count_busy', i, pipe=0)) for i in range(8)]
        return state

    def half_closed_rst(self, cseq, native_sseq, wire_sseq, tag='half_rst'):
        """c50 counterexample: a valid master RSTACK after master FIN + relay ACK (owner 0109).

        The work cell is held busy so the RST takes the actual busy_retry_rst path, then
        released. Reset forwarding, retirement and a fresh handshake+READ are recorded as
        separate checks; a failed SYN stops before any dependent READ is counted.
        """
        m, h, v, add = self.m, self.h, self.v, self.report.add
        meta = self.report.record['meta'].setdefault(tag, {})
        cseq, native_sseq, wire_sseq = self.read_exchange(tag + '_read', cseq, native_sseq, wire_sseq, seq=5)
        self.exchange(tag + '_master_FIN', v.packet(17, cseq, wire_sseq), v.packet(17, cseq, native_sseq))
        self.exchange(tag + '_relay_ACK', v.packet(16, native_sseq, cseq + 1, reverse=True),
                      v.packet(16, wire_sseq, cseq + 1, reverse=True), reverse=True)
        half = meta['half_closed'] = self.n_state()
        self.add(tag + '_owner_half_closed_0109', 0x109, h.scalar(half['owner']) >> 16)
        work = half['work.work']
        generation = work['n_Ingress.work.work.generation']
        generation = generation[0] if isinstance(generation, list) else generation
        # Hold the cell busy (phase1) with its real generation; restore phase4 on unlock.
        m.register_write('p0.n_Ingress.work.work', 0,
                         {'n_Ingress.work.work.generation': generation, 'n_Ingress.work.work.phase': 1}, pipe=0)
        m.drain(self.ports)
        sent = v.packet(20, cseq + 1, wire_sseq)
        self.captures['sent'].append((time.time_ns() // 1000, sent))
        m.send(self.master.dev_port, sent)
        anchor, deadline = None, time.monotonic() + 3
        while time.monotonic() < deadline:   # one register read per poll: the retry budget is finite
            busy2 = h.scalar(m.register_read('p0.n_Ingress.count_busy', 2, pipe=0))
            if busy2 > half['busy'][2]:
                anchor = busy2
                break
        meta['busy_anchor_before_unlock'] = anchor
        m.register_write('p0.n_Ingress.work.work', 0,
                         {'n_Ingress.work.work.generation': generation, 'n_Ingress.work.work.phase': 4}, pipe=0)
        got = m.capture(self.ports, timeout=3, quiet=.3)
        self.captures['received'].extend((time.time_ns() // 1000, f) for fs in got.values() for f in fs)
        after = meta['after_reset'] = self.n_state()
        meta['received'] = {str(p): [f.hex() for f in fs] for p, fs in got.items()}
        expected = v.packet(20, cseq + 1, native_sseq)
        relay_frames = got.get(self.relay.dev_port, [])
        add(tag + '_busy_retry_rst_anchor_before_unlock', True, anchor is not None)
        add(tag + '_RSTACK_forwarded_exactly_once', 1,
            sum(h.same_frame(f, expected, sent) for f in relay_frames),
            ok=len(relay_frames) == 1 and h.same_frame(relay_frames[0], expected, sent) and
            not got.get(self.master.dev_port), received=meta['received'], expected_frame=expected.hex())
        add(tag + '_no_stale', 0, after['busy'][4] - half['busy'][4])
        add(tag + '_not_exhausted', 0, after['busy'][3] - half['busy'][3])
        add(tag + '_retired_0200', 0x200, h.scalar(after['owner']) >> 16)
        # A failed SYN ends the case: the dependent READ is never attempted or counted.
        try:
            state = self.handshake(cseq + 3000, native_sseq + 3000, tag + '_fresh_')
        except AssertionError:
            add(tag + '_fresh_handshake', 'completed', 'failed', ok=False)
            return None
        add(tag + '_fresh_handshake', 'completed', 'completed')
        return self.read_exchange(tag + '_fresh_read', *state, seq=6)

    def relay_fpa_close(self, cseq, native_sseq, wire_sseq, tag='relay_fpa'):
        """Graceful close as the SEL-751 performs it: its FIN is FIN+PSH+ACK (0x19, no payload; native02 and
        rc01_hw_c51_20261024_20). c51 dropped it and left the tuple half-closed; the FIN must reach the master
        exactly once with mapped sequence, the master's last ACK must map back, and the same tuple must reconnect."""
        v, add = self.v, self.report.add
        cseq, native_sseq, wire_sseq = self.read_exchange(tag + '_read', cseq, native_sseq, wire_sseq, seq=7)
        self.exchange(tag + '_master_FIN', v.packet(17, cseq, wire_sseq), v.packet(17, cseq, native_sseq))
        self.exchange(tag + '_relay_ACK', v.packet(16, native_sseq, cseq + 1, reverse=True),
                      v.packet(16, wire_sseq, cseq + 1, reverse=True), reverse=True)
        self.exchange(tag + '_relay_FPA_FIN', v.packet(25, native_sseq, cseq + 1, reverse=True),
                      v.packet(25, wire_sseq, cseq + 1, reverse=True), reverse=True)
        self.exchange(tag + '_master_last_ACK', v.packet(16, cseq + 1, wire_sseq + 1),
                      v.packet(16, cseq + 1, native_sseq + 1))
        owner = self.h.scalar(self.n_state()['owner']) >> 16
        add(tag + '_owner_closed', 'closed (0x10f or 0x200)', hex(owner), ok=owner in (0x10f, 0x200))
        try:
            state = self.handshake(cseq + 4000, native_sseq + 4000, tag + '_fresh_')
        except AssertionError:
            add(tag + '_fresh_handshake', 'completed', 'failed', ok=False)
            return None
        add(tag + '_fresh_handshake', 'completed', 'completed')
        return self.read_exchange(tag + '_fresh_read', *state, seq=8)


def model_main():
    h = load('_seg61_packets_helpers', REARM.parent / 'response_only/model_drive_composite.py')
    cp = load('_seg61_packets_cp', REARM / 'cp.py')
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False,
                      scope='E61 extended compiled packet gate',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    gate = None
    try:
        gate = PacketGate(report, h.Model(ports=[], enable=False), h, cp)
        gate.configure()
        gate.run()
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    if gate is not None:
        for name, packets in gate.captures.items():
            pcaptk.write_pcap(str(out / (name + '.pcap')), packets)
        report.record['meta']['capture_sha256'] = {
            name: hashlib.sha256((out / (name + '.pcap')).read_bytes()).hexdigest()
            for name in gate.captures}
    return 0 if report.finish(out / 'packet_results.json') else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validate-vectors', action='store_true')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args(argv)
    if args.validate_vectors:
        return run_vector_validation(args.out)
    return model_main()


if __name__ == '__main__':
    raise SystemExit(main())
