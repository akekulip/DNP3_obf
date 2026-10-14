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
import dnp3_std as std
import wire_check
import pcaptk

IMAGE_LEN = 61
READ_NATIVE = 49
CONTROL_NATIVE = 37
READ_GROWTH = IMAGE_LEN - READ_NATIVE
CONTROL_GROWTH = IMAGE_LEN - CONTROL_NATIVE
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
    return std.frame(bytes.fromhex('0564264401000000'), read_user(seq, statuses, app, iin))


def crob_object(index=1, code=1, count=1, on=100, off=100, status=0):
    return (bytes.fromhex('0c01280100') + struct.pack('<H', index) + bytes([code, count])
            + struct.pack('<I', on) + struct.pack('<I', off) + bytes([status]))


def control_request(seq=0, app=0, fc=3, index=1, code=1, count=1, on=100, off=100, status=0):
    user = bytes([0xc0 | (seq & 0x3f), 0xc0 | (app & 0x0f), fc]) + crob_object(index, code, count, on, off, status)
    return std.frame(bytes.fromhex('05641ac40a000100'), user)


def control_response(seq=0, app=0, fc=3, index=1, code=1, count=1, on=100, off=100,
                     status=0, iin=b'\x00\x00', con=False):
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
    frame[TCP_PAYLOAD_OFFSET:14 + total] = payload
    return fix_checksums(bytes(frame))


def assert_ip_tcp(frame):
    ip_ok, tcp_ok, _ = wire_check.ip_tcp_checksum({'frame': frame})
    if not (ip_ok and tcp_ok):
        raise AssertionError('bad IP/TCP checksum')


def validate_read_image(native, image, expected_statuses=None):
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


def validate_control_image(req, native, image):
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
    std.check_control_echo(req_user, std.fragment_user(fragments[0][0]))
    outcome = std.check_control_outcome(req_user, std.fragment_user(fragments[0][0]))
    if not outcome['authorizes_or_succeeds']:
        raise AssertionError('control success semantics failed: %r' % outcome)
    ths = [std.deframe(frame)[1][0] for frame in frames]
    return {'native_len': len(native), 'image_len': len(image), 'frame_lengths': [len(f) for f in frames],
            'transport_headers': ths, 'first_seq': ths[0] & 0x3f}


def vector_cases():
    cases = []
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
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params',
                      dict(da=50_000_000, readiness=400_000_000, cap=16_000_000,
                           gap=50_000_000, op_j=200_000_000, budget=240_000, enabled=0))

    def add(self, name, expect, actual, ok=True, **extra):
        self.report.add(name, expect, actual, ok=ok, **extra)
        if not ok:
            raise AssertionError(name)

    def exchange(self, name, sent, expected=None, reverse=False, allow_drop=False):
        self.captures['sent'].append((time.time_ns() // 1000, sent))
        got = self.m.exchange(self.relay.dev_port if reverse else self.master.dev_port,
                              sent, self.ports, timeout=3, quiet=.15)
        flat = [frame for frames in got.values() for frame in frames]
        self.captures['received'].extend((time.time_ns() // 1000, frame) for frame in flat)
        if allow_drop:
            self.add(name, 'no transformed output', len(flat), ok=not any(len(tcp_payload(f)) == IMAGE_LEN for f in flat),
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
        ack = self.rs.ack_packet(seq=native_sseq, ack=cseq + 20)
        self.exchange(name + '_server_ack', ack, self.rs.ack_packet(seq=wire_sseq, ack=cseq + 20), reverse=True)
        native = read_frame(seq, statuses, app=0xc0 | (seq & 0x0f), iin=iin)
        image = encode61.read61(native)
        validate_read_image(native, image, statuses)
        got = self.exchange(name + '_response61',
                            self.v.packet(24, native_sseq, cseq + 20, reverse=True, payload=native),
                            self.v.packet(24, wire_sseq, cseq + 20, reverse=True, payload=image),
                            reverse=True)
        self.add(name + '_payload_len', IMAGE_LEN, len(tcp_payload(got)))
        if expect_growth:
            self.exchange(name + '_mapped_ack',
                          self.v.packet(16, cseq + 20, wire_sseq + IMAGE_LEN),
                          self.v.packet(16, cseq + 20, native_sseq + READ_NATIVE))
        return cseq + 20, native_sseq + READ_NATIVE, wire_sseq + IMAGE_LEN

    def control_exchange(self, name, cseq, native_sseq, wire_sseq, seq=0, app=0, fc=3, **kw):
        req = control_request(seq=seq, app=app, fc=fc, **kw)
        self.exchange(name + '_request', self.v.packet(24, cseq, wire_sseq, payload=req),
                      self.v.packet(24, cseq, native_sseq, payload=req))
        native = control_response(seq=seq, app=app, fc=fc, **kw)
        image = encode61.ctl61(native)
        validate_control_image(req, native, image)
        got = self.exchange(name + '_response61',
                            self.v.packet(24, native_sseq, cseq + 35, reverse=True, payload=native),
                            self.v.packet(24, wire_sseq, cseq + 35, reverse=True, payload=image),
                            reverse=True)
        self.add(name + '_payload_len', IMAGE_LEN, len(tcp_payload(got)))
        self.exchange(name + '_mapped_ack',
                      self.v.packet(16, cseq + 35, wire_sseq + IMAGE_LEN),
                      self.v.packet(16, cseq + 35, native_sseq + CONTROL_NATIVE))
        return cseq + 35, native_sseq + CONTROL_NATIVE, wire_sseq + IMAGE_LEN

    def growth(self):
        acct = self.m.register_read('p0.r_Egress.acct', 0, pipe=0)
        front = self.m.register_read('p0.r_Egress.front', 0, pipe=0)
        return (self.h.scalar({k: v for k, v in acct.items() if k.endswith('.lo')}) - self.h.scalar(front)) & 0xffffffff

    def run(self):
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
        ack = self.rs.ack_packet(seq=native_sseq, ack=cseq + 20)
        self.exchange('retx_server_ack', ack, self.rs.ack_packet(seq=wire_sseq, ack=cseq + 20), reverse=True)
        before = self.growth()
        native = read_frame(7, [0x55] * 23)
        image = encode61.read61(native)
        first = self.exchange('retx_response_first',
                              self.v.packet(24, native_sseq, cseq + 20, reverse=True, payload=native),
                              self.v.packet(24, wire_sseq, cseq + 20, reverse=True, payload=image), reverse=True)
        second = self.exchange('retx_response_second',
                               self.v.packet(24, native_sseq, cseq + 20, reverse=True, payload=native),
                               self.v.packet(24, wire_sseq, cseq + 20, reverse=True, payload=image), reverse=True)
        self.add('retx_identical_image', first.hex(), second.hex())
        self.add('retx_no_doublegrowth_before_ack', before + READ_GROWTH, self.growth())
        self.exchange('retx_ack_maps_once', self.v.packet(16, cseq + 20, wire_sseq + IMAGE_LEN),
                      self.v.packet(16, cseq + 20, native_sseq + READ_NATIVE))
        cseq += 20
        native_sseq += READ_NATIVE
        wire_sseq += IMAGE_LEN

        # Explicit admission negatives: observe actual model behavior and require no transformed 61-byte output.
        bad_read = read_frame(0, range(23))
        bad_read = std.frame(bytes.fromhex('0564264401000000'), std.deframe(bad_read)[1][:9] + b'\x17'
                             + std.deframe(bad_read)[1][10:])
        for name, native in (('neg_read_wrongshape', bad_read),
                             ('neg_control_con', control_response(con=True)),
                             ('neg_control_status', control_response(status=1))):
            sent = self.v.packet(24, native_sseq, cseq, reverse=True, payload=native)
            self.exchange(name, sent, allow_drop=True, reverse=True)

        # Clean close/rearm, then a wrap-adjacent rearmed flow.
        self.exchange('close_fin', self.v.packet(17, cseq, wire_sseq), self.v.packet(17, cseq, native_sseq))
        self.exchange('close_fin_ack', self.v.packet(17, native_sseq, cseq + 1, reverse=True),
                      self.v.packet(17, wire_sseq, cseq + 1, reverse=True), reverse=True)
        self.exchange('close_last_ack', self.v.packet(16, cseq + 1, wire_sseq + 1),
                      self.v.packet(16, cseq + 1, native_sseq + 1))
        wc, wn, ww = self.handshake(0xffffffe0, 0xfffffff0, 'rearm_wrap_')
        self.read_exchange('rearm_wrap_read', wc, wn, ww, seq=62)
        self.report.record['meta']['reflections'] = {r.port: r.summary() for r in self.reflectors}


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
