"""First compiled E61 gate: clean handshake, distinct READ, then native SBO.

Run only inside integration/core/launch_model.sh's private namespace. Exact
image comparison uses the software encoder; independent framing, application
and TCP checksum checks use the standards and wire checkers separately.
"""
import hashlib
import importlib.util
import json
import os
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


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main():
    h = load('_seg61_helpers', REARM.parent / 'response_only/model_drive_composite.py')
    cp = load('_seg61_cp', REARM / 'cp.py')
    v, rs = h.vectors, h.rs
    master, relay, pm = h.MASTER, h.OUTSTATION, h.PM
    out = Path(os.environ['OUT'])
    report = h.Report(os.environ['PROG'], physical=False, scope='E61 first compiled packet gate',
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    captures = {'sent': [], 'received': []}
    pad = os.environ.get('PAD_ENABLE', '1') == '1'
    read_len, control_len = (61, 61) if pad else (49, 37)
    report.record['meta']['padding'] = pad
    try:
        m = h.Model(ports=[], enable=False)
        ports = sorted({master.dev_port, relay.dev_port})
        m.enable_ports(ports + h.FRONT_LOOPS)
        m.enable_ports([p for p in h.LOOP_PORTS if p not in h.FRONT_LOOPS])
        reflectors = [h.Reflector(p) for p in h.FRONT_LOOPS]
        for reflector in reflectors:
            reflector.start()
        rows = cp.n_ports_rows(master.dev_port, relay.dev_port, master.ip_int, relay.ip_int,
                               n_ack_return=pm.n_ack_return)
        rows += cp.n_connection_rows(relay, master, n_ack_return=pm.n_ack_return)
        rows += cp.n_read_rows(relay, master)
        for table, key, action, data, priority in rows:
            m.add('p0.n_' + table, dict(key), 'n_' + action, dict(data), priority)
        dc = dict(zip(('index', 'code', 'repeat', 'on', 'off'), v.decoy_config()))
        for source, dest in ((master, relay), (relay, master)):
            key = {'hdr.ip.src': source.ip_int, 'hdr.ip.dst': dest.ip_int,
                   'hdr.tcp.sport': source.port, 'hdr.tcp.dport': dest.port}
            m.add('p0.n_Ingress.data_connection', key, 'n_Ingress.configure', dc)
        for table, key, action, data, priority in cp.e_conn_rows(0, relay, master, pad_enable=pad, n_ack_return=pm.n_ack_return):
            m.add('p0.r_' + table, dict(key), 'r_' + action, dict(data), priority)
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params',
                      dict(da=50_000_000, readiness=400_000_000, cap=16_000_000,
                           gap=50_000_000, op_j=200_000_000, budget=240_000, enabled=0))

        def step(name, sent, expected, reverse=False):
            captures['sent'].append((time.time_ns() // 1000, sent))
            got = m.exchange(relay.dev_port if reverse else master.dev_port,
                             sent, ports, timeout=3, quiet=.15)
            flat = [frame for frames in got.values() for frame in frames]
            captures['received'].extend((time.time_ns() // 1000, frame) for frame in flat)
            exact = len(flat) == 1 and h.same_frame(flat[0], expected, sent)
            report.add(name, 'one exact frame', len(flat), ok=exact,
                       sent=sent, received=got, expected_frame=expected)
            if not exact:
                raise AssertionError(name + ': packet image/count mismatch')
            ip_ok, tcp_ok, _ = wire_check.ip_tcp_checksum({'frame': flat[0]})
            report.add(name + '_checksums', True, ip_ok and tcp_ok)
            if not ip_ok or not tcp_ok:
                raise AssertionError(name + ': invalid network checksum')
            return flat[0]

        for name, frame, reverse in (
                ('SYN', v.packet(2, 100, mss=1460), False),
                ('SYNACK', v.packet(18, 900, 101, reverse=True, mss=1460), True),
                ('ACK', v.packet(16, 101, 901), False)):
            step(name, frame, frame, reverse)
        request = rs.request_packet(seq=101, ack=901)
        step('READ_request', request, request)
        ack = rs.ack_packet(seq=901, ack=121)
        step('READ_ack', ack, ack, True)
        native = rs.response_frame()
        image = encode61.read61(native) if pad else native
        got = step('distinct_READ_%d' % read_len, v.packet(24, 901, 121, reverse=True, payload=native),
                   v.packet(24, 901, 121, reverse=True, payload=image), True)
        payload = got[54:14 + int.from_bytes(got[16:18], 'big')]
        _, native_user = std.deframe(native)
        _, user = std.deframe(payload)
        _, points = std.check_read_response(native_user)
        std.check_read_response(user, points)
        report.add('READ_independent_crc_points', True,
                   len(payload) == read_len and wire_check.dnp3_ok(payload)[0] and user[:5] == native_user[:5])
        step('READ_mapped_ACK', v.packet(16, 121, 901 + read_len), v.packet(16, 121, 950))

        for fc, app, cseq, snative, swire in ((3, 0, 121, 950, 901 + read_len),
                                           (4, 1, 156, 987, 901 + read_len + control_len)):
            kind = 'SELECT' if fc == 3 else 'OPERATE'
            req = v.native_select(app, fc)
            step(kind + '_request', v.packet(24, cseq, swire, payload=req),
                 v.packet(24, cseq, snative, payload=req))
            native = h.native_response37(app, fc)
            image = encode61.ctl61(native) if pad else native
            got = step(kind + '_%d' % control_len, v.packet(24, snative, cseq + 35, reverse=True, payload=native),
                       v.packet(24, swire, cseq + 35, reverse=True, payload=image), True)
            payload = got[54:14 + int.from_bytes(got[16:18], 'big')]
            frames = encode61.split_frames(payload)
            fragments, errors = std.reassemble(frames)
            _, native_user = std.deframe(native)
            _, req_user = std.deframe(req)
            exact = (len(payload) == control_len and [len(f) for f in frames] == ([28, 19, 14] if pad else [37])
                     and not errors and len(fragments) == 1 and fragments[0][0] == native_user[1:]
                     and wire_check.dnp3_ok(payload)[0])
            report.add(kind + '_independent_application_and_framing', True, exact)
            std.check_control_echo(req_user, std.fragment_user(fragments[0][0]))
            step(kind + '_mapped_ACK', v.packet(16, cseq + 35, swire + control_len),
                 v.packet(16, cseq + 35, snative + 37))
        accounting = m.register_read('p0.r_Egress.acct', 0, pipe=0)
        wire_front = h.scalar({k: value for k, value in accounting.items() if k.endswith('.lo')})
        native_front = h.scalar(m.register_read('p0.r_Egress.front', 0, pipe=0))
        report.add('cumulative_growth', 60 if pad else 0, (wire_front - native_front) & 0xffffffff)
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    for name, packets in captures.items():
        pcaptk.write_pcap(str(out / (name + '.pcap')), packets)
    report.record['meta']['capture_sha256'] = {
        name: hashlib.sha256((out / (name + '.pcap')).read_bytes()).hexdigest() for name in captures}
    return 0 if report.finish(out / 'smoke_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())
