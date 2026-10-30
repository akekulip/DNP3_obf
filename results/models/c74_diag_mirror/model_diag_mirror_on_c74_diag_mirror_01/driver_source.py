"""Diagnostic-mirror (BASE_diag_mirror) model driver: relay-leg mirror fidelity on the copy port for one session state.

DIAG_MIRROR_STATE = on | off | absent is written through scripts/hardware/diag_mirror_sessions.apply, the code the
switch would run, over the model's BF Runtime connection. The stimulus is model_smoke's exchange set (handshake,
READ, SELECT, OPERATE, the padded responses and the sequence-mapped ACKs) with padding on and T timing off, then
three master probes classified by what the model did with them (a frame emitted on the relay port must be copied
exactly; any other outcome must leave no copy), and
an LLDP frame arriving on the copy port (it must go nowhere).
Each step injects one frame and records dev9, dev64 and the copy port, and the model-log segment of that step
(ingress passes, transmissions, recirculations and mirror-session lines per port). Model evidence only.
"""
import hashlib
import importlib.util
import json
import os
import re
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / 'checks'), str(HERE.parent / 'hardware')]
import encode61  # noqa: E402
import read_policy_expect as rp  # noqa: E402
rp.install(encode61)
import wire_check  # noqa: E402
import pcaptk  # noqa: E402
import telemetry_from_log  # noqa: E402
import diag_mirror_sessions  # noqa: E402

BANNER = re.compile(r'========== (Ingress Pkt from port|Tx Pkt to port|Packet to egress parser: to port) (\d+)'
                    r'(?: \(\d+ bytes\))?( recirculated| \(Bypass Egress\))?')
MIRROR = re.compile(r'---- Mirroring session (\d+) : (ingress|egress)')
MIRROR_OFF = re.compile(r'Mirroring session (\d+) is not enabled')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def log_counts(text):
    """Per-port pass counts and mirror-session lines in one model-log segment."""
    out = dict(ingress_from={}, tx_to={}, recirculated={}, bypass_egress_tx={}, egress_parser_to={},
               mirror_requests={}, mirror_not_enabled={})
    for kind, port, tail in BANNER.findall(text):
        key = {'Ingress Pkt from port': 'ingress_from', 'Packet to egress parser: to port': 'egress_parser_to'}.get(kind)
        if kind == 'Tx Pkt to port':
            key = {' recirculated': 'recirculated', ' (Bypass Egress)': 'bypass_egress_tx'}.get(tail, 'tx_to')
        out[key][port] = out[key].get(port, 0) + 1
    for sid, gress in MIRROR.findall(text):
        k = '%s:%s' % (sid, gress)
        out['mirror_requests'][k] = out['mirror_requests'].get(k, 0) + 1
    for sid in MIRROR_OFF.findall(text):
        out['mirror_not_enabled'][sid] = out['mirror_not_enabled'].get(sid, 0) + 1
    return out


def switch_over(model):
    """switch.Switch on the model's existing BF Runtime client (no second bind)."""
    import switch
    sw = switch.Switch.__new__(switch.Switch)
    sw.iface, sw.bi, sw.sw_read = model.iface, model.info, set()
    return sw


def odd_ip_request(v, seq, ack):
    """The master's next segment with 4 bytes of IP options (IHL 6): r_EgParser marks it ip_odd and r_Egress drops it."""
    frame = bytearray(v.packet(16, seq, ack))
    ip = frame[14:34]
    options = b'\x01\x01\x01\x00'
    ip[0] = 0x46
    total = int.from_bytes(ip[2:4], 'big') + 4
    ip[2:4] = total.to_bytes(2, 'big')
    ip[10:12] = b'\x00\x00'
    header = bytes(ip) + options
    s = sum(int.from_bytes(header[i:i + 2], 'big') for i in range(0, len(header), 2))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    ip[10:12] = (~s & 0xffff).to_bytes(2, 'big')
    return bytes(frame[:14]) + bytes(ip) + options + bytes(frame[34:])


def _sum16(data):
    data = data + b'\x00' * (len(data) % 2)
    s = sum(int.from_bytes(data[i:i + 2], 'big') for i in range(0, len(data), 2))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return s


def without_tcp_options(frame):
    """The same segment with no TCP options (data offset 5) and correct IPv4/TCP checksums."""
    ihl = (frame[14] & 0x0f) * 4
    ip, tcp = bytearray(frame[14:14 + ihl]), bytearray(frame[14 + ihl:14 + ihl + 20])
    total = int.from_bytes(ip[2:4], 'big')
    offset = (frame[14 + ihl + 12] >> 4) * 4
    payload = frame[14 + ihl + offset:14 + total]
    ip[2:4] = (ihl + 20 + len(payload)).to_bytes(2, 'big')
    ip[10:12] = b'\x00\x00'
    ip[10:12] = (~_sum16(bytes(ip)) & 0xffff).to_bytes(2, 'big')
    tcp[12] = (5 << 4) | (tcp[12] & 0x0f)
    tcp[16:18] = b'\x00\x00'
    pseudo = bytes(ip[12:20]) + b'\x00\x06' + (20 + len(payload)).to_bytes(2, 'big')
    tcp[16:18] = (~_sum16(pseudo + bytes(tcp) + payload) & 0xffff).to_bytes(2, 'big')
    return frame[:14] + bytes(ip) + bytes(tcp) + payload


def lldp_frame():
    return (bytes.fromhex('0180c200000e' '3cfdfe000001' '88cc') + bytes.fromhex('020704' '3cfdfe000001')
            + bytes.fromhex('0403' '05' '7031') + bytes.fromhex('0602' '0078') + b'\x00\x00').ljust(60, b'\x00')


def main():
    state = os.environ['DIAG_MIRROR_STATE']
    h = load('_diag_helpers', HERE / 'model_drive_composite.py')
    rp.configure_helpers(h)
    cp = load('_diag_cp', HERE / 'cp.py')
    v, rs = h.vectors, h.rs
    master, relay, pm = h.MASTER, h.OUTSTATION, h.PM
    out = Path(os.environ['OUT'])
    build = Path(os.environ['PORT_MAP']).parent
    c = diag_mirror_sessions.load(build)
    copy = c['copy_port']
    report = h.Report(os.environ['PROG'], physical=False, scope='diagnostic mirror (%s) relay-leg mirror fidelity' % Path(os.environ['PORT_MAP']).parent.name,
                      state=state, constants=c, build=build.name,
                      source_sha256=hashlib.sha256((build / 'response_only.p4').read_bytes()).hexdigest(),
                      driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    steps, captures = [], {'sent': [], 'received': []}
    read_len, control_len = rp.read_image_len(61), rp.CONTROL_IMAGE_LEN
    request_len, control_request_len = (25 if rp.SEL751 else 20), rp.CONTROL_REQUEST_LEN
    read_end, native_read_end = 101 + request_len, 901 + rp.READ_NATIVE_LEN
    try:
        m = h.Model(ports=[], enable=False)
        ports = sorted({master.dev_port, relay.dev_port, copy})
        m.enable_ports(ports + h.FRONT_LOOPS)
        m.enable_ports([p for p in h.LOOP_PORTS if p not in h.FRONT_LOOPS])
        reflectors = [h.Reflector(p) for p in h.FRONT_LOOPS]
        for reflector in reflectors:
            reflector.start()
        rows = cp.n_ports_rows(master.dev_port, relay.dev_port, master.ip_int, relay.ip_int, n_ack_return=pm.n_ack_return)
        rows += cp.n_connection_rows(relay, master, n_ack_return=pm.n_ack_return)
        rows += cp.n_read_rows(relay, master)
        for table, key, action, data, priority in rows:
            m.add('p0.n_' + table, dict(key), 'n_' + action, dict(data), priority)
        dc = dict(zip(('index', 'code', 'repeat', 'on', 'off'), v.decoy_config()))
        for source, dest in ((master, relay), (relay, master)):
            m.add('p0.n_Ingress.data_connection', {'hdr.ip.src': source.ip_int, 'hdr.ip.dst': dest.ip_int,
                  'hdr.tcp.sport': source.port, 'hdr.tcp.dport': dest.port}, 'n_Ingress.configure', dc)
        for table, key, action, data, priority in cp.e_conn_rows(0, relay, master, pad_enable=True, n_ack_return=pm.n_ack_return):
            m.add('p0.r_' + table, dict(key), 'r_' + action, dict(data), priority)
        if rp.POLICY:
            for table, key, action, data, priority in cp.p1_pad_rows(relay, master, True):
                m.add(table, dict(key), action, dict(data), priority)
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params',
                      dict(da=50_000_000, readiness=400_000_000, cap=16_000_000,
                           gap=50_000_000, op_j=200_000_000, budget=240_000, enabled=0))
        applied = diag_mirror_sessions.apply(switch_over(m), c, state)
        report.record['meta']['session_apply'] = json.loads(json.dumps(applied, default=str))
        log = telemetry_from_log.model_log()
        # Frames reflected before the first step are not stimulus: the Reflector's ETH_P_ALL socket can hear the
        # switchd<->model loopback TCP before bind() and reflect one such frame into its port (seen on dev48).
        report.record['meta']['reflections_before_steps'] = {r.port: r.frames for r in reflectors}

        def step(name, in_port, sent, expected=None, forward=True):
            """One frame in; dev9/dev64/copy captured; returns the forwarded frame (or None)."""
            if expected is not None:
                expected = rp.preserve_options(sent, expected)
            rp.advance_timestamp()
            telemetry_from_log.wait_idle(log)
            start = log.stat().st_size
            captures['sent'].append((time.time_ns() // 1000, sent))
            got = m.exchange(in_port, sent, ports, timeout=3, quiet=.2)
            telemetry_from_log.wait_idle(log, quiet=0.2, timeout=3)
            with log.open('rb') as f:
                f.seek(start)
                counts = log_counts(f.read().decode(errors='replace'))
            for frames in got.values():
                captures['received'].extend((time.time_ns() // 1000, frame) for frame in frames)
            fwd_port = relay.dev_port if in_port == master.dev_port else master.dev_port
            forwarded = got.get(fwd_port, [])
            row = dict(name=name, in_port=in_port, sent=sent.hex(), outputs={str(p): [f.hex() for f in got[p]] for p in ports},
                       log=counts)
            steps.append(row)
            if forward is None:
                pass
            elif forward:
                ok = len(forwarded) == 1 and not got[in_port] and (expected is None or h.same_frame(forwarded[0], expected, sent))
                report.add(name + '_forwarded', 'one exact frame on %d' % fwd_port, len(forwarded), ok=ok)
                if ok:
                    ip_ok, tcp_ok, _ = wire_check.ip_tcp_checksum({'frame': forwarded[0]})
                    report.add(name + '_checksums', True, ip_ok and tcp_ok)
            else:
                report.add(name + '_nothing_forwarded', 0, sum(len(got[p]) for p in ports if p != copy))
            copies = got[copy]
            if forward is None:            # probe toward the relay: classified by what the model did with it
                sent64, reached64 = counts['tx_to'].get(str(relay.dev_port), 0), counts['egress_parser_to'].get(str(relay.dev_port), 0)
                row['probe'] = 'emitted_on_relay_port' if sent64 else ('dropped_in_relay_egress' if reached64 else 'not_at_relay_egress')
                report.add(name + '_classified', 'observed', row['probe'], ok=True)
                forward = bool(sent64)
            if state != 'on' or in_port == copy or (in_port == master.dev_port and not forward):
                report.add(name + '_no_copy', 0, len(copies))
            elif in_port == relay.dev_port:
                exact = len(copies) == 1 and copies[0] == sent
                padded = len(copies) == 1 and h.same_frame(copies[0], sent)
                row['copy_match'] = 'exact' if exact else ('ethernet_min_padding' if padded else 'mismatch')
                report.add(name + '_copy_equals_frame_received_on_relay_port', True, exact or (padded and len(sent) < 60),
                           copy_lengths=[len(f) for f in copies], sent_length=len(sent), match=row['copy_match'])
            else:
                exact = len(copies) == 1 and len(forwarded) == 1 and copies[0] == forwarded[0]
                row['copy_match'] = 'exact' if exact else 'mismatch'
                report.add(name + '_copy_equals_frame_emitted_on_relay_port', True, exact,
                           copy_lengths=[len(f) for f in copies], emitted_lengths=[len(f) for f in forwarded])
            report.add(name + '_copy_port_never_ingresses', 0, counts['ingress_from'].get(str(copy), 0) - (1 if in_port == copy else 0))
            return forwarded[0] if forwarded else None

        for name, frame, port in (('SYN', v.packet(2, 100, mss=1460), master.dev_port),
                                  ('SYNACK', v.packet(18, 900, 101, reverse=True, mss=1460), relay.dev_port),
                                  ('ACK', v.packet(16, 101, 901), master.dev_port)):
            step(name, port, frame, frame)
        request = rs.request_packet(seq=101, ack=901)
        step('READ_request', master.dev_port, request, request)
        ack = rs.ack_packet(seq=901, ack=read_end)
        step('READ_ack', relay.dev_port, ack, ack)
        native = rs.response_frame()
        step('READ_response', relay.dev_port, v.packet(24, 901, read_end, reverse=True, payload=native),
             v.packet(24, 901, read_end, reverse=True, payload=encode61.read61(native)))
        step('READ_mapped_ACK', master.dev_port, v.packet(16, read_end, 901 + read_len), v.packet(16, read_end, native_read_end))
        for fc, app, cseq, snative, swire in ((3, 0, read_end, native_read_end, 901 + read_len),
                                           (4, 1, read_end + control_request_len, native_read_end + rp.CONTROL_NATIVE_LEN,
                                            901 + read_len + control_len)):
            kind = 'SELECT' if fc == 3 else 'OPERATE'
            req = v.native_select(app, fc)
            step(kind + '_request', master.dev_port, v.packet(24, cseq, swire, payload=req), v.packet(24, cseq, snative, payload=req))
            native = h.native_response37(app, fc)
            step(kind + '_response', relay.dev_port, v.packet(24, snative, cseq + control_request_len, reverse=True, payload=native),
                 v.packet(24, swire, cseq + control_request_len, reverse=True, payload=encode61.ctl61(native)))
            step(kind + '_mapped_ACK', master.dev_port, v.packet(16, cseq + control_request_len, swire + control_len),
                 v.packet(16, cseq + control_request_len, snative + rp.CONTROL_NATIVE_LEN))
        last_seq, last_ack = read_end + 2 * control_request_len, 901 + read_len + 2 * control_len
        for name, frame in (('PROBE_ip_options', odd_ip_request(v, last_seq, last_ack)),
                            ('PROBE_ack_without_timestamps', without_tcp_options(v.packet(16, last_seq, last_ack))),
                            ('PROBE_ack_far_ahead', v.packet(16, last_seq, last_ack + 100000))):
            step(name, master.dev_port, frame, forward=None)
        # N disposes of these before relay egress in c72 (port-48 lap or ingress); the dropped-in-relay-egress
        # path is exercised by the companion runs of the c72 drivers that reach it (select_lifecycle, two_read_robust).
        report.record['meta']['probe_outcomes'] = {s['name']: s.get('probe') for s in steps if 'probe' in s}
        step('LLDP_into_copy_port', copy, lldp_frame(), forward=False)
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
        report.record['meta']['port_errors'] = m.port_errors
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    (out / 'diag_mirror_steps.json').write_text(json.dumps(dict(state=state, steps=steps), indent=1) + '\n')
    for name, packets in captures.items():
        pcaptk.write_pcap(str(out / (name + '.pcap')), packets)
    report.record['meta']['capture_sha256'] = {
        name: hashlib.sha256((out / (name + '.pcap')).read_bytes()).hexdigest() for name in captures}
    return 0 if report.finish(out / 'diag_mirror_results.json') else 1


if __name__ == '__main__':
    raise SystemExit(main())
