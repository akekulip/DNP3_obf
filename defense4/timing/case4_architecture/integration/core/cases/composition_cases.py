#!/usr/bin/env python3
"""egress_selected_wire composition: role dispatch by (ingress port, IP length) on the model.
Roles exercised: read (validator oracle), forward/reverse (pure-ACK mapping vs serial-arithmetic oracle),
cache (native35 -> padded55 via ingress+egress banks, then one-byte tail replay vs scapy-built expected packets).
Not exercised: carving (needs multicast/PRE setup)."""
import os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); CORE = os.path.dirname(HERE)
ARCH = os.path.abspath(os.path.join(CORE, '..', '..'))
sys.path[:0] = [HERE, CORE, os.path.join(ARCH, 'protocol/egress/tests'), os.path.join(ARCH, 'protocol/egress'),
                os.path.join(ARCH, 'protocol/tests'), os.path.join(ARCH, 'protocol/payload_mapping/tests'),
                os.path.join(ARCH, 'tests')]
import frames as F
import validator_cases as V
from model_driver import Model, Report, same_frame
import test_packets as TP          # scapy-built expected packets, ExactImages native35 fixtures
import test_mapping as TM          # forward()/inverse() serial arithmetic oracle

m = Model(ports=[1, 9, 64])
rep = Report(os.environ['PROG'], ports=m.ports)
MASK = 0xffffffff
TUP = {'hdr.ip.src': 0x0a000001, 'hdr.ip.dst': 0x0a000002, 'hdr.tcp.sport': 42000, 'hdr.tcp.dport': 20000}
REV = {'hdr.ip.src': 0x0a000002, 'hdr.ip.dst': 0x0a000001, 'hdr.tcp.sport': 20000, 'hdr.tcp.dport': 42000}
OUTP = 1
def routes(role, ports):
    for p in ports: m.add('Ingress.%s.forwarding' % role, {'ig.ingress_port': p}, 'Ingress.%s.route' % role, {'port': OUTP})

# ---------------- read role -----------------------------------------------------------------------
CLs, SVs = (0x0a000001, 42000), (0x0a000002, 20000)
V.CL, V.SV = CLs, SVs
routes('read', [9, 64])
m.add('Ingress.read.connection', TUP, 'Ingress.read.forward', {'port': 1, 'dst': V.be(V.OUTSTATION), 'src': V.be(V.MASTER)})
m.add('Ingress.read.connection', REV, 'Ingress.read.reverse', {'port': 9, 'dst': V.be(V.MASTER), 'src': V.be(V.OUTSTATION)})
def rcounts(): return [m.register_total('Ingress.read.qualified', i, 'Ingress.read.qualified.f1') for i in (0, 1)]
def read_case(name, frame, port):
    iplen = int.from_bytes(frame[16:18], 'big')
    role_hit = (port, iplen) in ((9, 60), (64, 89))
    exp = V.oracle(frame, 1 if port == 64 else port) if role_hit else 'none'
    b = rcounts(); out = m.exchange(port, frame, [1, 9, 64], timeout=0.8, quiet=0.2); a = rcounts()
    d = [a[0] - b[0], a[1] - b[1]]
    obs = 'req' if d == [1, 0] else 'resp' if d == [0, 1] else 'none' if d == [0, 0] else 'odd%s' % d
    rep.add('read/' + name, exp, obs, in_port=port, frame=frame, out={p: v for p, v in out.items() if v}, counter_delta=d)
base_q, base_r = V.request(s=CLs, d=SVs), V.response(s=SVs, d=CLs)
read_case('request_valid', base_q, 9); read_case('response_valid', base_r, 64)
read_case('bad_ip_csum_req', V.request(s=CLs, d=SVs, bad_ip=True), 9)
read_case('bad_tcp_csum_resp', V.response(s=SVs, d=CLs, bad_tcp=True), 64)
read_case('ttl0_req', V.request(s=CLs, d=SVs, ttl=0), 9)
P = 54
for nm, off in (('hdr_crc', P + 8), ('blk_crc', P + 18)): read_case('bad_dnp3_%s_req' % nm, F.corrupt(base_q, off), 9)
for nm, off in (('hdr_crc', P + 8), ('first_crc', P + 26), ('second_crc', P + 44), ('tail_crc', P + 47)):
    read_case('bad_dnp3_%s_resp' % nm, F.corrupt(base_r, off), 64)
read_case('wrong_sport_req', V.request(s=(CLs[0], CLs[1] + 1), d=SVs), 9)
read_case('wrong_link_dst_req', V.request(s=CLs, d=SVs, dst=V.OUTSTATION + 1), 9)
read_case('wrong_function_req', V.request(s=CLs, d=SVs, user=bytes([0xc0, 0xc0, 2, 10, 2, 0, 0, 22])), 9)
read_case('request_on_port64(role miss)', base_q, 64)
read_case('response_on_port9(role miss)', base_r, 9)

# ---------------- forward / reverse mapping on pure ACKs ----------------------------------------------
routes('forward', [9]); routes('reverse', [64])
for base in (1000, 0xfffffff0):
    for valid in (0, 1, 3):
        m.clear('Ingress.forward.connection'); m.clear('Ingress.reverse.connection')
        m.add('Ingress.forward.connection', TUP, 'Ingress.forward.configure', {'first': base, 'second': (base + 35) & MASK, 'valid': valid, 'direction': 1})
        m.add('Ingress.reverse.connection', TUP, 'Ingress.reverse.configure', {'first': base, 'second': (base + 35) & MASK, 'valid': valid, 'direction': 2})
        for pos in (-1, 0, 34, 35, 36, 54, 55, 69, 70, 89, 90, 91, 109, 110, 130):
            val = (base + pos) & MASK
            if valid == 3 or pos < 35:      # geometry of valid=3 is fixed 35 apart; other valids tested at all positions too
                pass
            exp_seq = TM.forward(val, base, valid)
            fr = TM.packet(b'', val, 123456, flags=0x10)
            out = [x for v in m.exchange(9, fr, [OUTP], timeout=0.8, quiet=0.15).values() for x in v]
            exp = TM.packet(b'', exp_seq, 123456, flags=0x10)
            rep.add('forward/base%d/valid%d/seq%+d' % (base, valid, pos), 'mapped', 'mapped' if out and same_frame(out[0], exp) else ('none' if not out else 'different'),
                    input=fr, expected_packet=exp, got=out[0] if out else b'')
            for window in (0, 20, 65535):
                ack = val
                eack = TM.inverse(ack, base, valid); ewin = (TM.inverse((ack + window) & MASK, base, valid) - eack) & MASK
                fr = TM.packet(b'', 700, ack, window, flags=0x10); exp = TM.packet(b'', 700, eack, ewin, flags=0x10)
                out = [x for v in m.exchange(64, fr, [OUTP], timeout=0.8, quiet=0.15).values() for x in v]
                # inverse-window growth is refused by the program (no output): oracle says output only when window did not grow
                growth_refused = ewin > window if False else None
                rep.add('reverse/base%d/valid%d/ack%+d/win%d' % (base, valid, pos, window), 'mapped', 'mapped' if out and same_frame(out[0], exp) else ('none' if not out else 'different'),
                        input=fr, expected_packet=exp, got=out[0] if out else b'')

# ---------------- cache role (native35 -> padded55, then tail replay) --------------------------------------
routes('cache', [9])
m.add('Ingress.cache.connection', TUP, 'Ingress.cache.configure', {'index': 0xc900, 'code': 1, 'repeat': 1, 'on': 0x64000000, 'off': 0x64000000, 'generation': 2})
for fc in (3, 4):
    native = TP.fixtures.ExactImages().native(fc)
    padded = TP.codec.expand_control(native, TP.codec.Decoy(201, bytes.fromhex('0101640000006400000000')))[0]
    fr = TP.packet(native); exp = TP.expected_packet(padded)
    out = [x for v in m.exchange(9, fr, [OUTP], timeout=1.0, quiet=0.2).values() for x in v]
    rep.add('cache/native35_fc%d_to_padded55' % fc, 'padded55', 'padded55' if out and same_frame(out[0], exp) else ('none' if not out else 'different'),
            input=fr, expected_packet=exp, got=out[0] if out else b'')
    try: m.clear('Ingress.cache.replay_context')
    except Exception: pass
    m.add('Ingress.cache.replay_context', dict(TUP, **{'hdr.tcp.seq': 18}), 'Ingress.cache.cached',
          {'generation': 2, 'wire_start': 0xfffffff0, 'native_last': native[-1], 'slot': fc - 3})
    fr = TP.packet(native[-1:], seq=18, ack=987654, window=0, flags=0x10)
    exp = TP.expected_packet(padded, seq=0xfffffff0, ack=987654, window=0, flags=0x10)
    out = [x for v in m.exchange(9, fr, [OUTP], timeout=1.0, quiet=0.2).values() for x in v]
    rep.add('cache/tail_replay_fc%d' % fc, 'padded55-replay', 'padded55-replay' if out and same_frame(out[0], exp, fr) else ('none' if not out else 'different'),
            input=fr, expected_packet=exp, got=out[0] if out else b'')
native = TP.fixtures.ExactImages().native(3)
for nm, fr in (('bad_ip_csum', None), ('bad_tcp_csum', None), ('crc_header', None), ('crc_block', None), ('wrong_tuple', None)):
    good = bytearray(TP.packet(native))
    if nm == 'bad_ip_csum': good[24] ^= 1
    elif nm == 'bad_tcp_csum': good[50] ^= 1
    elif nm == 'crc_header': good[54 + 8] ^= 1
    elif nm == 'crc_block': good[54 + 26] ^= 1
    else: good[34 + 1] ^= 1
    out = [x for v in m.exchange(9, bytes(good), [OUTP], timeout=0.8, quiet=0.2).values() for x in v]
    padded = TP.expected_packet(TP.codec.expand_control(native, TP.codec.Decoy(201, bytes.fromhex('0101640000006400000000')))[0])
    # contract: a refused packet must never come out padded (no output, or the original untouched)
    state = 'none' if not out else 'original' if same_frame(out[0], bytes(good)) else 'padded-or-changed'
    rep.add('cache/refused_' + nm, 'not-padded', 'not-padded' if state in ('none', 'original') else state,
            input=bytes(good), got=out[0] if out else b'', refused_output=state)
ok = rep.finish(os.path.join(os.environ['OUT'], 'cases.json'))
sys.exit(0 if ok else 1)
