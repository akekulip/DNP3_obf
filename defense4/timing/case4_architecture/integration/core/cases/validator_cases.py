#!/usr/bin/env python3
"""validator.p4 (READ20/response49 observer) driven with real frames; oracle is independent software."""
import os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import frames as F
from model_driver import Model, Report

CL, SV = F.CLIENT, F.SERVER
OUTSTATION, MASTER = 1, 2                       # link addresses
def be(v): return struct.unpack('>H', struct.pack('<H', v))[0]   # wire (LE) address as the P4 sees it
REQ = bytes([0xc0, 0xc0, 1, 10, 2, 0, 0, 22])
RESP = bytes([0xc0, 0xc0, 0x81, 0, 0, 10, 2, 0, 0, 22]) + bytes(6) + bytes(range(16)) + b'\x55'
assert len(RESP) == 33

def request(**kw):
    ctrl = kw.pop('ctrl', 0xc4); dst = kw.pop('dst', OUTSTATION); src = kw.pop('src', MASTER); user = kw.pop('user', REQ)
    return F.tcp_frame(kw.pop('s', CL), kw.pop('d', SV), kw.pop('flags', 0x18), kw.pop('seq', 1000), 1, F.dnp3(ctrl, dst, src, user), **kw)

def response(**kw):
    ctrl = kw.pop('ctrl', 0x44); dst = kw.pop('dst', MASTER); src = kw.pop('src', OUTSTATION); user = kw.pop('user', RESP)
    return F.tcp_frame(kw.pop('s', SV), kw.pop('d', CL), kw.pop('flags', 0x18), kw.pop('seq', 5000), 1, F.dnp3(ctrl, dst, src, user), **kw)

def oracle(frame, port):
    """Independent verdict: 0 none, 'req', 'resp'. Mirrors the README profile, using only reference codecs."""
    if port not in (9, 1) or frame[12:14] != b'\x08\x00':
        return 'none'
    ip, tcp = frame[14:34], frame[34:]
    if ip[0] != 0x45 or ip[9] != 6 or ip[8] == 0 or F.checksum(ip) != 0 or ip[6:8] not in (b'\x00\x00', b'\x40\x00'):
        return 'none'
    tl = struct.unpack('!H', ip[2:4])[0]
    tcp = frame[34:14 + tl]
    src, dst = struct.unpack('!II', ip[12:20]); sp, dp = struct.unpack('!HH', tcp[:4])
    if F.checksum(struct.pack('!IIBBH', src, dst, 0, 6, len(tcp)) + tcp) != 0:
        return 'none'
    if tcp[12] != 0x50 or tcp[13] not in (0x10, 0x18) or tcp[18:20] != b'\0\0':
        return 'none'
    if (src, sp, dst, dp) == (CL[0], CL[1], SV[0], SV[1]): want = (OUTSTATION, MASTER, 'req')
    elif (src, sp, dst, dp) == (SV[0], SV[1], CL[0], CL[1]): want = (MASTER, OUTSTATION, 'resp')
    else: return 'none'
    pay = tcp[20:]
    if not rrc_ok(pay): return 'none'
    head, user = F.dnp3_decode(pay)
    if (struct.unpack('<HH', head[4:8]) != want[:2]) or head[3] != (0xc4 if want[2] == 'req' else 0x44): return 'none'
    if want[2] == 'req':
        ok = len(user) == 8 and user[0] & 0xc0 == 0xc0 and user[1] & 0xc0 == 0xc0 and user[2:] == bytes([1, 10, 2, 0, 0, 22])
        ok = ok and user[1] & 0xf0 == 0xc0
    else:
        ok = len(user) == 33 and user[0] & 0xc0 == 0xc0 and user[1] & 0xf0 == 0xc0 and user[2] == 0x81 and user[5:10] == bytes([10, 2, 0, 0, 22])
    return want[2] if ok else 'none'

def rrc_ok(pay):
    return F.rrc.dnp3_frame_ok(pay) and pay[:2] == b'\x05\x64'

def main():
    m = Model()
    rep = Report(os.environ['PROG'], ports=m.ports, port_errors=m.port_errors)
    m.add('Ingress.forwarding', {'ig.ingress_port': 9}, 'Ingress.route', {'port': 1})
    m.add('Ingress.forwarding', {'ig.ingress_port': 1}, 'Ingress.route', {'port': 9})
    m.add('Ingress.connection', {'hdr.ip.src': CL[0], 'hdr.ip.dst': SV[0], 'hdr.tcp.sport': CL[1], 'hdr.tcp.dport': SV[1]},
          'Ingress.forward', {'port': 1, 'dst': be(OUTSTATION), 'src': be(MASTER)})
    m.add('Ingress.connection', {'hdr.ip.src': SV[0], 'hdr.ip.dst': CL[0], 'hdr.tcp.sport': SV[1], 'hdr.tcp.dport': CL[1]},
          'Ingress.reverse', {'port': 9, 'dst': be(MASTER), 'src': be(OUTSTATION)})
    # hash tables for CRC are const-default; request/response profiles are const entries.
    def counts(): return [m.register_total('Ingress.qualified', i, 'Ingress.qualified.f1') for i in (0, 1)]
    def run(name, frame, port, note=''):
        before = counts()
        out = m.exchange(port, frame, [1, 9, 2], timeout=0.8, quiet=0.25)
        after = counts()
        d = [after[0] - before[0], after[1] - before[1]]
        observed = 'req' if d == [1, 0] else 'resp' if d == [0, 1] else 'none' if d == [0, 0] else 'odd%s' % d
        egress = {p: v for p, v in out.items() if v}
        fwd_expected = 'identical-out' if port in (9, 1) else 'no-out'
        # admitted ports forward original bytes regardless of validity (README: original forwarding)
        got_fwd = 'identical-out' if any(f == frame for v in egress.values() for f in v) else ('no-out' if not egress else 'changed-out')
        rep.add(name, oracle(frame, port), observed, note=note, in_port=port, frame=frame, out=egress,
                counter_delta=d, forwarding_expected=fwd_expected, forwarding_observed=got_fwd,
                forwarding_ok=(fwd_expected == got_fwd))
    base_q, base_r = request(), response()
    # positives
    run('request_valid', base_q, 9); run('response_valid', base_r, 1)
    run('request_valid_df_flag', request(ip_flags_frag=0x4000), 9)
    run('request_psh_ack_off(flags=ACK)', request(flags=0x10), 9)
    # malformed envelopes
    run('bad_ip_checksum_req', request(bad_ip=True), 9); run('bad_ip_checksum_resp', response(bad_ip=True), 1)
    run('bad_tcp_checksum_req', request(bad_tcp=True), 9); run('bad_tcp_checksum_resp', response(bad_tcp=True), 1)
    run('ttl_zero_req', request(ttl=0), 9)
    run('ip_mf_fragment_req', request(ip_flags_frag=0x2000), 9)
    run('tcp_syn_flag_req', request(flags=0x02), 9)
    run('tcp_urgent_req', request(urgent=1), 9)
    # DNP3 CRC corruption (offsets in the TCP payload: 34+20=54 start of payload)
    P = 54
    for nm, off in (('crc_header', P + 8), ('crc_request_block', P + 10 + 8)):
        run('bad_dnp3_%s_req' % nm, F.corrupt(base_q, off), 9)
    for nm, off in (('crc_header', P + 8), ('crc_first_block', P + 10 + 16), ('crc_second_block', P + 10 + 18 + 16),
                    ('crc_tail', P + 10 + 18 + 18 + 1)):
        run('bad_dnp3_%s_resp' % nm, F.corrupt(base_r, off), 1)
    run('bad_dnp3_data_byte_req(crc stale)', F.corrupt(base_q, P + 12), 9)
    # wrong tuple / link / ports / profile
    run('wrong_sport_req', request(s=(CL[0], CL[1] + 1)), 9)
    run('wrong_dst_ip_req', request(d=(SV[0] + 1, SV[1])), 9)
    run('wrong_link_dst_req', request(dst=OUTSTATION + 1), 9)
    run('wrong_link_src_req', request(src=MASTER + 1), 9)
    run('wrong_link_dst_resp', response(dst=MASTER + 1), 1)
    run('wrong_ingress_port_req(port2)', base_q, 2)
    run('reverse_tuple_on_client_port', base_r, 9)
    run('wrong_ctrl_req', request(ctrl=0xc3), 9)
    run('wrong_function_req', request(user=bytes([0xc0, 0xc0, 2, 10, 2, 0, 0, 22])), 9)
    run('wrong_range_last_req', request(user=bytes([0xc0, 0xc0, 1, 10, 2, 0, 0, 21])), 9)
    run('wrong_group_req', request(user=bytes([0xc0, 0xc0, 1, 11, 2, 0, 0, 22])), 9)
    run('transport_no_fir_fin_req', request(user=bytes([0x40, 0xc0, 1, 10, 2, 0, 0, 22])), 9)
    run('app_no_fir_fin_resp', response(user=bytes([0xc0, 0x40]) + RESP[2:]), 1)
    run('wrong_resp_function', response(user=RESP[:2] + b'\x82' + RESP[3:]), 1)
    run('repeat_request_valid', base_q, 9)
    ok = rep.finish(os.path.join(os.environ['OUT'], 'cases.json'))
    fw = [r for r in rep.record['cases'] if not r['forwarding_ok']]
    print('forwarding mismatches:', [r['name'] for r in fw])
    sys.exit(0 if ok and not fw else 1)

if __name__ == '__main__':
    main()
