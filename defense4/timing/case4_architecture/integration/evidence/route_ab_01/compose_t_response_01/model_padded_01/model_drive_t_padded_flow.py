"""Local Tofino-1 model run of the COMPOSED program (compose_t_response.py): a padding-eligible READ whose
ACK and response are held and released by T (pipe 2) and then transformed by the B' response path's
egress (pipe 0). Functional model execution only (not hardware, not timing).

The connection is armed exactly as protocol/model_drive_response_path.py arms it, but on the composed
program's tables (p0.r_*): rows from response_path_cp.Registry, then a direct master SYN, outstation
SYN-ACK (MSS only, arms the mapping) and master ACK through pipe 0. The READ transaction then goes through
T as N would hand it over on T_IN (325): the master's request, the outstation's ACK, and the outstation's
DNP3 READ response. Every frame leaving the switch is predicted byte for byte by the same software oracle
the standalone driver uses (framework/size/case4_response_mapper.py with the pad58b codec), fed in the
order the frames actually leave: the request on RELAY 64, then T's released ACK and response on FORWARD 9.

  integration/core/launch_model.sh -p <composed out/> -o <new dir> -P "9 64 324 325 326 327" \
      -d integration/read/model_drive_t_padded_flow.py
"""
import os
import struct
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASE4 = HERE.parent.parent
sys.path[:0] = [str(HERE / 'tests'), str(CASE4 / 'integration' / 'core'), str(CASE4 / 'protocol'),
                str(CASE4.parent / 'framework' / 'size')]
import queue_sim as qs  # noqa: E402
from model_driver import Model, Report, same_frame, gc  # noqa: E402
import case4_pad58b as b  # noqa: E402
import case4_padding as pad  # noqa: E402
import case4_response_mapper as rm  # noqa: E402
import response_path_cp as cp  # noqa: E402

T_IN, PKTGEN_RETURN, MASTER, OUTST, SID = 325, 324, 9, 64, 7
KIND = {'request': 9, 'ack': 10, 'response': 11}
PARAMS = dict(da=50_000_000, readiness=400_000_000, cap=16_000_000, gap=50_000_000, op_j=200_000_000,
              budget=240_000, enabled=1)
# Frame helpers copied from protocol/model_drive_response_path.py (that file runs its scenario on import).
ETH = bytes.fromhex('0a0000000002' '0a0000000001') + b'\x08\x00'
O_IP, M_IP, O_PORT, M_PORT = bytes([10, 0, 0, 1]), bytes([10, 0, 0, 2]), 20000, 40000
LINK_HEAD = bytes.fromhex('056419c40a000100')
MSS = b'\x02\x04\x05\xb4'
CODES = {'commit': 1, 'translate': 2, 'zero': 3, 'replay': 4, 'stale': 5, 'passthrough': 12, 'arm_map': 13,
         'rev_translate': 9}
MASK = 0xffffffff


def csum(data):
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def packet(src, dst, sport, dport, seq, ack, flags, window, payload=b'', options=b''):
    off = (20 + len(options)) // 4
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq & MASK, ack & MASK, off << 4, flags, window, 0, 0) + options
    pseudo = src + dst + struct.pack('!BBH', 0, 6, len(tcp) + len(payload))
    tcp = tcp[:16] + struct.pack('!H', csum(pseudo + tcp + payload)) + tcp[18:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp) + len(payload), 0x1234, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', csum(ip)) + ip[12:]
    return ETH + ip + tcp + payload


def read_frame(n):
    data = bytes((n * 7 + i) & 0xff for i in range(23))
    return pad.build_frame(LINK_HEAD, bytes([0xc0 | (n & 15), 0xc0 | (n & 15), 0x81, 0x80, 0]) + b.HEADER_READ23 + data)


def leading(payload):
    if len(payload) >= 10 and payload[:2] == b'\x05\x64' and payload[2] >= 5:
        n = payload[2] - 5
        flen = 10 + n + 2 * ((n + 15) // 16)
        if len(payload) >= flen:
            image, delta = b.pad_read_response(payload[:flen])
            if delta:
                return delta, image, flen
    return 0, None, 0


def main():
    m = Model(ports=[], enable=False)
    rep = Report(os.environ['PROG'], params=PARAMS, physical=False,
                 scope='T-held READ through the composed program; B\' padding on T\'s released response')
    m.enable_ports([MASTER, OUTST])
    time.sleep(2.0)
    rep.add('ports_enabled', {}, m.port_errors, ok=not m.port_errors)
    target = gc.Target(device_id=0, pipe_id=0xffff)
    mc = m.table('$mirror.cfg', raw=True)
    mc.entry_add(target, [mc.make_key([gc.KeyTuple('$sid', SID)])], [mc.make_data([
        gc.DataTuple('$direction', str_val='INGRESS'), gc.DataTuple('$ucast_egress_port', PKTGEN_RETURN),
        gc.DataTuple('$ucast_egress_port_valid', bool_val=True), gc.DataTuple('$session_enable', bool_val=True)],
        '$normal')])
    m.set_default('p2.t_Ingress.params', 't_Ingress.set_params', PARAMS)

    # Composed-program names: table X.y -> p0.r_X.y, action X.z -> r_X.z.
    def add(table, key, action, data):
        m.add('p0.r_' + table, key, 'r_' + action, data)

    def delete(table, key):
        t = m.table('p0.r_' + table)
        t.entry_del(m.target, [m._key(t, key)])
    registry = cp.Registry()
    registry.install(0, cp.Endpoint('10.0.0.1', O_PORT, OUTST), cp.Endpoint('10.0.0.2', M_PORT, MASTER), add, delete)
    counter = m.table('p0.r_Egress.outcome')

    def counts():
        for op in ('Sync', 'SyncCounters'):
            try:
                counter.operations_execute(m.target, op)
                break
            except Exception:
                pass
        out = {}
        for code in range(16):
            for data, _k in counter.entry_get(m.target, [counter.make_key([gc.KeyTuple('$COUNTER_INDEX', code)])],
                                              {'from_hw': True}):
                v = data.to_dict()['$COUNTER_SPEC_PKTS']
                out[code] = sum(v) if isinstance(v, list) else v
        return out

    sw = rm.ResponseMapper(merged_suffix_ok=False)
    isn, mseq = 0x10000000, 7000
    snd_nxt = (isn + 1) & MASK

    def direct(name, in_port, sent, expected, code):
        before = counts()
        out_port = MASTER if in_port == OUTST else OUTST
        got = m.exchange(in_port, sent, [OUTST, MASTER], timeout=2.0, quiet=0.5)
        after = counts()
        ok = len(got[out_port]) == 1 and not got[in_port] and same_frame(got[out_port][0], expected, sent)
        rep.add(name, 'frame', 'frame' if ok else 'mismatch', ok=ok, received=[g.hex() for g in got[out_port]])
        rep.add(name + '_outcome', {code: 1}, {c: after[c] - before[c] for c in after if after[c] != before[c]})

    # Handshake directly through pipe 0, as the standalone driver does.
    res = sw.reverse(0, 8192)
    syn = packet(M_IP, O_IP, M_PORT, O_PORT, mseq - 1, 0, 0x02, 8192)
    direct('master_SYN', MASTER, syn, packet(M_IP, O_IP, M_PORT, O_PORT, mseq - 1, res.ack, 0x02, res.window),
           CODES['rev_translate' if res.case == 'translate' else res.case])
    sw.syn_ack(isn)
    synack = packet(O_IP, M_IP, O_PORT, M_PORT, isn, mseq, 0x12, 8192, b'', MSS)
    direct('outstation_SYNACK_arms_mapping', OUTST, synack, synack, CODES['arm_map'])
    rcv_nxt = snd_nxt
    res = sw.reverse(rcv_nxt, 8192)
    direct('master_handshake_ACK', MASTER, packet(M_IP, O_IP, M_PORT, O_PORT, mseq, rcv_nxt, 0x10, 8192),
           packet(M_IP, O_IP, M_PORT, O_PORT, mseq, res.ack, 0x10, res.window),
           CODES['rev_translate' if res.case == 'translate' else res.case])

    # The READ transaction through T, in the order its frames will leave the switch.
    request = packet(M_IP, O_IP, M_PORT, O_PORT, mseq, rcv_nxt, 0x18, 8192, bytes(20))
    r_req = sw.reverse(rcv_nxt, 8192)
    exp_req = packet(M_IP, O_IP, M_PORT, O_PORT, mseq, r_req.ack, 0x18, r_req.window, bytes(20))
    mseq = (mseq + 20) & MASK
    ack = packet(O_IP, M_IP, O_PORT, M_PORT, snd_nxt, mseq, 0x10, 4096)
    r_ack = sw.forward(snd_nxt, 0, 0, fin=False, rst=False, supported=True)
    exp_ack = packet(O_IP, M_IP, O_PORT, M_PORT, r_ack.seq, mseq, 0x10, 4096)
    frame = read_frame(0)
    delta, image, flen = leading(frame)
    response = packet(O_IP, M_IP, O_PORT, M_PORT, snd_nxt, mseq, 0x18, 4096, frame)
    r_rsp = sw.forward(snd_nxt, len(frame), delta, fin=False, rst=False, supported=True)
    wire = image + frame[flen:] if r_rsp.pad else frame
    exp_rsp = packet(O_IP, M_IP, O_PORT, M_PORT, r_rsp.seq, mseq, 0x18, 4096, wire)
    rep.add('oracle_says_response_commits_and_pads', ('commit', True, len(wire) > len(frame)),
            (r_rsp.case, r_rsp.pad, len(wire) > len(frame)), frame_len=len(frame), image_len=len(wire))

    consts = qs.QueueSim().consts()

    def t_counter(name):
        r = m.register_read('p2.t_Ingress.outcomes', consts[name])
        v = [val for k, val in r.items() if k.endswith('.f1')][0]
        return sum(v) if isinstance(v, list) else v
    t_before = {n: t_counter(n) for n in ('OUT_ACK_COMMIT', 'OUT_RESP_RELEASE', 'OUT_HELD_REWAIT')}
    e_before = counts()
    m.drain([MASTER, OUTST])
    start = time.time()
    for off, kind, original in ((0.00, 'request', request), (0.05, 'ack', ack), (0.10, 'response', response)):
        delay = start + off - time.time()
        if delay > 0:
            time.sleep(delay)
        m.send(T_IN, struct.pack('!IIIBBH', 1, 0, 0, KIND[kind], 0, 0) + original)
    got = m.capture([MASTER, OUTST], timeout=3.0, quiet=3.0)
    e_after = counts()
    t_after = {n: t_counter(n) for n in t_before}
    rep.add('request_relayed_through_T_then_reverse_mapped', 1,
            len(got[OUTST]), ok=len(got[OUTST]) == 1 and same_frame(got[OUTST][0], exp_req, request),
            received=[g.hex() for g in got[OUTST]], want=exp_req)
    rep.add('T_released_ack_then_response_on_master_port', 2, len(got[MASTER]), received=[g.hex() for g in got[MASTER]])
    rep.add('T_released_ACK_mapped_byte_exact', True,
            len(got[MASTER]) >= 1 and same_frame(got[MASTER][0], exp_ack, ack), want=exp_ack)
    rep.add('T_released_response_PADDED_byte_exact', True,
            len(got[MASTER]) >= 2 and same_frame(got[MASTER][1], exp_rsp, response), want=exp_rsp,
            sent_len=len(response), want_len=len(exp_rsp))
    e_delta = {c: e_after[c] - e_before[c] for c in e_after if e_after[c] != e_before[c]}
    want_delta = {}
    for case in ('rev_translate' if r_req.case == 'translate' else r_req.case, r_ack.case, r_rsp.case):
        want_delta[CODES[case]] = want_delta.get(CODES[case], 0) + 1
    rep.add('pipe0_egress_outcomes_once_per_release', want_delta, e_delta)
    t_delta = {n: t_after[n] - t_before[n] for n in t_before}
    rep.add('T_held_and_committed', dict(OUT_ACK_COMMIT=1, OUT_RESP_RELEASE=1, held_laps=True),
            dict(OUT_ACK_COMMIT=t_delta['OUT_ACK_COMMIT'], OUT_RESP_RELEASE=t_delta['OUT_RESP_RELEASE'],
                 held_laps=t_delta['OUT_HELD_REWAIT'] > 0), laps=t_delta['OUT_HELD_REWAIT'])
    sys.exit(0 if rep.finish(os.path.join(os.environ['OUT'], 'cases.json')) else 1)


if __name__ == '__main__':
    main()
