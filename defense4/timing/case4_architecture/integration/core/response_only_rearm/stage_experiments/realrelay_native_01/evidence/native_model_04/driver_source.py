"""realrelay_native_01 on the LOCAL Tofino model: option-bearing connections stay native, clean ones still map.

Run through read_reencode_01/model_drive_oracle.py (CASE4_STRICT_CONTROLS=1) so padded READs are checked against
the re-encoding oracle. Functional model only: not hardware, not timing.

Sequence on one tuple (master 10.0.0.1, relay 10.0.0.2, both on dev port 9 as in the retained drivers):
  A  clean connection 1 (100/900): MSS-only handshake, READ padded to 58, master FIN, relay FIN|PSH|ACK (0x19)
     answer (requirement C), master last ACK -> N owner phase 0x10f; E stays mode 1 (stale).
  B  TS connection 1 (2000/3000), option bytes from the SEL-751 capture as in realrelay_01: TS SYN (offset 10),
     TS SYN-ACK (offset 11), TS ACK, 3 x [TS READ request, relay separate TS ACK, 49-octet native READ
     response], SACK ACK (offset 11), relay 0x19 with TS, master final ACK, master FIN|ACK, relay last ACK.
     Every frame must leave exactly once, byte-identical, in its own direction; N, E and T registers equal
     the snapshot taken before the TS SYN after every step; E outcome 16 counts each frame.
  C  TS connection 2 (2600/3600) closed by a TS RST|ACK from the master: same checks.
  D  INFO: an offset-5 RST|ACK on the idle tuple (outside the native profile; N refuses it as before).
     Hard check: registers unchanged.
  E  clean connection 2 (4000/7000) on the same tuple: opens, arms (phase 5, mode 1, front 7001), READ padded
     to 58; while it is live, TS segments are still dropped and change nothing; relay-initiated 0x19 close,
     master ACK, master FIN|ACK, relay last ACK -> phase 0x10f.
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

# exact option bytes from protocol/evidence/hw_range_read_01/native_ip_retest_20261010.pcap (as realrelay_01)
OPT_SYN = bytes.fromhex('020405b4' '0402080a52a36613045f0966' '01030307')                     # pcap #0, offset 10
OPT_SYNACK = bytes.fromhex('020405b4' '01030300' '01010402' '0101080a045f6ae652a36613')         # pcap #1, offset 11
OPT_M = bytes.fromhex('0101080a52a36614045f6ae6')                                               # pcap #2/#3, offset 8
OPT_R_ACK = bytes.fromhex('0101080a045f6ae652a36614')                                           # pcap #4, offset 8
OPT_R_RSP = bytes.fromhex('0101080a045f6b0452a36614')                                           # pcap #5, offset 8
OPT_R_FPA = bytes.fromhex('0101080a045f827452a37da5')                                           # pcap #9 (0x19), offset 8
NATIVE_PASS = 16          # E outcome index of pass_native (generate.py E_NATIVE_PASS)
T_OUTCOMES = 25


def sack_opts(left, right):
    """NOP NOP SACK(one block) + NOP NOP TS (pcap #6 TS values): 24 octets, offset 11."""
    return bytes.fromhex('0101050a') + struct.pack('!II', left, right) + bytes.fromhex('0101080a52a3662e045f6b04')


def build(flags, seq, ack, opts=b'', payload=b'', reverse=False, window=4096):
    """vectors.packet with arbitrary options; relay frames (reverse=True) carry the relay's addresses."""
    assert len(opts) % 4 == 0
    src, dst, sport, dport = vectors.CLIENT, vectors.SERVER, vectors.CLIENT_PORT, vectors.SERVER_PORT
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq & 0xffffffff, ack & 0xffffffff,
                      ((20 + len(opts)) // 4) << 4, flags, window, 0, 0) + opts + payload
    pseudo = struct.pack('!IIBBH', src, dst, 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack('!H', vectors.checksum(pseudo + tcp)) + tcp[18:]
    ip = struct.pack('!BBHHHBBHII', 0x45, 0, 20 + len(tcp), 1, 0x4000, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack('!H', vectors.checksum(ip)) + ip[12:]
    return bytes.fromhex('001122334455aabbccddeeff0800') + ip + tcp


def checksums_ok(frame):
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    total = struct.unpack('!H', ip[2:4])[0]
    pseudo = ip[12:20] + bytes((0, 6)) + struct.pack('!H', total - ihl)
    return vectors.checksum(ip[:ihl]) == 0 and vectors.checksum(pseudo + ip[ihl:total]) == 0


def main():
    report = Report(os.environ['PROG'], physical=False,
                    scope='realrelay_native_01: option-bearing connections native, clean connections mapped',
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
        counter = m.table('p0.r_Egress.outcome')

        def e_counts():
            for op in ('Sync', 'SyncCounters'):
                try:
                    counter.operations_execute(m.target, op)
                    break
                except Exception:
                    pass
            got = {}
            for code in range(32):
                for data, _k in counter.entry_get(m.target, [counter.make_key([gc.KeyTuple('$COUNTER_INDEX', code)])],
                                                  {'from_hw': True}):
                    v = data.to_dict()['$COUNTER_SPEC_PKTS']
                    got[code] = sum(v) if isinstance(v, list) else v
            return got

        def snapshot():
            """Every N, E and T register the spec names, plus N's private banks and T's outcome cells."""
            names = {'N': ('owner', 'epoch', 'client', 'server', 'counter', 'work.work', 'application', 'read_app'),
                     'E': ('mode', 'front', 'acct', 'img_end', 'img_start', 'img_wend', 'epoch', 'master_isn'),
                     'T': ('cur_epoch_reg', 'gen_alloc_reg', 'op_gen_alloc_reg', 't0_reg', 'op_t0_reg', 'ack_done_reg',
                           'resp_done_reg', 'op_done_reg', 'child_seen0_reg', 'child_seen1_reg', 'child_seen2_reg',
                           'ack_commit_at_reg', 'ack_commit_gen_reg')}
            prefix = {'N': 'p0.n_Ingress.', 'E': 'p0.r_Egress.', 'T': 'p1.t_Ingress.'}
            state = {role: {n: m.register_read(prefix[role] + n, 0, pipe=1 if role == 'T' else 0) for n in ns}
                     for role, ns in names.items()}
            state['T']['outcomes'] = [scalar(m.register_read('p1.t_Ingress.outcomes', i, pipe=1))
                                      for i in range(T_OUTCOMES)]
            return state

        def owner_phase():
            return scalar(m.register_read('p0.n_Ingress.owner', 0, pipe=0)) >> 16

        def e_reg(name):
            raw = m.register_read('p0.r_Egress.' + name, 0, pipe=0)
            fields = {k.split('.')[-1]: (v[0] if isinstance(v, list) else v) for k, v in raw.items()
                      if k.startswith('r_Egress.')}
            return fields['f1'] if list(fields) == ['f1'] else fields

        def direction(frame):
            src = int.from_bytes(frame[26:30], 'big')
            return 'to_master' if src == RELAY.ip_int else 'to_relay' if src == MASTER.ip_int else 'other'

        def step(name, sent, expected, relay=False):
            """expected: a frame (exactly one, byte-exact) or None (dropped)."""
            assert checksums_ok(sent), name
            m.drain(ports)
            c0 = e_counts()
            got = m.exchange(RELAY.dev_port if relay else MASTER.dev_port, sent, ports, timeout=3, quiet=.15)
            c1 = e_counts()
            flat = [f for p in ports for f in got[p]]
            delta = {k: c1[k] - c0.get(k, 0) for k in c1 if c1[k] != c0.get(k, 0)}
            if expected is None:
                good = not flat
            else:
                good = (len(flat) == 1 and same_frame(flat[0], expected, sent)
                        and direction(flat[0]) == ('to_master' if relay else 'to_relay'))
            report.add(name, 'drop' if expected is None else 'one exact frame',
                       'drop' if not flat else '%d frames %s' % (len(flat), [direction(f) for f in flat]),
                       ok=good, E_outcome_delta=delta, received={str(p): [f.hex() for f in got[p]] for p in ports},
                       want='' if expected is None else expected.hex())
            return delta

        def native(name, sent, relay, reference):
            """One option-bearing frame: forwarded unchanged once, counted as native pass, no register moves.
            A master frame crosses E twice: the 0xe0 lap (settle_t's lap row is NoAction, so outcome 0) and the
            departure (pass_native, outcome 16). A relay frame crosses E once, at its departure."""
            delta = step(name, sent, sent, relay)
            report.add(name + '_E_outcome_delta', {NATIVE_PASS: 1} if relay else {0: 1, NATIVE_PASS: 1}, delta)
            report.add(name + '_registers_unchanged', reference, snapshot())

        def clean_handshake(c, s, tag):
            syn = vectors.packet(2, c, mss=1460)
            step('%s_SYN_%d' % (tag, c), syn, syn)
            synack = vectors.packet(18, s, c + 1, reverse=True, mss=1460)
            step('%s_SYNACK_%d' % (tag, s), synack, synack, relay=True)
            ack = vectors.packet(16, c + 1, s + 1)
            step('%s_ACK_%d' % (tag, c), ack, ack)
            report.add('%s_owner_phase_established' % tag, 5, owner_phase())
            report.add('%s_E_mode_mapped' % tag, 1, e_reg('mode'))
            report.add('%s_E_front_armed' % tag, s + 1, e_reg('front'))

        def clean_read(c, s, tag):
            request = rs.request_packet(seq=c + 1, ack=s + 1)
            step('%s_READ_request' % tag, request, request)
            ack = rs.ack_packet(seq=s + 1, ack=c + 21)
            step('%s_READ_relay_ACK' % tag, ack, ack, relay=True)
            padded, _ = b.pad_read_response(rs.response_frame())
            report.add('%s_oracle_image_58' % tag, 58, len(padded))
            step('%s_READ_response_padded_58' % tag, rs.response_packet(seq=s + 1, ack=c + 21),
                 vectors.packet(24, s + 1, c + 21, reverse=True, payload=padded), relay=True)

        report.record['meta']['initial_state'] = snapshot()
        req_frame, rsp_frame = rs.request_frame(), rs.response_frame()
        report.add('frame_lengths_read_request_20_response_49', (20, 49), (len(req_frame), len(rsp_frame)))

        # ---- A: clean connection 1; relay answers the master's FIN with 0x19 (requirement C) ----
        c, s = 100, 900
        clean_handshake(c, s, 'A')
        clean_read(c, s, 'A')
        step('A_master_FIN', vectors.packet(17, 121, 959), vectors.packet(17, 121, 950))
        step('A_relay_FIN_PSH_ACK_0x19', vectors.packet(0x19, 950, 122, reverse=True),
             vectors.packet(0x19, 959, 122, reverse=True), relay=True)
        step('A_master_last_ACK', vectors.packet(16, 122, 960), vectors.packet(16, 122, 951))
        report.add('A_closed_phase_0x10f', 0x10f, owner_phase())

        # ---- B: TS connection on the same tuple, entirely native ----
        before_b = snapshot()
        report.record['meta']['before_native_state'] = before_b
        c, s = 2000, 3000
        native('B_TS_SYN_off10', build(2, c, 0, OPT_SYN), False, before_b)
        native('B_TS_SYNACK_off11', build(18, s, c + 1, OPT_SYNACK, reverse=True), True, before_b)
        native('B_TS_ACK_off8', build(16, c + 1, s + 1, OPT_M), False, before_b)
        mseq, rseq = c + 1, s + 1
        for k in (1, 2, 3):
            native('B_TS_READ%d_request_off8' % k, build(24, mseq, rseq, OPT_M, req_frame), False, before_b)
            mseq += len(req_frame)
            native('B_TS_READ%d_relay_ACK_off8' % k, build(16, rseq, mseq, OPT_R_ACK, reverse=True), True, before_b)
            native('B_TS_READ%d_response49_off8' % k, build(24, rseq, mseq, OPT_R_RSP, rsp_frame, reverse=True),
                   True, before_b)
            rseq += len(rsp_frame)
        native('B_SACK_ACK_off11', build(16, mseq, rseq, sack_opts(rseq + 10, rseq + 30)), False, before_b)
        native('B_relay_FIN_PSH_ACK_0x19_off8', build(0x19, rseq, mseq, OPT_R_FPA, reverse=True), True, before_b)
        native('B_master_final_ACK_off8', build(16, mseq, rseq + 1, OPT_M), False, before_b)
        native('B_master_FIN_ACK_off8', build(0x11, mseq, rseq + 1, OPT_M), False, before_b)
        native('B_relay_last_ACK_off8', build(16, rseq + 1, mseq + 1, OPT_R_ACK, reverse=True), True, before_b)

        # ---- C: second TS connection, closed by a TS RST|ACK ----
        c, s = 2600, 3600
        native('C_TS_SYN_off10', build(2, c, 0, OPT_SYN), False, before_b)
        native('C_TS_SYNACK_off11', build(18, s, c + 1, OPT_SYNACK, reverse=True), True, before_b)
        native('C_TS_ACK_off8', build(16, c + 1, s + 1, OPT_M), False, before_b)
        native('C_TS_RST_ACK_off8', build(0x14, c + 1, s + 1, OPT_M), False, before_b)

        # ---- D: INFO, an offset-5 RST|ACK on the idle tuple (outside the native profile) ----
        m.drain(ports)
        got = m.exchange(MASTER.dev_port, vectors.packet(0x14, c + 1, s + 1), ports, timeout=3, quiet=.15)
        report.add('D_INFO_off5_RST_ACK_idle', 'recorded',
                   'forwarded' if any(got.values()) else 'dropped', ok=True)
        report.add('D_off5_RST_registers_unchanged', before_b, snapshot())

        # ---- E: fresh clean connection on the same tuple ----
        c, s = 4000, 7000
        clean_handshake(c, s, 'E')
        clean_read(c, s, 'E')
        step('E_master_wire_ACK_commit', vectors.packet(16, 4021, 7059), vectors.packet(16, 4021, 7050))
        live = snapshot()
        step('E_live_TS_READ_request_dropped', build(24, 4021, 7059, OPT_M, req_frame), None)
        step('E_live_TS_response_dropped', build(24, 7050, 4021, OPT_R_RSP, rsp_frame, reverse=True), None, relay=True)
        report.add('E_live_TS_drops_change_nothing', live, snapshot())
        step('E_relay_FIN_PSH_ACK_0x19_first', vectors.packet(0x19, 7050, 4021, reverse=True),
             vectors.packet(0x19, 7059, 4021, reverse=True), relay=True)
        step('E_master_ACK_of_FIN', vectors.packet(16, 4021, 7060), vectors.packet(16, 4021, 7051))
        step('E_master_FIN_ACK', vectors.packet(17, 4021, 7060), vectors.packet(17, 4021, 7051))
        step('E_relay_last_ACK', vectors.packet(16, 7051, 4022, reverse=True),
             vectors.packet(16, 7060, 4022, reverse=True), relay=True)
        report.add('E_closed_phase_0x10f', 0x10f, owner_phase())
        report.record['meta']['final_state'] = snapshot()
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / 'native_results.json')
    (Path(os.environ['OUT']) / 'driver_source.py').write_bytes(Path(__file__).read_bytes())
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
