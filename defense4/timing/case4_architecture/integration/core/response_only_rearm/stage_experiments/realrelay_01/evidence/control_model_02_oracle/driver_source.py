"""Real-relay TCP-option probe on the LOCAL Tofino model (rearm_57s local compile).

Tests a read-only source audit's prediction: N admits the Linux-master / SEL-751 timestamp-profile
handshake (it checks only the MSS), E arms mode=1 from N's SYN-ACK kind 0xe7 while front/acct/img stay
unarmed (they need SH_SYNACK_OK = offset 6 with MSS), and every later offset-8 NOP NOP TS segment is
SH_ODD and dropped by drop_odd in both directions. Also: master ACK with SACK, relay FIN|PSH|ACK (0x19).

Option bytes are copied verbatim from protocol/evidence/hw_range_read_01/native_ip_retest_20261010.pcap
(packet index in the pcap given beside each). Addresses, ports, ISNs, window (4096), IP id/DF/TTL follow
the existing model drivers (vectors.packet conventions), so only the TCP options differ from the clean
profile. Functional model only: not hardware, not timing.

  argv[1] = 'ts'      cases 1-4 on a fresh tuple, then an informational in-run RST + clean reconnect
  argv[1] = 'control' clean (MSS-only) handshake + READ on a fresh bring-up (case 5)
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

# ---- exact option bytes from the real capture -------------------------------------------------------
OPT_SYN = bytes.fromhex('020405b4' '0402080a52a36613045f0966' '01030307')                     # pcap #0, offset 10
OPT_SYNACK = bytes.fromhex('020405b4' '01030300' '01010402' '0101080a045f6ae652a36613')         # pcap #1, offset 11
OPT_M_ACK = bytes.fromhex('0101080a52a36614045f6ae6')                                           # pcap #2, offset 8
OPT_M_READ = bytes.fromhex('0101080a52a36614045f6ae6')                                          # pcap #3, offset 8
OPT_R_ACK = bytes.fromhex('0101080a045f6ae652a36614')                                           # pcap #4, offset 8
OPT_R_RSP = bytes.fromhex('0101080a045f6b0452a36614')                                           # pcap #5, offset 8
OPT_R_FPA = bytes.fromhex('0101080a045f827452a37da5')                                           # pcap #9 (0x19), offset 8
OUTCODES = {1: 'commit', 2: 'translate', 3: 'zero', 4: 'replay', 5: 'stale', 6: 'drop_overlap', 7: 'drop_ahead',
            8: 'DROP_ODD', 9: 'rev_translate', 10: 'rev_withhold', 11: 'rev_drop_stale', 12: 'native',
            13: 'arm_map', 14: 'arm_nat', 15: 'drop_merged', 0: 'unparsed/other'}


def sack_opts(left, right):
    """NOP NOP SACK(kind 5, len 10, one block) + NOP NOP TS (TS values of pcap #6): 24 bytes, offset 11."""
    return bytes.fromhex('0101050a') + struct.pack('!II', left, right) + bytes.fromhex('0101080a52a3662e045f6b04')


def build(flags, seq, ack, opts=b'', payload=b'', reverse=False, window=4096):
    """vectors.packet with arbitrary options; IPv4 and TCP checksums computed over everything."""
    if len(opts) % 4:
        raise ValueError('options not 32-bit aligned')
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


def verify_checksums(frame):
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    total = struct.unpack('!H', ip[2:4])[0]
    ok_ip = vectors.checksum(ip[:ihl]) == 0
    pseudo = ip[12:20] + bytes((0, 6)) + struct.pack('!H', total - ihl)
    ok_tcp = vectors.checksum(pseudo + ip[ihl:total]) == 0
    return ok_ip and ok_tcp


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else 'ts'
    report = Report(os.environ['PROG'], physical=False,
                    scope='realrelay_01 TCP-option probe (%s) on rearm_57s local compile' % mode,
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
        report.record['meta']['mode'] = mode
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
            for code in range(16):
                for data, _k in counter.entry_get(m.target, [counter.make_key([gc.KeyTuple('$COUNTER_INDEX', code)])],
                                                  {'from_hw': True}):
                    v = data.to_dict()['$COUNTER_SPEC_PKTS']
                    got[code] = sum(v) if isinstance(v, list) else v
            return got

        def regs():
            e = {}
            for name in ('mode', 'front', 'acct', 'img_end', 'img_start', 'img_wend', 'epoch', 'master_isn'):
                raw = m.register_read('p0.r_Egress.' + name, 0, pipe=0)
                fields = {k.split('.')[-1]: (v[0] if isinstance(v, list) else v)
                          for k, v in raw.items() if k.startswith('r_Egress.')}
                e[name] = fields['f1'] if list(fields) == ['f1'] else fields
            n = {name: scalar(m.register_read('p0.n_Ingress.' + name, 0, pipe=0)) for name in ('owner', 'epoch', 'client', 'server')}
            n['owner_phase'] = hex(n['owner'] >> 16)
            n['owner'] = hex(n['owner'])
            return dict(E=e, N=n)

        CASES = []

        def step(case, name, sent, reverse, prediction):
            """prediction: 'forwarded' | 'dropped' | 'translated' | None (control: one exact expected frame)."""
            if not verify_checksums(sent):
                raise ValueError('%s: built frame has a bad checksum' % name)
            m.drain(ports)
            c0 = e_counts()
            got = m.exchange(RELAY.dev_port if reverse else MASTER.dev_port, sent, ports, timeout=3, quiet=.2)
            c1 = e_counts()
            flat = [f for p in ports for f in got[p]]
            if not flat:
                verdict = 'dropped'
            elif len(flat) == 1 and same_frame(flat[0], sent):
                verdict = 'forwarded'
            elif len(flat) == 1:
                verdict = 'translated'
            else:
                verdict = '%d frames' % len(flat)
            out_dir = []
            for f in flat:
                src = int.from_bytes(f[26:30], 'big') if len(f) >= 34 else None
                out_dir.append('to_master' if src == RELAY.ip_int else 'to_relay' if src == MASTER.ip_int else 'other')
            outcome = {OUTCODES.get(k, k): c1[k] - c0[k] for k in c1 if c1[k] != c0[k]}
            state = regs()
            row = dict(case=case, step=name, sent_len=len(sent), sent=sent.hex(), verdict=verdict,
                       directions=out_dir, received=[f.hex() for f in flat], E_outcome_delta=outcome, state=state,
                       predicted=prediction)
            CASES.append(row)
            report.add(name, prediction, verdict, ok=(prediction == verdict) if prediction else True,
                       E_outcome_delta=outcome, E=state['E'], N=state['N'], received={str(p): [f.hex() for f in got[p]] for p in ports})
            return flat, row

        def exact(case, name, sent, expected, reverse):
            flat, row = step(case, name, sent, reverse, None)
            good = len(flat) == 1 and same_frame(flat[0], expected, sent)
            row['exact_expected'] = expected.hex()
            row['exact_match'] = good
            report.add(name + '_exact', 'one exact frame', 'match' if good else row['verdict'], ok=good)
            return good

        report.record['meta']['initial_state'] = regs()
        req_frame, rsp_frame = rs.request_frame(), rs.response_frame()
        report.record['meta']['payload_lengths'] = dict(read_request=len(req_frame), read_response=len(rsp_frame))
        padded, _ = b.pad_read_response(rsp_frame)

        def clean_control(case, c, s):
            ok = True
            syn = vectors.packet(2, c, mss=1460)
            ok &= exact(case, 'C_SYN_%d' % c, syn, syn, False)
            synack = vectors.packet(18, s, c + 1, reverse=True, mss=1460)
            ok &= exact(case, 'C_SYNACK_%d' % s, synack, synack, True)
            ack = vectors.packet(16, c + 1, s + 1)
            ok &= exact(case, 'C_ACK_%d' % c, ack, ack, False)
            st = regs()
            report.add('C_front_armed_%d' % s, s + 1, st['E']['front'])
            report.add('C_mode_mapped_%d' % s, 1, st['E']['mode'])
            req = rs.request_packet(seq=c + 1, ack=s + 1)
            ok &= exact(case, 'C_READ_%d' % c, req, req, False)
            rack = rs.ack_packet(seq=s + 1, ack=c + 21)
            ok &= exact(case, 'C_READ_relay_ACK', rack, rack, True)
            ok &= exact(case, 'C_READ_response_padded58', rs.response_packet(seq=s + 1, ack=c + 21),
                        vectors.packet(24, s + 1, c + 21, reverse=True, payload=padded), True)
            return ok

        if mode == 'control':
            report.add('CASE5_clean_profile_handshake_and_READ_work', True, clean_control(5, 100, 900))
        elif mode == 'variants':
            # Discriminating follow-up (added after ts_model_01 showed N refusing the TS SYN-ACK).
            c, s = 100, 900
            step(1, 'V_TS_SYN_master_off10', build(2, c, 0, OPT_SYN), False, 'forwarded')
            step(1, 'V_TS_SYNACK_off11_as_ts_model_01', build(18, s, c + 1, OPT_SYNACK), True, None)
            # exact pcap #1 IP/TCP header fields: no DF, IP id 37, window 8688
            f = bytearray(build(18, s, c + 1, OPT_SYNACK, window=8688))
            f[18:20] = struct.pack('!H', 37)
            f[20:22] = b'\x00\x00'
            f[24:26] = b'\x00\x00'
            f[24:26] = struct.pack('!H', vectors.checksum(bytes(f[14:34])))
            step(1, 'V_TS_SYNACK_off11_pcap_ip_noDF_id37_win8688', bytes(f), True, None)
            # same SYN-ACK, MSS first then NOP padding to offset 11 (no WS/SACK/TS): is it the offset or the options?
            step(1, 'V_SYNACK_off11_MSS_plus_NOPs', build(18, s, c + 1, OPT_SYNACK[:4] + b'\x01' * 20), True, None)
            # clean MSS-only SYN-ACK (offset 6) after the TS SYN: hybrid, to put E in mode 1
            _, row = step(1, 'V_clean_SYNACK_off6_after_TS_SYN', vectors.packet(18, s, c + 1, reverse=True, mss=1460), True, 'forwarded')
            e = row['state']['E']
            report.add('V_mode_after_clean_SYNACK', 1, e['mode'])
            report.add('V_front_after_clean_SYNACK', s + 1, e['front'])
            step(1, 'V_TS_third_ACK_master_off8_mode1', build(16, c + 1, s + 1, OPT_M_ACK), False, 'dropped')
            step(2, 'V_TS_READ_request_master_off8_mode1', build(24, c + 1, s + 1, OPT_M_READ, req_frame), False, 'dropped')
            step(2, 'V_TS_relay_ACK_off8_mode1', build(16, s + 1, c + 21, OPT_R_ACK, reverse=True), True, 'dropped')
            step(2, 'V_TS_READ_response49_off8_mode1', build(24, s + 1, c + 21, OPT_R_RSP, rsp_frame, reverse=True),
                 True, 'dropped')
            send = s + 1 + len(rsp_frame)
            step(3, 'V_SACK_ACK_master_off11_mode1', build(16, c + 21, send, sack_opts(send + 10, send + 30)), False, 'dropped')
            step(4, 'V_FIN_PSH_ACK_0x19_relay_off8_mode1', build(0x19, send, c + 21, OPT_R_FPA, reverse=True), True, 'dropped')
            # same-state clean-profile positive controls: does the connection still carry a clean READ?
            req = rs.request_packet(seq=c + 1, ack=s + 1)
            step(5, 'V_clean_off5_READ_after_TS_drops', req, False, 'forwarded')
        else:
            c, s = 100, 900
            # ---- case 1: TS handshake ----
            step(1, 'TS_SYN_master_off10', build(2, c, 0, OPT_SYN, window=4096), False, 'forwarded')
            _, row = step(1, 'TS_SYNACK_relay_off11', build(18, s, c + 1, OPT_SYNACK), True, 'forwarded')
            e = row['state']['E']
            report.add('P_mode_armed_1_by_TS_SYNACK', 1, e['mode'])
            report.add('P_front_unarmed_after_TS_SYNACK', 0, e['front'])
            report.add('P_acct_unarmed_after_TS_SYNACK', {'hi': 0, 'lo': 0}, e['acct'])
            report.add('P_img_unarmed_after_TS_SYNACK', (0, 0, 0), (e['img_end'], e['img_start'], e['img_wend']))
            step(1, 'TS_third_ACK_master_off8', build(16, c + 1, s + 1, OPT_M_ACK), False, 'dropped')
            # ---- case 2: TS READ ----
            step(2, 'TS_READ_request_master_off8', build(24, c + 1, s + 1, OPT_M_READ, req_frame), False, 'dropped')
            step(2, 'TS_relay_separate_ACK_off8', build(16, s + 1, c + 21, OPT_R_ACK, reverse=True), True, 'dropped')
            step(2, 'TS_READ_response49_relay_off8', build(24, s + 1, c + 21, OPT_R_RSP, rsp_frame, reverse=True),
                 True, 'dropped')
            # ---- case 3: master pure ACK with SACK ----
            send = s + 1 + len(rsp_frame)
            step(3, 'SACK_ACK_master_off11', build(16, c + 21, send, sack_opts(send + 10, send + 30)), False, 'dropped')
            # ---- case 4: relay FIN|PSH|ACK 0x19 with TS ----
            step(4, 'FIN_PSH_ACK_0x19_relay_off8', build(0x19, send, c + 21, OPT_R_FPA, reverse=True), True, 'dropped')
            # ---- informational: does a clean-profile RST retire the dead TS connection, and can a fresh
            #      clean connection follow in the same run? Not part of the prediction.
            step(6, 'INFO_master_RST_ACK_off5', vectors.packet(0x14, c + 21, s + 1), False, None)
            report.record['meta']['after_RST_state'] = regs()
            info_ok = clean_control(6, 4000, 7000)
            report.record['meta']['in_run_control_after_RST_worked'] = bool(info_ok)
            report.add('INFO_in_run_clean_reconnect_after_RST', 'recorded', 'worked' if info_ok else 'failed', ok=True)
        report.record['meta']['steps'] = CASES
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / 'ts_results.json')
    (Path(os.environ['OUT']) / 'driver_source.py').write_bytes(Path(__file__).read_bytes())
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
