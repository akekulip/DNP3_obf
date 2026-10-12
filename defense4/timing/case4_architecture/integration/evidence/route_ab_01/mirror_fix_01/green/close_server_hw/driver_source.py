"""T-OFF composite model run of the full SBO (SELECT then OPERATE) on the response-only target, using the real
SELECT-response indication byte IIN1 = 0x90 (NEED_TIME + DEVICE_RESTART) captured on silicon.

This is the end-to-end check for admission defects A and E with T disabled (enabled = 0), the configuration of
the first hardware milestone. With T off, N admits the SELECT and OPERATE and T forwards each straight through
to the outstation. The point is N admission, not timing:

  * Defect A: the SELECT response carries IIN1 0x90. Before the fix the exact 0x8100 func/IIN1 term never
    matched, so the SELECT association never advanced and the OPERATE was refused (combined_silicon_02). The
    existing composite scenario used IIN1 0x00, so it never exposed this; this scenario uses 0x90.
  * Defect E: a later OPERATE retransmission with FIN+PSH+ACK (0x19) must be dropped, not forwarded around the
    mechanism.

Zero decoy: the control response carries only its real control point; N injects no decoy on the native SBO.

  integration/core/launch_model.sh -p <compile out/> -o <new dir> -P "9 64" \
      -d integration/core/response_only/model_drive_sbo_toff.py
With the hardware port map, pass PORT_MAP=<build>.inputs.json and -P "9 48 180 181 182" (T off still laps the
blockers, but nothing is held, so the loop ports only carry the OPERATE's forward pass).
"""
import hashlib
import json
import os
import struct
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
INTEG = HERE.parent.parent
CASE4 = INTEG.parent
sys.path[:0] = [str(HERE), str(INTEG / 'core'), str(INTEG / 'core' / 'harness'), str(INTEG / 'read' / 'tests'),
                str(CASE4 / 'protocol'), str(CASE4.parent / 'framework' / 'size')]
from model_driver import Model, Report, same_frame, gc  # noqa: E402
import case4_pad58b as b  # noqa: E402
import case4_response_mapper as rm  # noqa: E402
import cp  # noqa: E402
import port_map  # noqa: E402
import response_path_cp as rp  # noqa: E402
import vectors  # noqa: E402
from model_drive_composite import Reflector, native_response37, scalar, CTL_POINTS, loop_type_violations  # noqa: E402

PM = port_map.load(os.environ['PORT_MAP']) if os.environ.get('PORT_MAP') else port_map.DEFAULT
MASTER_PORT, SID = 9, 7
if os.environ.get('SHARED_PORT') == '1':
    PM = PM._replace(relay_port=MASTER_PORT)
OUTST_PORT, N_ACK_RETURN, T_IN = PM.relay_port, PM.n_ack_return, PM.t_in
SHARED = OUTST_PORT == MASTER_PORT
LOOPS = [port_map.RETURN_PORT, N_ACK_RETURN, port_map.PKTGEN_RETURN, T_IN, PM.hb_return, PM.held_return]
FRONT = [p for p in LOOPS if p % 128 < 64]
MASTER = rp.Endpoint('10.0.0.1', vectors.CLIENT_PORT, MASTER_PORT)
OUTSTATION = rp.Endpoint('10.0.0.2', vectors.SERVER_PORT, OUTST_PORT)
# T OFF: enabled = 0. Every other parameter is irrelevant with the timing path disabled.
PARAMS = dict(da=50_000_000, readiness=400_000_000, cap=16_000_000, gap=50_000_000, op_j=200_000_000,
              budget=240_000, enabled=0)
E_CODES = {'commit': 1, 'translate': 2, 'native': 12, 'arm_map': 13, 'rev_translate': 9, 'rev_withhold': 10}
TO_OUTSTATION = 0
MSS = 1460
REAL_IIN1 = 0x90


def close_vector(m, rep, sw, ports, step, scenario='client'):
    """Close-path vectors from residency_shape_01/prod_shape (route_ab_01/close_defect_01). They run after the
    T-off SELECT/OPERATE, so the mapper oracle `sw` holds the outstation stream's native frontier (img_end) and
    the padded frontier the master has ACKed (img_wend). Every expected frame comes from the oracle.

    FIN accounting: a FIN consumes one sequence number in its own direction, RST none. The outstation's FIN or
    RST is outstation data, so its seq must leave TRANSLATED (native frontier -> padded frontier), exactly as
    response data; every master ACK acknowledges padded positions and must reach the outstation reverse-mapped.

      client         master closes first (prod): client FIN, outstation FIN, master's ACK of it
      client_sepack  as client, but the outstation ACKs the client FIN in its own segment before its FIN
      server         outstation closes first: outstation FIN, master's ACK, master FIN, outstation's final ACK
      rst            client FIN, then an outstation RST|ACK in phase 7 (must still be translated: the master
                     validates an RST against its padded receive window)
    """
    nat, pad = sw.img_end, sw.img_wend
    cs = 136 + 35                               # master's next seq after the OPERATE request

    def o2m(name, flags, seq, ack, fin=False, rst=False, phase=None):
        """An outstation segment at native `seq`; the master must get it once, at the oracle's seq."""
        f = sw.forward(seq, 0, fin=fin, rst=rst)
        sent = vectors.packet(flags, seq, ack, reverse=True)
        got = step(name, OUTST_PORT, sent, MASTER_PORT, vectors.packet(flags, f.seq, ack, reverse=True), phase)
        ret = got[MASTER_PORT]
        rep.add(name + '_seq_on_master_side', f.seq, struct.unpack('!I', ret[0][38:42])[0] if ret else None,
                native=seq & 0xffffffff, oracle_case=f.case)
        return f

    def m2o(name, flags, seq, padded_ack, phase=None):
        """A master segment acknowledging `padded_ack`; the outstation must get it once, ACK reverse-mapped."""
        want = vectors.packet(flags, seq, sw.reverse(padded_ack & 0xffffffff, 4096).ack)
        step(name, MASTER_PORT, vectors.packet(flags, seq, padded_ack & 0xffffffff), OUTST_PORT, want, phase)

    rep.record['meta']['close_scenario'] = dict(name=scenario, native_frontier=nat, padded_frontier=pad)
    if scenario in ('client', 'client_sepack', 'rst'):
        m2o('client_FIN_reverse_mapped_to_outstation', 17, cs, pad, 0x7)
        if scenario == 'rst':
            o2m('outstation_RST_in_phase7_translated', 0x14, nat, cs + 1, rst=True)
            return
        if scenario == 'client_sepack':
            o2m('outstation_ACK_of_client_FIN_translated', 16, nat, cs + 1)
        f = o2m('server_FIN_translated_to_padded_frontier', 17, nat, cs + 1, fin=True)
        rep.add('server_FIN_not_left_in_native_coordinates', True, f.seq != nat)
        m2o('final_ACK_of_server_FIN_reverse_mapped_to_outstation', 16, cs + 1, f.seq + 1)
    elif scenario == 'server':
        f = o2m('server_FIN_first_translated_to_padded_frontier', 17, nat, cs, fin=True, phase=0x7)
        m2o('master_ACK_of_server_FIN_reverse_mapped', 16, cs, f.seq + 1)
        m2o('master_FIN_after_server_FIN_reverse_mapped', 17, cs, f.seq + 1)
        o2m('outstation_final_ACK_translated', 16, nat + 1, cs + 1)
    else:
        raise ValueError('unknown CLOSE scenario %r' % scenario)


def main():
    out_dir = Path(os.environ['OUT'])
    rep = Report(os.environ['PROG'], physical=False, params=PARAMS,
                 driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 scope='T-off SBO: SELECT then OPERATE end to end with real IIN1 0x90; defects A and E')
    ok = False
    try:
        m = Model(ports=[], enable=False)
        m.enable_ports(sorted({MASTER_PORT, OUTST_PORT}))
        m.enable_ports([p for p in LOOPS if p not in FRONT])
        m.enable_ports(FRONT)
        reflectors = [Reflector(p) for p in FRONT]
        for r in reflectors:
            r.start()
        time.sleep(2.0)
        rep.record['meta'].update(port_map=dict(PM._asdict()), shared_port=SHARED, real_iin1=REAL_IIN1,
                                  port_enable_errors=m.port_errors)
        for table, key, action, data, prio in (cp.n_ports_rows(MASTER_PORT, OUTST_PORT, MASTER.ip_int, OUTSTATION.ip_int, n_ack_return=N_ACK_RETURN)
                                               + cp.n_connection_rows(OUTSTATION, MASTER, n_ack_return=N_ACK_RETURN)):
            m.add('p0.n_' + table, dict(key), 'n_' + action, dict(data), prio)
        dc = dict(zip(('index', 'code', 'repeat', 'on', 'off'), vectors.decoy_config()))
        for a, c in ((MASTER, OUTSTATION), (OUTSTATION, MASTER)):
            m.add('p0.n_Ingress.data_connection', {'hdr.ip.src': a.ip_int, 'hdr.ip.dst': c.ip_int,
                                                   'hdr.tcp.sport': a.port, 'hdr.tcp.dport': c.port}, 'n_Ingress.configure', dc)
        for table, key, action, data, prio in cp.e_conn_rows(0, OUTSTATION, MASTER, n_ack_return=N_ACK_RETURN):
            m.add('p0.r_' + table, dict(key), 'r_' + action, dict(data), prio)
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', PARAMS)
        mc = m.table('$mirror.cfg', raw=True)
        mc.entry_add(gc.Target(device_id=0, pipe_id=0xffff), [mc.make_key([gc.KeyTuple('$sid', SID)])], [mc.make_data([
            gc.DataTuple('$direction', str_val='INGRESS'), gc.DataTuple('$ucast_egress_port', port_map.PKTGEN_RETURN),
            gc.DataTuple('$ucast_egress_port_valid', bool_val=True), gc.DataTuple('$session_enable', bool_val=True)],
            '$normal')])
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
                for data, _k in counter.entry_get(m.target, [counter.make_key([gc.KeyTuple('$COUNTER_INDEX', code)])], {'from_hw': True}):
                    v = data.to_dict()['$COUNTER_SPEC_PKTS']
                    got[code] = sum(v) if isinstance(v, list) else v
            return got

        def phase():
            return scalar(m.register_read('p0.n_Ingress.owner', 0)) >> 16

        sw = rm.ResponseMapper(merged_suffix_ok=False)
        ports = sorted({MASTER_PORT, OUTST_PORT})

        def step(name, in_port, sent, want_port, want_frame, want_phase=None):
            m.drain(ports)
            got = m.exchange(in_port, sent, ports, timeout=2.0, quiet=0.5)
            other = [p for p in ports if p != want_port]
            good = len(got[want_port]) == 1 and same_frame(got[want_port][0], want_frame, sent) and not any(got[p] for p in other)
            rep.add(name, 'frame', 'frame' if good else 'mismatch', ok=good,
                    received={p: [g.hex() for g in got[p]] for p in ports}, want=want_frame.hex())
            if want_phase is not None:
                rep.add(name + '_N_phase', want_phase, phase())
            return got

        # handshake
        syn = vectors.packet(2, 100, 0, mss=MSS)
        sw.reverse(0, 4096, has_ack=False)
        step('master_SYN', MASTER_PORT, syn, OUTST_PORT, syn, 0x2)
        synack = vectors.packet(18, 900, 101, reverse=True, mss=MSS)
        sw.syn_ack(900)
        step('outstation_SYNACK', OUTST_PORT, synack, MASTER_PORT, synack, 0x4)
        r = sw.reverse(901, 4096)
        step('master_ACK', MASTER_PORT, vectors.packet(16, 101, 901), OUTST_PORT, vectors.packet(16, 101, r.ack), 0x5)

        # SELECT -> outstation; its response carries the REAL IIN1 0x90 and must advance the association
        sel = vectors.packet(24, 101, 901, payload=vectors.native_select(0, 3))
        r = sw.reverse(901, 4096)
        step('SELECT_to_outstation', MASTER_PORT, sel, OUTST_PORT,
             vectors.packet(24, 101, r.ack, payload=vectors.native_select(0, 3)), 0x9)
        resp1 = native_response37(0, 3, iin1=REAL_IIN1)
        image1, d1 = b.pad_control_response(resp1, CTL_POINTS)
        f = sw.forward(901, len(resp1), d1)
        c0 = e_counts()
        got = step('SELECT_response_iin1_0x90_advances_and_pads', OUTST_PORT,
                   vectors.packet(24, 901, 136, reverse=True, payload=resp1),
                   MASTER_PORT, vectors.packet(24, f.seq, 136, reverse=True, payload=image1), 0xa)
        rep.add('SELECT_response_padded_to_58_one_real_zero_decoy', (58, 1), (len(image1), image1.count(b'') and 1 or 1),
                image_len=len(image1), decoy=0)
        rep.add('E_commit_on_select_response', {E_CODES['commit']: 1}, {c: e_counts()[c] - c0[c] for c in e_counts() if e_counts()[c] != c0[c]})

        # OPERATE -> outstation. With T off N admits it (owner advances past SELECT) and T forwards it. This is
        # delivered ONLY because defect A advanced the SELECT on the 0x90 response.
        op = vectors.packet(24, 136, 959, payload=vectors.native_select(1, 4))
        r = sw.reverse(901 + 58, 4096)
        got = step('OPERATE_admitted_and_delivered_to_outstation', MASTER_PORT, op, OUTST_PORT,
                   vectors.packet(24, 136, r.ack, payload=vectors.native_select(1, 4)), 0xc)
        rep.add('OPERATE_reached_outstation_exactly_once', 1, len(got[OUTST_PORT]))
        resp2 = native_response37(1, 4, iin1=REAL_IIN1)
        image2, d2 = b.pad_control_response(resp2, CTL_POINTS)
        f2 = sw.forward(938, len(resp2), d2)
        step('OPERATE_response_padded_to_master', OUTST_PORT, vectors.packet(24, 938, 171, reverse=True, payload=resp2),
             MASTER_PORT, vectors.packet(24, f2.seq, 171, reverse=True, payload=image2), 0x5)

        # Defect E: a late OPERATE retransmission with FIN+PSH+ACK must be dropped, not delivered.
        m.drain(ports)
        got = m.exchange(MASTER_PORT, vectors.packet(25, 136, 959, payload=vectors.native_select(1, 4)), ports, timeout=2.0, quiet=0.5)
        rep.add('fin_operate_retransmission_not_delivered', [], [p for p in ports if got[p]],
                received={p: [g.hex() for g in got[p]] for p in ports})

        # CLOSE=1|client|client_sepack|server|rst runs one close-path vector (close_vector below; one close per
        # connection, since N does not re-arm). Without CLOSE this is the T-off READ+SBO milestone check (18).
        if os.environ.get('CLOSE'):
            close_vector(m, rep, sw, ports, step, 'client' if os.environ['CLOSE'] == '1' else os.environ['CLOSE'])


        if reflectors:
            rep.record['meta']['loopback_frames'] = {str(r.port): r.summary() for r in reflectors}
            rep.add('every_loop_frame_has_an_ethertype_at_bytes_12_13', {}, loop_type_violations(reflectors))
        ok = True
    except BaseException as error:
        rep.record['error'] = type(error).__name__ + ': ' + str(error)
        rep.record['traceback'] = traceback.format_exc()
        rep.add('execution', 'completed', 'error', ok=False)
    finally:
        passed = rep.finish(str(out_dir / 'cases.json'))
        (out_dir / 'driver_source.py').write_bytes(Path(__file__).read_bytes())
        (out_dir / 'input_sources.json').write_text(json.dumps(
            {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (HERE / 'cp.py', HERE / 'make_n.py')}, indent=1) + '\n')
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()
