"""Local Tofino-1 model run of the response-only composite (compose.py): real N in pipe 0 ingress, the B'
response path (E) in pipe 0 egress, T in pipe 2. Functional model execution only: not hardware, not
timing, not stage fit.

Every rule comes from core/response_only/cp.py and is installed on the model through BF Runtime
(Model.add, with real $MATCH_PRIORITY on N's ternary ports table). The scenario is the execution
document's vector in native coordinates, sent by the endpoints exactly as they would be:

  handshake   master SYN 100, outstation SYN-ACK 900 (arms E's mapping), master ACK 101/901
  SELECT      master 101+35, ACK 901            -> lap (E reverse-maps) -> N binds -> outstation
  response    outstation 901+37, ACK 136        -> N binds -> E pads 37 -> 58 -> master
  OPERATE     master 136+35, ACK 959 (padded)   -> lap: E maps 959 -> 938 -> N admits -> T holds -> outstation
  response    outstation 938+37, ACK 171        -> N (idle) -> E pads -> master at SEQ 959
  forged      outstation 4-tuple injected on the MASTER port -> no E state change, nothing to the master

Expected frames come from the software oracles (framework/size/case4_response_mapper.py, case4_pad58b),
fed in the order frames leave the switch.

  integration/core/launch_model.sh -p <compile out/> -o <new dir> -P "9 64" \
      -d integration/core/response_only/model_drive_composite.py
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
import case4_padding as codec  # noqa: E402
import case4_response_mapper as rm  # noqa: E402
import cp  # noqa: E402
import queue_sim as qs  # noqa: E402
import response_path_cp as rp  # noqa: E402
import vectors  # noqa: E402
sys.path.insert(0, str(INTEG / 'connection' / 'binding' / 'tests'))
import read_support as rs  # noqa: E402  (READ request / response / ACK frames, as the binding tests use)

MASTER_PORT, OUTST_PORT, N_ACK_RETURN, T_IN, PKTGEN_RETURN, SID = 9, 64, 70, 197, 196, 7   # read/ports.p4, two-pipe
CTL_POINTS = [b.AnalogFloatPoint(301, 10.0, 0), b.AnalogFloatPoint(302, 20.0, 0)]   # E's ctl_eligible constant
PARAMS = dict(da=50_000_000, readiness=400_000_000, cap=16_000_000, gap=50_000_000, op_j=200_000_000,
              budget=240_000, enabled=1)
E_CODES = {'commit': 1, 'translate': 2, 'zero': 3, 'replay': 4, 'stale': 5, 'rev_translate': 9,
           'rev_withhold': 10, 'native': 12, 'arm_map': 13}
E_STATE_CODES = {1, 2, 3, 4, 5, 9, 10, 11, 13, 14}
TO_OUTSTATION = 0   # E's outcome counter records each unparsed departure on 64 (parser `accept`) as code 0
MASTER = rp.Endpoint('10.0.0.1', vectors.CLIENT_PORT, MASTER_PORT)       # vectors.CLIENT
OUTSTATION = rp.Endpoint('10.0.0.2', vectors.SERVER_PORT, OUTST_PORT)    # vectors.SERVER
# Second connection: N does not bind it. A different master host: E's odd_ip_t is keyed on the host pair, so
# two slots cannot share one (response_path_cp.Registry refuses it too; first attempt: ALREADY_EXISTS).
MASTER_B = rp.Endpoint('10.0.0.3', vectors.CLIENT_PORT, MASTER_PORT)
TUPLE_B = (MASTER_B.ip_int, vectors.SERVER, vectors.CLIENT_PORT, vectors.SERVER_PORT)
MSS = 1460


def native_response37(app, fc, status=0):
    _head, user = codec.decode_frame(vectors.native_select(app, fc))
    objects = bytearray(user[3:])
    objects[17] = status
    return codec.build_frame(bytes.fromhex('05641c4401000a00'), user[:2] + bytes((0x81, 0, 0)) + bytes(objects))


def scalar(regs):
    """First value of a register_read() dict (pipe 0 for a per-pipe list)."""
    v = next(iter(regs.values()))
    return v[0] if isinstance(v, list) else v


def main():
    out_dir = Path(os.environ['OUT'])
    rep = Report(os.environ['PROG'], physical=False, params=PARAMS,
                 driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 scope='response-only composite: real N + E + T; document vector; forged tuple; READ x2 after SBO; '
                       'second connection in slot 1; late READ reply; reset; reconnect refusal')
    ok = False
    try:
        m = Model(ports=[], enable=False)
        m.enable_ports([MASTER_PORT, OUTST_PORT])
        m.enable_ports([68, N_ACK_RETURN, PKTGEN_RETURN, T_IN, 198, 199])   # refusals recorded, not fatal
        time.sleep(2.0)
        rep.record['meta']['port_enable_errors'] = m.port_errors
        # ---- configuration: every row from cp.py ------------------------------------------------
        installed = []
        for table, key, action, data, priority in (cp.n_ports_rows(MASTER_PORT, OUTST_PORT) +
                                                   cp.n_connection_rows(OUTSTATION, MASTER)):
            m.add('p0.n_' + table, dict(key), 'n_' + action, dict(data), priority)
            installed.append((table, key, action, data, priority))
        dc = dict(zip(('index', 'code', 'repeat', 'on', 'off'), vectors.decoy_config()))
        fwd4 = {'hdr.ip.src': MASTER.ip_int, 'hdr.ip.dst': OUTSTATION.ip_int, 'hdr.tcp.sport': MASTER.port,
                'hdr.tcp.dport': OUTSTATION.port}
        rev4 = {'hdr.ip.src': OUTSTATION.ip_int, 'hdr.ip.dst': MASTER.ip_int, 'hdr.tcp.sport': OUTSTATION.port,
                'hdr.tcp.dport': MASTER.port}
        for key in (fwd4, rev4):
            m.add('p0.n_Ingress.data_connection', key, 'n_Ingress.configure', dc)
        for table, key, action, data, priority in cp.n_read_rows(OUTSTATION, MASTER):
            m.add('p0.n_' + table, dict(key), 'n_' + action, dict(data), priority)
            installed.append((table, key, action, data, priority))
        for table, key, action, data, priority in (cp.e_conn_rows(0, OUTSTATION, MASTER) +
                                                   cp.e_conn_rows(1, OUTSTATION, MASTER_B)):
            m.add('p0.r_' + table, dict(key), 'r_' + action, dict(data), priority)
            installed.append((table, key, action, data, priority))
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', PARAMS)
        mc = m.table('$mirror.cfg', raw=True)
        mc.entry_add(gc.Target(device_id=0, pipe_id=0xffff), [mc.make_key([gc.KeyTuple('$sid', SID)])], [mc.make_data([
            gc.DataTuple('$direction', str_val='INGRESS'), gc.DataTuple('$ucast_egress_port', PKTGEN_RETURN),
            gc.DataTuple('$ucast_egress_port_valid', bool_val=True), gc.DataTuple('$session_enable', bool_val=True)],
            '$normal')])
        rep.record['meta']['rows'] = [[t, list(k), a, list(d), p] for t, k, a, d, p in installed]

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

        def e_state(slot=0):
            return {r: m.register_read('p0.r_Egress.' + r, slot) for r in
                    ('mode', 'front', 'acct', 'img_end', 'img_start', 'img_wend')}

        def n_state():
            return {r: scalar(m.register_read('p0.n_Ingress.' + r, 0)) for r in ('owner', 'epoch', 'read_app')}

        consts = qs.QueueSim().consts()

        def t_counts():
            res = {}
            for name in ('OUT_OP_RELEASE', 'OUT_HELD_REWAIT', 'OUT_UNMATCHED', 'OUT_ACK_COMMIT', 'OUT_RESP_RELEASE',
                         'OUT_ACK_FALLBACK', 'OUT_RESP_FALLBACK'):
                r = m.register_read('p1.t_Ingress.outcomes', consts[name])
                v = [val for k, val in r.items() if k.endswith('.f1')][0]
                res[name] = sum(v) if isinstance(v, list) else v
            return res

        def delta(before, after):
            return {c: after[c] - before[c] for c in after if after[c] != before[c]}

        sw = rm.ResponseMapper(merged_suffix_ok=False)
        ports = [MASTER_PORT, OUTST_PORT]

        def step(name, in_port, sent, want_port, want_frame, want_codes, owner_hi=None, timeout=2.0, quiet=0.5):
            m.drain(ports)
            before = e_counts()
            got = m.exchange(in_port, sent, ports, timeout=timeout, quiet=quiet)
            after = e_counts()
            other = [p for p in ports if p != want_port]
            good = (len(got[want_port]) == 1 and same_frame(got[want_port][0], want_frame, sent)
                    and not any(got[p] for p in other))
            rep.add(name, 'frame', 'frame' if good else 'mismatch', ok=good,
                    received={p: [g.hex() for g in got[p]] for p in ports}, want=want_frame.hex())
            rep.add(name + '_E_outcomes', want_codes, delta(before, after))
            if owner_hi is not None:
                st = n_state()
                rep.add(name + '_N_owner_phase', owner_hi, st['owner'] >> 16, owner=hex(st['owner']), epoch=st['epoch'])
            return got

        # ---- handshake ------------------------------------------------------------------------------
        syn = vectors.packet(2, 100, 0, mss=MSS)
        r = sw.reverse(0, 4096, has_ack=False)
        step('master_SYN', MASTER_PORT, syn, OUTST_PORT, syn, {E_CODES['native']: 1, TO_OUTSTATION: 1}, owner_hi=0x2)
        synack = vectors.packet(18, 900, 101, reverse=True, mss=MSS)
        sw.syn_ack(900)
        step('outstation_SYNACK_arms_mapping', OUTST_PORT, synack, MASTER_PORT, synack, {E_CODES['arm_map']: 1}, owner_hi=0x4)
        ack = vectors.packet(16, 101, 901)
        r = sw.reverse(901, 4096)
        step('master_handshake_ACK', MASTER_PORT, ack, OUTST_PORT, vectors.packet(16, 101, r.ack),
             {E_CODES['rev_' + r.case]: 1, TO_OUTSTATION: 1}, owner_hi=0x5)   # idle; source-level interpreter: SYN 2, SYN-ACK 4, ACK 5

        # ---- SELECT and its padded response ----------------------------------------------------------
        sel = vectors.packet(24, 101, 901, payload=vectors.native_select(0, 3))
        r = sw.reverse(901, 4096)
        step('SELECT_native_through_lap', MASTER_PORT, sel, OUTST_PORT,
             vectors.packet(24, 101, r.ack, payload=vectors.native_select(0, 3)), {E_CODES['rev_' + r.case]: 1, TO_OUTSTATION: 1},
             owner_hi=0x9)
        resp1 = native_response37(0, 3)
        image1, d1 = b.pad_control_response(resp1, CTL_POINTS)
        f = sw.forward(901, len(resp1), d1)
        rep.add('oracle_response1_commits_and_pads', ('commit', 21, 58), (f.case, d1, len(image1)))
        step('response1_padded_to_master', OUTST_PORT, vectors.packet(24, 901, 136, reverse=True, payload=resp1),
             MASTER_PORT, vectors.packet(24, f.seq, 136, reverse=True, payload=image1), {E_CODES[f.case]: 1},
             owner_hi=0xa)

        # ---- OPERATE: master ACKs the padded response (959); the lap maps it to 938; T holds it -------
        op_payload = vectors.native_select(1, 4)
        r = sw.reverse(901 + 58, 4096)
        rep.add('oracle_maps_master_959_to_938', ('translate', 938), (r.case, r.ack))
        t_before = t_counts()
        operate = vectors.packet(24, 136, 959, payload=op_payload)
        start = time.time()
        got = step('OPERATE_mapped_admitted_held_by_T_then_released', MASTER_PORT, operate, OUTST_PORT,
                   vectors.packet(24, 136, r.ack, payload=op_payload), {E_CODES['rev_' + r.case]: 1, TO_OUTSTATION: 1},
                   owner_hi=0xc, timeout=3.0, quiet=1.0)
        rep.record['meta']['operate_round_trip_s'] = round(time.time() - start, 3)
        t_after = t_counts()
        td = delta(t_before, t_after)
        rep.add('T_released_the_OPERATE_once_after_holding', dict(OUT_OP_RELEASE=1, held=True),
                dict(OUT_OP_RELEASE=td.get('OUT_OP_RELEASE', 0), held=td.get('OUT_HELD_REWAIT', 0) > 0), t_delta=td)

        # ---- second response: N back to idle; E pads it at the master's SEQ 959 ------------------------
        resp2 = native_response37(1, 4)
        image2, d2 = b.pad_control_response(resp2, CTL_POINTS)
        f = sw.forward(938, len(resp2), d2)
        rep.add('oracle_response2_commits_at_959', ('commit', 959), (f.case, f.seq))
        step('response2_padded_to_master', OUTST_PORT, vectors.packet(24, 938, 171, reverse=True, payload=resp2),
             MASTER_PORT, vectors.packet(24, f.seq, 171, reverse=True, payload=image2), {E_CODES[f.case]: 1},
             owner_hi=0x5)

        # ---- forged: the outstation's 4-tuple injected on the MASTER link ----------------------------
        e0, n0, c0 = e_state(), n_state(), e_counts()
        forged = vectors.packet(24, 975, 171, reverse=True, payload=native_response37(2, 4))
        m.drain(ports)
        got = m.exchange(MASTER_PORT, forged, ports, timeout=2.0, quiet=0.5)
        e1, n1, c1 = e_state(), n_state(), e_counts()
        cd = delta(c0, c1)
        rep.add('forged_tuple_touches_no_E_state', e0, e1)
        rep.add('forged_tuple_no_E_mapping_outcome', set(), set(cd) & E_STATE_CODES, outcome_delta=cd)
        rep.add('forged_tuple_N_state_unchanged', n0, n1)
        rep.add('forged_tuple_never_reaches_master', 0, len(got[MASTER_PORT]),
                received={p: [g.hex() for g in got[p]] for p in ports})

        # ---- composition acceptance (execution document line 104) ------------------------------------
        LATE_S = 2.0   # well past T's readiness window (PARAMS readiness 400 ms): a genuinely late outstation

        def read_exchange(name, cseq, mack, sseq, app, late=False):
            """One READ on connection A: master request (ACK in padded space) -> lap -> N kind 9 -> T ->
            outstation; outstation ACK and response -> N kinds 10, 11 -> T -> master, response padded.
            On time: request, ACK, response 0 / 50 / 100 ms apart (model_drive_t_padded_flow.py), so T commits
            the ACK and releases the response. late=True: the outstation answers LATE_S after the request,
            and T must still deliver both, through its deadline fallbacks."""
            r = sw.reverse(mack, 4096)
            rep.add(name + '_oracle_maps_master_ack', ('translate', sseq), (r.case, r.ack), master_ack=mack)
            req = rs.request_packet(cseq, mack, app=app)
            want_req = rs.request_packet(cseq, r.ack, app=app)
            cend = cseq + len(rs.request_frame(app=app))
            rsp_frame = rs.response_frame(app=app)
            image, d = b.pad_read_response(rsp_frame)
            fa = sw.forward(sseq, 0, 0)
            fr = sw.forward(sseq, len(rsp_frame), d)
            rep.add(name + '_oracle_response_commits_and_pads', ('commit', 9, 58), (fr.case, d, len(image)))
            want_ack = rs.ack_packet(fa.seq, cend)
            want_rsp = vectors.packet(24, fr.seq, cend, reverse=True, payload=image)
            t0, c0 = t_counts(), e_counts()
            m.drain(ports)
            # The outstation answers only after it RECEIVES the request (wall-clock 50 ms spacing from the
            # injection overlapped N's busy work record on the slow model: the ACK then bypassed T, model_01
            # of response_only_17). late=True adds LATE_S on top, past T's readiness window.
            got_req = m.exchange(MASTER_PORT, req, ports, timeout=5.0, quiet=0.3)
            if late:
                time.sleep(LATE_S)
            m.send(OUTST_PORT, rs.ack_packet(sseq, cend))
            time.sleep(0.05)
            m.send(OUTST_PORT, rs.response_packet(sseq, cend, app=app))
            got = m.capture(ports, timeout=15.0, quiet=4.0)    # fallback releases take many laps on the model
            got = {p: got_req[p] + got[p] for p in ports}
            t1, c1 = t_counts(), e_counts()
            good_req = len(got[OUTST_PORT]) == 1 and same_frame(got[OUTST_PORT][0], want_req, req)
            rep.add(name + '_request_mapped_relayed_once', 'frame', 'frame' if good_req else 'mismatch', ok=good_req,
                    received=[g.hex() for g in got[OUTST_PORT]], want=want_req.hex())
            good = (len(got[MASTER_PORT]) == 2 and same_frame(got[MASTER_PORT][0], want_ack)
                    and same_frame(got[MASTER_PORT][1], want_rsp))
            rep.add(name + '_ack_then_PADDED_response_to_master', 'frames', 'frames' if good else 'mismatch', ok=good,
                    received=[g.hex() for g in got[MASTER_PORT]], want=[want_ack.hex(), want_rsp.hex()])
            rep.add(name + '_E_outcomes', {E_CODES['rev_' + r.case]: 1, TO_OUTSTATION: 1, E_CODES[fa.case]: 1,
                                           E_CODES[fr.case]: 1}, delta(c0, c1))
            td = delta(t0, t1)
            # T held and released each original exactly once. Which path (commit vs fallback) is a timing
            # verdict on global_tstamp, which the local model cannot rank (coarse clock, slow multi-pass
            # latency): response_only_17 model_01 vs model_02 swapped them between on-time and late runs.
            # The paths are asserted in deterministic time by read/tests (F_BoundedFallback incl. the late-reply
            # case) and are recorded here, not judged.
            rep.add(name + '_T_released_ack_once_and_response_once', {'ack': 1, 'response': 1},
                    {'ack': td.get('OUT_ACK_COMMIT', 0) + td.get('OUT_ACK_FALLBACK', 0),
                     'response': td.get('OUT_RESP_RELEASE', 0) + td.get('OUT_RESP_FALLBACK', 0)}, t_delta=td)
            st = n_state()
            rep.add(name + '_N_idle_after', 0x5, st['owner'] >> 16, owner=hex(st['owner']), read_app=st['read_app'])
            return cend, sseq + len(rsp_frame), fr.seq + len(image)

        # mixed READ/SBO on one connection: two READs after the SELECT/OPERATE, each with an ACK that is
        # already in the enlarged (master) space: 1017 -> 975, then 1075 -> 1024
        cseq, sseq, mseq = read_exchange('READ1_after_SBO', 171, 1017, 975, 0xc0)
        rep.add('READ1_N_read_app_is_its_sequence', 0, n_state()['read_app'])   # app 0xc0: sequence 0

        # two independent connection slots: connection B (slot 1) between A's READs; N binds only A, so B
        # crosses N natively and only E maps it. A's slot-0 state and N's state must not move.
        swb = rm.ResponseMapper(merged_suffix_ok=False)
        a_before, n_before = e_state(0), n_state()
        syn_b = vectors.packet(2, 300, 0, mss=MSS, tuple4=TUPLE_B)
        step('B_SYN', MASTER_PORT, syn_b, OUTST_PORT, syn_b, {E_CODES['native']: 1, TO_OUTSTATION: 1})
        synack_b = vectors.packet(18, 400, 301, reverse=True, mss=MSS, tuple4=TUPLE_B)
        swb.syn_ack(400)
        step('B_SYNACK_arms_slot1', OUTST_PORT, synack_b, MASTER_PORT, synack_b, {E_CODES['arm_map']: 1})
        r = swb.reverse(401, 4096)
        step('B_ACK', MASTER_PORT, vectors.packet(16, 301, 401, tuple4=TUPLE_B), OUTST_PORT,
             vectors.packet(16, 301, r.ack, tuple4=TUPLE_B), {E_CODES['rev_' + r.case]: 1, TO_OUTSTATION: 1})
        sel_b = vectors.packet(24, 301, 401, payload=vectors.native_select(0, 3), tuple4=TUPLE_B)
        r = swb.reverse(401, 4096)
        step('B_SELECT', MASTER_PORT, sel_b, OUTST_PORT,
             vectors.packet(24, 301, r.ack, payload=vectors.native_select(0, 3), tuple4=TUPLE_B),
             {E_CODES['rev_' + r.case]: 1, TO_OUTSTATION: 1})
        rsp_b = native_response37(0, 3)
        image_b, db = b.pad_control_response(rsp_b, CTL_POINTS)
        f = swb.forward(401, len(rsp_b), db)
        step('B_response_padded_by_slot1', OUTST_PORT, vectors.packet(24, 401, 336, reverse=True, payload=rsp_b, tuple4=TUPLE_B),
             MASTER_PORT, vectors.packet(24, f.seq, 336, reverse=True, payload=image_b, tuple4=TUPLE_B), {E_CODES[f.case]: 1})
        rep.add('B_left_slot0_state_unchanged', a_before, e_state(0))
        rep.add('B_left_N_state_unchanged', n_before, n_state())
        rep.add('B_slot1_mapped', (1, 401 + 37), (scalar(e_state(1)['mode']), scalar(e_state(1)['img_end'])))

        cseq, sseq, mseq = read_exchange('READ2_enlarged_ack', cseq, mseq, sseq, 0xc1)
        rep.add('READ2_N_read_app_is_its_sequence', 1, n_state()['read_app'])   # app 0xc1: sequence 1
        # genuinely late outstation (a separate scenario from the scheduling artifact fixed above)
        cseq, sseq, mseq = read_exchange('READ3_late_outstation_reply', cseq, mseq, sseq, 0xc2, late=True)
        rep.add('READ3_N_read_app_is_its_sequence', 2, n_state()['read_app'])   # app 0xc2: sequence 2

        # reset: the master's RST|ACK (enlarged ACK) is mapped, N closes (phase 7) and hands it to T, which
        # forwards it once to the outstation
        r = sw.reverse(mseq, 4096)
        rst = vectors.packet(0x14, cseq, mseq)
        step('RESET_genuine_master_RST_mapped_closed_forwarded_once', MASTER_PORT, rst, OUTST_PORT, vectors.packet(0x14, cseq, r.ack),
             {E_CODES['rev_' + r.case]: 1, TO_OUTSTATION: 1}, owner_hi=0x7)
        # reconnect on the same 4-tuple: N has no verified rearm from phase 7 (connection/binding tests call
        # their reset preset a diagnostic fixture; STEP2_DESIGN.md: no controller rearm authorized). Recorded,
        # not worked around: the new SYN must be refused and N must stay closed.
        m.drain(ports)
        got = m.exchange(MASTER_PORT, vectors.packet(2, 5000, 0, mss=MSS), ports, timeout=2.0, quiet=0.5)
        rep.add('RECONNECT_refused_by_N_until_a_rearm_exists', (0, 0, 0x7),
                (len(got[MASTER_PORT]), len(got[OUTST_PORT]), n_state()['owner'] >> 16))
        ok = True
    except BaseException as error:
        rep.record['error'] = type(error).__name__ + ': ' + str(error)
        rep.record['traceback'] = traceback.format_exc()
        rep.add('execution', 'completed', 'error', ok=False)
    finally:
        passed = rep.finish(str(out_dir / 'cases.json'))
        (out_dir / 'driver_source.py').write_bytes(Path(__file__).read_bytes())
        (out_dir / 'cp_source.py').write_bytes((HERE / 'cp.py').read_bytes())
        (out_dir / 'input_sources.json').write_text(json.dumps(
            {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
             for p in (HERE / 'cp.py', HERE / 'make_n.py', HERE / 'make_e.py', HERE / 'compose.py')}, indent=2) + '\n')
    return 0 if (ok and passed) else 1


if __name__ == '__main__':
    sys.exit(main())
