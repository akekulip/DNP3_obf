"""Local Tofino-1 model run of the response-only composite on the REAL stack's TCP profile (timestamps,
SACK-permitted, window scale): the capture protocol/evidence/hw_range_read_01/native_ip_retest_20261010.pcap
as it was on the wire (real_profile.wire()), continued with further READs in the same profile
(real_profile.session). Functional only: not hardware, not timing.

E is not edited and does not pad this profile (its padding arms on the clean MSS-only handshake), so every frame
must leave the switch byte for byte as it was sent. What this run shows is N's part: N parses and binds the
timestamped handshake, hands each READ request / ACK / response to T, and T releases each once, in order.

  PORT_MAP=<build>.inputs.json (optional; default ports otherwise) READS=3 \\
  integration/core/launch_model.sh -p <compile out/> -o <new dir> -P "9 64" -d .../model_drive_real_profile.py
For the hardware map (relay on 9, loops on 48/180/181/182): -P "9 48 180 181 182".
"""
import hashlib
import json
import os
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
INTEG = HERE.parent.parent
CASE4 = INTEG.parent
sys.path[:0] = [str(HERE), str(INTEG / 'core'), str(INTEG / 'core' / 'harness'), str(INTEG / 'read' / 'tests'),
                str(CASE4 / 'protocol'), str(CASE4.parent / 'framework' / 'size')]
from model_driver import Model, Report, gc  # noqa: E402
import cp  # noqa: E402
import port_map  # noqa: E402
import queue_sim as qs  # noqa: E402
import real_profile as real  # noqa: E402
import response_path_cp as rp  # noqa: E402
import vectors  # noqa: E402
from model_drive_composite import Reflector, PARAMS, SID, scalar  # noqa: E402

PM = port_map.load(os.environ['PORT_MAP']) if os.environ.get('PORT_MAP') else port_map.DEFAULT
MASTER_PORT, OUTST_PORT, LAP = 9, PM.relay_port, PM.n_ack_return
LOOPS = [port_map.RETURN_PORT, LAP, port_map.PKTGEN_RETURN, PM.t_in, PM.hb_return, PM.held_return]
FRONT = [p for p in LOOPS if p % 128 < 64]
MASTER = rp.Endpoint(real.MASTER_IP, real.MASTER_TCP, MASTER_PORT)
RELAY = rp.Endpoint(real.RELAY_IP, real.RELAY_TCP, OUTST_PORT)
READS = int(os.environ.get('READS', '3'))
PHASE_IDLE, PHASE_CLOSED = 0x5, 0x7


def main():
    out_dir = Path(os.environ['OUT'])
    rep = Report(os.environ['PROG'], physical=False, params=PARAMS,
                 driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 scope='real timestamped TCP profile: captured handshake, %d READs, captured close' % READS)
    try:
        m = Model(ports=[], enable=False)
        m.enable_ports(sorted({MASTER_PORT, OUTST_PORT}))
        m.enable_ports([p for p in LOOPS if p not in FRONT])
        m.enable_ports(FRONT)
        reflectors = [Reflector(p) for p in FRONT]
        for r in reflectors:
            r.start()
        time.sleep(2.0)
        rep.record['meta'].update(port_map=dict(PM._asdict()), port_enable_errors=m.port_errors,
                                  capture_sha256=hashlib.sha256(real.PCAP.read_bytes()).hexdigest())
        rows = (cp.n_ports_rows(MASTER_PORT, OUTST_PORT, MASTER.ip_int, RELAY.ip_int, n_ack_return=LAP)
                + cp.n_connection_rows(RELAY, MASTER, n_ack_return=LAP) + cp.n_read_rows(RELAY, MASTER))
        for table, key, action, data, prio in rows:
            m.add('p0.n_' + table, dict(key), 'n_' + action, dict(data), prio)
        dc = dict(zip(('index', 'code', 'repeat', 'on', 'off'), vectors.decoy_config()))
        for a, b in ((MASTER, RELAY), (RELAY, MASTER)):
            m.add('p0.n_Ingress.data_connection', {'hdr.ip.src': a.ip_int, 'hdr.ip.dst': b.ip_int,
                                                   'hdr.tcp.sport': a.port, 'hdr.tcp.dport': b.port}, 'n_Ingress.configure', dc)
        for table, key, action, data, prio in cp.e_conn_rows(0, RELAY, MASTER, n_ack_return=LAP):
            m.add('p0.r_' + table, dict(key), 'r_' + action, dict(data), prio)
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', PARAMS)
        mc = m.table('$mirror.cfg', raw=True)
        mc.entry_add(gc.Target(device_id=0, pipe_id=0xffff), [mc.make_key([gc.KeyTuple('$sid', SID)])], [mc.make_data([
            gc.DataTuple('$direction', str_val='INGRESS'), gc.DataTuple('$ucast_egress_port', port_map.PKTGEN_RETURN),
            gc.DataTuple('$ucast_egress_port_valid', bool_val=True), gc.DataTuple('$session_enable', bool_val=True)],
            '$normal')])
        consts = qs.QueueSim().consts()
        names = ('OUT_ACK_COMMIT', 'OUT_ACK_FALLBACK', 'OUT_RESP_RELEASE', 'OUT_RESP_FALLBACK', 'OUT_REQ_BYPASS', 'OUT_UNMATCHED')

        def t_counts():
            res = {}
            for n in names:
                r = m.register_read('p1.t_Ingress.outcomes', consts[n])
                v = [val for k, val in r.items() if k.endswith('.f1')][0]
                res[n] = sum(v) if isinstance(v, list) else v
            return res

        def phase():
            return scalar(m.register_read('p0.n_Ingress.owner', 0)) >> 16

        ports = sorted({MASTER_PORT, OUTST_PORT})

        def frames_to(got, port):
            return [g for g in got[port]]

        def one(name, master, frame, want_phase=None, delivered=True):
            m.drain(ports)
            got = m.exchange(MASTER_PORT if master else OUTST_PORT, frame, ports, timeout=5.0, quiet=0.4)
            dst = OUTST_PORT if master else MASTER_PORT
            want = [frame] if delivered else []
            ok = frames_to(got, dst) == want and sum(len(v) for v in got.values()) == len(want)
            rep.add(name + ('_forwarded_byte_exact_once' if delivered else '_not_delivered'), 'ok', 'ok' if ok else 'mismatch',
                    ok=ok, received={p: [g.hex() for g in got[p]] for p in ports}, sent=frame.hex())
            if want_phase is not None:
                rep.add(name + '_N_phase', want_phase, phase())

        script = real.session(reads=READS)
        (_, _, syn), (_, _, synack), (_, _, ack) = script[:3]
        one('SYN', True, syn, 0x2)
        one('SYNACK', False, synack, 0x4)
        one('handshake_ACK', True, ack, PHASE_IDLE)
        for n in range(READS):
            (_, _, req), (_, _, rack), (_, _, rsp), (_, _, mack) = script[3 + 4 * n:7 + 4 * n]
            tag = 'READ%d' % (n + 1)
            t0 = t_counts()
            m.drain(ports)
            got_req = m.exchange(MASTER_PORT, req, ports, timeout=5.0, quiet=0.3)
            m.send(OUTST_PORT, rack)
            time.sleep(0.05)
            m.send(OUTST_PORT, rsp)
            got_rep = m.capture(ports, timeout=15.0, quiet=4.0)
            t1 = t_counts()
            d = {k: t1[k] - t0[k] for k in names}
            good_req = got_req[OUTST_PORT] == [req] and sum(len(v) for v in got_req.values()) == 1
            rep.add(tag + '_request_relayed_byte_exact_once', 'ok', 'ok' if good_req else 'mismatch', ok=good_req,
                    received={p: [g.hex() for g in got_req[p]] for p in ports})
            if OUTST_PORT == MASTER_PORT:   # shared port: the request was seen in the first capture, replies here
                good_rep = got_rep[MASTER_PORT] == [rack, rsp]
            else:
                good_rep = got_rep[MASTER_PORT] == [rack, rsp] and not got_rep[OUTST_PORT]
            rep.add(tag + '_ack_then_response_to_master_byte_exact_once', 'ok', 'ok' if good_rep else 'mismatch',
                    ok=good_rep, received={p: [g.hex() for g in got_rep[p]] for p in ports})
            rep.add(tag + '_T_released_ack_once_and_response_once', {'ack': 1, 'response': 1},
                    {'ack': d['OUT_ACK_COMMIT'] + d['OUT_ACK_FALLBACK'], 'response': d['OUT_RESP_RELEASE'] + d['OUT_RESP_FALLBACK']},
                    t_outcomes=d)
            rep.add(tag + '_N_idle_after', PHASE_IDLE, phase())
            rep.add(tag + '_N_read_app', n, scalar(m.register_read('p0.n_Ingress.read_app', 0)))
            one(tag + '_master_ACK', True, mack, PHASE_IDLE)
        (_, _, fin), (_, _, rfa), (_, _, rfin), (_, _, last) = script[-4:]
        one('master_FIN_forwarded_once_and_closes_N', True, fin, PHASE_CLOSED)
        one('relay_ACK_of_FIN', False, rfa, PHASE_CLOSED)
        one('relay_FIN', False, rfin, PHASE_CLOSED)
        # N is terminal after a qualified close (phase 7) and has no rearm yet: the master's last ACK is refused,
        # as on the clean profile and in the source-level replay. Recorded, not hidden.
        one('master_last_ACK_after_close', True, last, PHASE_CLOSED, delivered=False)
        if reflectors:
            seen = {str(r.port): r.summary() for r in reflectors}
            rep.record['meta']['loopback_frames'] = seen
            rep.add('every_front_panel_loop_port_carried_frames', sorted(seen), sorted(p for p, v in seen.items() if v['frames']))
    except BaseException as error:
        rep.record['error'] = type(error).__name__ + ': ' + str(error)
        rep.record['traceback'] = traceback.format_exc()
        rep.add('execution', 'completed', 'error', ok=False)
    finally:
        passed = rep.finish(str(out_dir / 'cases.json'))
        (out_dir / 'driver_source.py').write_bytes(Path(__file__).read_bytes())
        (out_dir / 'input_sources.json').write_text(json.dumps(
            {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
             for p in (HERE / 'cp.py', HERE / 'real_profile.py', HERE / 'make_n.py', real.PCAP)}, indent=1) + '\n')
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()
