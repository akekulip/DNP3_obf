"""Reproduction probe (no fix): an identical request duplicate arriving while T holds the original.

Runs inside launch_model.sh's private namespace against the rearm_56r compiled build
(candidate56 + retx_passthrough_01). Reuses the retained transport, padding and reflector
helpers exactly as retx_passthrough_01/model_drive_retx.py does. Software model only; host
monotonic timestamps are model-relative wall time, not ASIC timing.

Cases (each on a fresh TCP connection, retired by a qualified RST before the next):
  A10 / A50  OPERATE duplicate sent at 10% / 50% of op_j after the original OPERATE.
  B          OPERATE duplicate sent after the original's observed release (recovery control).
  C          READ request duplicate sent while the original READ transaction is open with T
             enabled; first establishes whether the READ request itself is held.
Property per case: no request copy reaches the outstation side before the original's
deadline, and exactly one original release (outcomes[5] delta == 1 for OPERATE).
"""
import hashlib
import importlib.util
import os
import select
import sys
import time
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
PACKET_OUTGOING = 4

OP_J_NS = 1_000_000_000
PARAMS = dict(da=50_000_000, readiness=400_000_000, cap=16_000_000,
              gap=50_000_000, op_j=OP_J_NS, budget=240_000, enabled=0)
DEADLINE_TOL = None     # superseded: the oracle uses the original's observed release (see operate_case)


def classify(frame):
    """Direction and DNP3 function code of a captured frame (None fc for non-DNP3 / pure TCP)."""
    if len(frame) < 54 or frame[12:14] != b'\x08\x00':
        return dict(dir='other', fc=None, flags=None, plen=0)
    src = int.from_bytes(frame[26:30], 'big')
    ihl = (frame[14] & 0x0f) * 4
    tcp = 14 + ihl
    total = int.from_bytes(frame[16:18], 'big')
    doff = (frame[tcp + 12] >> 4) * 4
    payload = frame[tcp + doff:14 + total]
    direction = 'to_outstation' if src == vectors.CLIENT else 'to_master' if src == vectors.SERVER else 'other'
    fc = payload[12] if len(payload) >= 13 and payload[:2] == b'\x05\x64' else None
    return dict(dir=direction, fc=fc, flags=frame[tcp + 13], plen=len(payload),
                seq=int.from_bytes(frame[tcp + 4:tcp + 8], 'big'))


def main():
    report = Report(os.environ['PROG'], physical=False,
                    scope='REPRODUCE early-duplicate timing bypass; rearm_56r compiled model; no fix',
                    driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    params=PARAMS, deadline_tolerance=DEADLINE_TOL)
    results = report.record['meta'].setdefault('dup_cases', {})
    try:
        m = Model(ports=[], enable=False)
        ports = sorted({MASTER.dev_port, RELAY.dev_port})
        m.enable_ports(ports + helpers.FRONT_LOOPS)
        m.enable_ports([p for p in helpers.LOOP_PORTS if p not in helpers.FRONT_LOOPS])
        reflectors = [helpers.Reflector(p) for p in helpers.FRONT_LOOPS]
        for reflector in reflectors:
            reflector.start()
        report.record['meta']['port_map'] = dict(PM._asdict())
        report.record['meta']['capture_ports'] = ports
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
        params = dict(PARAMS)

        def set_t(**kw):
            params.update(kw)
            m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)

        set_t(enabled=0)
        mirror = m.table('$mirror.cfg', raw=True)
        mirror.entry_add(gc.Target(device_id=0, pipe_id=0xffff),
                         [mirror.make_key([gc.KeyTuple('$sid', 7)])],
                         [mirror.make_data([gc.DataTuple('$direction', str_val='INGRESS'),
                                            gc.DataTuple('$ucast_egress_port', helpers.PKTGEN_RETURN),
                                            gc.DataTuple('$ucast_egress_port_valid', bool_val=True),
                                            gc.DataTuple('$session_enable', bool_val=True)], '$normal')])

        def released():
            return scalar(m.register_read('p1.t_Ingress.outcomes', 5, pipe=1))

        def step(name, sent, expected, master=True):
            got = m.exchange(MASTER.dev_port if master else RELAY.dev_port, sent, ports, timeout=3, quiet=.15)
            flat = [frame for frames in got.values() for frame in frames]
            good = len(flat) == (0 if expected is None else 1)
            if good and expected is not None:
                good = same_frame(flat[0], expected, sent)
            report.add(name, 'drop' if expected is None else 'one exact frame',
                       'drop' if not flat else '%d frames' % len(flat), ok=good)
            return good

        def timed(t_ref, until, events=()):
            """Capture on the shared port with host-monotonic offsets from t_ref; fire (offset, fn) events."""
            socks = {m._listen(p): p for p in ports}
            pending = sorted(events, key=lambda e: e[0])
            log = []
            while True:
                now = time.monotonic() - t_ref
                while pending and now >= pending[0][0]:
                    offset, label, fn = pending.pop(0)
                    fired = time.monotonic() - t_ref
                    fn()
                    log.append(dict(t=round(fired, 4), event=label))
                if now >= until and not pending:
                    break
                r, _, _ = select.select(list(socks), [], [], 0.005)
                for s in r:
                    try:
                        data, addr = s.recvfrom(4096)
                    except BlockingIOError:
                        continue
                    if addr[2] == PACKET_OUTGOING:
                        continue
                    info = classify(data)
                    log.append(dict(t=round(time.monotonic() - t_ref, 4), port=socks[s], **info,
                                    frame=data.hex()))
            return log

        def open_connection(tag, c, s):
            """Handshake + READ + SELECT with T disabled, exactly as model_drive_retx.py (offset by ISNs)."""
            set_t(enabled=0)
            ok = step(tag + '_SYN', vectors.packet(2, c, mss=1460), vectors.packet(2, c, mss=1460))
            ok &= step(tag + '_SYNACK', vectors.packet(18, s, c + 1, reverse=True, mss=1460),
                       vectors.packet(18, s, c + 1, reverse=True, mss=1460), master=False)
            ok &= step(tag + '_ACK', vectors.packet(16, c + 1, s + 1), vectors.packet(16, c + 1, s + 1))
            return ok

        def read_and_select(tag, c, s):
            request = rs.request_packet(seq=c + 1, ack=s + 1)
            m.drain(ports)
            t0 = time.monotonic()
            m.send(MASTER.dev_port, request)
            log = timed(t0, 0.5)
            got = [e for e in log if 'dir' in e]
            ok = len(got) == 1 and same_frame(bytes.fromhex(got[0]['frame']), request, request)
            results[tag]['read_request_latency_T_off_s'] = got[0]['t'] if got else None
            report.add(tag + '_READ', 'one exact frame', '%d frames at %s' % (len(got), [e['t'] for e in got]), ok=ok)
            ok &= step(tag + '_READ_server_ACK', rs.ack_packet(seq=s + 1, ack=c + 21),
                       rs.ack_packet(seq=s + 1, ack=c + 21), master=False)
            padded, _ = b.pad_read_response(rs.response_frame())
            ok &= step(tag + '_READ_padded_58', rs.response_packet(seq=s + 1, ack=c + 21),
                       vectors.packet(24, s + 1, c + 21, reverse=True, payload=padded), master=False)
            ok &= step(tag + '_READ_wire_ACK_commit', vectors.packet(16, c + 21, s + 59),
                       vectors.packet(16, c + 21, s + 50))
            ok &= step(tag + '_SELECT', vectors.packet(24, c + 21, s + 59, payload=vectors.native_select(0, 3)),
                       vectors.packet(24, c + 21, s + 50, payload=vectors.native_select(0, 3)))
            response = helpers.native_response37(0, 3)
            image, _ = b.pad_control_response(response, helpers.CTL_POINTS)
            ok &= step(tag + '_SELECT_response_58', vectors.packet(24, s + 50, c + 56, reverse=True, payload=response),
                       vectors.packet(24, s + 59, c + 56, reverse=True, payload=image), master=False)
            return ok

        def summarize(log, want_fc, t_deadline):
            copies = [e for e in log if e.get('dir') == 'to_outstation' and e.get('fc') == want_fc]
            early = [e for e in copies if e['t'] < t_deadline]
            return copies, early

        def operate_case(tag, c, s, dup_frac=None, after_release=False):
            rec = dict(case=tag, client_isn=c, server_isn=s, op_j_s=OP_J_NS / 1e9)
            results[tag] = rec
            rec['setup_ok'] = open_connection(tag, c, s) and read_and_select(tag, c, s)
            if not rec['setup_ok']:
                report.add(tag + '_setup', True, False)
                return
            set_t(enabled=1)
            operate = vectors.packet(24, c + 56, s + 117, payload=vectors.native_select(1, 4))
            operate_out = vectors.packet(24, c + 56, s + 87, payload=vectors.native_select(1, 4))
            rel0 = released()
            m.drain(ports)
            send = lambda: m.send(MASTER.dev_port, operate)  # noqa: E731
            t0 = time.monotonic()
            send()
            if after_release:
                log = [dict(t=0.0, event='original_OPERATE_sent')]
                # wait for the original's release, then 0.2 s, then the duplicate
                first = None
                part = timed(t0, 3.0 * OP_J_NS / 1e9)
                log += part
                for e in part:
                    if e.get('dir') == 'to_outstation' and e.get('fc') == 4:
                        first = e['t']
                        break
                rec['original_release_seen_at_s'] = first
                rel_mid = released()
                rec['outcomes5_after_release_before_dup'] = rel_mid - rel0
                t_dup = time.monotonic() - t0 + 0.2
                log += timed(t0, t_dup + 1.5, events=[(t_dup, 'duplicate_OPERATE_sent', send)])
            else:
                t_dup = dup_frac * OP_J_NS / 1e9
                log = [dict(t=0.0, event='original_OPERATE_sent')]
                log += timed(t0, 2.5 * OP_J_NS / 1e9, events=[(t_dup, 'duplicate_OPERATE_sent', send)])
            rel1 = released()
            # dup_model_01 showed the undisturbed release lands at ~0.90 s on the model clock for
            # op_j = 1.0 s, so the deadline is the original's OBSERVED release: the last OPERATE
            # copy for A (the held original), the first for B (the dup is sent after it).
            arrivals = [e['t'] for e in log if e.get('dir') == 'to_outstation' and e.get('fc') == 4]
            release_t = (min(arrivals) if after_release else max(arrivals)) if arrivals else 0.0
            rec['observed_release_s'] = release_t
            copies, early = summarize(log, 4, release_t - 0.05)
            rec.update(dup_planned_at_s=round(t_dup, 4), log=log,
                       operate_arrivals_to_outstation_s=[e['t'] for e in copies],
                       operate_copies_to_outstation=len(copies),
                       early_copies_before_deadline=len(early),
                       copies_exact_wire_image=[same_frame(bytes.fromhex(e['frame']), operate_out, operate)
                                                for e in copies],
                       outcomes5_delta=rel1 - rel0, outcomes5_total=rel1,
                       other_frames=[{k: e[k] for k in ('t', 'dir', 'fc', 'flags', 'plen')}
                                     for e in log if 'dir' in e and not (e['dir'] == 'to_outstation' and e['fc'] == 4)])
            prop = len(early) == 0 and rel1 - rel0 == 1
            rec['property_pass'] = prop
            if after_release:
                exp = 'original at >=op_j; dup forwarded once after release; 2 copies total; outcomes5 +1'
                rec['expected_if_correct'] = exp
            else:
                exp = 'exactly one OPERATE copy at >=op_j (dup not forwarded before deadline); outcomes5 +1'
                rec['expected_if_correct'] = exp
            report.add(tag + '_no_early_copy_and_one_release', exp,
                       'copies=%d at %s; early=%d; outcomes5_delta=%d' % (
                           len(copies), [e['t'] for e in copies], len(early), rel1 - rel0), ok=prop)
            # finish the transaction and retire the connection so the next case is fresh
            response = helpers.native_response37(1, 4)
            image, _ = b.pad_control_response(response, helpers.CTL_POINTS)
            step(tag + '_OPERATE_response_58', vectors.packet(24, s + 87, c + 91, reverse=True, payload=response),
                 vectors.packet(24, s + 117, c + 91, reverse=True, payload=image), master=False)
            step(tag + '_qualified_RST', vectors.packet(20, c + 91, s + 175), vectors.packet(20, c + 91, s + 124))
            set_t(enabled=0)

        def read_case(tag, c, s):
            rec = dict(case=tag, client_isn=c, server_isn=s)
            results[tag] = rec
            rec['setup_ok'] = open_connection(tag, c, s)
            if not rec['setup_ok']:
                report.add(tag + '_setup', True, False)
                return
            set_t(enabled=1)
            request = rs.request_packet(seq=c + 1, ack=s + 1)
            send = lambda: m.send(MASTER.dev_port, request)  # noqa: E731
            rel0 = released()
            m.drain(ports)
            t0 = time.monotonic()
            send()
            log = [dict(t=0.0, event='original_READ_sent')]
            # da 50 ms, readiness 400 ms: duplicates at 5% and 50% of readiness, inside the READ window
            log += timed(t0, 1.5, events=[(0.02, 'duplicate_READ_sent_20ms', send),
                                          (0.2, 'duplicate_READ_sent_200ms', send)])
            copies = [e for e in log if e.get('dir') == 'to_outstation' and e.get('fc') == 1]
            first = copies[0]['t'] if copies else None
            rec.update(log=log, read_arrivals_to_outstation_s=[e['t'] for e in copies],
                       read_copies_to_outstation=len(copies),
                       copies_exact=[same_frame(bytes.fromhex(e['frame']), request, request) for e in copies],
                       original_read_latency_s=first,
                       outcomes5_delta=released() - rel0,
                       other_frames=[{k: e[k] for k in ('t', 'dir', 'fc', 'flags', 'plen')}
                                     for e in log if 'dir' in e and not (e['dir'] == 'to_outstation' and e['fc'] == 1)])
            held = first is not None and first >= 0.02
            rec['read_request_held'] = held
            early = [e for e in copies if first is not None and e['t'] < max(e2['t'] for e2 in copies) - 0.05]
            rec['early_copies_before_release'] = len(early)
            report.add(tag + '_no_early_READ_copy', 'one READ copy, none before the held release',
                       'copies=%d early=%d' % (len(copies), len(early)), ok=len(copies) == 1 and not early)
            report.add(tag + '_READ_request_hold_observed', 'informational',
                       'first READ copy at %s s; copies=%d at %s' % (first, len(copies), [e['t'] for e in copies]),
                       ok=True)

        operate_case('A10', 1000, 5000, dup_frac=0.10)
        operate_case('A50', 2000, 6000, dup_frac=0.50)
        operate_case('B_after_release', 3000, 7000, after_release=True)
        # C runs last: no transaction completion is attempted afterwards.
        read_case('C_read_dup', 9000, 12000)
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    for tag, rec in results.items():
        brief = {k: v for k, v in rec.items() if k not in ('log', 'other_frames')}
        print('CASE', tag, brief)
    ok = report.finish(Path(os.environ['OUT']) / 'dup_results.json')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
