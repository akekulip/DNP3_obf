"""E61 duplicate-hold compiled-model regression.

Derived from dup_hold_01/model_drive_dup.py, with explicit 61-byte response
expectations and a corrected READ case C. READ requests are forwarded; this
fixture sends real server ACK/response packets and checks their hold/release.
The retained historical 88/89 result and its original fixture remain unchanged.
"""
import hashlib
import importlib.util
import os
import select
import struct
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE.parents[1]
BASE = CANDIDATE.parent / 'response_only'
READ_IMAGE = CTL_IMAGE = 61
READ_NATIVE, CTL_NATIVE = 49, 37
sys.path.insert(0, str(HERE.parent / "seg61_01"))
import encode61
sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parent))  # read_policy_expect is beside this file
import read_policy_expect as rp  # noqa: E402
rp.install(encode61)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


helpers = load('_retained_model_helpers', BASE / 'model_drive_composite.py')
cp = load('_protected_model_cp', CANDIDATE / 'cp.py')
sealed_profile = load('_dup_model_profile', CANDIDATE / 'hw/sealed_profile.py')
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
                    scope='E61: OPERATE duplicate held in T; READ ACK/response duplicate contract; compiled model',
                    driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    params=PARAMS, deadline_tolerance=DEADLINE_TOL)
    results = report.record['meta'].setdefault('dup_cases', {})
    try:
        child_regs = sealed_profile.child_registers(sealed_profile.describe(
            Path(os.environ['PORT_MAP']).parent / 'compile_local/out'))
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

        def dup_dropped():
            return scalar(m.register_read('p1.t_Ingress.outcomes', 16, pipe=1))

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
            padded = encode61.read61(rs.response_frame())
            ok &= step(tag + '_READ_padded_61', rs.response_packet(seq=s + 1, ack=c + 21),
                       vectors.packet(24, s + 1, c + 21, reverse=True, payload=padded), master=False)
            ok &= step(tag + '_READ_wire_ACK_commit', vectors.packet(16, c + 21, (s + 1 + READ_IMAGE)),
                       vectors.packet(16, c + 21, s + 50))
            ok &= step(tag + '_SELECT', vectors.packet(24, c + 21, (s + 1 + READ_IMAGE), payload=vectors.native_select(0, 3)),
                       vectors.packet(24, c + 21, s + 50, payload=vectors.native_select(0, 3)))
            response = helpers.native_response37(0, 3)
            image = encode61.ctl61(response)
            ok &= step(tag + '_SELECT_response_61', vectors.packet(24, s + 50, c + 56, reverse=True, payload=response),
                       vectors.packet(24, (s + 1 + READ_IMAGE), c + 56, reverse=True, payload=image), master=False)
            return ok

        def summarize(log, want_fc, t_deadline):
            copies = [e for e in log if e.get('dir') == 'to_outstation' and e.get('fc') == want_fc]
            early = [e for e in copies if e['t'] < t_deadline]
            return copies, early

        def operate_case(tag, c, s, dup_frac=None, after_release=False, t_enabled=1, n_dups=1):
            rec = dict(case=tag, client_isn=c, server_isn=s, op_j_s=OP_J_NS / 1e9, t_enabled=t_enabled)
            results[tag] = rec
            rec['setup_ok'] = open_connection(tag, c, s) and read_and_select(tag, c, s)
            if not rec['setup_ok']:
                report.add(tag + '_setup', True, False)
                return
            set_t(enabled=t_enabled)
            operate = vectors.packet(24, c + 56, (s + 1 + READ_IMAGE) + CTL_IMAGE, payload=vectors.native_select(1, 4))
            rec['operate_frame'] = operate.hex()
            operate_out = vectors.packet(24, c + 56, s + 87, payload=vectors.native_select(1, 4))
            rel0, drop0 = released(), dup_dropped()
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
                log += timed(t0, t_dup + 0.3 * (n_dups - 1) + 1.5,
                             events=[(t_dup + 0.3 * i, 'duplicate_OPERATE_sent', send) for i in range(n_dups)])
            else:
                t_dup = dup_frac * OP_J_NS / 1e9
                log = [dict(t=0.0, event='original_OPERATE_sent')]
                log += timed(t0, 2.5 * OP_J_NS / 1e9, events=[(t_dup, 'duplicate_OPERATE_sent', send)])
            rel1, drop1 = released(), dup_dropped()
            dup_sent = [e['t'] for e in log if e.get('event') == 'duplicate_OPERATE_sent']
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
            rec.update(duplicate_sent_at_s=dup_sent, outcomes16_delta=drop1 - drop0, outcomes16_total=drop1)
            times = [e['t'] for e in copies]
            if not t_enabled:
                # D: no hold. Original passes through at once, the duplicate is forwarded by T's enabled-0 row.
                held = (len(copies) == 2 and len(dup_sent) == 1 and times[0] < dup_sent[0] <= times[1]
                        and drop1 - drop0 == 0 and rel1 - rel0 == 0)
                exp_h = 'T off: 2 copies (original, then duplicate after its send); outcomes16 +0; outcomes5 +0'
            elif after_release:
                # B / F: every post-release duplicate is forwarded (n_dups of them), none counted as dropped.
                held = (len(copies) == 1 + n_dups and len(dup_sent) == n_dups and (not dup_sent or times[0] < dup_sent[0])
                        and all(times[1 + i] >= dup_sent[i] for i in range(n_dups))
                        and drop1 - drop0 == 0 and rel1 - rel0 == 1)
                exp_h = '%d copies: original before the first duplicate, each duplicate after its send; outcomes16 +0; outcomes5 +1' % (1 + n_dups)
            else:
                # A: independent of the observed release: the one copy is >= 0.8*op_j after the ORIGINAL send
                # (t = 0) and after the duplicate's send. model_clock_ratio = copy time / op_j (host seconds).
                op_j_s = OP_J_NS / 1e9
                rec['model_clock_ratio_host_per_model'] = round(times[0] / op_j_s, 4) if len(copies) == 1 else None
                held = (len(copies) == 1 and len(dup_sent) == 1 and times[0] >= 0.8 * op_j_s
                        and times[0] > dup_sent[0] and drop1 - drop0 == 1 and rel1 - rel0 == 1)
                exp_h = '1 copy, >= 0.8*op_j after the original send and after the duplicate send; outcomes5 +1; outcomes16 +1'
            held = held and all(rec['copies_exact_wire_image']) and not rec['other_frames']
            rec['dup_hold_pass'] = held
            report.add(tag + '_dup_hold', exp_h, 'copies=%d at %s; dup sent at %s; outcomes5_delta=%d; outcomes16_delta=%d'
                       % (len(copies), times, dup_sent, rel1 - rel0, drop1 - drop0), ok=held)
            if after_release:
                exp = 'original at >=op_j; dup forwarded once after release; 2 copies total; outcomes5 +1'
                rec['expected_if_correct'] = exp
            else:
                exp = 'exactly one OPERATE copy at >=op_j (dup not forwarded before deadline); outcomes5 +1'
                rec['expected_if_correct'] = exp
            if t_enabled:
              report.add(tag + '_no_early_copy_and_one_release', exp,
                         'copies=%d at %s; early=%d; outcomes5_delta=%d' % (
                             len(copies), [e['t'] for e in copies], len(early), rel1 - rel0), ok=prop)
            # finish the transaction and retire the connection so the next case is fresh
            response = helpers.native_response37(1, 4)
            image = encode61.ctl61(response)
            step(tag + '_OPERATE_response_61', vectors.packet(24, s + 87, c + 91, reverse=True, payload=response),
                 vectors.packet(24, (s + 1 + READ_IMAGE) + CTL_IMAGE, c + 91, reverse=True, payload=image), master=False)
            step(tag + '_qualified_RST', vectors.packet(20, c + 91, (s + 1 + READ_IMAGE) + 2 * CTL_IMAGE), vectors.packet(20, c + 91, s + 124))
            set_t(enabled=0)

        def snapshot():
            registers = {'N': ('owner', 'client', 'server', 'epoch'),
                         'E': ('epoch', 'master_isn', 'mode', 'front', 'acct', 'img_end', 'img_start', 'img_wend'),
                         'T': ('cur_epoch_reg', 'gen_alloc_reg', 'op_gen_alloc_reg', 't0_reg', 'op_t0_reg',
                               'ack_done_reg', 'resp_done_reg', 'op_done_reg') + child_regs +
                              ('ack_commit_at_reg', 'ack_commit_gen_reg')}
            prefix = {'N': 'p0.n_Ingress.', 'E': 'p0.r_Egress.', 'T': 'p1.t_Ingress.'}
            return {role: {name: m.register_read(prefix[role] + name, 0, pipe=1 if role == 'T' else 0)
                           for name in names} for role, names in registers.items()}

        def outcome(index):
            return scalar(m.register_read('p1.t_Ingress.outcomes', index, pipe=1))

        def old_case(tag, c, s, c2, s2):
            """E: a completed OPERATE transaction (T on), qualified RST, new handshake (epoch advances), then
            (E1) the old OPERATE's exact wire frame from the master and (E2) a T-input event of kind 15
            carrying that frame with the OLD epoch, as N would hand it to T. Neither may reach the relay;
            E2 must hit tin_verdict's default drop_old_epoch (outcomes[14] +1); no register changes."""
            operate_case(tag + '_setup_txn', c, s, dup_frac=None, after_release=True, n_dups=0)
            rec = dict(case=tag)
            results[tag] = rec
            old = results[tag + '_setup_txn']
            operate = bytes.fromhex(old['operate_frame'])
            old_epoch = scalar(snapshot()['N']['epoch'])
            set_t(enabled=1)
            rec['setup_ok'] = open_connection(tag + '_new', c2, s2)
            set_t(enabled=1)
            new_state = snapshot()
            new_epoch = scalar(new_state['N']['epoch'])
            rec.update(old_epoch=old_epoch, new_epoch=new_epoch,
                       t_cur_epoch_reg=scalar(new_state['T']['cur_epoch_reg']))
            report.add(tag + '_epoch_advanced', True, new_epoch > old_epoch)
            for sub, port, frame in (
                    ('E1_wire_copy', MASTER.dev_port, operate),
                    ('E2_t_event_old_epoch', PM.t_in, struct.pack('!IIIBBH', old_epoch, 0, 0, 15, 0, 0) + operate)):
                before = snapshot()
                o14, o16, o5 = outcome(14), outcome(16), outcome(5)
                m.drain(ports)
                m.send(port, frame)
                got = m.capture(ports, timeout=1.0, quiet=.2)
                flat = [f for frames in got.values() for f in frames]
                after = snapshot()
                d = dict(frames_out=len(flat), outcomes14_delta=outcome(14) - o14,
                         outcomes16_delta=outcome(16) - o16, outcomes5_delta=outcome(5) - o5,
                         registers_unchanged=before == after)
                rec[sub] = d
                want14 = 1 if sub.startswith('E2') else d['outcomes14_delta']   # E1: informational only
                ok = (not flat and d['registers_unchanged'] and d['outcomes16_delta'] == 0
                      and d['outcomes5_delta'] == 0 and d['outcomes14_delta'] == want14)
                report.add(tag + '_' + sub, 'nothing out; registers unchanged; outcomes16/5 +0' +
                           ('; outcomes14 +1' if sub.startswith('E2') else ''), str(d), ok=ok)
            # Retire the new connection so case C can open the same 4-tuple (dup_model_02 left it open
            # and C's handshake was dropped).
            step(tag + '_new_RST', vectors.packet(20, c2 + 1, s2 + 1), vectors.packet(20, c2 + 1, s2 + 1))
            set_t(enabled=0)

        def read_case(tag, c, s):
            rec = dict(case=tag, client_isn=c, server_isn=s,
                       contract='requests forward; ACK/response are admitted only after the real request reaches the outstation; late duplicate READ is forwarded without new allocation/release')
            results[tag] = rec
            rec['setup_ok'] = open_connection(tag, c, s)
            if not rec['setup_ok']:
                report.add(tag + '_setup', True, False)
                return
            set_t(enabled=1, da=800_000_000, readiness=2_000_000_000, gap=250_000_000)
            request = rs.request_packet(seq=c + 1, ack=s + 1)
            ack = rs.ack_packet(seq=s + 1, ack=c + 21)
            response = rs.response_packet(seq=s + 1, ack=c + 21)
            expected = vectors.packet(24, s + 1, c + 21, reverse=True,
                                      payload=encode61.read61(rs.response_frame()))
            before = snapshot()
            counts = {i: outcome(i) for i in (1, 2, 3, 4, 5)}
            m.drain(ports)
            t0 = time.monotonic()
            m.send(MASTER.dev_port, request)
            log = [dict(t=0.0, event='original_READ_sent')]
            log += timed(t0, 0.35, events=[
                (.06, 'early_READ_duplicate', lambda: m.send(MASTER.dev_port, request)),
            ])
            first_request = next((e for e in log if e.get('dir') == 'to_outstation' and e.get('fc') == 1), None)
            rec['first_request_to_outstation_s'] = first_request['t'] if first_request else None
            if first_request is None:
                report.add(tag + '_fixture_saw_request_before_server_reply', True, False)
            else:
                report.add(tag + '_fixture_saw_request_before_server_reply', True, True)
                # Send the server side only after the model has emitted the actual request.  Earlier
                # dup_01 injected ACK/response before the request reached the outstation, so E correctly
                # treated them as fallback/native traffic instead of as held READ data.
                base_t = time.monotonic() - t0
                log += timed(t0, base_t + 1.8, events=[
                    (base_t + 0.12, 'server_ACK_after_request', lambda: m.send(RELAY.dev_port, ack)),
                    (base_t + 0.28, 'server_response_after_request', lambda: m.send(RELAY.dev_port, response)),
                    (base_t + 0.45, 'held_READ_duplicate', lambda: m.send(MASTER.dev_port, request)),
                ])
            after_release = snapshot()
            replies = [e for e in log if e.get('dir') == 'to_master']
            acks = [e for e in replies if e['plen'] == 0 and e['flags'] == 16]
            responses = [e for e in replies if e['plen']]
            requests = [e for e in log if e.get('dir') == 'to_outstation' and e.get('fc') == 1]
            # Independent minimum bounds tolerate model/host clock ratio, without
            # deriving the deadline from the very packet whose hold is tested.
            report.add(tag + '_request_forwarded', True,
                       bool(requests) and
                       all(same_frame(bytes.fromhex(e['frame']), request, request) for e in requests))
            ack_send = next((e['t'] for e in log if e.get('event') == 'server_ACK_after_request'), None)
            rsp_send = next((e['t'] for e in log if e.get('event') == 'server_response_after_request'), None)
            report.add(tag + '_ACK_held_then_released_once', True,
                       len(acks) == 1 and ack_send is not None and acks[0]['t'] > ack_send and acks[0]['t'] >= .65 and
                       same_frame(bytes.fromhex(acks[0]['frame']), ack, ack))
            report.add(tag + '_response_held_after_ACK_once', True,
                       len(responses) == 1 and len(acks) == 1 and rsp_send is not None and
                       responses[0]['t'] > rsp_send and responses[0]['t'] - acks[0]['t'] >= .18 and
                       same_frame(bytes.fromhex(responses[0]['frame']), expected, response))
            report.add(tag + '_no_OPERATE_allocation', before['T']['op_gen_alloc_reg'],
                       after_release['T']['op_gen_alloc_reg'])
            old_gen = scalar(before['T']['gen_alloc_reg'])
            report.add(tag + '_one_READ_generation', old_gen + 1,
                       scalar(after_release['T']['gen_alloc_reg']))
            report.add(tag + '_epoch_unchanged', before['N']['epoch'], after_release['N']['epoch'])
            # A real ACK commits the complete image before the post-release duplicate.
            step(tag + '_mapped_data_ACK', vectors.packet(16, c + 21, s + 1 + READ_IMAGE),
                 vectors.packet(16, c + 21, s + 1 + READ_NATIVE))
            state = snapshot()
            counts_after = {i: outcome(i) for i in counts}
            m.drain(ports)
            td = time.monotonic()
            m.send(MASTER.dev_port, request)
            late_log = timed(td, .8)
            late_external = [e for e in late_log if e.get('dir') in ('to_outstation', 'to_master')]
            late_read = [e for e in late_external if e.get('dir') == 'to_outstation' and e.get('fc') == 1]
            expected_late_request = bytearray(request)
            expected_late_request[48:50] = (4096 - (READ_IMAGE - READ_NATIVE)).to_bytes(2, 'big')
            expected_late_request[50:52] = b'\0\0'
            pseudo = expected_late_request[26:34] + struct.pack('!BBH', 0, 6, len(expected_late_request) - 34)
            expected_late_request[50:52] = struct.pack('!H', vectors.checksum(pseudo + expected_late_request[34:]))
            report.add(tag + '_late_duplicate_forwarded_once', 'one normalized READ request to outstation',
                       [{k: e[k] for k in ('t', 'dir', 'fc', 'flags', 'plen', 'seq')} for e in late_external],
                       ok=(len(late_external) == 1 and len(late_read) == 1 and
                           same_frame(bytes.fromhex(late_read[0]['frame']), bytes(expected_late_request), request)))
            late = snapshot()
            for name in ('gen_alloc_reg', 'op_gen_alloc_reg'):
                report.add(tag + '_late_duplicate_preserves_' + name, state['T'][name], late['T'][name])
            stable_e = {k: v for k, v in state['E'].items() if k != 'acct'}
            late_stable_e = {k: v for k, v in late['E'].items() if k != 'acct'}
            report.add(tag + '_late_duplicate_preserves_mapping_except_replay_marker', stable_e, late_stable_e)
            expected_acct = dict(state['E']['acct'])
            # acct.hi tracks reverse pending distance; lo is the wire frontier.
            expected_acct['r_Egress.acct.hi'] = [READ_IMAGE]
            report.add(tag + '_late_duplicate_replay_marker_only', expected_acct, late['E']['acct'])
            report.add(tag + '_late_duplicate_no_extra_release', counts_after,
                       {i: outcome(i) for i in counts})
            rec.update(log=log, after_release_duplicate_log=late_log,
                       outcomes_delta={i: counts_after[i] - counts[i] for i in counts},
                       before=before, after_release=after_release, after_late_duplicate=late)
            step(tag + '_qualified_RST', vectors.packet(20, c + 21, s + 1 + READ_IMAGE),
                 vectors.packet(20, c + 21, s + 1 + READ_NATIVE))
            set_t(enabled=0)

        operate_case('A10', 1000, 5000, dup_frac=0.10)
        operate_case('A50', 2000, 6000, dup_frac=0.50)
        operate_case('B_after_release', 3000, 7000, after_release=True)
        operate_case('D_T_off', 13000, 17000, dup_frac=0.30, t_enabled=0)
        operate_case('F_two_after_release', 14000, 18000, after_release=True, n_dups=2)
        old_case('E_old_epoch', 15000, 19000, 16000, 20000)
        # C runs last and now completes the response and retires the connection. Its ISNs sit above E's last
        # connection (client 16000): a same-tuple reconnect must advance the client frontier, so the
        # earlier 9000/12000 was correctly refused once E had run (dup_model_02/_03 C setup failures).
        read_case('C_read_dup', 23000, 26000)
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
