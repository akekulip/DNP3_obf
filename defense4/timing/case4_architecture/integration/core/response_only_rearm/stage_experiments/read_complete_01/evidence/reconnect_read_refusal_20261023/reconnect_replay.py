"""Model replay for the reconnect first-READ refusal (c26 hardware, 2026-10-23).

Scenarios (fresh model each; same 4-tuple, hardware rows and T params of the c26 trial reused by
../forwarding_loss_20261023/replay_forwarding_loss.py):
  collide        conn1: handshake, READ app 3, outstation ACK, response app 3, master ACK, graceful close;
                 conn2 (new ISNs): handshake in order, READ app 3 (same app sequence as the stale read_app latch)
  overtake       conn1 as above; conn2: SYN, SYN-ACK, READ app 0 BEFORE the final ACK, then the ACK, then the READ
                 retransmission (what the hardware captures show)
  overtake_first one connection only: SYN, SYN-ACK, READ before the final ACK, ACK, READ retransmission

  python3 reconnect_replay.py --launch SCENARIO [--build-out DIR --tag T --port-map inputs.json]
"""
import argparse, hashlib, json, os, subprocess, sys, time, traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'forwarding_loss_20261023'))
import replay_forwarding_loss as R  # noqa: E402

SCENARIOS = ('collide', 'overtake', 'overtake_first', 'lifecycle', 'race')


def read_with_app(template, seq, ack, app):
    sys.path.insert(0, str(R.STAGE / 'read_reencode_01'))
    import dnp3_std as std
    pl = template[54:54 + 25]
    hdr, user = std.deframe(pl)
    pl2 = std.frame(hdr, bytes([0xC0 | (app & 63), 0xC0 | (app & 15)]) + user[2:])
    return R.make_tcp(template, seq, ack, 0x18, pl2)


def driver():
    sys.path[:0] = [str(R.CORE), str(R.CORE / 'response_only')]
    from model_driver import Model, Report
    import importlib.util
    import bfrt_grpc.client as gc
    spec = importlib.util.spec_from_file_location('_composite', R.CORE / 'response_only/model_drive_composite.py')
    h = importlib.util.module_from_spec(spec); spec.loader.exec_module(h)
    scenario, out = os.environ['RECONNECT_SCENARIO'], Path(os.environ['OUT'])
    report = Report(os.environ['PROG'], physical=False, scope='reconnect READ refusal ' + scenario,
                    driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    m = Model(ports=[], enable=False)
    log = []
    try:
        m.enable_ports([9] + h.FRONT_LOOPS)
        m.enable_ports([p for p in h.LOOP_PORTS if p not in h.FRONT_LOOPS])
        refl = [h.Reflector(p) for p in h.FRONT_LOOPS]
        for r in refl:
            r.start()
        for row in R.hardware_rows():
            if row['kind'] == 'default':
                t = m.table(row['table'])
                t.default_entry_set(m.target, t.make_data([gc.DataTuple(k, v) for k, v in row['data'].items()], row['action']))
            else:
                m.add(row['table'], row['key'], row['action'], row['data'], row['priority'])
        mc = m.table('$mirror.cfg', raw=True)
        mc.entry_add(gc.Target(device_id=0, pipe_id=0xffff), [mc.make_key([gc.KeyTuple('$sid', 7)])], [mc.make_data([
            gc.DataTuple('$direction', str_val='INGRESS'), gc.DataTuple('$ucast_egress_port', 196),
            gc.DataTuple('$ucast_egress_port_valid', bool_val=True), gc.DataTuple('$session_enable', bool_val=True)], '$normal')])

        def regs():
            snap = {}
            for name, idx in R.REGS:
                try:
                    v = m.register_read(name, idx, pipe=0)
                    snap['%s[%d]' % (name.split('.', 1)[1], idx)] = {k.rsplit('.', 1)[-1]: (x[0] if isinstance(x, list) else x) for k, x in v.items()}
                except Exception as exc:
                    snap[name] = 'read error %s' % str(exc)[:80]
            return snap

        def inj(name, frame):
            m.drain([9, 48, 180]); m.send(9, frame)
            got = m.capture([9, 180], timeout=3, quiet=0.5)
            log.append(dict(step=name, injected=R.describe(frame),
                            out={str(p): [R.describe(f) for f in fs] for p, fs in got.items()}, registers=regs()))

        fr = {n: f for n, _, f in R.trial_frames()}
        syn_t, sa_t, ack_t, rd_t = fr['SYN1'], fr['SYNACK1'], fr['ACK1'], fr['READ1']

        def inj_batch(names_frames, label):
            m.drain([9, 48, 180])
            for _, f in names_frames:
                m.send(9, f)
            got = m.capture([9, 180], timeout=3, quiet=0.5)
            log.append(dict(step=label, injected=[(n, R.describe(f)) for n, f in names_frames],
                            out={str(p): [R.describe(f) for f in fs] for p, fs in got.items()}, registers=regs()))

        def handshake(c, s, tag, read_app=None, overtake=False):
            inj(tag + 'SYN', R.make_tcp_syn(syn_t, c) if hasattr(R, 'make_tcp_syn') else syn_like(syn_t, c, 0, 0x02))
            inj(tag + 'SYNACK', syn_like(sa_t, s, c + 1, 0x12))
            ack = R.make_tcp(ack_t, c + 1, s + 1, 0x10)
            rd = read_with_app(rd_t, c + 1, s + 1, read_app)
            if overtake:
                inj(tag + 'READ_before_ACK', rd); inj(tag + 'ACK', ack); inj(tag + 'READ_retx', rd)
            else:
                inj(tag + 'ACK', ack); inj(tag + 'READ', rd)
            return c + 1 + 25, s + 1

        def respond(c, s, app, tag):
            """outstation ACK of the READ, the response, the master's ACK; returns the new server seq"""
            inj(tag + 'O_ACK', R.make_tcp(sa_t, s, c, 0x10))
            rsp = R.mixed_response(0xC0 | app)
            inj(tag + 'RSP', R.make_tcp(sa_t, s, c, 0x18, rsp))
            s2 = s + len(rsp)
            inj(tag + 'M_ACK', R.make_tcp(ack_t, c, s2, 0x10))
            return s2

        def close(c, s2, tag):
            inj(tag + 'M_FIN', R.make_tcp(ack_t, c, s2, 0x11))
            inj(tag + 'O_FIN', R.make_tcp(sa_t, s2, c + 1, 0x11))
            inj(tag + 'M_LASTACK', R.make_tcp(ack_t, c + 1, s2 + 1, 0x10))

        def exchange_and_close(c, s, app, tag):
            s2 = respond(c, s, app, tag)
            inj(tag + 'M_FIN', R.make_tcp(ack_t, c, s2, 0x11))
            inj(tag + 'O_FIN', R.make_tcp(sa_t, s2, c + 1, 0x11))
            inj(tag + 'M_LASTACK', R.make_tcp(ack_t, c + 1, s2 + 1, 0x10))

        log.append(dict(step='initial', registers=regs()))
        c1, s1 = 1000000, 5000000
        if scenario == 'lifecycle':
            # overtake, then a full normal life: response, a second READ cycle, graceful close, reconnect + first READ
            c, s = handshake(c1, s1, 'c1_', read_app=0, overtake=True)
            s = respond(c, s, 0, 'c1_r1_')
            inj('c1_READ2', read_with_app(rd_t, c, s, 1))
            c += 25
            s = respond(c, s, 1, 'c1_r2_')
            close(c, s, 'c1_')
            handshake(c1 + 1000000000, s1 + 1000000000, 'c2_', read_app=0)
        elif scenario == 'race':
            # READ immediately followed by the delayed final ACK, back to back; then a READ retransmission
            inj('c1_SYN', syn_like(syn_t, c1, 0, 0x02))
            inj('c1_SYNACK', syn_like(sa_t, s1, c1 + 1, 0x12))
            rd = read_with_app(rd_t, c1 + 1, s1 + 1, 0)
            inj_batch([('READ', rd), ('ACK', R.make_tcp(ack_t, c1 + 1, s1 + 1, 0x10))], 'c1_READ+ACK_b2b')
            inj('c1_READ_retx', rd)
        elif scenario == 'overtake_first':
            handshake(c1, s1, 'c1_', read_app=0, overtake=True)
        else:
            c, s = handshake(c1, s1, 'c1_', read_app=3)
            exchange_and_close(c, s, 3, 'c1_')
            c2, s2 = c1 + 1000000000, s1 + 1000000000   # forward of the old connection, as Linux same-tuple ISNs are
            if scenario == 'collide':
                handshake(c2, s2, 'c2_', read_app=3)
            else:
                handshake(c2, s2, 'c2_', read_app=0, overtake=True)
        report.record['meta']['reflections'] = {r.port: r.summary() for r in refl}
        report.add('completed', True, True)
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    (out / 'replay_steps.json').write_text(json.dumps(log, indent=1) + '\n')
    return 0 if report.finish(out / 'replay_results.json') else 1


def syn_like(template, seq, ack, flags):
    """SYN / SYN-ACK keeping the template's MSS option (44-octet IP)."""
    import struct
    f = bytearray(template[:14 + 20 + 24])
    t = 34
    f[t + 4:t + 8] = struct.pack('!I', seq & 0xffffffff)
    f[t + 8:t + 12] = struct.pack('!I', ack & 0xffffffff)
    f[t + 13] = flags
    return R.fix_checksums(R.pad60(bytes(f[:58])))


def launch(scenario, build_out, tag, port_map):
    out = HERE / ('model_%s%s_01' % (tag, scenario))
    assert not out.exists()
    env = dict(os.environ, PORT_MAP=port_map, SHARED_PORT='1', PAD_ENABLE='0', MILESTONE='m12', RECONNECT_SCENARIO=scenario)
    cmd = ['bash', str(R.CORE / 'launch_model.sh'), '-p', build_out, '-o', str(out), '-P', R.PORTS, '-d', str(Path(__file__).resolve())]
    rc = subprocess.run(cmd, env=env).returncode
    if out.is_dir():
        (out / 'launch_command.json').write_text(json.dumps(dict(command=cmd, scenario=scenario, build_out=build_out,
                                                                 port_map=port_map, exit_code=rc), indent=1) + '\n')
    return rc


if __name__ == '__main__':
    if os.environ.get('RECONNECT_SCENARIO') and os.environ.get('OUT'):
        raise SystemExit(driver())
    ap = argparse.ArgumentParser()
    ap.add_argument('--launch', choices=SCENARIOS, required=True)
    ap.add_argument('--build-out', default=str(R.BUILD / 'compile_local/out'))
    ap.add_argument('--port-map', default=str(R.BUILD / 'response_only.inputs.json'))
    ap.add_argument('--tag', default='c26_')
    a = ap.parse_args()
    raise SystemExit(launch(a.launch, a.build_out, a.tag, a.port_map))
