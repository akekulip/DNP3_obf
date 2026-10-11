#!/usr/bin/env python3
"""Tofino-model driver, phase T: timing ON (mode D4) and padding in the same pipeline.

Configures the timing ingress with the repository's own setup path (stage_reduction/control/
defense4_timing_setup.hw_configure_all: ports, dp8/dp10 queue ladders, pktgen apps, mirror, session, params,
codebook), pointed at the private tofino-model gRPC endpoint and program `single_pipe`. That path is guarded by
DEFENSE4_HW_AUTHORIZED; this driver calls the function directly and only ever inside launch_model.sh's private
namespace, where the only "switch" is tofino-model. No hardware is reachable from it.

Then: handshake (scrubbed SYN, arming SYN-ACK), one READ. Checks that the outstation's ACK and response are not
forwarded at once (held), that both are released, and that the released response leaves the master port as the
58-byte image with the mapper's sequence translation. The model clock is not wall time: hold durations are
recorded, not judged.
"""
import hashlib
import importlib.util
import json
import os
import sys
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import model_drive_single_pipe as p  # noqa: E402  (paths, oracles, frames, rows)
from model_drive_single_pipe import (Model, Report, same_frame, gc, b, rm, cps, rs, vectors, CODES,  # noqa: E402
                                     MASTER, OUTSTATION, MASTER_PORT, RELAY_PORT, MSS, RIG_OPTIONS, SCRUBBED)

SETUP = HERE.parents[2] / 'stage_reduction' / 'control' / 'defense4_timing_setup.py'

# The setup (written against SDE 9.13.1's client) releases its binding with iface._tear_down_stream(); this
# SDE's client calls it tear_down_stream. Alias it so the setup's own `finally` releases the program.
if not hasattr(gc.ClientInterface, '_tear_down_stream'):
    gc.ClientInterface._tear_down_stream = gc.ClientInterface.tear_down_stream


PREFIXES = (('pipe.Ingress.', 'pipe.d_Ingress.'), ('pipe.IgParser.', 'pipe.d_IgParser.'),
            ('Ingress.', 'd_Ingress.'), ('IgParser.', 'd_IgParser.'))


def to_merged(name):
    """A name as the standalone timing program spells it -> its d_-prefixed spelling in the merged program."""
    for old, new in PREFIXES:
        if isinstance(name, str) and name.startswith(old):
            return new + name[len(old):]
    return name


def to_standalone(name):
    for old, new in PREFIXES:
        if isinstance(name, str) and name.startswith(new):
            return old + name[len(new):]
    return name


class _Data:
    def __init__(self, data):
        self._d = data

    def to_dict(self):
        return {to_standalone(k): (to_standalone(v) if k == 'action_name' else v) for k, v in self._d.to_dict().items()}

    def __getattr__(self, k):
        return getattr(self._d, k)


class _Table:
    """Names only: action names and data-field names are translated on the way in and back on the way out."""

    def __init__(self, table):
        self._t = table

    def make_data(self, fields, action_name=None, *args, **kw):
        for f in fields or []:
            if hasattr(f, 'name'):
                f.name = to_merged(f.name)
        return self._t.make_data(fields, to_merged(action_name) if action_name else action_name, *args, **kw)

    def entry_get(self, *args, **kw):
        for data, key in self._t.entry_get(*args, **kw):
            yield _Data(data), key

    def default_entry_get(self, *args, **kw):
        for data, key in self._t.default_entry_get(*args, **kw):
            yield _Data(data), key

    def __getattr__(self, k):
        return getattr(self._t, k)


class _Info:
    def __init__(self, info):
        self._i = info

    def table_get(self, name):
        return _Table(self._i.table_get(to_merged(name)))

    def __getattr__(self, k):
        return getattr(self._i, k)


class LoopbackCable:
    """tofino-model does not emulate a port's MAC-near loopback: a frame the program sends out of dp8 or dp10 (the
    timing queue ladders) appears on the port's test-side veth and is gone. This thread is the loopback cable: every
    frame the model emits on those ports is written straight back into the same port. Counts are recorded."""

    def __init__(self, ports):
        import socket
        import threading
        self.socks = {}
        for port in ports:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            s.bind((p.veth_for(port) if hasattr(p, 'veth_for') else 'veth%d' % (2 * port + 1), 0))
            s.setblocking(False)
            self.socks[s] = port
        self.counts = {port: 0 for port in ports}
        self.stop = False
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        import select
        outgoing = 4   # PACKET_OUTGOING: our own re-injections
        while not self.stop:
            ready, _, _ = select.select(list(self.socks), [], [], 0.01)
            for s in ready:
                try:
                    data, addr = s.recvfrom(9216)
                except BlockingIOError:
                    continue
                if addr[2] == outgoing:
                    continue
                s.send(data)
                self.counts[self.socks[s]] += 1


def load_setup():
    spec = importlib.util.spec_from_file_location('timing_setup_model', SETUP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.PROGRAM = os.environ['PROG']          # the merged program, not defense4_timing
    connect = mod._connect

    def _connect(a):
        iface, bi, tgt, tdev = connect(a)
        return iface, _Info(bi), tgt, tdev
    mod._connect = _connect
    return mod


def main():
    out_dir = Path(os.environ['OUT'])
    rep = Report(os.environ['PROG'], physical=False,
                 driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 scope='single-pipe candidate, phase T: timing D4 configured, READ held and released, response padded')
    ok = False
    try:
        setup = load_setup()
        a = setup.build_argparser().parse_args([
            'configure-all', '--grpc', os.environ.get('MODEL_GRPC', '127.0.0.1:50052'), '--mode', 'D4',
            '--relay-ip', OUTSTATION.ip, '--master-ip', MASTER.ip, '--relay-dst-port', str(OUTSTATION.port)])
        chk = setup.Checks()
        ok_dl, _plan = setup.validate_bor_deadlines(a, chk)
        # tofino-model pre-creates its port list at 10G; the setup is written for a cold switch with no $PORT
        # entries (and asserts dp8 at 25G), so remove the model's defaults and let the setup add its own.
        pre = Model(ports=[], enable=False)
        pt = pre.table('$PORT', raw=True)
        removed = []
        for port in (8, 9, 10, 64, 68):
            try:
                pt.entry_del(gc.Target(device_id=0, pipe_id=0xffff), [pt.make_key([gc.KeyTuple('$DEV_PORT', port)])])
                removed.append(port)
            except Exception:
                pass
        rep.record['meta']['model_default_ports_removed'] = removed
        pre.iface._tear_down_stream()     # release the program binding: the setup binds as client 0
        time.sleep(1.0)
        setup.hw_configure_all(a, chk)
        rendered = chk.render()
        (out_dir / 'timing_setup_readback.txt').write_text(rendered + '\n')
        failures = [l.strip() for l in rendered.splitlines() if '[FAIL]' in l]
        # read_len is a dead parameter (defense4_timing.p4: "KEPT ... but no longer drives EXP_ACK"); bf-p4c
        # 9.13.4 drops the unused value, so it reads back 0. Only when that is the SOLE failure does the driver
        # make the setup's own last call, enabling the packet generator; anything else stays fail-closed.
        only_dead = bool(failures) and all('tbl_params read_len' in l for l in failures)
        rep.add('timing_setup_configure_all', 'pass or only the dead read_len readback', 'pass' if not failures
                else 'only dead read_len' if only_dead else 'failed', ok=ok_dl and (not failures or only_dead),
                n_warn=chk.n_warn, failures=failures[:20])
        if only_dead:
            iface, bi, tgt, _tdev = setup._connect(a)
            try:
                chk2 = setup.Checks()
                setup.hw_config_pktgen_two_apps(bi, tgt, a, {}, chk2, enable=True)
                rep.add('pktgen_enabled_after_setup', 0, chk2.n_fail, readback=chk2.render().splitlines()[-6:])
            finally:
                iface.tear_down_stream()

        m = Model(ports=[], enable=False)
        cable = LoopbackCable([8, 10])      # dp8 (RRC ladder) and dp10 (BOR ladder) loop back on hardware
        rows = cps.e_conn_rows(0, OUTSTATION, MASTER)
        for table, key, action, data, priority in rows:
            m.add('pipe.r_' + table, dict(key), 'r_' + action, dict(data), priority)
        ports = [MASTER_PORT, RELAY_PORT]
        sw = rm.ResponseMapper(merged_suffix_ok=False)

        def send(name, in_port, sent, want_port, want_frame, timeout=3.0):
            m.drain(ports)
            got = m.exchange(in_port, sent, ports, timeout=timeout, quiet=0.8)
            good = (len(got[want_port]) == 1 and same_frame(got[want_port][0], want_frame, sent)
                    and not any(got[q] for q in ports if q != want_port))
            rep.add(name, 'frame', 'frame' if good else 'mismatch', ok=good,
                    received={q: [g.hex() for g in got[q]] for q in ports}, want=want_frame.hex())

        send('master_SYN_scrubbed', MASTER_PORT, p.syn_with_options(RIG_OPTIONS), RELAY_PORT,
             p.syn_with_options(SCRUBBED))
        synack = vectors.packet(18, 900, 101, reverse=True, mss=MSS)
        sw.syn_ack(900)
        send('outstation_SYNACK_arms', RELAY_PORT, synack, MASTER_PORT, synack)
        r = sw.reverse(901, 4096)
        send('master_ACK', MASTER_PORT, vectors.packet(16, 101, 901), RELAY_PORT, vectors.packet(16, 101, r.ack))

        # READ: request to the relay; the outstation's ACK and response come back and are held by the timing
        # ingress, then released; the egress pads the response on its way to the master.
        req = rs.request_frame()
        r = sw.reverse(901, 4096)
        send('READ_request_to_relay', MASTER_PORT, vectors.packet(24, 101, 901, payload=req), RELAY_PORT,
             vectors.packet(24, 101, r.ack, payload=req))
        nxt = 101 + len(req)
        resp = rs.response_frame()
        image, delta = b.pad_read_response(resp)
        f_ack = sw.forward(901, 0)
        f_resp = sw.forward(901, len(resp), delta)
        want_ack = vectors.packet(16, f_ack.seq, nxt, reverse=True)
        want_resp = vectors.packet(24, f_resp.seq, nxt, reverse=True, payload=image)
        m.drain(ports)
        t0 = time.time()
        m.send(RELAY_PORT, vectors.packet(16, 901, nxt, reverse=True))
        immediate = m.capture(ports, timeout=0.05, quiet=0.05)
        m.send(RELAY_PORT, vectors.packet(24, 901, nxt, reverse=True, payload=resp))
        got = m.capture(ports, timeout=20.0, quiet=3.0)
        elapsed = time.time() - t0
        to_master = got[MASTER_PORT]
        rep.add('ACK_not_forwarded_immediately', 0, len(immediate[MASTER_PORT]),
                immediate=[g.hex() for g in immediate[MASTER_PORT]])
        rep.add('ACK_released_to_master', True, any(same_frame(g, want_ack) for g in to_master),
                received=[g.hex() for g in to_master], want=want_ack.hex())
        rep.add('response_released_padded_to_58', True, any(same_frame(g, want_resp) for g in to_master),
                want=want_resp.hex())
        order = [('ack' if same_frame(g, want_ack) else 'resp' if same_frame(g, want_resp) else 'other') for g in to_master]
        rep.add('ACK_before_response', ['ack', 'resp'], [o for o in order if o != 'other'])
        rep.add('nothing_leaked_toward_relay', 0, len(got[RELAY_PORT]), received=[g.hex() for g in got[RELAY_PORT]])
        rep.record['meta']['read_hold_wall_s'] = round(elapsed, 3)
        cable.stop = True
        rep.record['meta']['loopback_frames_echoed'] = dict(cable.counts)
        ok = True
    except BaseException as error:
        rep.record['error'] = type(error).__name__ + ': ' + str(error)
        rep.record['traceback'] = traceback.format_exc()
        rep.add('execution', 'completed', 'error', ok=False)
    finally:
        passed = rep.finish(str(out_dir / 'cases.json'))
        (out_dir / 'driver_source.py').write_bytes(Path(__file__).read_bytes())
        (out_dir / 'input_sources.json').write_text(json.dumps(
            {q.name: hashlib.sha256(q.read_bytes()).hexdigest()
             for q in (HERE / 'single_pipe.p4', HERE / 'cp_single_pipe.py', SETUP)}, indent=2) + '\n')
    return 0 if (ok and passed) else 1


if __name__ == '__main__':
    sys.exit(main())
