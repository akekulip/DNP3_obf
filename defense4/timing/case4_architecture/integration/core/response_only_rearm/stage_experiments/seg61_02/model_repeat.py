"""Compiled candidate61: repeated SELECT/OPERATE cycles on one persistent connection, inside launch_model.sh.

One connection carries READ, then CYCLES x (SELECT, OPERATE, READ). Master transport and application sequence
numbers advance as an OpenDNP3 master's do (mod 64 and mod 16), the outstation's transport sequence advances per
native response (mod 64), and each cycle's CROB on-time is 100 + cycle so every echo is distinct. Expected wire
images come from the seg61_01 encode61 oracle; requests must reach the relay unchanged except for the normalized
acknowledgment. Phase A runs with T disabled (size and N authority); phase B repeats a few cycles with T enabled
and checks one OPERATE release per cycle. Probes (T enabled): a READ after an SBO, or a READ alone, authorizes no
OPERATE (dropped, nothing released); a SELECT followed by a READ is unsupported (READ dropped; reset recovers),
except under source-bound ctl_timing profiles implementing Table 4-9, where READ cancels the selection and is answered.
Queue timing observed here is model behavior, not host timing or ASIC evidence. No register clear or CPU rearm.

  REPEAT_CYCLES (default 64), REPEAT_TIMED_CYCLES (default 3)
"""
import copy
import hashlib
import importlib.util
import json
import os
import sys
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parents[2]
BASE = HERE.parent / 'response_only'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


helpers = load('_retained_model_helpers', BASE / 'model_drive_composite.py')
cp = load('_protected_model_cp', HERE / 'cp.py')
Model, Report, gc, same_frame = helpers.Model, helpers.Report, helpers.gc, helpers.same_frame
vectors, scalar, codec = helpers.vectors, helpers.scalar, helpers.codec
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'seg61_01'))
import encode61  # noqa: E402
IMAGE_LEN = 61
READ_NATIVE, CONTROL_NATIVE = 49, 37
PM, MASTER, RELAY = helpers.PM, helpers.MASTER, helpers.OUTSTATION
# Link headers exactly as the retained model vectors use them (codec.build_frame rewrites LEN and the CRC):
# READ from read_support.request_frame/response_frame, SELECT/OPERATE from vectors.native_select/native_response37.
REQ_HEAD = {'READ': bytes.fromhex('05640bc400000100'), 'CONTROL': bytes.fromhex('05641ac40a000100')}
RSP_HEAD = {'READ': bytes.fromhex('0564004401000000'), 'CONTROL': bytes.fromhex('05641c4401000a00')}


class Sequences:
    """Native protocol sequence state of one OpenDNP3 master/outstation pair."""

    def __init__(self):
        self.master_transport, self.app, self.outstation_transport = 0, 0, 0
        self.wraps = {'master_transport': 0, 'application': 0, 'outstation_transport': 0}

    def request(self, fc, objects):
        tp = 0xc0 | self.master_transport
        app = 0xc0 | self.app
        self.master_transport = (self.master_transport + 1) % 64
        self.wraps['master_transport'] += self.master_transport == 0
        head = REQ_HEAD['READ' if fc == 1 else 'CONTROL']
        frame = codec.build_frame(head, bytes((tp, app, fc)) + objects)
        return frame, self.app

    def response(self, app_seq, body, kind):
        tp = 0xc0 | self.outstation_transport
        self.outstation_transport = (self.outstation_transport + 1) % 64
        self.wraps['outstation_transport'] += self.outstation_transport == 0
        head = RSP_HEAD['READ' if kind == 'READ' else 'CONTROL']
        return codec.build_frame(head, bytes((tp, 0xc0 | app_seq, 0x81)) + body)

    def next_app(self):
        self.app = (self.app + 1) % 16
        self.wraps['application'] += self.app == 0


def crob(on_ms):
    return bytes.fromhex('0c012801000100') + bytes((0x01, 0x01)) + on_ms.to_bytes(4, 'little') + \
        (100).to_bytes(4, 'little') + b'\x00'


READ_OBJECTS = bytes.fromhex('0a02000016')


def repeat_milestone():
    """Resolve CT expectations by source identity; keep the original non-CT driver's no-milestone behavior."""
    inputs_path = os.environ.get('PORT_MAP')
    if not inputs_path:
        if os.environ.get('MILESTONE') is None:
            return None
        raise ValueError('CT repeat expectations require a source-bound PORT_MAP')
    inputs = json.loads(Path(inputs_path).read_text())
    if os.environ.get('MILESTONE') is None and 'milestone' not in inputs and 'supported_profile' not in inputs:
        return None
    profile = load('_repeat_model_profile', HERE / 'stage_experiments/ctl_timing_01/model_profile.py')
    return profile.from_env()['milestone']


def main():
    cycles = int(os.environ.get('REPEAT_CYCLES', '64'))
    timed_cycles = int(os.environ.get('REPEAT_TIMED_CYCLES', '3'))
    report = Report(os.environ['PROG'], physical=False,
                    scope='E61 compiled repeated SBO: READ, %d x (SELECT, OPERATE, READ) on one connection, then '
                          '%d timed cycles; sequence wraps; unpaired OPERATE after READ' % (cycles, timed_cycles),
                    driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    try:
        milestone = repeat_milestone()
        report.record['meta']['expectation_milestone'] = milestone
        m = Model(ports=[], enable=False)
        ports = sorted({MASTER.dev_port, RELAY.dev_port})
        m.enable_ports(ports + helpers.FRONT_LOOPS)
        m.enable_ports([p for p in helpers.LOOP_PORTS if p not in helpers.FRONT_LOOPS])
        reflectors = [helpers.Reflector(p) for p in helpers.FRONT_LOOPS]
        for reflector in reflectors:
            reflector.start()
        report.record['meta']['port_errors'] = m.port_errors
        report.record['meta']['cycles'] = cycles
        report.record['meta']['timed_cycles'] = timed_cycles
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

        def snapshot():
            names = {'N': ('owner', 'epoch'), 'E': ('front', 'acct', 'img_end', 'img_start', 'img_wend'),
                     'T': ('gen_alloc_reg', 'op_gen_alloc_reg', 'op_done_reg')}
            prefix = {'N': 'p0.n_Ingress.', 'E': 'p0.r_Egress.', 'T': 'p1.t_Ingress.'}
            return {role: {n: scalar(m.register_read(prefix[role] + n, 0, pipe=1 if role == 'T' else 0))
                           for n in ns} for role, ns in names.items()}

        def outcome(index):
            return scalar(m.register_read('p1.t_Ingress.outcomes', index, pipe=1))

        def step(name, sent, expected, master=True):
            got = m.exchange(MASTER.dev_port if master else RELAY.dev_port, sent, ports, timeout=3, quiet=.15)
            flat = [frame for frames in got.values() for frame in frames]
            good = len(flat) == (0 if expected is None else 1)
            if good and expected is not None:
                good = same_frame(flat[0], expected, sent)
            report.add(name, 'drop' if expected is None else 'one exact frame',
                       'drop' if not flat else '%d frames' % len(flat), ok=good,
                       received=got, want='' if expected is None else expected.hex())
            return good

        # TCP coordinates: client (master) c; server native s and wire s + growth
        c, s, growth = 100, 900, 0
        syn = vectors.packet(2, c, mss=1460)
        step('SYN', syn, syn)
        synack = vectors.packet(18, s, c + 1, reverse=True, mss=1460)
        step('SYNACK', synack, synack, master=False)
        c, s = c + 1, s + 1
        step('final_ACK', vectors.packet(16, c, s), vectors.packet(16, c, s))
        seqs = Sequences()
        counts = {'READ': 0, 'SELECT': 0, 'OPERATE': 0}

        def exchange(tag, kind, fc, objects, response_body, separate_ack):
            nonlocal c, s, growth
            request, app = seqs.request(fc, objects)
            seqs.next_app()
            ok = step('%s_%s_request' % (tag, kind), vectors.packet(24, c, s + growth, payload=request),
                      vectors.packet(24, c, s, payload=request))
            c += len(request)
            if separate_ack:
                ok &= step('%s_%s_server_ACK' % (tag, kind), vectors.packet(16, s, c, reverse=True),
                           vectors.packet(16, s + growth, c, reverse=True), master=False)
            native = seqs.response(app, response_body, kind)
            image = encode61.read61(native) if kind == 'READ' else encode61.ctl61(native)
            if image is None or len(image) != IMAGE_LEN:
                raise AssertionError('%s %s: oracle produced no 61-octet image' % (tag, kind))
            ok &= step('%s_%s_response_61' % (tag, kind), vectors.packet(24, s, c, reverse=True, payload=native),
                       vectors.packet(24, s + growth, c, reverse=True, payload=image), master=False)
            s += len(native)
            growth += IMAGE_LEN - len(native)
            counts[kind] += 1
            return ok, native, image

        read_body = bytes((0x80, 0x00)) + READ_OBJECTS + bytes(range(23))

        def control_body(on_ms):
            return bytes((0x00, 0x00)) + crob(on_ms)

        def read(tag):
            return exchange(tag, 'READ', 1, READ_OBJECTS, read_body, True)[0]

        def sbo(tag, cycle):
            on_ms = 100 + cycle
            ok, _, _ = exchange(tag, 'SELECT', 3, crob(on_ms), control_body(on_ms), False)
            ok2, _, _ = exchange(tag, 'OPERATE', 4, crob(on_ms), control_body(on_ms), False)
            return ok and ok2

        def master_ack(tag):
            step('%s_wire_ACK' % tag, vectors.packet(16, c, s + growth), vectors.packet(16, c, s))

        start = snapshot()
        report.record['meta']['start_snapshot'] = start
        read('c00')
        failed_cycle = None
        for cycle in range(cycles):
            tag = 'c%02d' % cycle
            ok = sbo(tag, cycle)
            ok &= read(tag)
            if not ok and failed_cycle is None:
                failed_cycle = cycle
                break
        master_ack('phaseA_end')
        end = snapshot()
        report.record['meta']['phaseA_end_snapshot'] = end
        report.add('phaseA_all_cycles_exact', None, failed_cycle)
        report.add('phaseA_counts', {'READ': cycles + 1, 'SELECT': cycles, 'OPERATE': cycles}, dict(counts))
        report.add('phaseA_growth_12_per_READ_24_per_control', 12 * (cycles + 1) + 24 * 2 * cycles, growth)
        # Observed rollovers of the counters whose values every exact frame above carried on the wire.
        wraps = dict(seqs.wraps)
        report.record['meta']['phaseA_wraps'] = wraps
        report.add('phaseA_master_transport_wrapped', True, wraps['master_transport'] >= 1)
        report.add('phaseA_application_sequence_wrapped', True, wraps['application'] >= 4)
        report.add('phaseA_outstation_transport_wrapped', True, wraps['outstation_transport'] >= 1)

        # Phase B: T enabled; one OPERATE release per cycle, no duplicates.
        params['enabled'] = 1
        m.set_default('p1.t_Ingress.params', 't_Ingress.set_params', params)
        releases = outcome(5)
        read('timed_lead')
        for cycle in range(timed_cycles):
            tag = 't%02d' % cycle
            sbo(tag, 200 + cycle)
            report.add('%s_one_OPERATE_release' % tag, releases + cycle + 1, outcome(5))
            read(tag)
        master_ack('phaseB_end')
        report.add('phaseB_releases', releases + timed_cycles, outcome(5))

        # Authority probes with T enabled. Each ends its connection: a dropped OPERATE leaves its TCP sequence
        # slot outstanding, so the connection is retired (qualified RST) and a fresh one is opened.
        def unpaired_operate(tag):
            before_state, before_release = snapshot(), outcome(5)
            request, _app = seqs.request(4, crob(999))
            seqs.next_app()
            got = m.exchange(MASTER.dev_port, vectors.packet(24, c, s + growth, payload=request), ports,
                             timeout=3, quiet=.15)
            report.add('%s_OPERATE_dropped' % tag, 0, sum(len(v) for v in got.values()), received=got)
            report.add('%s_no_OPERATE_release' % tag, before_release, outcome(5))
            report.add('%s_no_OPERATE_generation' % tag, before_state['T']['op_gen_alloc_reg'],
                       snapshot()['T']['op_gen_alloc_reg'])

        def reconnect(tag, client, server):
            nonlocal c, s, growth, seqs
            step('%s_qualified_RST' % tag, vectors.packet(20, c, s + growth), vectors.packet(20, c, s))
            c, s, growth, seqs = client, server, 0, Sequences()
            syn = vectors.packet(2, c, mss=1460)
            step('%s_SYN' % tag, syn, syn)
            synack = vectors.packet(18, s, c + 1, reverse=True, mss=1460)
            step('%s_SYNACK' % tag, synack, synack, master=False)
            c, s = c + 1, s + 1
            step('%s_final_ACK' % tag, vectors.packet(16, c, s), vectors.packet(16, c, s))

        # A READ after a completed SBO grants no OPERATE authority (unpaired OPERATE dropped, nothing released).
        read('probe1')
        unpaired_operate('probe1_SBO_READ_then')
        reconnect('probe2', 20000, 30000)
        read('probe2')
        unpaired_operate('probe2_READ_then_no_SELECT')
        # SELECT then READ (an abandoned SELECT) is an unsupported shape: N admits only the matching OPERATE, so the
        # READ is dropped and the connection must be reset (model_abandon.py characterizes it in detail).
        # ctl_timing m4 and its supported successors implement Table 4-9: READ cancels the selection and is answered.
        reconnect('probe3', 40000, 50000)
        exchange('probe3', 'SELECT', 3, crob(500), control_body(500), False)
        if milestone in ('m4', 'm5', 'm6', 'm7', 'm8', 'm9', 'm9d', 'm10'):
            report.add('probe3_READ_after_SELECT_cancels_selection', True, read('probe3_cancel'))
        else:
            request, _app = seqs.request(1, READ_OBJECTS)
            seqs.next_app()
            got = m.exchange(MASTER.dev_port, vectors.packet(24, c, s + growth, payload=request), ports, timeout=3,
                             quiet=.15)
            report.add('probe3_READ_after_SELECT_dropped_unsupported_shape', 0, sum(len(v) for v in got.values()),
                       received=got)
        reconnect('probe4', 60000, 70000)
        read('probe4_after_reset')
        report.record['meta']['final_snapshot'] = snapshot()
        report.record['meta']['reflections'] = {r.port: r.summary() for r in reflectors}
    except Exception:
        report.add('exception', 'none', traceback.format_exc(), ok=False)
    ok = report.finish(Path(os.environ['OUT']) / 'repeat_results.json')
    return 0 if ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
