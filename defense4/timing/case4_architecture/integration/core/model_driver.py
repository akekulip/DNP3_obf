"""Drive a compiled P4 program on the local Tofino-1 model (BF Runtime gRPC + raw veth frames).

Runs INSIDE the namespace made by integration/core/launch_model.sh (python3.8, the SDE client).
This is functional model execution only: not hardware, not timing, not stage-fit evidence.

    from model_driver import Model
    m = Model()                                  # connects, binds pipeline PROG, enables DEV_PORTS
    m.add('Ingress.forwarding', {'ig.ingress_port': 9}, 'Ingress.route', {'port': 1})
    out = m.exchange(9, frame, [1])              # {1: [bytes, ...]}
    m.register_read('Ingress.qualified', 0)      # -> [per-pipe values]
"""
import os
import select
import socket
import sys
import time

SDE = os.environ.get('SDE', '/home/philip/bf-sde-9.13.2')
_P = SDE + '/install/lib/python3.8/site-packages'
for _p in (_P, _P + '/tofino', _P + '/tofino/bfrt_grpc'):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import bfrt_grpc.client as gc  # noqa: E402

PACKET_OUTGOING = 4


def same_frame(got, sent, original=None):
    """True when `got` is `sent` followed only by zero bytes that can be Ethernet minimum-length padding
    of the injected frame (`original`, default `sent`): the model pads short frames to 62-64 bytes and a
    program that lengthens a short frame leaves that padding behind as a trailer (observed: 54 -> 62,
    55-byte replay input -> 5 trailing zeros after the longer image)."""
    allowed = max(0, 64 - len(original if original is not None else sent))
    return got[:len(sent)] == sent and not any(got[len(sent):]) and len(got) - len(sent) <= allowed


def veth_for(port):
    """Test-side interface of a device port (the model owns veth(2N))."""
    return 'veth%d' % (2 * port + 1)


def t_params_for_build(values_ns):
    """T durations are configured in ns and written in the build's T units through the one shared writer conversion,
    t_config.t_units. The units come from the build's compiled source (t_config.t_time_of_source on the
    response_only.p4 beside PORT_MAP's inputs.json) and must agree with the inputs.json "t_time" declaration (absent:
    ns); a disagreement fails closed. The values written are appended to $OUT/t_params_written.json."""
    import json
    import os
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent / 'response_only/hw'))
    import t_config
    port_map = os.environ.get('PORT_MAP')
    if not port_map:
        return values_ns
    inputs = Path(port_map)
    document = json.loads(inputs.read_text())
    declared = document.get('t_time') or dict(t_config.T_TIME_NS)
    supplied_ns = dict(values_ns)
    contract = None
    if (document.get('supported_profile') or {}).get('timing_contract') is not None:
        sys.path.insert(0, str(Path(__file__).resolve().parent /
            'response_only_rearm/stage_experiments/ctl_timing_01'))
        import model_profile
        profile = model_profile.resolve(document, inputs.parent / 'response_only.p4')
        values_ns = model_profile.model_params(profile, values_ns)
        contract = profile.get('timing_contract')
    source = inputs.parent / 'response_only.p4'
    actual = t_config.t_time_of_source(source.read_text()) if source.is_file() else None
    if actual is not None and (actual['unit_ns'], actual['grid_ns']) != (declared['unit_ns'], declared['grid_ns']):
        raise ValueError('T time base: inputs.json declares %r, the source implements %r' % (declared, actual))
    written = t_config.t_units(values_ns, declared['unit_ns'], declared['grid_ns'])
    if os.environ.get('OUT'):
        log = Path(os.environ['OUT']) / 't_params_written.json'
        rows = json.loads(log.read_text()) if log.is_file() else []
        rows.append(dict(timing_contract=contract, supplied_ns=supplied_ns, values_ns=values_ns, t_time=declared, written=written))
        log.write_text(json.dumps(rows, indent=1) + '\n')
    return written


class Model:
    def __init__(self, prog=None, grpc=None, ports=None, enable=True, speed='BF_SPEED_10G',
                 pipe=0xffff, settle=2.0, client_id=1):
        self.prog = prog or os.environ['PROG']
        self.grpc = grpc or os.environ.get('MODEL_GRPC', '127.0.0.1:50052')
        self.iface = gc.ClientInterface(self.grpc, client_id=client_id, device_id=0)
        self.iface.bind_pipeline_config(self.prog)
        self.info = self.iface.bfrt_info_get(self.prog)
        self.target = gc.Target(device_id=0, pipe_id=pipe)
        self._tables = {}
        self._rx = {}
        self.ports = list(ports if ports is not None else
                          [int(p) for p in os.environ.get('MODEL_ENABLE_PORTS', '').split()])
        self.port_errors = {}
        if enable and self.ports:
            self.enable_ports(self.ports, speed)
            time.sleep(settle)

    # ---- ports -------------------------------------------------------------------------------
    def enable_ports(self, ports, speed='BF_SPEED_10G', loopback=None):
        """loopback: a $LOOPBACK_MODE value (e.g. 'BF_LPBK_MAC_NEAR') for front-panel ports that must loop."""
        t = self.table('$PORT', raw=True)
        for p in ports:
            try:
                fields = [gc.DataTuple('$SPEED', str_val=speed), gc.DataTuple('$FEC', str_val='BF_FEC_TYP_NONE'),
                          gc.DataTuple('$PORT_ENABLE', bool_val=True)]
                if loopback:
                    fields.append(gc.DataTuple('$LOOPBACK_MODE', str_val=loopback))
                t.entry_add(self.target, [t.make_key([gc.KeyTuple('$DEV_PORT', p)])], [t.make_data(fields)])
            except Exception as exc:  # recorded, not hidden: some ports (68) may be refused
                self.port_errors[p] = '%s: %s' % (type(exc).__name__, str(exc).splitlines()[0][:160])

    # ---- tables ------------------------------------------------------------------------------
    def table(self, name, raw=False):
        import re
        import telemetry_from_log
        full = name if raw or name.startswith('pipe.') or re.match(r'p\d+\.', name) else 'pipe.' + name
        if full == telemetry_from_log.E_COUNTER and not telemetry_from_log.build_has_telemetry():
            return telemetry_from_log.CounterTable()            # c68: E's removed outcome Counter, from the log
        if full == telemetry_from_log.E_COUNTER and os.environ.get('TELEMETRY_SHIM_VERIFY'):
            return telemetry_from_log.CounterTable(self.info.table_get(full))
        if full not in self._tables:
            self._tables[full] = self.info.table_get(full)
        return self._tables[full]

    def _key(self, t, keys, priority=None):
        tuples = []
        for k, v in (keys or {}).items():
            if isinstance(v, tuple):
                tuples.append(gc.KeyTuple(k, v[0], v[1]))      # ternary (value, mask)
            else:
                tuples.append(gc.KeyTuple(k, v))
        if priority is not None:
            tuples.append(gc.KeyTuple('$MATCH_PRIORITY', priority))
        return t.make_key(tuples)

    def add(self, table, keys, action=None, data=None, priority=None, pipe=None):
        """Install one entry. keys: {field: int | (value, mask)}; action is the full action name; pipe: target one pipe."""
        t = self.table(table)
        d = t.make_data([gc.DataTuple(k, v) for k, v in (data or {}).items()], action) \
            if action else t.make_data([])
        t.entry_add(self.target if pipe is None else gc.Target(device_id=0, pipe_id=pipe), [self._key(t, keys, priority)], [d])

    def set_default(self, table, action, data=None):
        if action == 't_Ingress.set_params' and data is not None:
            data = t_params_for_build(data)
        t = self.table(table)
        t.default_entry_set(self.target, t.make_data([gc.DataTuple(k, v) for k, v in (data or {}).items()], action))

    def clear(self, table):
        self.table(table).entry_del(self.target, [])

    # ---- registers ---------------------------------------------------------------------------
    def register_write(self, name, index, values, pipe=None):
        """values: {field: int} (field names as in bfrt, e.g. 'Ingress.counter.f1')."""
        t = self.table(name)
        tgt = self.target if pipe is None else gc.Target(device_id=0, pipe_id=pipe)
        t.entry_add(tgt, [t.make_key([gc.KeyTuple('$REGISTER_INDEX', index)])],
                    [t.make_data([gc.DataTuple(k, v) for k, v in values.items()])])

    def register_read(self, name, index, field=None, pipe=None):
        """Return {field: [value per pipe]} (or one list when field is given). Syncs from the model first.
        A build without switch telemetry (c68) answers its removed counters from the model log."""
        import telemetry_from_log
        if name in telemetry_from_log.REGISTERS and not telemetry_from_log.build_has_telemetry():
            out = telemetry_from_log.register_value(name, index)
            return out[field] if field else out
        out = self._register_read(name, index, pipe)
        if name in telemetry_from_log.REGISTERS and os.environ.get('TELEMETRY_SHIM_VERIFY'):
            telemetry_from_log.record_check(name, index, out)
        return out[field] if field else out

    def _register_read(self, name, index, pipe=None):
        t = self.table(name)
        tgt = self.target if pipe is None else gc.Target(device_id=0, pipe_id=pipe)
        try:
            t.operations_execute(tgt, 'Sync')
        except Exception:
            pass
        out = {}
        for data, _key in t.entry_get(tgt, [t.make_key([gc.KeyTuple('$REGISTER_INDEX', index)])],
                                      {'from_hw': True}):
            out.update(data.to_dict())
        return out

    def register_total(self, name, index, field):
        return sum(self.register_read(name, index, field))

    # ---- packets -----------------------------------------------------------------------------
    def _listen(self, port):
        if port not in self._rx:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            s.bind((veth_for(port), 0))
            s.setblocking(False)
            self._rx[port] = s
        return self._rx[port]

    def drain(self, ports=None):
        for p in (ports or self.ports):
            s = self._listen(p)
            while True:
                try:
                    s.recvfrom(4096)
                except BlockingIOError:
                    break

    def send(self, port, frame):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((veth_for(port), 0))
        s.send(frame)
        s.close()

    def capture(self, ports, timeout=1.0, quiet=0.3):
        """Frames received on each port's test-side interface. Stops after `quiet` s of silence once
        something arrived, or at `timeout`. Our own transmissions are filtered (PACKET_OUTGOING)."""
        socks = {self._listen(p): p for p in ports}
        got = {p: [] for p in ports}
        end = time.time() + timeout
        last = None
        while time.time() < end:
            r, _, _ = select.select(list(socks), [], [], 0.05)
            for s in r:
                try:
                    data, addr = s.recvfrom(4096)
                except BlockingIOError:
                    continue
                if addr[2] == PACKET_OUTGOING:
                    continue
                got[socks[s]].append(data)
                last = time.time()
            if last and time.time() - last > quiet:
                break
        return got

    def exchange(self, in_port, frame, out_ports, timeout=1.0, quiet=0.3):
        """Inject one frame on in_port, return {out_port: [frames]} (empty lists mean nothing came out)."""
        self.drain(out_ports)
        self.send(in_port, frame)
        return self.capture(out_ports, timeout, quiet)


class Report:
    """Collects one record per case (bytes in/out, oracle verdict, observed verdict) and writes JSON."""

    def __init__(self, program, **meta):
        self.record = dict(program=program, meta=meta, cases=[])

    def add(self, name, expected, observed, ok=None, **fields):
        row = dict(name=name, expected=expected, observed=observed,
                   ok=(expected == observed) if ok is None else ok)
        for k, v in fields.items():
            if isinstance(v, bytes):
                v = v.hex()
            elif isinstance(v, dict):
                v = {str(a): [x.hex() if isinstance(x, bytes) else x for x in b] if isinstance(b, list) else b
                     for a, b in v.items()}
            row[k] = v
        self.record['cases'].append(row)
        print('%-4s %-34s expected=%-10s observed=%s' % ('PASS' if row['ok'] else 'FAIL', name, expected, observed))
        return row['ok']

    def finish(self, path):
        import json
        c = self.record['cases']
        self.record['summary'] = dict(total=len(c), passed=sum(1 for r in c if r['ok']),
                                      failed=[r['name'] for r in c if not r['ok']])
        with open(path, 'w') as f:
            json.dump(self.record, f, indent=1, sort_keys=True, default=lambda o: o.hex() if isinstance(o, (bytes, bytearray)) else str(o))
        print('SUMMARY', self.record['summary'])
        return not self.record['summary']['failed']
