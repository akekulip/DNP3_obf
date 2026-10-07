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

SDE = os.environ.get('SDE', '/home/philip/bf-sde-9.13.1')
_P = SDE + '/install/lib/python3.8/site-packages'
for _p in (_P, _P + '/tofino', _P + '/tofino/bfrt_grpc'):
    if _p not in sys.path:
        sys.path.insert(0, _p)
import bfrt_grpc.client as gc  # noqa: E402

PACKET_OUTGOING = 4


def veth_for(port):
    """Test-side interface of a device port (the model owns veth(2N))."""
    return 'veth%d' % (2 * port + 1)


class Model:
    def __init__(self, prog=None, grpc=None, ports=None, enable=True, speed='BF_SPEED_10G',
                 pipe=0xffff, settle=2.0):
        self.prog = prog or os.environ['PROG']
        self.grpc = grpc or os.environ.get('MODEL_GRPC', '127.0.0.1:50052')
        self.iface = gc.ClientInterface(self.grpc, client_id=1, device_id=0)
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
    def enable_ports(self, ports, speed='BF_SPEED_10G'):
        t = self.table('$PORT', raw=True)
        for p in ports:
            try:
                t.entry_add(self.target, [t.make_key([gc.KeyTuple('$DEV_PORT', p)])],
                            [t.make_data([gc.DataTuple('$SPEED', str_val=speed),
                                          gc.DataTuple('$FEC', str_val='BF_FEC_TYP_NONE'),
                                          gc.DataTuple('$PORT_ENABLE', bool_val=True)])])
            except Exception as exc:  # recorded, not hidden: some ports (68) may be refused
                self.port_errors[p] = '%s: %s' % (type(exc).__name__, str(exc).splitlines()[0][:160])

    # ---- tables ------------------------------------------------------------------------------
    def table(self, name, raw=False):
        full = name if raw or name.startswith('pipe.') else 'pipe.' + name
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

    def add(self, table, keys, action=None, data=None, priority=None):
        """Install one entry. keys: {field: int | (value, mask)}; action is the full action name."""
        t = self.table(table)
        d = t.make_data([gc.DataTuple(k, v) for k, v in (data or {}).items()], action) \
            if action else t.make_data([])
        t.entry_add(self.target, [self._key(t, keys, priority)], [d])

    def set_default(self, table, action, data=None):
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

    def register_read(self, name, index, field=None):
        """Return {field: [value per pipe]} (or one list when field is given). Syncs from the model first."""
        t = self.table(name)
        try:
            t.operations_execute(self.target, 'Sync')
        except Exception:
            pass
        out = {}
        for data, _key in t.entry_get(self.target, [t.make_key([gc.KeyTuple('$REGISTER_INDEX', index)])],
                                      {'from_hw': True}):
            out.update(data.to_dict())
        return out[field] if field else out

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
            json.dump(self.record, f, indent=1, sort_keys=True)
        print('SUMMARY', self.record['summary'])
        return not self.record['summary']['failed']
