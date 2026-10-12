"""Execute candidate N, E and T source with the retained queue scheduler.

Parser, control, register actions, and emitted headers come from the generated
candidate P4. Traffic-manager/mirror/pktgen behavior has exactly QueueSim's
documented assumptions. E deparser checksum externs are outside this adapter.
"""
import sys
import tempfile
from pathlib import Path
import baseline
import make_n
import make_e
import make_t
from interpreter import ESource, checksum_oracle, source_text
import cp

sys.path[:0] = [str(baseline.INTEG / 'connection' / 'binding' / 'tests'),
                str(baseline.INTEG / 'read' / 'tests')]
import read_support as rs
import queue_sim as qs
import vectors


class ClockN(rs.ReadPipeline):
    def run_pass(self, number, port, raw):
        self.src.env['ig.global_tstamp'] = self.time + (number - 1) * 1000
        result = rs.driver.Pipeline.run_pass(self, number, port, raw)
        if result[1] and result[1][0] == self.config.return_port:
            self.returns.append(result[1][1])
        return result


class DepartingT(qs.QueueSim):
    def ingress(self, time, port, raw):
        count = len(self.emitted)
        super().ingress(time, port, raw)
        for stamp, destination, emitted in self.emitted[count:]:
            self.owner.egress(stamp, destination, emitted)


class SourcePipeline:
    def __init__(self, **timing):
        self.now, self.wire, self.trace = qs.T0, [], []
        self.temp = tempfile.TemporaryDirectory()
        source = Path(self.temp.name) / 't.p4'
        source.write_text(make_t.generate())
        self.t = DepartingT(source=source, **timing)
        self.t.owner = self
        self.n = ClockN(text=source_text(make_n.generate())).start(0, 0, 0, epoch=0)
        self.n.time = self.now
        self.n.returns = []
        self.e = ESource(make_e.generate())
        self.master = cp.rp.Endpoint('10.0.0.1', vectors.CLIENT_PORT, 9)
        self.relay = cp.rp.Endpoint('10.0.0.2', vectors.SERVER_PORT, 64)
        for table in ('ports', 'connection', 'read_connection'):
            rs.drop_runtime(self.n, table)
        cp.install_ingress(self.n.src, cp.n_ports_rows(9, 64)
                           + cp.n_connection_rows(self.relay, self.master)
                           + cp.n_read_rows(self.relay, self.master))
        for table, key, action, data, priority in cp.e_conn_rows(0, self.relay, self.master):
            params = self.e.controls['Ingress'].actions[action.split('.', 1)[1]][0]
            values = dict(data)
            self.e.install(table.split('.', 1)[1], tuple(v for _, v in key),
                           action.split('.', 1)[1], tuple(values[name] for name, _ in params), priority=priority)

    def close(self):
        self.temp.cleanup()

    def egress(self, time, destination, raw):
        if destination == qs.PORTS['T_IN']:
            self.t.handoff(time, raw)
            return
        result = self.e.inject(destination, raw)
        self.trace.append(('E', time, destination, raw, result))
        if result is None:
            return
        if destination == cp.N_ACK_RETURN:
            self.ingress(time + 1000, destination, checksum_oracle(result))
        else:
            self.wire.append((time, destination, result))

    def ingress(self, time, port, frame):
        self.n.time = time
        out = self.n.inject(port, frame)
        self.trace.append(('N', time, port, frame, out))
        for destination, raw in out.emitted:
            self.egress(time + 1000 * out.passes, destination, raw)
        return out

    def send(self, frame, master=True, time=None):
        self.now = self.now + 50_000 if time is None else time
        out = self.ingress(self.now, 9 if master else 64, frame)
        self.t.run(self.now + 20_000)
        return out

    def handshake(self, client_isn=100, server_isn=900):
        self.send(vectors.packet(2, client_isn, mss=1460))
        self.send(vectors.packet(18, server_isn, client_isn + 1, reverse=True, mss=1460), master=False)
        self.send(vectors.packet(16, client_isn + 1, server_isn + 1))
        assert self.n.state()['owner'] >> 16 == 5, self.n.state()
        return self

    def run(self, until):
        self.t.run(until)
        self.now = until
        return self
