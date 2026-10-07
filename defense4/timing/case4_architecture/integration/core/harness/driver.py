"""Pipeline driver: parser -> Ingress -> deparser, with recirculation on RETURN_PORT.

SOURCE-LEVEL harness. It executes the P4 text through interp_ext.ExtSource. It is not the
Tofino compiler, ASIC, packet generator or traffic manager, and nothing it reports is
target-verified.
"""
from pathlib import Path

from interp_ext import ExtSource

RETURN_PORT = 68
MAX_PASSES = 8


class Config:
    """Runtime-installed table state: port routes, flow tuples, data_connection entries."""

    def __init__(self, ports, flows, data_connections=(), return_port=RETURN_PORT):
        self.ports = dict(ports)                  # ingress port -> route(egress port)
        self.flows = list(flows)                  # (src, dst, sport, dport, 'forward'|'reverse', out port)
        self.data_connections = list(data_connections)  # (src, dst, sport, dport, index, code, repeat, on, off)
        self.return_port = return_port

    def install(self, src):
        for ingress, egress in self.ports.items():
            src.install('ports', (ingress,), 'route', (egress,))
        for *tuple4, direction, port in self.flows:
            src.install('connection', tuple4, direction + '_flow', (port,))
        for *tuple4, index, code, repeat, on, off in self.data_connections:
            src.install('data_connection', tuple4, 'configure', (index, code, repeat, on, off))


class Outcome:
    def __init__(self):
        self.emitted = []         # [(egress_port, bytes)]
        self.dropped = False
        self.drop_reason = None
        self.passes = 0
        self.trace = []           # one list of event strings per pass
        self.registers = {}
        self.parse_errors = []    # (pass number, message) for parser errors


class Pipeline:
    def __init__(self, source_text, config, include_dir=None, on_parser_error='drop'):
        self.config = config
        self.on_parser_error = on_parser_error
        self.src = ExtSource(source_text, include_dir)
        config.install(self.src)

    @classmethod
    def from_path(cls, path, config, **kwargs):
        path = Path(path)
        return cls(path.read_text(), config, include_dir=path.parent, **kwargs)

    def cell(self, path, name):
        return self.src.cells[(path, name)][0]

    def preset(self, owner=None, client=None, server=None, epoch=None, work=None):
        """Set register state directly. work=(generation, phase)."""
        for name, value in (('owner', owner), ('client', client), ('server', server), ('epoch', epoch)):
            if value is not None:
                self.src.cells[('', name)][0] = value
        if work is not None:
            self.src.cells[('work', 'work')][0] = {'generation': work[0], 'phase': work[1]}

    def state(self):
        work = self.cell('work', 'work')
        return dict(owner=self.cell('', 'owner'), client=self.cell('', 'client'),
                    server=self.cell('', 'server'), epoch=self.cell('', 'epoch'),
                    counter=self.cell('', 'counter'), work=dict(work))

    def run_pass(self, number, port, raw):
        src = self.src
        src.begin_pass(port)
        accepted, cursor = src.packet_parser(raw)
        note = 'parser: states=%s accepted=%s cursor=%d' % ('>'.join(src.parser_states), accepted, cursor)
        events = [note]
        if src.parse_error:
            events.append('parser error: ' + src.parse_error)
            if self.on_parser_error == 'drop':
                return events, None, 'parser error: ' + src.parse_error
        src.apply_control('Ingress')
        events += src.events
        events.append('m.parsed=%d m.stage=%d m.kind=%d egress=%d bypass=%d drop_ctl=%d' % (
            src.env.get('m.parsed', 0), src.env.get('m.stage', 0), src.env.get('m.kind', 0),
            src.env.get('tm.ucast_egress_port', 0), src.env.get('tm.bypass_egress', 0),
            src.env.get('md.drop_ctl', 0)))
        if src.invalid_reads:
            events.append('reads of invalid headers: ' + ', '.join(sorted(src.invalid_reads)))
        if src.env.get('md.drop_ctl', 0) & 1:
            return events, None, 'drop_ctl set by deny() (m.parsed=%d, stage=%d)' % (
                src.env.get('m.parsed', 0), src.env.get('m.stage', 0))
        out = src.deparse() + raw[cursor:]
        return events, (src.env.get('tm.ucast_egress_port', 0), out), None

    def inject(self, port, frame):
        outcome = Outcome()
        raw, ingress = bytes(frame), port
        for number in range(1, MAX_PASSES + 1):
            outcome.passes = number
            events, result, reason = self.run_pass(number, ingress, raw)
            outcome.trace.append(events)
            if self.src.parse_error:
                outcome.parse_errors.append((number, self.src.parse_error))
            if result is None:
                outcome.dropped, outcome.drop_reason = True, 'pass %d: %s' % (number, reason)
                break
            egress, raw = result
            if egress == self.config.return_port:
                ingress = self.config.return_port
                continue
            outcome.emitted.append((egress, raw))
            break
        else:
            outcome.dropped = True
            outcome.drop_reason = 'recirculation limit of %d passes exceeded' % MAX_PASSES
        outcome.registers = self.state()
        return outcome
