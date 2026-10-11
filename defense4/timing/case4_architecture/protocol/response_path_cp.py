"""Control plane for case4_response_path.p4: the one place connection and forwarding rows are made.

Invariants it enforces (TRANSPORT_MAPPER_SPEC.md section 8):

- Same pipe. The mapper's registers are per pipe and live in egress; forward packets leave on the
  master-facing port and reverse packets on the outstation-facing port, so both must be in one pipe.
  The Ingress.forwarding rows that decide those egress ports are generated here from the same Endpoint
  objects, so the checked ports and the installed ports cannot differ.
- No partial install. Every row of a connection is validated against what is already installed before
  anything is written; if the switch still refuses a row, the rows already added are deleted again.
- One mapped connection per (master, outstation) host pair: odd_ip_t (IP options / fragments, no
  parsed ports) can only key on the host pair. A reconnect must remove the old slot first.
- Policy changes modify the conn entry's enable flag; they never delete it (deleting would expose native
  numbering mid-connection).
- Retirement only when the connection has closed, or the registers show zero growth and nothing
  unacknowledged (W == N, U == 0).

On this rig the master is dev_port 9 and the outstation relay leg is dev_port 64; both are pipe 0.
"""
from dataclasses import dataclass
import ipaddress

TOFINO1_PORTS_PER_PIPE = 128
SLOTS = 16
MASK = 0xffffffff


class PipeMismatch(ValueError):
    pass


class Conflict(ValueError):
    pass


def pipe_of(dev_port):
    if not 0 <= dev_port < 4 * TOFINO1_PORTS_PER_PIPE:
        raise ValueError('not a Tofino-1 dev_port: %r' % dev_port)
    return dev_port // TOFINO1_PORTS_PER_PIPE


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int
    dev_port: int          # switch port the endpoint is reached through (its packets' ingress port)

    @property
    def ip_int(self):
        return int(ipaddress.IPv4Address(self.ip))


@dataclass(frozen=True)
class Row:
    table: str
    key: tuple             # sorted (field, value) pairs, hashable
    action: str
    data: tuple

    @property
    def key_dict(self):
        return dict(self.key)

    @property
    def data_dict(self):
        return dict(self.data)


def _row(table, key, action, data):
    return Row(table, tuple(sorted(key.items())), action, tuple(sorted(data.items())))


def _conn_rows(slot, o, m, pad_enable):
    fwd = {'hdr.ip.src': o.ip_int, 'hdr.ip.dst': m.ip_int, 'hdr.tcp.sport': o.port, 'hdr.tcp.dport': m.port}
    rev = {'hdr.ip.src': m.ip_int, 'hdr.ip.dst': o.ip_int, 'hdr.tcp.sport': m.port, 'hdr.tcp.dport': o.port}
    return [_row('Egress.conn', fwd, 'Egress.fwd_conn', {'idx': slot, 'enable': int(pad_enable)}),
            _row('Egress.conn', rev, 'Egress.rev_conn', {'idx': slot}),
            _row('Egress.odd_ip_t', {'hdr.ip.src': o.ip_int, 'hdr.ip.dst': m.ip_int}, 'Egress.odd_conn', {'idx': slot}),
            _row('Egress.odd_ip_t', {'hdr.ip.src': m.ip_int, 'hdr.ip.dst': o.ip_int}, 'Egress.odd_conn', {'idx': slot})]


def _forwarding_rows(o, m):
    if o.dev_port == m.dev_port:   # both endpoints behind one port (VEPA): one reflecting row, not two copies
        return [_row('Ingress.forwarding', {'ig.ingress_port': o.dev_port}, 'Ingress.route', {'port': o.dev_port})]
    return [_row('Ingress.forwarding', {'ig.ingress_port': o.dev_port}, 'Ingress.route', {'port': m.dev_port}),
            _row('Ingress.forwarding', {'ig.ingress_port': m.dev_port}, 'Ingress.route', {'port': o.dev_port})]


class Registry:
    """Tracks what is installed. `add(table, key, action, data)`, `delete(table, key)` and
    `modify(table, key, action, data)` are the switch writers (BFRT, model driver, or a test fake)."""

    def __init__(self):
        self.slots = {}          # slot -> (outstation, master, [conn rows])
        self.rows = {}           # (table, key) -> Row, everything installed through this registry
        self.forward_users = {}  # forwarding (table, key) -> set of slots using it

    def plan(self, slot, outstation, master, pad_enable=True):
        """Rows to add for this connection, after every check; raises before anything is written."""
        if not 0 <= slot < SLOTS:
            raise ValueError('slot out of range')
        if pipe_of(outstation.dev_port) != pipe_of(master.dev_port):
            raise PipeMismatch('master dev_port %d (pipe %d) and outstation dev_port %d (pipe %d): the mapper '
                               'registers are per pipe and must see both directions' %
                               (master.dev_port, pipe_of(master.dev_port), outstation.dev_port, pipe_of(outstation.dev_port)))
        if slot in self.slots:
            raise Conflict('slot %d is installed; remove it first' % slot)
        rows = _conn_rows(slot, outstation, master, pad_enable)
        for r in rows:
            if (r.table, r.key) in self.rows:
                what = 'host pair (odd_ip_t)' if r.table == 'Egress.odd_ip_t' else 'TCP 4-tuple'
                raise Conflict('%s already mapped by slot %d; remove that slot first' %
                               (what, self.rows[(r.table, r.key)].data_dict['idx']))
        for r in _forwarding_rows(outstation, master):
            have = self.rows.get((r.table, r.key))
            if have is None:
                rows.append(r)
            elif have.data != r.data:
                raise Conflict('dev_port %d already forwards to %d, not %d' %
                               (r.key_dict['ig.ingress_port'], have.data_dict['port'], r.data_dict['port']))
        return rows

    def install(self, slot, outstation, master, add, delete, pad_enable=True):
        rows = self.plan(slot, outstation, master, pad_enable)
        done = []
        try:
            for r in rows:
                add(r.table, r.key_dict, r.action, r.data_dict)
                done.append(r)
        except Exception:
            for r in reversed(done):           # leave nothing half-installed
                delete(r.table, r.key_dict)
            raise
        for r in rows:
            self.rows[(r.table, r.key)] = r
        for r in _forwarding_rows(outstation, master):
            self.forward_users.setdefault((r.table, r.key), set()).add(slot)
        self.slots[slot] = (outstation, master, [r for r in rows if r.table != 'Ingress.forwarding'])
        return rows

    def set_enable(self, slot, enable, modify):
        """Policy change: modify the forward conn entry in place; never delete it."""
        outstation, master, conn = self.slots[slot]
        old = conn[0]
        new = _row(old.table, old.key_dict, old.action, {'idx': slot, 'enable': int(enable)})
        modify(new.table, new.key_dict, new.action, new.data_dict)
        conn[0] = new
        self.rows[(new.table, new.key)] = new

    def remove(self, slot, delete, closed=False, registers=None):
        """Retire a slot. Allowed when the connection has closed (FIN/RST observed by the caller), or when
        a register readback {'front': N, 'acct_lo': W, 'acct_hi': U} shows W == N and U == 0."""
        outstation, master, conn = self.slots[slot]
        if not closed:
            if registers is None:
                raise Conflict('retirement needs closed=True or a register readback')
            if (registers['acct_lo'] - registers['front']) & MASK or registers['acct_hi'] & MASK:
                raise Conflict('slot %d still has growth or unacknowledged bytes; it cannot be retired live' % slot)
        for r in conn:
            delete(r.table, r.key_dict)
            del self.rows[(r.table, r.key)]
        for r in _forwarding_rows(outstation, master):
            users = self.forward_users[(r.table, r.key)]
            users.discard(slot)
            if not users:
                delete(r.table, r.key_dict)
                del self.rows[(r.table, r.key)]
                del self.forward_users[(r.table, r.key)]
        del self.slots[slot]


def connection_entries(slot, outstation, master, pad_enable=True):
    """Rows for one connection on an empty switch (kept for callers that only need the plan)."""
    return [(r.table, r.key_dict, r.action, r.data_dict) for r in Registry().plan(slot, outstation, master, pad_enable)]
