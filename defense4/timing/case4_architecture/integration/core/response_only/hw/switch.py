"""The only module that talks BF Runtime gRPC. Imported by bringup_composite.py, bringup_teardown.py, readback.py
and snapshot_counters.py on the switch host; nothing here runs in dry-run. Patterns follow
protocol/evidence/hw_first_traffic_01/scripts/install_connection.py (real add/delete on this switch) and
case_a_defense3_fixed_ack_delay_setup.py (get_entry, set_app_enable).
"""
import os
import sys

SDE_INSTALL = os.environ.get('SDE_INSTALL', '/home/decps/Downloads/bf-sde-9.13.2/install')
sys.path.insert(0, SDE_INSTALL + '/lib/python3.8/site-packages/tofino')
import bfrt_grpc.client as gc  # noqa: E402

# Text the driver puts in a missing-entry error. UNVERIFIED on this SDE: any other error is raised, so a wrong
# guess here fails closed (an absent entry would be reported as an error, never an error as absent).
NOT_FOUND = ('not found', 'not_found', 'object not found', 'does not exist')


def oneline(e):
    """The whole gRPC error on one line: BfruntimeReadWriteRpcException puts the detail on its second line."""
    return ' | '.join(l.strip() for l in str(e).splitlines() if l.strip())[:400]


class Switch:
    def __init__(self, program, client_id, grpc='localhost:50052'):
        self.iface = gc.ClientInterface(grpc, client_id=client_id, device_id=0)
        self.iface.bind_pipeline_config(program)
        self.bi = self.iface.bfrt_info_get(program)

    def close(self):
        for name in ('tear_down_stream', '_tear_down_stream'):
            if hasattr(self.iface, name):
                getattr(self.iface, name)()
                return

    def target(self, pipe):
        return gc.Target(device_id=0, pipe_id=pipe)

    def table(self, name):
        return self.bi.table_get(name)

    def key(self, t, key, priority=None):
        tuples = [gc.KeyTuple(n, v) if m is None else gc.KeyTuple(n, v, m) for n, v, m in key]
        if priority is not None:
            tuples.append(gc.KeyTuple('$MATCH_PRIORITY', priority))
        return t.make_key(tuples)

    @staticmethod
    def _datum(name, value):
        if isinstance(value, bool):
            return gc.DataTuple(name, bool_val=value)
        if isinstance(value, str):
            return gc.DataTuple(name, str_val=value)
        if isinstance(value, (bytes, bytearray)):
            return gc.DataTuple(name, bytearray(value))
        return gc.DataTuple(name, value)

    def data(self, t, fields, action=None):
        items = [self._datum(n, v) for n, v in fields]
        return t.make_data(items, action) if action else t.make_data(items)

    def get(self, table, pipe, key, priority=None):
        """entry_get one key from hardware -> dict; None only when the driver says the entry does not exist."""
        t = self.table(table)
        try:
            for d, _k in t.entry_get(self.target(pipe), [self.key(t, key, priority)], {'from_hw': True}):
                return self.as_dict(d)
        except Exception as e:
            if any(s in str(e).lower() for s in NOT_FOUND):
                return None
            raise RuntimeError('entry_get %s %s: %s' % (table, key, oneline(e)))
        raise RuntimeError('entry_get %s %s: empty read without a not-found error' % (table, key))

    @staticmethod
    def as_dict(d):
        """to_dict(), plus the raw stream of a repeated bytes field. The client parses such a field (pktgen
        `buffer`) into .val but to_dict() returns int_arr_val, which is None (bfrt_grpc/client.py _get_val)."""
        out = d.to_dict()
        for name, value in list(out.items()):
            raw = getattr(getattr(d, 'field_dict', {}).get(name), 'val', None)
            if value is None and raw is not None:
                out[name] = bytes(raw)
        return out

    def must_get(self, table, pipe, key, priority=None):
        got = self.get(table, pipe, key, priority)
        if got is None:
            raise RuntimeError('%s %s: entry expected but absent' % (table, key))
        return got

    def count(self, table, pipe):
        """Number of installed entries; raises if the table cannot be listed."""
        return sum(1 for _ in self.table(table).entry_get(self.target(pipe), None, {'from_hw': False}))

    def default_get(self, table, pipe):
        for item in self.table(table).default_entry_get(self.target(pipe), {'from_hw': True}):
            d = item[0] if isinstance(item, tuple) else item
            return self.as_dict(d)
        raise RuntimeError('%s: no default entry readable' % table)

    def resolve_queue(self, dev_port, qid, pipe):
        """(pg_id, pg_queue, port cfg). pg_queue is the port's own egress_qid_queues[qid], with the qid mapped to
        itself (ingress_qid_map[qid] == qid); fails if the port does not report its queue count."""
        cfg = self.must_get('tf1.tm.port.cfg', pipe, [('dev_port', dev_port, None)])
        n = cfg.get('port_queues_count')
        qmap, queues = cfg.get('ingress_qid_map'), cfg.get('egress_qid_queues')
        if n is None or qmap is None or queues is None:
            raise RuntimeError('dev_port %d: tf1.tm.port.cfg lacks port_queues_count / ingress_qid_map / '
                               'egress_qid_queues: %s' % (dev_port, sorted(cfg)))
        if qid >= n or qid >= len(qmap) or qmap[qid] != qid or qid >= len(queues):
            raise RuntimeError('dev_port %d: qid %d not an identity-mapped queue (count %s, ingress_qid_map %s)'
                               % (dev_port, qid, n, qmap[:8]))
        return cfg['pg_id'], queues[qid], cfg

    def write(self, op):
        """Perform one planned write; returns the undo record. A pre-read that fails raises (no empty undo)."""
        t = self.table(op['table'])
        tgt = self.target(op['pipe'])
        kind = op['kind']
        if kind == 'default':
            before = self.default_get(op['table'], op['pipe'])
            t.default_entry_set(tgt, self.data(t, op['data'], op['action']))
            return dict(undo='default_reset', before=before)
        if kind in ('p4', 'mirror'):
            t.entry_add(tgt, [self.key(t, op['key'], op.get('priority'))], [self.data(t, op['data'], op['action'])])
            return dict(undo='delete')
        before = self.must_get(op['table'], op['pipe'], op['key'])     # mod-only fixed tables: keep the old values
        names = {n for n, _ in op['data']}
        saved = {k: v for k, v in before.items() if k in names or k == 'action_name'}
        lost = sorted(n for n in names if saved.get(n) is None)
        if kind == 'pktgen_app' and saved.get('action_name') != op.get('action'):
            lost = []                            # another trigger type: its fields differ; teardown reports it
        if lost:                                 # an undo that cannot put the old value back is not an undo
            raise RuntimeError('%s %s: pre-read has no value for %s; refusing to write' % (op['table'], op['key'], lost))
        action = None if kind == 'pktgen_enable' else op.get('action')  # set_app_enable passes no action
        t.entry_mod(tgt, [self.key(t, op['key'])], [self.data(t, op['data'], action)])
        return dict(undo='disable' if kind == 'pktgen_enable' else 'restore', before=saved)

    def register(self, name, pipe, index=0):
        """All values (per pipe) of one register cell, flattened."""
        got = self.must_get(name, pipe, [('$REGISTER_INDEX', index, None)])
        vals = []
        for k, v in got.items():
            if k.endswith('.f1'):
                vals.extend(v if isinstance(v, list) else [v])
        return vals
