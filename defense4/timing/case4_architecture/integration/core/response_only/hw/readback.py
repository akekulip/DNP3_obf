"""Read back every write, assert T's register reset values, and snapshot the generator and TM queue counters.

verify(sw, op) returns a list of mismatch strings (empty = the hardware holds exactly what was written).
"""
import t_config as tc

# Register<bit<32>, bit<1>>(1, init) in read_queue_timing.p4. The five 0xffffffff ones are compared for
# equality with a live generation or epoch, so a zero there is wrong (TIMING_QUEUE_MIGRATION_STATUS.md).
T_REGISTER_INIT = dict(cur_epoch_reg=0, quarantine_reg=0xffffffff, gen_alloc_reg=0, t0_reg=0, ack_done_reg=0,
                       ack_commit_at_reg=0, ack_commit_gen_reg=0xffffffff, resp_done_reg=0,
                       child_seen0_reg=0xffffffff, child_seen1_reg=0xffffffff, child_seen2_reg=0xffffffff,
                       op_gen_alloc_reg=0, op_done_reg=0, op_t0_reg=0)
COUNTER_FIELDS = ('trigger_counter', 'batch_counter', 'pkt_counter')   # live; never compared to the written 0


def _norm(name, value):
    if name == 'max_priority':          # sched_cfg reads back 'LOW' | '0'..'7' | 'HIGH'
        s = str(value).upper()
        return {'LOW': 0, 'HIGH': 7}.get(s, int(s) if s.isdigit() else s)
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, list) and value and all(isinstance(x, int) for x in value) and name == 'buffer':
        return bytes(value)
    return value


# Action parameters the P4 accepts but never assigns, so the compiler stores nothing and hardware reads 0.
# Measured on the switch 2026-10-11: T's set_params(cap) read 0 before and after writing 16000000
# (read_queue_timing.p4: "cap is accepted ... but not stored -- nothing in this design uses it as a deadline").
# Same on N's data_connection: configure() only sets m.enabled; the five decoy fields it also assigns are never
# read in the response-only N, so they are not stored either (second stop of the same kind, same day).
NOT_STORED = {('p1.t_Ingress.params', 'cap')} | {('p0.n_Ingress.data_connection', f) for f in ('index', 'code', 'repeat', 'on', 'off')}


def verify(sw, op):
    where = '%s %s' % (op['table'], op.get('label') or [k[1] for k in op.get('key', [])])
    try:
        if op['kind'] == 'default':
            got = sw.default_get(op['table'], op['pipe'])
        else:
            got = sw.get(op['table'], op['pipe'], op['key'], op.get('priority'))
    except Exception as e:
        return ['%s: readback error %s' % (where, e)]
    if got is None:
        return ['%s: not found on readback' % where]
    bad = []
    if op['kind'] in ('p4', 'default', 'mirror', 'pktgen_app'):
        name = got.get('action_name')
        if name != op['action']:
            bad.append('%s: action %r on readback, wrote %s' % (where, name, op['action']))
    for name, want in op['data']:
        if name in COUNTER_FIELDS or (op['table'], name) in NOT_STORED:
            continue
        have = got.get(name)
        if _norm(name, have) != _norm(name, want):
            bad.append('%s: %s reads %r, wrote %r' % (where, name, have, want))
    return bad


def enabled_app_op(app_op):
    """The full app write with app_enable True: what the hardware must hold after the enable."""
    return dict(app_op, data=[(n, True if n == 'app_enable' else v) for n, v in app_op['data']])


def same(name, have, want):
    return _norm(name, have) == _norm(name, want)


def registers(sw):
    """{register: (values, expected)} for every T register; a cell is clean when every pipe's value equals init."""
    out = {}
    for reg, init in T_REGISTER_INIT.items():
        out[reg] = (sw.register('p1.t_Ingress.' + reg, tc.ALL_PIPES), init)
    return out


def register_errors(regs):
    return ['%s reads %s, P4 init is 0x%x' % (r, [hex(v) for v in vals], init)
            for r, (vals, init) in regs.items() if not vals or any(v != init for v in vals)]


def snapshot(sw):
    """Generator app counters and TM queue counters on 198/199 (watermark/drops; usage_cells is unreliable)."""
    snap = {'pktgen': {}, 'queues': {}}
    for name, app_id, _pattern in tc.PKTGEN_APPS:
        got = sw.get('tf1.pktgen.app_cfg', tc.T_PIPE, [('app_id', app_id, None)]) or {}
        snap['pktgen'][name] = {k: got.get(k) for k in COUNTER_FIELDS + ('app_enable',)}
    for port, qid, label in tc.QUEUE_PLAN:
        pg_id, pgq, _cfg = sw.resolve_queue(port, qid, tc.T_PIPE)
        got = sw.get('tf1.tm.counter.queue', tc.T_PIPE, [('pg_id', pg_id, None), ('pg_queue', pgq, None)]) or {}
        snap['queues'][label] = dict(dev_port=port, qid=qid, pg_id=pg_id, pg_queue=pgq,
                                     watermark_cells=got.get('watermark_cells'),
                                     drop_count_packets=got.get('drop_count_packets'))
    return snap
