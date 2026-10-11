"""Offline check of every planned write against the compiled bfrt.json (P4 tables) and the SDE's shared
fixed-function schemas (bf_rt_{mirror,pktgen,tm,port}_tf1.json). No switch needed.

Checks: table exists; key field names exactly match (including $MATCH_PRIORITY when the table has one);
exact keys get no mask and ternary keys get one; values fit the key/data width; the action exists on the
table; data field names belong to that action (P4) or to the table/action (fixed); row count <= table size.
"""
import json
from collections import Counter
from pathlib import Path

FIXED_FILES = ('bf_rt_mirror_tf1.json', 'bf_rt_pktgen_tf1.json', 'bf_rt_tm_tf1.json', 'bf_rt_port_tf1.json')


def _width(field):
    return field.get('type', {}).get('width')


def load(bfrt_json, fixed_dir):
    tables = {t['name']: t for t in json.loads(Path(bfrt_json).read_text())['tables']}
    for name in FIXED_FILES:
        for t in json.loads((Path(fixed_dir) / name).read_text())['tables']:
            tables.setdefault(t['name'], t)
    return tables


def _actions(t):
    return {a['name']: a for a in t.get('action_specs', [])}


def _check_one(op, t, errs):
    where = '%s (%s)' % (op['table'], op.get('label') or op['kind'])
    keys = {k['name']: k for k in t.get('key', [])}
    if op['kind'] not in ('queue', 'queue_shaping', 'default'):
        given = [k[0] for k in op['key']] + (['$MATCH_PRIORITY'] if op.get('priority') is not None else [])
        if sorted(given) != sorted(keys):
            errs.append('%s: key fields %s, table has %s' % (where, sorted(given), sorted(keys)))
        for name, value, mask in op['key']:
            k = keys.get(name)
            if k is None:
                continue
            mt = k.get('match_type')
            if mt == 'Ternary' and mask is None or mt == 'Exact' and mask is not None:
                errs.append('%s: %s is %s, given mask %r' % (where, name, mt, mask))
            w = _width(k)
            if w and isinstance(value, int) and value >= 1 << w:
                errs.append('%s: %s=%d exceeds %d bits' % (where, name, value, w))
    if op['kind'] in ('queue', 'queue_shaping') and sorted(keys) != ['pg_id', 'pg_queue']:
        errs.append('%s: queue key is %s' % (where, sorted(keys)))
    fields = {d['singleton']['name']: d['singleton'] for d in t.get('data', []) if 'singleton' in d}
    acts = _actions(t)
    if op.get('action') is not None:
        if op['action'] not in acts:
            errs.append('%s: no action %s (has %s)' % (where, op['action'], sorted(acts)))
            return
        fields.update({d['name']: d for d in acts[op['action']].get('data', [])})
        if op['table'].startswith(('p0.', 'p1.')):
            want = {d['name'] for d in acts[op['action']].get('data', [])}
            if {d[0] for d in op['data']} != want:
                errs.append('%s: data %s, action needs %s' % (where, sorted(d[0] for d in op['data']), sorted(want)))
    for name, value in op['data']:
        f = fields.get(name)
        if f is None:
            errs.append('%s: no data field %s' % (where, name))
        elif isinstance(value, int) and not isinstance(value, bool) and _width(f) and value >= 1 << _width(f):
            errs.append('%s: %s=%d exceeds %d bits' % (where, name, value, _width(f)))


def check(ops, tables):
    """Return a list of error strings (empty = every name validated)."""
    errs = []
    for op in ops:
        t = tables.get(op['table'])
        if t is None:
            errs.append('%s: table not in bfrt.json or shared schemas' % op['table'])
        else:
            _check_one(op, t, errs)
    seen = Counter((op['table'], repr(op['key']), op.get('priority')) for op in ops if op['kind'] == 'p4')
    errs += ['%s: duplicate key %s (entry_add would fail)' % (t, k) for (t, k, _p), n in seen.items() if n > 1]
    rows = Counter(op['table'] for op in ops if op['kind'] == 'p4')
    for name, n in rows.items():
        size = tables.get(name, {}).get('size')
        if size is not None and n > size:
            errs.append('%s: %d rows > size %d' % (name, n, size))
    return errs


def check_registers(names, tables):
    errs = []
    for n in names:
        t = tables.get(n)
        if t is None:
            errs.append('%s: register not in bfrt.json' % n)
        elif not any(d['singleton']['name'].endswith('.f1') for d in t.get('data', []) if 'singleton' in d):
            errs.append('%s: no .f1 data field' % n)
    return errs


# Tables only READ (readback.py, switch.resolve_queue, snapshot_counters.py): table -> (key names, data names).
READ_ONLY = {'tf1.tm.port.cfg': (['dev_port'], ['pg_id', 'port_queues_count', 'ingress_qid_map', 'egress_qid_queues']),
             'tf1.tm.counter.queue': (['pg_id', 'pg_queue'], ['watermark_cells', 'drop_count_packets']),
             'tf1.tm.queue.sched_cfg': (['pg_id', 'pg_queue'], ['max_rate_enable']),
             'tf1.tm.queue.sched_shaping': (['pg_id', 'pg_queue'], ['unit', 'max_rate', 'max_burst_size']),
             '$PORT_STAT': (['$DEV_PORT'], []),
             '$PORT': (['$DEV_PORT'], ['$PORT_ENABLE', '$PORT_UP', '$MEDIA_TYPE', '$LOOPBACK_MODE'])}


def check_reads(tables, extra_fixed=()):
    errs = []
    for name, (keys, fields) in READ_ONLY.items():
        t = tables.get(name)
        if t is None:
            errs.append('%s: not in shared schemas' % name)
            continue
        have = {d['singleton']['name'] for d in t.get('data', []) if 'singleton' in d}
        if sorted(k['name'] for k in t.get('key', [])) != sorted(keys):
            errs.append('%s: key %s' % (name, [k['name'] for k in t.get('key', [])]))
        errs += ['%s: no field %s' % (name, f) for f in fields if f not in have]
    return errs
