"""Read back every write, assert T's register reset values, and snapshot the generator and TM queue counters.

verify(sw, op) returns a list of mismatch strings (empty = the hardware holds exactly what was written).
"""
import build_ports
import t_config as tc

# Every live T register and its compiled reset value.
T_REGISTER_INIT = dict(cur_epoch_reg=0, gen_alloc_reg=0, ack_done_reg=0,
                       ack_commit_at_reg=0, ack_commit_gen_reg=0xffffffff, resp_done_reg=0,
                       child_seen0_reg=0xffffffff)
COUNTER_FIELDS = ('trigger_counter', 'batch_counter', 'pkt_counter')
# $PORT_STAT fields for total internal packets AND bytes on each loop port (names from bf_rt_port_tf1.json:
# there is no $OctetsTransmittedAll -- the total is $OctetsTransmittedTotal, and "withouterror" is lower case).
LOOP_PORT_STATS = ('$FramesTransmittedAll', '$FramesReceivedAll', '$OctetsTransmittedTotal',
                   '$OctetsTransmittedwithouterror', '$OctetsReceived', '$OctetsReceivedinGoodFrames')   # live; never compared to the written 0


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


# The TF1 TM shaper quantizes max_rate to a hardware-achievable step, so the sched_shaping readback is NOT
# exact: a 1000 PPS request read back 930 on silicon (~7% low). We accept the quantized achieved rate and
# record it (it is what the measurement uses), but still fail closed if it is implausible -- 0 (the write did
# not land) or more than SHAPE_RATE_TOL off the request (a genuinely wrong rate: a factor error, wrong unit
# scaling, or the wrong queue). 25% is well above any single quantization step seen (~7%) yet far below a real
# error (2x+), so it still catches a bad write. unit and max_burst_size are still checked exactly elsewhere.
SHAPE_RATE_TOL = 0.25


def _shaping_rate_bad(where, achieved, requested):
    if not isinstance(achieved, int) or achieved <= 0:
        return ['%s: max_rate reads %r (implausible; the shaping write did not land)' % (where, achieved)]
    if abs(achieved - requested) > SHAPE_RATE_TOL * requested:
        return ['%s: max_rate %d is >%.0f%% from requested %d (not hardware quantization)'
                % (where, achieved, SHAPE_RATE_TOL * 100, requested)]
    return []


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
        if op['kind'] == 'queue_shaping' and name == 'max_rate':
            bad += _shaping_rate_bad(where, got.get('max_rate'), want)   # quantized: tolerant, not exact
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


def snapshot(sw, ports, requested_pps=None, requested_block_pps=None, timing_contract=None):
    """Generator app counters, TM queue counters, and the shaping actually applied to each hold queue.

    requested_pps: optional {role -> pps} ('ack'/'resp'/'op') so the snapshot records requested vs the
    hardware-quantized achieved rate. Unknown (standalone read) -> requested recorded as None; achieved always
    comes from hardware."""
    requested_pps = requested_pps or {}
    requested_block_pps = requested_block_pps or {}
    snap = {'pktgen': {}, 'queues': {}, 'loop_ports': {}}
    # Total internal traffic per front-panel loop port (the build's N_ACK_RETURN / T_IN / HB_RETURN /
    # HELD_RETURN, read from its port map): a before/after delta gives packets and bytes per ladder port.
    # Read-only; a port whose stats cannot be read is recorded as None so the snapshot still completes.
    for role, port in sorted(build_ports.loopback_ports(ports, timing_contract=timing_contract).items(), key=lambda kv: kv[1]):
        try:
            got = sw.get('$PORT_STAT', tc.ALL_PIPES, [('$DEV_PORT', port, None)]) or {}
            stats = {f: got.get(f) for f in LOOP_PORT_STATS}
        except Exception:
            stats = {f: None for f in LOOP_PORT_STATS}
        snap['loop_ports'][role] = dict(dev_port=port, **stats)
    gen_pipe = tc.pipe_of(ports['pktgen_return'])
    for name, app_id, _pattern in tc.pktgen_apps(timing_contract):
        got = sw.get('tf1.pktgen.app_cfg', gen_pipe, [('app_id', app_id, None)]) or {}
        snap['pktgen'][name] = {k: got.get(k) for k in COUNTER_FIELDS + ('app_enable',)}
    snap['shaping'] = {}
    for port, qid, label in tc.queue_plan(ports, timing_contract=timing_contract):
        pipe = tc.pipe_of(port)
        pg_id, pgq, _cfg = sw.resolve_queue(port, qid, pipe)
        key = [('pg_id', pg_id, None), ('pg_queue', pgq, None)]
        got = sw.get('tf1.tm.counter.queue', pipe, key) or {}
        snap['queues'][label] = dict(dev_port=port, qid=qid, pg_id=pg_id, pg_queue=pgq,
                                     watermark_cells=got.get('watermark_cells'),
                                     drop_count_packets=got.get('drop_count_packets'))
        # Record the exact pacing applied to the three hold queues: sched_cfg max_rate_enable and the
        # sched_shaping row (unit, max_rate, max_burst_size). Blocker queues read unshaped (max_rate_enable 0).
        cfg = sw.get('tf1.tm.queue.sched_cfg', pipe, key) or {}
        shp = sw.get('tf1.tm.queue.sched_shaping', pipe, key) or {}
        if label in tc.HOLD_LABELS:
            req = requested_pps.get(tc.HOLD_LABELS[label])
        elif label in tc.BLOCK_LABELS:
            req = requested_block_pps.get(tc.BLOCK_LABELS[label])
        else:
            req = None
        snap['shaping'][label] = dict(dev_port=port, qid=qid, max_rate_enable=cfg.get('max_rate_enable'),
                                      unit=shp.get('unit'), requested_pps=(req or None),
                                      achieved_pps=shp.get('max_rate'), max_burst_size=shp.get('max_burst_size'))
    return snap
