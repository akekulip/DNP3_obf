"""Current D-only T configuration and shared physical-port setup operations."""
import re
import build_ports

ALL_PIPES = 0xffff
MIRROR_MAX_PKT_LEN = 2048
RESPONSE_READY_NO_J_CONTRACT = 'response_ready_ack_d_no_j_v3'
RESPONSE_READY_NO_J_KEYS = ('gap', 'budget', 'enabled')
RESPONSE_READY_NO_J_DEFAULTS = dict(gap=5000000, budget=240000, enabled=1)
T_PARAM_DEFAULTS = RESPONSE_READY_NO_J_DEFAULTS
T_TIME_NS = dict(unit_ns=256, grid_ns=512)
LADDER = (('held_return', 7, 'ACK_BLOCK'), ('held_return', 6, 'ACK_HOLD'),
          ('held_return', 5, 'RESP_BLOCK'), ('held_return', 4, 'RESP_HOLD'))
PKTGEN_APPS = (('READ', 0, 0xE1000000),)
PKTGEN_MASK = 0xFFFF0000
TOKEN_LEN, BUF_OFFSET = 60, 0
LOOPBACK_ON, LOOPBACK_OFF = 'BF_LPBK_MAC_NEAR', 'BF_LPBK_NONE'
HOLD_LABELS = {'ACK_HOLD': 'ack', 'RESP_HOLD': 'resp'}
BLOCK_LABELS = {'ACK_BLOCK': 'ack', 'RESP_BLOCK': 'resp'}
SHAPE_UNIT, HOLD_BURST, BLOCK_BURST = 'PPS', 1, 64


def t_units(values_ns, unit_ns=256, grid_ns=512):
    """Convert D conservatively; budget and enabled are not durations."""
    if (unit_ns, grid_ns) != (256, 512):
        raise ValueError('current T requires 256ns units and a 512ns grid')
    out = dict(values_ns)
    if 'gap' in out:
        if type(out['gap']) is not int or out['gap'] < 0:
            raise ValueError('T duration gap must be a nonnegative integer')
        out['gap'] = -(-(out['gap'] + grid_ns) // unit_ns)
        if out['gap'] >= 1 << 31:
            raise ValueError('T duration gap exceeds signed T range')
    return out


def t_time_of_source(text):
    if 'md.now = ig_prsr_md.global_tstamp[39:8] & 32w0xfffffffe;' not in text:
        raise ValueError('unrecognised current T clock')
    return dict(T_TIME_NS)


def timing_contract_of_source(text, timing_contract=None):
    declared = re.findall(r'timing_contract:\s*(\w+)', text)
    contract = timing_contract or (declared[0] if declared else None)
    if contract != RESPONSE_READY_NO_J_CONTRACT or any(x != contract for x in declared):
        raise ValueError('current source requires explicit D-only timing contract')
    actions = re.findall(r'action\s+set_params\s*\(([^)]*)\)', text, re.S)
    keys = tuple(re.findall(r'bit\s*<\s*\d+\s*>\s+(\w+)', actions[0])) if len(actions) == 1 else ()
    if keys != RESPONSE_READY_NO_J_KEYS:
        raise ValueError('current T parameter ABI mismatch')
    t_time_of_source(text)
    return contract


def _contract(value):
    if value not in (None, RESPONSE_READY_NO_J_CONTRACT):
        raise ValueError('unsupported timing contract')


def pktgen_apps(timing_contract=None):
    _contract(timing_contract)
    return PKTGEN_APPS


def queue_plan(ports, timing_contract=None):
    _contract(timing_contract)
    return [(ports[role], qid, label) for role, qid, label in LADDER]


def params_op(values, timing_contract=None):
    _contract(timing_contract)
    errors = check_params(values, timing_contract)
    if errors:
        raise ValueError('; '.join(errors))
    return dict(kind='default', table='p1.t_Ingress.params', pipe=ALL_PIPES,
                action='t_Ingress.set_params', data=[(key, values[key]) for key in RESPONSE_READY_NO_J_KEYS])


def check_params(values, timing_contract=None):
    _contract(timing_contract)
    errors = []
    if set(values) != set(RESPONSE_READY_NO_J_KEYS):
        errors.append('current T parameters require exactly gap, budget, enabled')
    if type(values.get('gap')) is not int or not 0 < values['gap'] < 1000000000:
        errors.append('invalid D duration gap')
    if type(values.get('budget')) is not int or not 0 < values['budget'] < 1 << 31:
        errors.append('invalid blocker budget')
    if type(values.get('enabled')) is not int or values['enabled'] not in (0, 1):
        errors.append('invalid enabled')
    return errors


def token_buffer():
    """The generator buffer: every seeded blocker frame is [8 B T ladder][this buffer], so buffer[4:6] lands
    at wire offset 12:13. That offset must NOT be 0x0000: on silicon a front-panel MAC loopback reads a zero
    there as an 802.3 length and drops the frame, which silently killed the commit path
    (OUT_ACK_FALLBACK / OUT_RESP_FALLBACK = 10, evidence/combined_silicon_01). Set it to a valid ethertype,
    0x0800. T reads nothing from the buffer, so no other byte matters."""
    buf = bytearray(TOKEN_LEN)
    buf[4:6] = b'\x08\x00'
    return bytes(buf)

def pipe_of(dev_port):
    return dev_port // 128

def loopback_ops(ports, timing_contract=None):
    """One $PORT write per front-panel looping port, before anything else. The only $PORT field ever written."""
    return [dict(kind='loopback', table='$PORT', pipe=ALL_PIPES, label='%s dev %d' % (role, port),
                 key=[('$DEV_PORT', port, None)], data=[('$LOOPBACK_MODE', LOOPBACK_ON)])
            for role, port in sorted(build_ports.loopback_ports(ports, timing_contract=timing_contract).items(), key=lambda kv: kv[1])]

def mirror_op(ports):
    return dict(kind='mirror', table='$mirror.cfg', pipe=ALL_PIPES, key=[('$sid', ports['clone_session'], None)],
                action='$normal', data=[('$direction', 'INGRESS'), ('$ucast_egress_port', ports['pktgen_return']),
                                        ('$ucast_egress_port_valid', True), ('$session_enable', True),
                                        ('$max_pkt_len', MIRROR_MAX_PKT_LEN)])

def queue_ops(ports, shape_pps=None, block_shape_pps=None, block_burst=BLOCK_BURST, timing_contract=None):
    """Key (pg_id, pg_queue) is resolved on the switch from the port's own tf1.tm.port.cfg entry; the target
    pipe is the port's pipe.

    shape_pps / block_shape_pps: optional {role -> pps} ('ack'/'resp'/'op') for the HOLD queues and the
    BLOCKER queues respectively. A queue with a positive rate gets max_rate_enable=True in sched_cfg and a
    tf1.tm.queue.sched_shaping row (unit PPS, max_rate=pps, max_burst_size = 1 for a hold queue, block_burst
    for a blocker queue). A queue with no rate is left exactly at the baseline (max_rate_enable False, no
    shaping write)."""
    shape_pps = shape_pps or {}
    block_shape_pps = block_shape_pps or {}
    ops = []
    for port, qid, label in queue_plan(ports, timing_contract=timing_contract):
        if label in HOLD_LABELS:
            rate, burst = int(shape_pps.get(HOLD_LABELS[label], 0) or 0), HOLD_BURST
        elif label in BLOCK_LABELS:
            rate, burst = int(block_shape_pps.get(BLOCK_LABELS[label], 0) or 0), block_burst
        else:
            rate, burst = 0, HOLD_BURST
        ops.append(dict(kind='queue', table='tf1.tm.queue.sched_cfg', pipe=pipe_of(port), dev_port=port, qid=qid,
                        label=label, data=[('min_rate_enable', False), ('max_rate_enable', rate > 0),
                                           ('max_priority', str(qid)), ('scheduling_enable', True)]))
        if rate > 0:
            ops.append(dict(kind='queue_shaping', table='tf1.tm.queue.sched_shaping', pipe=pipe_of(port),
                            dev_port=port, qid=qid, label='%s@%dpps' % (label, rate),
                            data=[('unit', SHAPE_UNIT), ('max_rate', rate), ('max_burst_size', burst)]))
    return ops

def pktgen_ops(k, ports, timing_contract=None):
    if k < 1:
        raise ValueError('k must be >= 1')
    count = 2 * k             # READ tokens split by packet_id parity, so the count must be even
    gen = ports['pktgen_return']
    pipe = pipe_of(gen)
    ops = [dict(kind='pktgen_port', table='tf1.pktgen.port_cfg', pipe=pipe, key=[('dev_port', gen, None)],
                data=[('pktgen_enable', True), ('recirculation_enable', True), ('pattern_matching_enable', True)]),
           dict(kind='pktgen_buffer', table='tf1.pktgen.pkt_buffer', pipe=pipe,
                key=[('pkt_buffer_offset', BUF_OFFSET, None), ('pkt_buffer_size', TOKEN_LEN, None)],
                data=[('buffer', token_buffer())])]
    if timing_contract == RESPONSE_READY_NO_J_CONTRACT:
        # App 1 is owned by the legacy installer. Stop a retained old OPERATE reservoir before app 0 starts.
        ops.append(dict(kind='pktgen_disable', table='tf1.pktgen.app_cfg', pipe=pipe, label='OPERATE stale',
                        key=[('app_id', 1, None)], action=None, data=[('app_enable', False)]))
    for name, app_id, pattern in pktgen_apps(timing_contract):
        ops.append(dict(kind='pktgen_app', table='tf1.pktgen.app_cfg', pipe=pipe, label=name,
                        key=[('app_id', app_id, None)], action='trigger_recirc_pattern',
                        data=[('pattern_value', pattern), ('pattern_mask', PKTGEN_MASK), ('pkt_len', TOKEN_LEN),
                              ('pkt_buffer_offset', BUF_OFFSET),
                              ('pipe_local_source_port', gen % 128),   # 68: required on this switch (Defense 2)
                              ('increment_source_port', False), ('batch_count_cfg', 0),
                              ('packets_per_batch_cfg', count - 1), ('ipg', 0), ('ibg', 0),
                              ('trigger_counter', 0), ('batch_counter', 0), ('pkt_counter', 0),
                              ('app_enable', False)]))
    return ops

def enable_ops(ports, timing_contract=None):
    """Written last, only when every earlier write read back clean. No action, as the silicon-proven
    set_app_enable (case_a_defense3_fixed_ack_delay_setup.py) writes it."""
    return [dict(kind='pktgen_enable', table='tf1.pktgen.app_cfg', pipe=pipe_of(ports['pktgen_return']), label=name,
                 key=[('app_id', app_id, None)], action=None, data=[('app_enable', True)])
            for name, app_id, _ in pktgen_apps(timing_contract)]
