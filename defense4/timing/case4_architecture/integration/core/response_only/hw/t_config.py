"""T's runtime state plus the mirror session and the loopback of the build's front-panel looping ports:
loopback, strict-priority ladder, packet generator, mirror, params.

Every port comes from the build (build_ports.read): nothing here names a device port. Patterns: TM ladder and
pktgen from anchor_fix/control/defense4_rrc_bor_unified12_setup.py (hw_config_queues_on_port,
hw_config_pktgen_two_apps); loopback from the same file's hw_config_bor_loopback and from the write that
worked on this switch on 2026-10-11 (evidence/recirc_ports_01/recirc_probe.py: entry_mod of $LOOPBACK_MODE on
the existing $PORT entry). App numbering from T's token_verdict (app_id 1 = OPERATE, any other id = READ).
"""
import build_ports

ALL_PIPES = 0xffff
# Clone = 4 B tag + 16 B tev + the whole original frame. Frames on these links are at most 1514 B (1500 B IP
# MTU), so 1514 + 20 = 1534 B fits under 2048 with margin. The model driver set no $max_pkt_len.
MIRROR_MAX_PKT_LEN = 2048
# set_params default in read_queue_timing.p4; units are ns of ig.global_tstamp on silicon.
T_PARAM_DEFAULTS = dict(da=2000000, readiness=12000000, cap=16000000, gap=800000, op_j=2400000,
                        budget=240000, enabled=1)
# (role of the port, qid, label): strict priority, qid == max_priority, descending within each port.
LADDER = (('held_return', 7, 'ACK_BLOCK'), ('held_return', 6, 'ACK_HOLD'), ('held_return', 5, 'RESP_BLOCK'),
          ('held_return', 4, 'RESP_HOLD'), ('hb_return', 3, 'OP_BLOCK'), ('hb_return', 2, 'OP_HOLD'))
# (name, pktgen app_id, recirc trigger pattern). The app_id is AUTHORITATIVE and must match T's parser:
# read_queue_timing.p4 parse_timer admits only (PKTGEN_PIPE, 0) and (PKTGEN_PIPE, 1) as tokens, and
# token_verdict routes app 1 -> OPERATE blocker, any other admitted app (i.e. app 0) -> READ blocker (ACK on
# even packet_id, response on odd). READ was app 2, which parse_timer sends to default:accept with token_ok=0
# and the apply block then drops via drop_foreign, so no READ blocker was ever seeded (defect B: on silicon
# the READ app generated 544 packets with ACK_BLOCK/RESP_BLOCK watermarks both zero). READ is app 0, the id
# the committed P4 admits; apps 0 and 1 are the only pktgen apps this composite uses in pipe 1, so neither
# overwrites a foreign app. The pattern matches the recirculating clone tag's top 16 bits (0xE100 READ,
# 0xE101 OPERATE), which is independent of the app_id.
PKTGEN_APPS = (('OPERATE', 1, 0xE1010000), ('READ', 0, 0xE1000000))
PKTGEN_MASK = 0xFFFF0000
TOKEN_LEN = 60                                      # buffer after the 6 B header the generator prepends
BUF_OFFSET = 0


def token_buffer():
    """The generator buffer: every seeded blocker frame is [8 B T ladder][this buffer], so buffer[4:6] lands
    at wire offset 12:13. That offset must NOT be 0x0000: on silicon a front-panel MAC loopback reads a zero
    there as an 802.3 length and drops the frame, which silently killed the commit path
    (OUT_ACK_FALLBACK / OUT_RESP_FALLBACK = 10, evidence/combined_silicon_01). Set it to a valid ethertype,
    0x0800. T reads nothing from the buffer, so no other byte matters."""
    buf = bytearray(TOKEN_LEN)
    buf[4:6] = b'\x08\x00'
    return bytes(buf)
LOOPBACK_ON, LOOPBACK_OFF = 'BF_LPBK_MAC_NEAR', 'BF_LPBK_NONE'


def pipe_of(dev_port):
    return dev_port // 128


def queue_plan(ports):
    return [(ports[role], qid, label) for role, qid, label in LADDER]


def params_op(values):
    return dict(kind='default', table='p1.t_Ingress.params', pipe=ALL_PIPES, action='t_Ingress.set_params',
                data=[(k, values[k]) for k in ('da', 'readiness', 'cap', 'gap', 'op_j', 'budget', 'enabled')]
                + ([('pb', values['pb'])] if values.get('pb') is not None else []))


def loopback_ops(ports):
    """One $PORT write per front-panel looping port, before anything else. The only $PORT field ever written."""
    return [dict(kind='loopback', table='$PORT', pipe=ALL_PIPES, label='%s dev %d' % (role, port),
                 key=[('$DEV_PORT', port, None)], data=[('$LOOPBACK_MODE', LOOPBACK_ON)])
            for role, port in sorted(build_ports.loopback_ports(ports).items(), key=lambda kv: kv[1])]


def mirror_op(ports):
    return dict(kind='mirror', table='$mirror.cfg', pipe=ALL_PIPES, key=[('$sid', ports['clone_session'], None)],
                action='$normal', data=[('$direction', 'INGRESS'), ('$ucast_egress_port', ports['pktgen_return']),
                                        ('$ucast_egress_port_valid', True), ('$session_enable', True),
                                        ('$max_pkt_len', MIRROR_MAX_PKT_LEN)])


# The hold queue (not the blocker queue) of each role, by the LADDER label suffix. Shaping these paces the
# held-original recirculation poll (residency_diag_01 finding); the blocker queues 7/5/3 stay unshaped.
# Every ladder queue is shapeable by its LADDER label. The HOLD queues (6/4/2) pace the held-original poll
# (P1 fix); the BLOCKER queues (7/5/3) pace blocker re-circulation so the high-priority reservoir stays
# backlogged across the recirc return gap (P2 occupancy hypothesis) -- a max_rate on qid 7 caps blocker
# dequeues/sec yet keeps the queue non-empty when max_burst_size >= the live blocker count, so the hold queue
# stays starved until the blockers withdraw at the deadline. Unset = baseline (unshaped), so sbo_admission_01
# is unchanged unless the operator passes a rate.
HOLD_LABELS = {'ACK_HOLD': 'ack', 'RESP_HOLD': 'resp', 'OP_HOLD': 'op'}
BLOCK_LABELS = {'ACK_BLOCK': 'ack', 'RESP_BLOCK': 'resp', 'OP_BLOCK': 'op'}
SHAPE_UNIT = 'PPS'           # max_rate is packets/sec; one served lap per 1/max_rate second
HOLD_BURST = 1              # held original: no burst -- one poll per interval
BLOCK_BURST = 64            # blocker reservoir: allow a burst up to the live blocker population so the queue
                           # stays occupied (a burst of 1 would drain it between returns, defeating the hold)


def queue_ops(ports, shape_pps=None, block_shape_pps=None, block_burst=BLOCK_BURST):
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
    for port, qid, label in queue_plan(ports):
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


def pktgen_ops(k, ports):
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
    for name, app_id, pattern in PKTGEN_APPS:
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


def enable_ops(ports):
    """Written last, only when every earlier write read back clean. No action, as the silicon-proven
    set_app_enable (case_a_defense3_fixed_ack_delay_setup.py) writes it."""
    return [dict(kind='pktgen_enable', table='tf1.pktgen.app_cfg', pipe=pipe_of(ports['pktgen_return']), label=name,
                 key=[('app_id', app_id, None)], action=None, data=[('app_enable', True)])
            for name, app_id, _ in PKTGEN_APPS]


def check_params(values):
    """Range check before anything is written; returns error strings."""
    errs = []
    for k in ('da', 'readiness', 'cap', 'gap', 'op_j'):
        if not 0 < values[k] < 1000000000:
            errs.append('T param %s=%d ns outside (0, 1e9)' % (k, values[k]))
    if values['budget'] <= 0:
        errs.append('T param budget=%d must be > 0' % values['budget'])
    if values['enabled'] not in (0, 1):
        errs.append('T param enabled=%d must be 0 or 1' % values['enabled'])
    errs += ['T param %s=%d >= 2^31' % (k, v) for k, v in values.items() if v is not None and v >= 1 << 31]
    # pb (ctl_timing_01 m3 builds only): the piggyback response bound, measured from the lane t0. bfrt name
    # checking refuses a build/params mismatch either way (pb missing on m3, or sent to an older build). It must
    # exceed op_j, because an OPERATE's piggybacked response cannot arrive before its J hold ends (pb <= op_j
    # would release it at once, unbounded), and stay below readiness.
    if values.get('pb') is not None and not values['op_j'] < values['pb'] < values['readiness']:
        errs.append('T param pb=%d must satisfy op_j=%d < pb < readiness=%d'
                    % (values['pb'], values['op_j'], values['readiness']))
    if not values['da'] < values['readiness'] <= values['cap']:
        errs.append('T params must satisfy da < readiness <= cap (da=%d readiness=%d cap=%d)'
                    % (values['da'], values['readiness'], values['cap']))
    return errs
