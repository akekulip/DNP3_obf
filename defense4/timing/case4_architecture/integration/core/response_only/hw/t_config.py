"""T's runtime state on pipe 1, plus the mirror session: params, mirror, strict-priority ladder, packet generator.

Patterns: TM ladder and pktgen from anchor_fix/control/defense4_rrc_bor_unified12_setup.py
(hw_config_queues_on_port, hw_config_pktgen_two_apps); app numbering from T's token_verdict
(app_id 1 = OPERATE, any other id = READ). Ports from read/ports.p4: 196 PKTGEN_RETURN, 198 HB_RETURN,
199 HELD_RETURN, all pipe 1.
"""
T_PIPE = 1
ALL_PIPES = 0xffff
PKTGEN_RETURN, HB_RETURN, HELD_RETURN = 196, 198, 199
CLONE_SESSION_ID = 7
# Clone = 4 B tag + 16 B tev + the whole original frame. Frames on these links are at most 1514 B (1500 B IP
# MTU), so 1514 + 20 = 1534 B fits under 2048 with margin. The model driver set no $max_pkt_len.
MIRROR_MAX_PKT_LEN = 2048
# set_params default in read_queue_timing.p4; units are ns of ig.global_tstamp on silicon.
T_PARAM_DEFAULTS = dict(da=2000000, readiness=12000000, cap=16000000, gap=800000, op_j=2400000,
                        budget=240000, enabled=1)
QUEUE_PLAN = ((HELD_RETURN, 7, 'ACK_BLOCK'), (HELD_RETURN, 6, 'ACK_HOLD'),
              (HELD_RETURN, 5, 'RESP_BLOCK'), (HELD_RETURN, 4, 'RESP_HOLD'),
              (HB_RETURN, 3, 'OP_BLOCK'), (HB_RETURN, 2, 'OP_HOLD'))
PKTGEN_APPS = (('OPERATE', 1, 0xE1010000), ('READ', 2, 0xE1000000))
PKTGEN_MASK = 0xFFFF0000
PIPE_LOCAL_SOURCE_PORT = PKTGEN_RETURN & 0x7F      # 68: required on this switch (Defense 2, SDE 9.13.2)
TOKEN_LEN = 60                                      # buffer after the 6 B header the generator prepends
BUF_OFFSET = 0


def params_op(values):
    return dict(kind='default', table='p1.t_Ingress.params', pipe=ALL_PIPES, action='t_Ingress.set_params',
                data=[(k, values[k]) for k in ('da', 'readiness', 'cap', 'gap', 'op_j', 'budget', 'enabled')])


def mirror_op():
    return dict(kind='mirror', table='$mirror.cfg', pipe=ALL_PIPES, key=[('$sid', CLONE_SESSION_ID, None)],
                action='$normal', data=[('$direction', 'INGRESS'), ('$ucast_egress_port', PKTGEN_RETURN),
                                        ('$ucast_egress_port_valid', True), ('$session_enable', True),
                                        ('$max_pkt_len', MIRROR_MAX_PKT_LEN)])


def queue_ops():
    """Key (pg_id, pg_queue = pg_port_nr * 8 + qid) is resolved on the switch from tf1.tm.port.cfg."""
    return [dict(kind='queue', table='tf1.tm.queue.sched_cfg', pipe=T_PIPE, dev_port=port, qid=qid, label=label,
                 data=[('min_rate_enable', False), ('max_rate_enable', False),
                       ('max_priority', str(qid)), ('scheduling_enable', True)])
            for port, qid, label in QUEUE_PLAN]


def pktgen_ops(k):
    if k < 1:
        raise ValueError('k must be >= 1')
    count = 2 * k             # READ tokens split by packet_id parity, so the count must be even
    ops = [dict(kind='pktgen_port', table='tf1.pktgen.port_cfg', pipe=T_PIPE, key=[('dev_port', PKTGEN_RETURN, None)],
                data=[('pktgen_enable', True), ('recirculation_enable', True), ('pattern_matching_enable', True)]),
           dict(kind='pktgen_buffer', table='tf1.pktgen.pkt_buffer', pipe=T_PIPE,
                key=[('pkt_buffer_offset', BUF_OFFSET, None), ('pkt_buffer_size', TOKEN_LEN, None)],
                data=[('buffer', bytes(TOKEN_LEN))])]
    for name, app_id, pattern in PKTGEN_APPS:
        ops.append(dict(kind='pktgen_app', table='tf1.pktgen.app_cfg', pipe=T_PIPE, label=name,
                        key=[('app_id', app_id, None)], action='trigger_recirc_pattern',
                        data=[('pattern_value', pattern), ('pattern_mask', PKTGEN_MASK), ('pkt_len', TOKEN_LEN),
                              ('pkt_buffer_offset', BUF_OFFSET),
                              ('pipe_local_source_port', PIPE_LOCAL_SOURCE_PORT),
                              ('increment_source_port', False), ('batch_count_cfg', 0),
                              ('packets_per_batch_cfg', count - 1), ('ipg', 0), ('ibg', 0),
                              ('trigger_counter', 0), ('batch_counter', 0), ('pkt_counter', 0),
                              ('app_enable', False)]))
    return ops


def enable_ops():
    """Written last, only when every earlier write read back clean. No action, as the silicon-proven
    set_app_enable (case_a_defense3_fixed_ack_delay_setup.py) writes it."""
    return [dict(kind='pktgen_enable', table='tf1.pktgen.app_cfg', pipe=T_PIPE, label=name,
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
    errs += ['T param %s=%d >= 2^31' % (k, v) for k, v in values.items() if v >= 1 << 31]
    if not values['da'] < values['readiness'] <= values['cap']:
        errs.append('T params must satisfy da < readiness <= cap (da=%d readiness=%d cap=%d)'
                    % (values['da'], values['readiness'], values['cap']))
    return errs
