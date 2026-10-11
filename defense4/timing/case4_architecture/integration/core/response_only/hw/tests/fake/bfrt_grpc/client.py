"""In-memory stand-in for bfrt_grpc.client, for driving switch.py, apply() and the teardown offline.

It reproduces the behaviours the real 9.13.1 client was read for, not the switch:
  - a repeated bytes field (pktgen `buffer`) reads back as None from to_dict(), with the stream in
    field_dict[name].val (client.py _parse_data_field / _get_val)
  - errors are two-line "Error(s):\\n\\t* At index 0: CODE, 'text'" messages
  - fixed tables (TM, pktgen, registers) hold an entry for every key; P4 tables and $mirror.cfg start empty
Knobs are module attributes, reset by reset().
"""
T_INIT = dict(cur_epoch_reg=0, quarantine_reg=0xffffffff, gen_alloc_reg=0, t0_reg=0, ack_done_reg=0,
              ack_commit_at_reg=0, ack_commit_gen_reg=0xffffffff, resp_done_reg=0, child_seen0_reg=0xffffffff,
              child_seen1_reg=0xffffffff, child_seen2_reg=0xffffffff, op_gen_alloc_reg=0, op_done_reg=0, op_t0_reg=0)
PARAMS = dict(da=2000000, readiness=12000000, cap=16000000, gap=800000, op_j=2400000, budget=240000, enabled=1,
              action_name='t_Ingress.set_params', is_default_entry=True)


def reset():
    global STATE, LOG, FAIL_ADD, PRIOR_BUFFER, PRIOR_APP_ACTION, OUTCOMES_MOVE, EMPTY_READ
    STATE, LOG = {}, []
    FAIL_ADD = None                     # (table, nth add to that table) whose entry_add raises
    PRIOR_BUFFER = bytes(60)            # what pkt_buffer holds before bring-up
    PRIOR_APP_ACTION = 'trigger_recirc_pattern'
    OUTCOMES_MOVE = False               # T's outcome counters never settle
    EMPTY_READ = None                   # table whose entry_get yields nothing and raises nothing


def error(code, text):
    return Exception("Error(s):\n\t* At index 0: %s, '%s'\n" % (code, text))


NO_HW_READ_PORT_CFG = True   # the real switch's behaviour; a test can switch it off

class KeyTuple:
    def __init__(self, name, value=None, mask=None):
        self.t = (name, value, mask)


class DataTuple:
    def __init__(self, name, val=None, float_val=None, str_val=None, int_arr_val=None, bool_arr_val=None, bool_val=None):
        self.name, self.val = name, val
        self.v = next((x for x in (val, str_val, bool_val, int_arr_val) if x is not None), None)


class Target:
    def __init__(self, device_id=0, pipe_id=0xffff):
        self.pipe = pipe_id


class Data:
    def __init__(self, d):
        self.d = d
        self.field_dict = {k: DataTuple(k, val=bytearray(v) if isinstance(v, (bytes, bytearray)) else None)
                           for k, v in d.items()}

    def to_dict(self):
        return {k: (None if isinstance(v, (bytes, bytearray)) else v) for k, v in self.d.items()}


class Table:
    def __init__(self, name):
        self.name, self.e, self.adds, self.reads = name, {}, 0, 0
        self.default = dict(PARAMS) if name.endswith('.params') else None

    def make_key(self, tuples):
        return tuple(sorted(t.t for t in tuples))

    def make_data(self, items=(), action=None):
        return ({i.name: i.v for i in items}, action)

    def _fixed(self, key):
        kd = {n: v for n, v, _ in key}
        n = self.name
        if n == 'tf1.tm.port.cfg':
            port = kd['dev_port']
            return dict(pg_id=port % 128 // 4, pg_port_nr=port % 4, port_queues_count=8, ingress_qid_map=list(range(32)),
                        egress_qid_queues=[(port % 4) * 8 + i for i in range(8)])
        if n == 'tf1.tm.queue.sched_cfg':
            return dict(min_rate_enable=False, max_rate_enable=True, max_priority='0', scheduling_enable=True)
        if n == 'tf1.tm.counter.queue':
            return dict(watermark_cells=0, drop_count_packets=0)
        if n == 'tf1.pktgen.port_cfg':
            return dict(pktgen_enable=False, recirculation_enable=False, pattern_matching_enable=False)
        if n == 'tf1.pktgen.pkt_buffer':
            return dict(buffer=bytearray(PRIOR_BUFFER))
        if n == 'tf1.pktgen.app_cfg':
            return dict(app_enable=False, pkt_len=0, pkt_buffer_offset=0, pipe_local_source_port=0, increment_source_port=False,
                        batch_count_cfg=0, packets_per_batch_cfg=0, ibg=0, ipg=0, batch_counter=5, pkt_counter=5,
                        trigger_counter=5, action_name=PRIOR_APP_ACTION,
                        **(dict(pattern_value=0, pattern_mask=0) if PRIOR_APP_ACTION == 'trigger_recirc_pattern' else {}))
        if n.endswith('_reg'):
            return {n[3:] + '.f1': [T_INIT[n.split('.')[-1]]]}
        return None

    def entry_get(self, tgt, keys=None, flags=None):
        if keys is None:
            for k, v in self.e.items():
                yield Data(v), k
            return
        if EMPTY_READ == self.name:
            return
        if self.name == 'tf1.pktgen.port_cfg' and (flags or {}).get('from_hw') and NO_HW_READ_PORT_CFG:
            # measured on the switch, SDE 9.13.2, 2026-10-11: this table has no hardware read
            raise error('UNIMPLEMENTED', "Entry not found in table:tf1.pktgen.port_cfg Operation not supported")
        for k in keys:
            if self.name.endswith('.outcomes'):
                self.reads += 1
                yield Data({'t_Ingress.outcomes.f1': [self.reads if OUTCOMES_MOVE else 3]}), k
                continue
            if k not in self.e:
                fixed = self._fixed(k)
                if fixed is None:
                    raise error('NOT_FOUND', 'Object not found')
                self.e[k] = fixed
            got = self.e[k]
            if self.name.endswith('n_Ingress.data_connection'):   # measured on the switch: these read 0
                got = dict(got, index=0, code=0, repeat=0, on=0, off=0)
            yield Data(got), k

    def entry_add(self, tgt, keys, datas):
        self.adds += 1
        LOG.append(('add', self.name, keys[0]))
        if FAIL_ADD == (self.name, self.adds):
            raise error('INTERNAL', 'boom in the driver')
        if keys[0] in self.e:
            raise error('ALREADY_EXISTS', 'entry exists')
        self.e[keys[0]] = dict(datas[0][0], action_name=datas[0][1], is_default_entry=False)

    def entry_mod(self, tgt, keys, datas):
        LOG.append(('mod', self.name, keys[0], datas[0]))
        list(self.entry_get(tgt, keys))
        self.e[keys[0]].update({k: v for k, v in datas[0][0].items() if v is not None})
        if datas[0][1]:
            self.e[keys[0]]['action_name'] = datas[0][1]

    def entry_del(self, tgt, keys):
        LOG.append(('del', self.name, keys[0]))
        if keys[0] not in self.e:
            raise error('NOT_FOUND', 'Object not found')
        del self.e[keys[0]]

    def default_entry_get(self, tgt, flags=None):
        got = dict(self.default)
        if 'cap' in got:      # measured on the switch: the P4 never assigns cap, so it always reads 0
            got['cap'] = 0
        yield Data(got), None

    def default_entry_set(self, tgt, data):
        LOG.append(('default_set', self.name, data))
        self.default = dict(data[0], action_name=data[1], is_default_entry=True)

    def default_entry_reset(self, tgt):
        LOG.append(('default_reset', self.name))
        self.default = dict(PARAMS)


class Info:
    def table_get(self, name):
        return STATE.setdefault(name, Table(name))


class ClientInterface:
    def __init__(self, *args, **kwargs):
        pass

    def bind_pipeline_config(self, program):
        pass

    def bfrt_info_get(self, program):
        return Info()

    def tear_down_stream(self):
        LOG.append(('close',))


reset()
