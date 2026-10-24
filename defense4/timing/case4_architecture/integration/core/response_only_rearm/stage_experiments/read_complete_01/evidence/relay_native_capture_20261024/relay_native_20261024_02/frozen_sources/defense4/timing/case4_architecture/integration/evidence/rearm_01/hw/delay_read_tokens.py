#!/usr/bin/env python3
"""Guarded one-batch READ token delay. No connection or allocator register writes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

TABLE = 'tf1.pktgen.app_cfg'
KEY = [('app_id', 0, None)]
COUNTERS = ('trigger_counter', 'batch_counter', 'pkt_counter')
EXPECTED = {'action_name': 'trigger_recirc_pattern', 'pattern_value': 0xe1000000,
            'pattern_mask': 0xffff0000, 'pipe_local_source_port': 68,
            'batch_count_cfg': 0, 'packets_per_batch_cfg': 3, 'app_enable': True}
CONFIG_FIELDS = ('pattern_value', 'pattern_mask', 'pkt_len', 'pkt_buffer_offset',
                 'pipe_local_source_port', 'increment_source_port', 'batch_count_cfg',
                 'packets_per_batch_cfg', 'ibg', 'ibg_jitter', 'ipg', 'ipg_jitter')


def ipg_operation(before, value):
    # The SDK ignores configuration fields without an action. With an action,
    # it constructs a fresh zero-filled config, so replay every config field.
    missing = [name for name in CONFIG_FIELDS if name not in before]
    if missing:
        raise ValueError('missing READ app configuration fields: ' + ', '.join(missing))
    return {'kind': 'pktgen_app', 'table': TABLE, 'pipe': 1, 'key': KEY,
            'action': EXPECTED['action_name'],
            'data': [(name, value if name == 'ipg' else before[name]) for name in CONFIG_FIELDS]}


def change_ipg(sw, before, value, old_triggers=1):
    check_app(before, restore=before.get('trigger_counter') != 0, old_triggers=old_triggers)
    operation = ipg_operation(before, value)
    enable = dict(kind='pktgen_enable', table=TABLE, pipe=1, key=KEY)
    sw.write(dict(enable, data=[('app_enable', False)]))
    disabled = sw.must_get(TABLE, 1, KEY)
    check_change(dict(before, app_enable=False), disabled, before['ipg'])
    sw.write(operation)
    sw.write(dict(enable, data=[('app_enable', True)]))
    after = sw.must_get(TABLE, 1, KEY)
    check_change(before, after, value)
    return after


def check_app(entry, restore=False, old_triggers=1):
    # old_triggers: c1's READ-lane triggers (1 on candidate61; READ + SELECT = 2 on a control-timed build).
    for name, value in EXPECTED.items():
        if entry.get(name) != value:
            raise ValueError('unexpected READ app field: ' + name)
    if type(old_triggers) is not int or not 1 <= old_triggers <= 2:
        raise ValueError('old READ-lane trigger count must be 1 or 2')
    tokens = EXPECTED['packets_per_batch_cfg'] + 1
    expected = (old_triggers, old_triggers, old_triggers * tokens) if restore else (0, 0, 0)
    if tuple(entry.get(name) for name in COUNTERS) != expected:
        if old_triggers == 1:
            raise ValueError('READ app must be fresh, or exactly one completed four-token batch on restore')
        raise ValueError('READ app must be fresh, or exactly the %d completed old batches on restore' % old_triggers)
    if type(entry.get('ipg')) is not int or not 0 <= entry['ipg'] <= 0xffffffff:
        raise ValueError('missing or malformed prior IPG')


WRITE_ALLOWANCE_S = 0.5     # disable, configure, enable and read back


def check_budget(started, budget_s, now):
    """Refuse the writes when they could not finish inside the caller's budget."""
    if budget_s is not None and now - started + WRITE_ALLOWANCE_S > budget_s:
        raise ValueError('restore budget %.3f s expired before the IPG writes (%.3f s elapsed)'
                         % (budget_s, now - started))


def check_change(before, after, value):
    if after.get('ipg') != value:
        raise ValueError('READ IPG did not read back')
    if {k: v for k, v in before.items() if k != 'ipg'} != {k: v for k, v in after.items() if k != 'ipg'}:
        raise ValueError('READ app fields changed beyond IPG')


def compare_schema(expected, live):
    observed = json.loads(live)
    if observed != expected:
        raise ValueError('live candidate BFRT schema differs from pinned artifact')
    return hashlib.sha256(live).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-out', type=Path, required=True)
    parser.add_argument('--expected-bfrt-sha256', required=True)
    parser.add_argument('--switch-tools', type=Path, required=True)
    parser.add_argument('--record', type=Path, required=True)
    parser.add_argument('--restore', type=Path)
    parser.add_argument('--ipg-ns', type=int, default=3_000_000_000)
    parser.add_argument('--old-triggers', type=int, default=1, choices=(1, 2),
                        help='READ-lane batches c1 left (restore only): 2 when SELECT also triggers the READ app')
    parser.add_argument('--budget-s', type=float,
                        help='restore only: refuse to start the IPG writes once this many seconds have passed since '
                             'this process started (the harness passes the time left before c2 may READ; ssh '
                             'connection time before process start is not counted)')
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    started = time.monotonic()
    if args.budget_s is not None and args.restore is None:
        parser.error('--budget-s applies to the restore only (requires --restore)')
    if not 1_000_000_000 <= args.ipg_ns <= 4_000_000_000:
        parser.error('delay IPG must be 1..4 seconds in nanoseconds')
    schema = args.build_out / 'bfrt.json'
    digest = hashlib.sha256(schema.read_bytes()).hexdigest()
    if digest != args.expected_bfrt_sha256:
        parser.error('candidate BFRT hash mismatch')
    definition = json.loads(schema.read_text())
    definitions = definition['tables']
    epoch = [item for item in definitions if item['name'] == 'p0.r_Egress.epoch' and item.get('table_type') == 'Register']
    if len(epoch) != 1:
        parser.error('candidate E lifetime register is missing; frozen baseline refused')
    prior = json.loads(args.restore.read_text()) if args.restore else None
    if prior and (prior.get('bfrt_sha256') != digest or prior.get('applied') is not True or prior.get('ok') is not True):
        parser.error('restore record does not match applied candidate delay')
    value = prior['before']['ipg'] if prior else args.ipg_ns
    record = {'time': time.time(), 'bfrt_sha256': digest, 'pipe': 1, 'app_id': 0,
              'ipg_ns': value, 'applied': args.apply, 'restore_from': str(args.restore) if args.restore else None,
              'old_triggers': args.old_triggers}
    if not args.apply:
        print(json.dumps(record))
        return 0
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        parser.error('apply requires DEFENSE4_HW_AUTHORIZED=1')
    if args.record.exists():
        parser.error('record already exists')
    sys.path.insert(0, str(args.switch_tools.resolve()))
    from switch import Switch, gc
    sw = Switch('response_only', 216)
    try:
        request = gc.bfruntime_pb2.GetForwardingPipelineConfigRequest()
        request.device_id, request.client_id = 0, 216
        response = sw.iface.stub.GetForwardingPipelineConfig(request)
        live = [config for config in response.config if config.p4_name == 'response_only']
        if len(live) != 1:
            raise ValueError('expected exactly one live candidate program')
        record['live_bfrt_sha256'] = compare_schema(definition, live[0].bfruntime_info)
        live_epoch = sw.table(epoch[0]['name'])
        if live_epoch.info.id_get() != epoch[0]['id']:
            raise ValueError('live candidate E lifetime schema differs')
        before = sw.must_get(TABLE, 1, KEY)
        record['before'] = before
        check_app(before, restore=bool(prior), old_triggers=args.old_triggers)
        if prior and before['ipg'] != prior['ipg_ns']:
            raise ValueError('current IPG differs from the saved delay')
        record['software_read_fallbacks_before'] = sorted(sw.sw_read)
        args.record.write_text(json.dumps(record, indent=2) + '\n')
        check_budget(started, args.budget_s, time.monotonic())
        after = change_ipg(sw, before, value, args.old_triggers)
        record['after'] = after
        record['software_read_fallbacks_after'] = sorted(sw.sw_read)
        check_change(before, after, value)
        record['ok'] = True
        args.record.write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record))
        return 0
    except Exception as error:
        record.update(ok=False, error=str(error))
        args.record.write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps(record))
        return 1
    finally:
        sw.close()


if __name__ == '__main__':
    sys.exit(main())
