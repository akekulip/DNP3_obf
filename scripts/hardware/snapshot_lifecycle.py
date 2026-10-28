#!/usr/bin/env python3
"""Read complete register fields for incarnation-isolation evidence, including paired registers."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

OLD_REJECTION_INDICES = (6, 14)  # OUT_TOKEN_STALE, OUT_OLD_EPOCH_DROP


def rejection_layout(definitions):
    tables = {item['name']: item for item in definitions}
    size = tables['p1.t_Ingress.outcomes']['size']
    if size == 25 and 'p1.t_Ingress.quarantine_reg' not in tables:
        return 'split_raw_timer_23_24', (6, 14, 23, 24)
    if size == 16:
        return 'aggregate_6', OLD_REJECTION_INDICES
    raise ValueError('unsupported timer rejection counter layout')


def allocated_registers(build_out):
    """BFRT may retain optimized-away declarations; context proves allocation."""
    names, hashes = set(), {}
    for pipe in ('p0', 'p1'):
        path = build_out / pipe / 'context.json'
        data = json.loads(path.read_text())
        hashes[pipe] = hashlib.sha256(path.read_bytes()).hexdigest()
        for table in data['tables']:
            if table.get('table_type') == 'stateful' and table.get('stage_tables'):
                names.add(pipe + '.' + table['name'])
    return names, hashes


def validate_register_fields(definition, values):
    required = [item['singleton']['name'] for item in definition['data'] if 'singleton' in item]
    if not required:
        raise ValueError('register schema has no data fields')
    for name in required:
        value = values.get(name)
        lanes = value if isinstance(value, list) else [value]
        if not lanes or any(not isinstance(lane, int) or isinstance(lane, bool) for lane in lanes):
            raise ValueError('missing or unreadable register field: ' + name)
    return values


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--build-out', required=True, type=Path)
    ap.add_argument('--switch-tools', required=True, type=Path)
    ap.add_argument('--program', default='response_only')
    ap.add_argument('--client-id', type=int, default=215)
    ap.add_argument('--slot', type=int, default=0)
    ap.add_argument('--read-app', action='store_true', help='also read pipe1 READ app0 counters without binding')
    ap.add_argument('--output', required=True, type=Path)
    args = ap.parse_args()
    schema = args.build_out / 'bfrt.json'
    definitions = json.loads(schema.read_text())['tables']
    layout, rejection_indices = rejection_layout(definitions) if args.read_app else (None, ())
    allocated, context_hashes = allocated_registers(args.build_out)
    sys.path.insert(0, str(args.switch_tools.resolve()))
    from switch import Switch, gc

    class ReadOnlySwitch(Switch):
        def __init__(self):
            # Independent BFRT readers do not subscribe or take the program's
            # exclusive binding from the installer/counter collector.
            self.iface = gc.ClientInterface('localhost:50052', client_id=args.client_id,
                                            device_id=0, perform_subscribe=False)
            self.bi = self.iface.bfrt_info_get(args.program)
            if self.bi is None:
                raise ValueError('requested program is not installed')
            self.sw_read = set()

        def close(self):
            self.iface.channel.close()

        def get(self, table, pipe, key, priority=None):
            entry = self.table(table)
            values = list(entry.entry_get(self.target(pipe), [self.key(entry, key, priority)],
                                          {'from_hw': True}, p4_name=args.program))
            if len(values) != 1:
                raise ValueError('expected exactly one hardware register entry')
            return self.as_dict(values[0][0])
    result = {'time': time.time(), 'program': args.program,
              'bfrt_sha256': hashlib.sha256(schema.read_bytes()).hexdigest(),
              'context_sha256': context_hashes, 'optimized_away': [],
              'slot': args.slot, 'registers': {}, 'errors': {}}
    result['T_epoch_sealed_encoding'] = not any(
        table['name'] == 'p1.t_Ingress.quarantine_reg' for table in definitions)
    if args.read_app:
        result['timer_rejection_layout'] = layout
    result['expected_registers'] = sorted(table['name'] for table in definitions
        if table.get('table_type') == 'Register' and table['name'] in allocated and
        table['name'].startswith(('p0.n_Ingress.', 'p0.r_Egress.', 'p1.t_Ingress.')))
    sw = None
    try:
        try:
            sw = ReadOnlySwitch()
        except Exception as error:
            result.update(valid=False, software_read_fallbacks=[])
            result['errors']['binding'] = str(error)
            args.output.write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps({'valid': False, 'errors': result['errors']}))
            return 1
        if args.read_app:
            try:
                result['read_app_before'] = sw.must_get('tf1.pktgen.app_cfg', 1, [('app_id', 0, None)])
                result['operate_app_before'] = sw.must_get('tf1.pktgen.app_cfg', 1, [('app_id', 1, None)])
                result['old_reject_before'] = {str(index): sw.must_get('p1.t_Ingress.outcomes', 1,
                    [('$REGISTER_INDEX', index, None)]) for index in rejection_indices}
            except Exception as error:
                result['errors']['read_app_before'] = str(error)
        for table in definitions:
            name = table['name']
            if table.get('table_type') != 'Register':
                continue
            if not name.startswith(('p0.n_Ingress.', 'p0.r_Egress.', 'p1.t_Ingress.')):
                continue
            if name not in allocated:
                result['optimized_away'].append(name)
                continue
            pipe = 1 if name.startswith('p1.') else 0
            index = args.slot if name.startswith('p0.r_Egress.') else 0
            try:
                # Read complete structured fields; Switch.register only flattens scalar .f1 fields.
                values = sw.must_get(name, pipe, [('$REGISTER_INDEX', index, None)])
                result['registers'][name] = validate_register_fields(table, values)
            except Exception as error:
                result['errors'][name] = str(error)
        if args.read_app:
            try:
                result['read_app_after'] = sw.must_get('tf1.pktgen.app_cfg', 1, [('app_id', 0, None)])
                result['operate_app_after'] = sw.must_get('tf1.pktgen.app_cfg', 1, [('app_id', 1, None)])
                result['old_reject_after'] = {str(index): sw.must_get('p1.t_Ingress.outcomes', 1,
                    [('$REGISTER_INDEX', index, None)]) for index in rejection_indices}
            except Exception as error:
                result['errors']['read_app_after'] = str(error)
        result['completed_time'] = time.time()
        if set(result['registers']) != set(result['expected_registers']):
            result['errors']['coverage'] = 'hardware read does not cover every allocated lifecycle register'
        result['software_read_fallbacks'] = sorted(sw.sw_read)
        result['valid'] = bool(result['registers']) and not result['errors'] and not sw.sw_read
        args.output.write_text(json.dumps(result, indent=2, default=str) + '\n')
        print(json.dumps({'valid': result['valid'], 'registers': len(result['registers']),
                          'errors': result['errors']}))
        return 0 if result['valid'] else 1
    finally:
        if sw is not None:
            sw.close()


if __name__ == '__main__':
    raise SystemExit(main())
