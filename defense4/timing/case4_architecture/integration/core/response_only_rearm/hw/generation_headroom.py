#!/usr/bin/env python3
"""Read and check candidate T generation allocator headroom from hardware."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time

MAX_GENERATION = 0xfffe
REGISTERS = {
    'read': 'p1.t_Ingress.gen_alloc_reg',
    'operate': 'p1.t_Ingress.op_gen_alloc_reg',
}


class HeadroomError(ValueError):
    pass


def require_authorized():
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        raise HeadroomError('generation headroom hardware read requires DEFENSE4_HW_AUTHORIZED=1')


def _ints(value):
    if isinstance(value, bool):
        return []
    if isinstance(value, int):
        return [value]
    if isinstance(value, list):
        out = []
        for item in value:
            out.extend(_ints(item))
        return out
    if isinstance(value, dict):
        out = []
        for item in value.values():
            out.extend(_ints(item))
        return out
    return []


def _one_int(registers, table):
    if table not in registers:
        raise HeadroomError('missing required hardware register: ' + table)
    values = _ints(registers[table])
    if len(values) != 1:
        raise HeadroomError('%s has no readable integer allocator value' % table)
    value = values[0]
    if not 0 <= value <= MAX_GENERATION:
        raise HeadroomError('%s allocator value %r is outside usable 16-bit range 0..%d' %
                            (table, value, MAX_GENERATION))
    return value


def current_generations(snapshot):
    if not isinstance(snapshot, dict):
        raise HeadroomError('generation headroom snapshot is malformed')
    if snapshot.get('valid') is not True:
        raise HeadroomError('generation headroom snapshot is not a complete hardware read')
    if snapshot.get('errors'):
        raise HeadroomError('generation headroom hardware read reported errors: %s' % snapshot.get('errors'))
    if snapshot.get('software_read_fallbacks'):
        raise HeadroomError('generation headroom refuses software fallback reads: %s' %
                            snapshot.get('software_read_fallbacks'))
    registers = snapshot.get('registers')
    if not isinstance(registers, dict):
        raise HeadroomError('generation headroom snapshot is missing registers')
    return {role: _one_int(registers, table) for role, table in REGISTERS.items()}


def evaluate_headroom(snapshot, reserve):
    if not isinstance(reserve, int) or isinstance(reserve, bool) or reserve < 1:
        raise HeadroomError('generation headroom reserve must be a positive integer')
    current = current_generations(snapshot)
    evidence = {
        'ok': True,
        'time': time.time(),
        'max_generation': MAX_GENERATION,
        'reserve': reserve,
        'current': current,
        'registers': dict(REGISTERS),
        'remaining_before_reserve': {},
        'remaining_after_reserve': {},
    }
    failures = []
    for role, value in current.items():
        evidence['remaining_before_reserve'][role] = MAX_GENERATION - value
        evidence['remaining_after_reserve'][role] = MAX_GENERATION - value - reserve
        if value + reserve > MAX_GENERATION:
            failures.append('%s generation headroom exhausted: current %d + reserve %d > %d' %
                            (role, value, reserve, MAX_GENERATION))
    if failures:
        evidence['ok'] = False
        evidence['failures'] = failures
    return evidence


def assess_headroom(snapshot, reserve):
    evidence = evaluate_headroom(snapshot, reserve)
    if evidence.get('failures'):
        raise HeadroomError('; '.join(evidence['failures']))
    return evidence


def _register_definitions(build_out):
    schema = build_out / 'bfrt.json'
    data = json.loads(schema.read_text())
    tables = {item.get('name'): item for item in data.get('tables', [])}
    missing = [table for table in REGISTERS.values()
               if tables.get(table, {}).get('table_type') != 'Register']
    if missing:
        raise HeadroomError('candidate allocator register(s) missing from BFRT schema: ' + ', '.join(missing))
    return schema, tables


def read_hardware(build_out, switch_tools, program='response_only', client_id=217):
    schema, _tables = _register_definitions(build_out)
    sys.path.insert(0, str(switch_tools.resolve()))
    from switch import Switch

    class HardwareOnlySwitch(Switch):
        def get(self, table, pipe, key, priority=None):
            entry = self.table(table)
            values = list(entry.entry_get(self.target(pipe), [self.key(entry, key, priority)],
                                          {'from_hw': True}, p4_name=program))
            if len(values) != 1:
                raise HeadroomError('expected exactly one hardware entry for ' + table)
            return self.as_dict(values[0][0])

    sw = HardwareOnlySwitch(program, client_id)
    try:
        registers = {}
        for table in REGISTERS.values():
            registers[table] = sw.must_get(table, 1, [('$REGISTER_INDEX', 0, None)])
        return {
            'valid': True,
            'time': time.time(),
            'program': program,
            'bfrt_sha256': hashlib.sha256(schema.read_bytes()).hexdigest(),
            'registers': registers,
            'errors': {},
            'software_read_fallbacks': [],
        }
    finally:
        sw.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-out', required=True, type=Path)
    parser.add_argument('--switch-tools', required=True, type=Path)
    parser.add_argument('--reserve', required=True, type=int)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--program', default='response_only')
    parser.add_argument('--client-id', type=int, default=217)
    args = parser.parse_args(argv)
    record = {'ok': False, 'reserve': args.reserve, 'time': time.time()}
    try:
        require_authorized()
        snapshot = read_hardware(args.build_out, args.switch_tools, args.program, args.client_id)
        record.update(snapshot=snapshot)
        record.update(evaluate_headroom(snapshot, args.reserve))
        if record.get('ok') is not True:
            raise HeadroomError('; '.join(record.get('failures') or ['generation headroom refused']))
    except Exception as error:
        record['error'] = str(error)
        if isinstance(error, HeadroomError):
            record.setdefault('failures', [str(error)])
        args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
        print(json.dumps(record, sort_keys=True))
        return 1
    args.output.write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps(record, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
