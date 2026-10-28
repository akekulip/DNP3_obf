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


def registers_for(timing_contract=None):
    if timing_contract not in (None, 'response_ready_ack_d_no_j_v3'):
        raise HeadroomError('current generation budget requires the D-only contract')
    return dict(REGISTERS)


def current_generations(snapshot, timing_contract=None):
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
    contract = timing_contract if timing_contract is not None else snapshot.get('timing_contract')
    return {role: _one_int(registers, table) for role, table in registers_for(contract).items()}


LIFECYCLE_PER_CONNECTION = 2      # OPEN and the live RESET each bump both allocators
MARGIN = 16


def _count(name, value):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise HeadroomError('generation budget %s must be a non-negative integer, got %r' % (name, value))
    return value


def workload_reserve(reads, sbo, connections, control_timed, timed=True, cancelled_selects=0,
                     margin=MARGIN, timing_contract=None):
    """Common allocator: two lifecycle changes per connection and one admitted READ/SELECT/OPERATE."""
    registers_for(timing_contract)
    if not control_timed:
        raise HeadroomError('common generation budget requires control-timed READ/SELECT/OPERATE')
    reads, sbo = _count('reads', reads), _count('sbo', sbo)
    connections = _count('connections', connections)
    cancelled = _count('cancelled_selects', cancelled_selects)
    if connections < 1:
        raise HeadroomError('generation budget needs at least one connection')
    lane = reads + 2*sbo + cancelled if timed else 0
    reserve = {'read': lane*connections + LIFECYCLE_PER_CONNECTION*connections + margin}
    explanation = dict(reads=reads,sbo_cycles=sbo,cancelled_selects=cancelled,
                       connections=connections,control_timed=True,timed=bool(timed),
                       open_close_per_connection=LIFECYCLE_PER_CONNECTION,margin=margin,
                       read_lane_per_connection=lane,
                       source='T gen_access and N first_event: common READ/SELECT/OPERATE allocator')
    return reserve, explanation


def _reserves(reserve, timing_contract=None):
    registers = registers_for(timing_contract)
    if isinstance(reserve, dict):
        if set(reserve) != set(registers):
            raise HeadroomError('generation headroom reserve needs exactly %s' % sorted(registers))
        out = dict(reserve)
    else:
        out = {role: reserve for role in registers}
    for role, value in out.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise HeadroomError('generation headroom reserve must be a positive integer (%s)' % role)
    return out


def evaluate_headroom(snapshot, reserve, timing_contract=None):
    contract = timing_contract if timing_contract is not None else snapshot.get("timing_contract") if isinstance(snapshot, dict) else None
    reserves = _reserves(reserve, contract)
    current = current_generations(snapshot, contract)
    evidence = {
        'ok': True,
        'time': time.time(),
        'max_generation': MAX_GENERATION,
        'reserve': reserve,
        'reserves': reserves,
        'current': current,
        'registers': registers_for(contract),
        'remaining_before_reserve': {},
        'remaining_after_reserve': {},
    }
    failures = []
    for role, value in current.items():
        evidence['remaining_before_reserve'][role] = MAX_GENERATION - value
        evidence['remaining_after_reserve'][role] = MAX_GENERATION - value - reserves[role]
        if value + reserves[role] > MAX_GENERATION:
            failures.append('%s generation headroom exhausted: current %d + reserve %d > %d' %
                            (role, value, reserves[role], MAX_GENERATION))
    if failures:
        evidence['ok'] = False
        evidence['failures'] = failures
    return evidence


def assess_headroom(snapshot, reserve, timing_contract=None):
    evidence = evaluate_headroom(snapshot, reserve, timing_contract)
    if evidence.get('failures'):
        raise HeadroomError('; '.join(evidence['failures']))
    return evidence


def _register_definitions(build_out, timing_contract=None):
    schema = build_out / 'bfrt.json'
    data = json.loads(schema.read_text())
    tables = {item.get('name'): item for item in data.get('tables', [])}
    missing = [table for table in registers_for(timing_contract).values()
               if tables.get(table, {}).get('table_type') != 'Register']
    if missing:
        raise HeadroomError('candidate allocator register(s) missing from BFRT schema: ' + ', '.join(missing))
    return schema, tables


def _build_timing_contract(build_out):
    """Only an explicit source-bound no-J profile can remove the second allocator requirement."""
    out = Path(build_out)
    directory = out / 'profile' if (out / 'profile').is_dir() else out.parent.parent
    declared_no_j = False
    for name in ('response_only.inputs.json', 'supported_profile.json'):
        path = directory / name
        if not path.is_file():
            continue
        try:
            value = json.loads(path.read_text())
            supported = value.get('supported_profile') if name.endswith('.inputs.json') else value
            declared_no_j |= isinstance(supported, dict) and \
                supported.get('timing_contract') == 'response_ready_ack_d_no_j_v3'
        except (ValueError, AttributeError):
            # Historical headroom reads validate the two-register schema only. Malformed or unknown metadata
            # never grants the no-J exception; a missing second allocator still fails the default schema check.
            continue
    if not declared_no_j:
        return None
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from sealed_profile import describe
    contract = describe(out).get('timing_contract')
    if contract != 'response_ready_ack_d_no_j_v3':
        raise HeadroomError('no-J headroom requires its source-bound compiled timing contract')
    return contract


def read_hardware(build_out, switch_tools, program='response_only', client_id=217):
    timing_contract = _build_timing_contract(build_out)
    schema, _tables = _register_definitions(build_out, timing_contract)
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
        for table in registers_for(timing_contract).values():
            registers[table] = sw.must_get(table, 1, [('$REGISTER_INDEX', 0, None)])
        snapshot = {
            'valid': True,
            'time': time.time(),
            'program': program,
            'bfrt_sha256': hashlib.sha256(schema.read_bytes()).hexdigest(),
            'registers': registers,
            'errors': {},
            'software_read_fallbacks': [],
        }
        if timing_contract is not None:
            snapshot['timing_contract'] = timing_contract
        return snapshot
    finally:
        sw.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-out', required=True, type=Path)
    parser.add_argument('--switch-tools', required=True, type=Path)
    parser.add_argument('--reserve', type=int, help='reserve for the common READ/SELECT/OPERATE allocator')
    parser.add_argument('--reserve-read', type=int)

    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--program', default='response_only')
    parser.add_argument('--client-id', type=int, default=217)
    args = parser.parse_args(argv)
    _build_timing_contract(args.build_out)
    if (args.reserve is None) == (args.reserve_read is None):
        parser.error('give --reserve or --reserve-read')
    reserve = args.reserve if args.reserve is not None else {'read': args.reserve_read}
    record = {'ok': False, 'reserve': reserve, 'time': time.time()}
    try:
        require_authorized()
        snapshot = read_hardware(args.build_out, args.switch_tools, args.program, args.client_id)
        record.update(snapshot=snapshot)
        record.update(evaluate_headroom(snapshot, reserve))
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
