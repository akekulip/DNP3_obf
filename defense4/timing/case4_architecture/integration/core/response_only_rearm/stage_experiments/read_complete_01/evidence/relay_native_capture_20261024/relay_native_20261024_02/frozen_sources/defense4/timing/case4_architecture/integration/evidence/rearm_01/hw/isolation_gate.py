"""Verify complete hardware bank isolation during an established pre-READ pause."""
import argparse
import copy
import json
from pathlib import Path

from candidate_series import _field_int, _pick


def compare_quiet_generation(before, after, connection_generation, server_isn):
    failures, allowed, observed = [], [], {}
    for label, snapshot in (('before', before), ('after', after)):
        if snapshot.get('valid') is not True or snapshot.get('errors') or snapshot.get('software_read_fallbacks'):
            failures.append(label + ': incomplete hardware snapshot')
    for field in ('bfrt_sha256', 'context_sha256', 'optimized_away'):
        if not before.get(field) and field != 'optimized_away' or before.get(field) != after.get(field):
            failures.append('snapshot artifact mismatch: ' + field)
    left, right = before.get('registers'), after.get('registers')
    if not isinstance(left, dict) or not left or not isinstance(right, dict) or set(left) != set(right):
        return dict(ok=False, failures=failures + ['allocated register set missing or changed'],
                    allowed_changes=allowed, observed=observed)
    expected = before.get('expected_registers')
    if not isinstance(expected, list) or not expected or expected != after.get('expected_registers') or \
            set(expected) != set(left):
        failures.append('hardware snapshots do not cover the pinned allocated register set')
    work_name = None
    for label, registers in (('before', left), ('after', right)):
        try:
            names = dict(
                N=_pick(registers, 'N epoch', lambda n: n == 'p0.n_Ingress.epoch'),
                E=_pick(registers, 'E epoch', lambda n: n == 'p0.r_Egress.epoch'),
                T=_pick(registers, 'T epoch', lambda n: n == 'p1.t_Ingress.cur_epoch_reg'),
                owner=_pick(registers, 'N owner', lambda n: n == 'p0.n_Ingress.owner'),
                work=_pick(registers, 'N WorkRecord', lambda n: n.startswith('p0.n_Ingress.') and 'work' in n),
                front=_pick(registers, 'E front', lambda n: n == 'p0.r_Egress.front'),
                acct=_pick(registers, 'E accounting', lambda n: n.startswith('p0.r_Egress.') and 'acct' in n))
            values = {key: _field_int(registers, names[key]) for key in ('N', 'E', 'T')}
            # ctl_timing m5: N's retry incarnation register must name the established connection's epoch
            if 'p0.n_Ingress.retry_epoch' in registers and \
                    _field_int(registers, 'p0.n_Ingress.retry_epoch') != values['N']:
                failures.append(label + ': N retry_epoch is not the current epoch')
            e_latched = bool(values['E'] & 0x80000000)
            # E's high bit is the atomic FIRST latch; only the lower 31 bits identify the lifetime.
            values['E'] &= 0x7fffffff
            phase = _field_int(registers, names['work'], r'phase')
            generation = _field_int(registers, names['work'], r'generation|gen')
            owner = _field_int(registers, names['owner'])
            mapper = dict(front=_field_int(registers, names['front']),
                          lo=_field_int(registers, names['acct'], r'(^|[.])lo$'),
                          hi=_field_int(registers, names['acct'], r'(^|[.])hi$'))
            observed[label] = dict(epochs=values, work_phase=phase, work_generation=generation,
                                   owner=owner, mapper=mapper)
            work_name = names['work']
            if not 0 < values['N'] <= 0x7ffffffe or len(set(values.values())) != 1 or not e_latched:
                failures.append(label + ': N/E/T must share a bounded current epoch with FIRST latched')
            if owner != (5 << 16) | connection_generation:
                failures.append(label + ': owner is not the established current connection')
            if phase != 4 or not 0 < generation <= 0x7ffffffe:
                failures.append(label + ': WorkRecord is not genuinely free with bounded generation')
            if values['N'] > generation:
                failures.append(label + ': current epoch exceeds the packet Work allocation')
            frontier = (server_isn + 1) & 0xffffffff
            if mapper != {'front': frontier, 'lo': frontier, 'hi': 0}:
                failures.append(label + ': E does not have fresh zero-growth mapping state')
        except (KeyError, ValueError, TypeError) as error:
            failures.append(label + ': ' + str(error))
    diagnostics = {'p0.n_Ingress.counter', 'p0.n_Ingress.count_first',
                   'p0.n_Ingress.count_busy', 'p0.n_Ingress.count_term'}
    for name in sorted(left):
        if left[name] == right[name]:
            continue
        if name in diagnostics:
            old, new = _field_int(left, name), _field_int(right, name)
            if new >= old:
                allowed.append(dict(register=name, before=old, after=new, reason='N diagnostic packet counter'))
                continue
        if name == work_name and all(observed.get(side, {}).get('work_phase') == 4 for side in ('before', 'after')):
            old_record, new_record = copy.deepcopy(left[name]), copy.deepcopy(right[name])
            keys = [key for key in old_record if key.endswith('.generation') or key == 'generation']
            if len(keys) == 1:
                key = keys[0]
                old, new = old_record.pop(key), new_record.pop(key, None)
                if old_record == new_record and observed['after']['work_generation'] >= observed['before']['work_generation']:
                    allowed.append(dict(register=name, before=old, after=new, reason='genuine free packet allocator'))
                    continue
        failures.append('authoritative register changed: ' + name)
    return dict(ok=not failures, failures=failures, allowed_changes=allowed, observed=observed)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('before', type=Path); parser.add_argument('after', type=Path)
    parser.add_argument('--connection-generation', type=int, required=True)
    parser.add_argument('--server-isn', type=int, required=True)
    parser.add_argument('--json', type=Path)
    args = parser.parse_args()
    result = compare_quiet_generation(json.loads(args.before.read_text()), json.loads(args.after.read_text()),
                                      args.connection_generation, args.server_isn)
    output = json.dumps(result, indent=2) + '\n'
    if args.json:
        args.json.write_text(output)
    print(output, end='')
    return 0 if result['ok'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
