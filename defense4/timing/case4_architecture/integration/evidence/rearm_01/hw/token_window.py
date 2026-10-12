"""Evidence gates for a real old READ batch drained inside the new connection's pause."""
from snapshot_lifecycle import OLD_REJECTION_INDICES


def rejection_delta(before, after):
    def total(snapshot, suffix):
        entries = snapshot['old_reject_' + suffix]
        result = 0
        for index in OLD_REJECTION_INDICES:
            fields = entries[str(index)]
            values = [item for name, value in fields.items() if name not in ('action_name', 'is_default_entry')
                      for item in (value if isinstance(value, list) else [value])]
            if not values or any(type(value) is not int for value in values):
                raise ValueError('missing or malformed rejection counter ' + str(index))
            result += sum(values)
        return result
    return total(after, 'before') - total(before, 'after')


def require_marker(marker):
    expected = dict(opens=1, pre_read_grace_ms=5000, first_read_issued_ns=0)
    if not isinstance(marker, dict) or marker.get('tcp_open') is not True or any(
            type(marker.get(key)) is not int or marker[key] != value for key, value in expected.items()):
        raise ValueError('marker must prove one open, bounded5000ms pause, and no issued READ')
    ready = marker.get('pre_read_ready_ns')
    if type(ready) is not int or ready <= 0:
        raise ValueError('marker has no valid ready timestamp')
    return ready


def window_proof(marker, master, before, after, restored_vision_ns):
    failures, count = [], None
    try:
        ready = require_marker(marker)
        issued = master.get('first_read_issued_ns')
        if type(issued) is not int or master.get('pre_read_ready_ns') != ready or \
                master.get('pre_read_grace_ms') != 5000 or issued < ready + 5_000_000_000:
            failures.append('final master does not confirm the established pause before first READ')
        if type(restored_vision_ns) is not int or not ready <= restored_vision_ns < ready + 5_000_000_000 or \
                type(issued) is not int or restored_vision_ns >= issued:
            failures.append('READ IPG restore was not confirmed on Vision before pause deadline and first READ')
        for label, snapshot in (('before', before), ('after', after)):
            entries = [snapshot.get('read_app_' + suffix) for suffix in ('before', 'after')]
            if not all(isinstance(entry, dict) for entry in entries):
                raise ValueError(label + ': missing READ app counters')
            if entries[0] != entries[1]:
                failures.append(label + ': READ app changed during full bank snapshot')
            for entry in entries:
                if any(type(entry.get(key)) is not int or entry[key] != 1 for key in ('trigger_counter', 'batch_counter')):
                    failures.append(label + ': app counters do not prove exactly one old batch')
                if entry.get('ipg') != 2_500_000_000:
                    failures.append(label + ': actual READ delay differs from 2.5seconds')
        old = before['read_app_after'].get('pkt_counter')
        new = after['read_app_before'].get('pkt_counter')
        if type(old) is not int or not 1 <= old < 4 or type(new) is not int or new != 4:
            failures.append('counter interval does not prove old tokens arriving after new connection readiness')
        else:
            count = new - old
    except (ValueError, KeyError, TypeError) as error:
        failures.append(str(error))
    return dict(ok=not failures, failures=failures, old_packets_during_pause=count)
