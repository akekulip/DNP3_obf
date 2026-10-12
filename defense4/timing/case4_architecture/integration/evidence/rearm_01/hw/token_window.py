"""Evidence gates for a real old READ batch drained inside the new connection's pause."""
SPLIT_LAYOUT = 'split_raw_timer_23_24'
RAW_INDICES = (6, 14, 23, 24)

PRE_READ_GRACE_MS = 10000
PRE_READ_GRACE_NS = PRE_READ_GRACE_MS * 1_000_000


def raw_counts(snapshot, suffix):
    if snapshot.get('timer_rejection_layout') != SPLIT_LAYOUT:
        raise ValueError('split raw token stale counters missing/unsupported layout')
    entries = snapshot['old_reject_' + suffix]
    result = {}
    for index in RAW_INDICES:
        fields = entries[str(index)]
        values = [item for name, value in fields.items() if name not in ('action_name', 'is_default_entry')
                  for item in (value if isinstance(value, list) else [value])]
        if not values or any(type(value) is not int or value < 0 for value in values):
            raise ValueError('missing or malformed rejection counter ' + str(index))
        result[str(index)] = sum(values)
    return result


def rejection_counts(before, after):
    start, end = raw_counts(before, 'after'), raw_counts(after, 'before')
    delta = {key: end[key] - start[key] for key in start}
    if any(value < 0 for value in delta.values()):
        raise ValueError('rejection counter moved backwards during quiet window')
    return delta


def rejection_delta(before, after):
    return rejection_counts(before, after)['24']


def operate_rejection_proof(before, after, baseline):
    # pkt_counter records generator emission, not arrival at T. Prove the
    # entire single old batch rejected; its emitted prefix may still be in flight.
    first, last = raw_counts(before, 'after')['23'], raw_counts(after, 'before')['23']
    initial = baseline['outcomes'].get('RAW_OPERATE_TIMER_STALE')
    if type(initial) is not int or initial != 0:
        raise ValueError('dirty OPERATE rejection baseline')
    emitted = before['operate_app_after'].get('pkt_counter')
    completed = after['operate_app_before'].get('pkt_counter')
    if any(type(value) is not int or value < 0 for value in (first, last, initial, emitted, completed)):
        raise ValueError('missing OPERATE cohort counters')
    prefix_rejected = first - initial
    if completed != 4 or not 0 <= prefix_rejected <= emitted <= completed or last-initial != completed:
        raise ValueError('all four tokens of the single old OPERATE batch must be rejected')
    generated = completed - emitted
    pending = emitted - prefix_rejected
    rejected = last - first
    if rejected <= 0 or rejected != generated + pending:
        raise ValueError('old OPERATE generation and in-flight prefix do not conserve rejections')
    return dict(generated_during_pause=generated, prefix_inflight_rejected=pending,
                rejected_during_pause=rejected,total_old_operate_rejected=completed)


def full_run_rejections(before, after, quiet_end):
    names = {'6': 'STALE_BLOCKER', '23': 'RAW_OPERATE_TIMER_STALE', '24': 'RAW_READ_TIMER_STALE',
             '14': 'index_14'}
    end = raw_counts(quiet_end, 'after')
    for role in ('READ', 'OPERATE'):
        for name in ('trigger_counter', 'batch_counter', 'pkt_counter'):
            value = before['pktgen'][role].get(name)
            if type(value) is not int or value != 0:
                raise ValueError('dirty old-batch generator baseline: ' + role + '.' + name)
    for name in ('STALE_BLOCKER', 'RAW_OPERATE_TIMER_STALE', 'RAW_READ_TIMER_STALE', 'OUT_TOKEN_STALE'):
        value = before['outcomes'].get(name)
        if type(value) is not int or value != 0:
            raise ValueError('dirty raw rejection baseline: ' + name)
    delta = {}
    for index, name in names.items():
        values = [snapshot['outcomes'].get(name) for snapshot in (before, after)]
        if any(type(value) is not int or value < 0 for value in values) or values[1] < values[0]:
            raise ValueError('missing or nonmonotonic rejection outcome ' + name)
        delta[name] = values[1] - values[0]
        if index != '14' and values[1] != end[index]:
            raise ValueError('new traffic caused rejection after old batches drained: ' + name)
    op_packets = quiet_end['operate_app_after'].get('pkt_counter')
    if type(op_packets) is not int or op_packets != 4 or delta['RAW_OPERATE_TIMER_STALE'] != op_packets:
        raise ValueError('raw OPERATE rejects must equal the single completed old batch')
    if delta['RAW_READ_TIMER_STALE'] != 3:
        raise ValueError('raw READ timer rejection count must equal exactly the three delayed c1 tokens')
    aggregate = sum(delta[name] for index, name in names.items() if index != '14')
    observed = after['outcomes']['OUT_TOKEN_STALE'] - before['outcomes']['OUT_TOKEN_STALE']
    if observed != aggregate:
        raise ValueError('ordinary stale aggregate differs from raw timer and blocker sum')
    return dict(expected_old_tokens=3, raw_timer_rejections=3,
                raw_operate_rejections=delta['RAW_OPERATE_TIMER_STALE'],
                stale_blocker_rejections=delta['STALE_BLOCKER'],
                strict_stale_total=aggregate, post_quiet_stale_rejections=0,
                old_epoch_cleanup=delta['index_14'], old_rejections_total=aggregate+delta['index_14'])


def require_marker(marker):
    expected = dict(opens=1, pre_read_grace_ms=PRE_READ_GRACE_MS, first_read_issued_ns=0)
    if not isinstance(marker, dict) or marker.get('tcp_open') is not True or any(
            type(marker.get(key)) is not int or marker[key] != value for key, value in expected.items()):
        raise ValueError('marker must prove one open, bounded%dms pause, and no issued READ' % PRE_READ_GRACE_MS)
    ready = marker.get('pre_read_ready_ns')
    if type(ready) is not int or ready <= 0:
        raise ValueError('marker has no valid ready timestamp')
    return ready


def window_proof(marker, master, before, after, restored_vision_ns):
    failures, count, op_count = [], None, None
    try:
        ready = require_marker(marker)
        issued = master.get('first_read_issued_ns')
        if type(issued) is not int or master.get('pre_read_ready_ns') != ready or \
                master.get('pre_read_grace_ms') != PRE_READ_GRACE_MS or issued < ready + PRE_READ_GRACE_NS:
            failures.append('final master does not confirm the established pause before first READ')
        if type(restored_vision_ns) is not int or not ready <= restored_vision_ns < ready + PRE_READ_GRACE_NS or \
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
        for label, snapshot in (('before', before), ('after', after)):
            op = [snapshot.get('operate_app_' + suffix) for suffix in ('before', 'after')]
            if not all(isinstance(entry, dict) for entry in op) or op[0] != op[1]:
                raise ValueError(label + ': missing or changing OPERATE app counters')
            if any(type(entry.get(key)) is not int or entry[key] != 1
                   for entry in op for key in ('trigger_counter', 'batch_counter')):
                raise ValueError(label + ': OPERATE app must prove exactly one old batch')
        old_op = before['operate_app_after'].get('pkt_counter')
        new_op = after['operate_app_before'].get('pkt_counter')
        if type(old_op) is not int or not 0 <= old_op <= 4 or type(new_op) is not int or new_op != 4:
            raise ValueError('old OPERATE batch must finish before the quiet window ends')
        if before['operate_app_after'].get('ipg') != after['operate_app_before'].get('ipg'):
            raise ValueError('OPERATE app IPG changed during quiet window')
        for role in ('read', 'operate'):
            left = before[role + '_app_after']
            right = after[role + '_app_before']
            if any(type(entry.get(key)) is not int or entry[key] != value
                   for entry in (left, right) for key, value in
                   (('batch_count_cfg', 0), ('packets_per_batch_cfg', 3))):
                raise ValueError(role + ': configured batch is not exactly four packets')
            if {k:v for k,v in left.items() if k != 'pkt_counter'} != \
                    {k:v for k,v in right.items() if k != 'pkt_counter'}:
                raise ValueError(role + ': app configuration changed during quiet window')
        op_count = new_op - old_op
    except (ValueError, KeyError, TypeError) as error:
        failures.append(str(error))
    return dict(ok=not failures, failures=failures, old_packets_during_pause=count, old_operate_packets_during_pause=op_count)
