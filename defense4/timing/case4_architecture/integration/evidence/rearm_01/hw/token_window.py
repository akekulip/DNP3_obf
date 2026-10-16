"""Evidence gates for real old generator tokens drained inside the new connection's pause.

Design (PLAN_m5 S3, revised 2026-10-15): the old-token population is derived from the configured workload, the
cleanup bound from that population and the configured IPGs, and c2's pre-READ pause from the bound. Every old
token must leave the generator, and the READ IPG must be restored, BEFORE c2 issues its first READ; only quiet
snapshots are taken. Isolation is then qualified through c2/c3's traffic by exact post-run rejection counts,
generations consistent with c2/c3's own workload, and c2/c3 delivery and timing.
"""
SPLIT_LAYOUT = 'split_raw_timer_23_24'
RAW_INDICES = (6, 14, 23, 24)

PRE_READ_GRACE_MS = 10000              # the candidate61 fixed pause, and the pinned barrier endpoint's maximum
PRE_READ_GRACE_NS = PRE_READ_GRACE_MS * 1_000_000
PAUSE_MAX_MS = PRE_READ_GRACE_MS
DEFAULT_DELAY_IPG_NS = 2_500_000_000
DELAY_IPG_MIN_NS, DELAY_IPG_GRID_NS = 1_000_000_000, 250_000_000   # delay_read_tokens accepts 1..4 s
ROLES = (('READ', 'read', 0), ('OPERATE', 'operate', 1))

# Allowances added to the emission span (stated, not measured per run):
TRIGGER_LATENCY_NS = 1_000_000          # c1 master READ issue -> generator trigger (one switch pass, microseconds)
SNAPSHOT_ALLOWANCE_NS = 3_000_000_000   # drain -> drained poll read, collected and Vision-ticked (retained poll
                                        # spacing 2.13-2.62 s; one full-bank read 0.28-0.31 s)
RESTORE_ALLOWANCE_NS = 4_000_000_000    # drained poll tick -> IPG restore confirmed on Vision (upper bound, gated);
                                        # retained candidate61: poll 0 read complete -> restore confirmed ~3.55 s
                                        # (switch->Vision clock mapped at the marker observation, an estimate)
# Measured c1 first READ issue (c1 master.json first_read_issued_ns) -> c2 readiness (c2 master.json
# pre_read_ready_ns), Vision clock: m4 ctl_m4_stale_tokens_950_01 5.399073266 s, candidate61
# candidate61_stale_tokens_950_02 5.515418587 s. ESTIMATE FROM TWO RUNS. The upper (pause) bound uses the
# minimum (c2 may be ready as early as that, leaving the most drain inside the pause); the lower (old token
# still pending at the c2-ready snapshot) bound uses the maximum.
C1_TO_C2_READY_MIN_NS = 5_399_073_266
C1_TO_C2_READY_MAX_NS = 5_515_418_587
# c2 ready -> the c2-ready snapshot's counter read. ESTIMATE: measured parts on the two runs are ready -> marker
# seen 0.129 s (m4) / 0.417 s (candidate61) and the full-bank read 0.31 s / 0.30 s (time -> completed_time); the
# ssh and python start-up between marker seen and read start is not logged (different clocks), so 1 s is a
# stated allowance, not a measurement. The c1 anchor read now happens after this snapshot, adding nothing.
FIRST_SNAPSHOT_NS = 1_000_000_000
LOWER_MARGIN_NS = 500_000_000
ESTIMATES = ('SNAPSHOT_ALLOWANCE_NS, RESTORE_ALLOWANCE_NS, C1_TO_C2_READY_MIN_NS/MAX_NS, FIRST_SNAPSHOT_NS and the '
             'OPERATE drain model are estimates or allowances from two retained runs (m4, candidate61), not '
             'generator or endpoint specifications.')
TEARDOWN_RESTORES_GENERATOR = (
    'Block-end rollback rewrites the generator: bringup_teardown.py disables both pktgen apps and restores '
    'tf1.pktgen.app_cfg READ and OPERATE to their pre-install entries (retained m4 teardown.log lines 1-2, 24-25, '
    '45-46: "left disabled (default was a disabled one-shot)"), and the block restore cold-swaps the production '
    'program (m4 restore_verify.json ok). A delay IPG left in place by a failed monitor therefore does not survive '
    'the block, but it does affect any c2/c3 traffic that runs before teardown; the monitor aborts c2 instead.')

DRAIN_BEFORE_C2_RATIONALE = (
    'Old tokens are drained, and the READ IPG restored, before c2 issues its first READ by design. A pktgen '
    'configuration write or a delayed batch overlapping c2/c3 traffic loses generator triggers: the retained '
    'm4 block ctl_m4_stale_tokens_950_01 left the 2.5 s IPG in place while c2/c3 ran and its full-run counters '
    'show READ trigger delta 4 against 6 expected and READ packets 13 against 24 expected (trial.json), so '
    'c2/c3 tokens cannot be separated from old ones once they overlap. No full-bank snapshot is taken during '
    'measured traffic.')


def old_token_population(k, reads, sbo, control_timed):
    """Old-token population left by c1, per role, from the configured workload.

    Each generator trigger emits one batch of 2k tokens (installer --k, service.k). The READ app (0) is
    triggered once per READ and, on a control-timed build, once more per SELECT (T admits each SELECT as a
    READ-lane request with the 0xE100 clone); the OPERATE app (1) once per SBO. Only the first READ-lane token,
    emitted at c1's READ trigger while its generation is current, is consumed; every later token waits at least
    one delay IPG (>= 1 s) behind a c1 transaction that lasts milliseconds, so it must be a raw timer stale.
    """
    for name, value in (('k', k), ('reads', reads), ('sbo', sbo)):
        if type(value) is not int or value < (1 if name != 'sbo' else 0):
            raise ValueError('population needs a positive integer ' + name)
    if type(control_timed) is not bool:
        raise ValueError('control_timed must be a boolean')
    per = 2 * k
    read_triggers = reads + (sbo if control_timed else 0)
    result = dict(k=k, tokens_per_trigger=per, control_timed=control_timed, reads=reads, sbo=sbo,
                  formula='tokens(role) = triggers(role) x 2k; triggers(READ) = reads + (sbo if control_timed '
                          'else 0); triggers(OPERATE) = sbo; expected raw stale: READ tokens - 1, OPERATE tokens')
    result['READ'] = dict(app_id=0, triggers=read_triggers, tokens=read_triggers * per,
                          expected_raw_stale=read_triggers * per - 1, raw_index='24')
    result['OPERATE'] = dict(app_id=1, triggers=sbo, tokens=sbo * per, expected_raw_stale=sbo * per,
                             raw_index='23')
    return result


# The single-READ, single-SBO candidate61 diagnostic this module was first written for.
LEGACY_POPULATION = old_token_population(2, 1, 1, False)


def check_population_config(population, entry, role):
    """The generator configuration the harness reads must emit exactly 2k tokens per trigger, one batch each."""
    expected = (('batch_count_cfg', 0), ('packets_per_batch_cfg', population['tokens_per_trigger'] - 1))
    if any(type(entry.get(key)) is not int or entry[key] != value for key, value in expected):
        raise ValueError(role + ': configured batch is not exactly %d packets' % population['tokens_per_trigger'])


def cleanup_bound(population, ipg_by_role):
    """Time from c1's first READ trigger by which every old token has left the generator and been observed.

    bound = max(READ span, OPERATE span) + TRIGGER_LATENCY + SNAPSHOT_ALLOWANCE, span = triggers x (2k-1) x IPG.
    One batch of 2k tokens spans (2k-1) IPGs; batches of one role are emitted in series (m4: batch 2 began after
    batch 1's fourth token). ipg_by_role are the configured IPGs (READ: the delay IPG; OPERATE: the installed
    app 1 IPG, 0). EMPIRICAL: with IPG 0 the OPERATE cohort should leave at once, but both retained runs show
    OPERATE pkt_counter 1 at c2 readiness (about 5.4 s after its trigger) and 4 only at the next poll, i.e. app 1
    is paced behind the delayed app 0. The OPERATE drain is therefore modelled as bounded by the READ-lane span,
    not by its own IPG; that bound is an observation on two runs, not a generator specification.
    """
    terms = {}
    for role, _, _ in ROLES:
        value = ipg_by_role.get(role)
        if type(value) is not int or value < 0:
            raise ValueError('cleanup bound needs a configured integer IPG for ' + role)
        triggers, gaps = population[role]['triggers'], population['tokens_per_trigger'] - 1
        terms[role] = dict(triggers=triggers, ipg_gaps_per_batch=gaps, ipg_ns=value, span_ns=triggers * gaps * value)
    terms['OPERATE']['drain_model'] = 'empirical: paced behind app 0, bounded by the READ-lane span'
    emission = max(terms['READ']['span_ns'], terms['OPERATE']['span_ns'])
    allowance = dict(trigger_latency_ns=TRIGGER_LATENCY_NS, snapshot_ns=SNAPSHOT_ALLOWANCE_NS)
    return dict(bound_ns=emission + sum(allowance.values()), emission_ns=emission, terms=terms,
                last_old_read_token_ns=terms['READ']['span_ns'], allowance=allowance,
                formula='bound = max(READ span, OPERATE span) + trigger latency + snapshot allowance; '
                        'span = triggers x (2k-1) x IPG; OPERATE drain bounded by the READ span (empirical)')


def pause_requirement(bound, credit_ns=C1_TO_C2_READY_MIN_NS, lower_credit_ns=C1_TO_C2_READY_MAX_NS):
    """c2's pre-READ pause (upper bound) and the old-token lower bound for one plan.

    upper: pause = ceil_ms(bound + restore allowance - credit) <= PAUSE_MAX_MS, where credit is the measured
    minimum c1 first READ -> c2 ready. lower: the last old READ token must leave after the c2-ready snapshot,
    last_old_read_token > maximum credit + first snapshot + margin, or no old token arrives inside c2's pause.
    The upper bound uses the minimum measured c1 -> c2-ready time, the lower bound the maximum.
    """
    required = bound['bound_ns'] + RESTORE_ALLOWANCE_NS - credit_ns
    pause_ms = max(1, -(-required // 1_000_000))
    floor = lower_credit_ns + FIRST_SNAPSHOT_NS + LOWER_MARGIN_NS
    last = bound['last_old_read_token_ns']
    return dict(required_ns=required, pause_ms=pause_ms, maximum_ms=PAUSE_MAX_MS, upper_ok=pause_ms <= PAUSE_MAX_MS,
                last_old_read_token_ns=last, lower_floor_ns=floor, lower_ok=last > floor,
                fits=pause_ms <= PAUSE_MAX_MS and last > floor,
                restore_allowance_ns=RESTORE_ALLOWANCE_NS, c1_credit_ns=credit_ns, c1_lower_credit_ns=lower_credit_ns,
                upper_margin_ns=PAUSE_MAX_MS * 1_000_000 - pause_ms * 1_000_000, lower_margin_over_floor_ns=last - floor,
                estimates=ESTIMATES,
                first_snapshot_ns=FIRST_SNAPSHOT_NS, lower_margin_ns=LOWER_MARGIN_NS,
                formula='upper: pause = ceil_ms(bound + restore allowance - c1->c2 ready minimum) <= %d ms; lower: '
                        'READ span > c1->c2 ready maximum + first snapshot + margin' % PAUSE_MAX_MS)


def plan_isolation(population, operate_ipg_ns, configured_delay_ipg_ns=None, legacy=False):
    """Delay IPG, cleanup bound and c2 pause for one block.

    legacy (single READ-lane batch, candidate61): the retained parameters run unchanged, 2.5 s delay and the
    10000 ms pause; the derived requirement is recorded, never used to refuse. Every plan that fits pauses c2
    for the endpoint maximum (PAUSE_MAX_MS); the derived pause and the resulting slack are recorded. Control-timed: a configured
    delay IPG must satisfy both bounds; otherwise the largest 250 ms grid IPG in [1 s, 2.5 s] that does is chosen.
    """
    def plan(ipg):
        bound = cleanup_bound(population, {'READ': ipg, 'OPERATE': operate_ipg_ns})
        return bound, pause_requirement(bound)

    def maximum_pause(pause):
        # When the derived pause fits, c2 pauses for the endpoint maximum: the difference is runtime slack.
        out = dict(pause, derived_pause_ms=pause['pause_ms'], pause_ms=PAUSE_MAX_MS,
                   planned_slack_ns=PAUSE_MAX_MS * 1_000_000 - pause['required_ns'],
                   slack_formula='slack = pause - restore allowance - worst drained tick after c2 ready '
                                 '(bound - minimum c1->c2 ready) = pause - required')
        return out
    if legacy:
        bound, pause = plan(DEFAULT_DELAY_IPG_NS)
        pause = dict(maximum_pause(pause), upper_ok=pause['required_ns'] <= PRE_READ_GRACE_NS,
                     upper_margin_ns=PRE_READ_GRACE_NS - pause['required_ns'])
        pause['fits'] = pause['upper_ok'] and pause['lower_ok']
        return dict(delay_ipg_ns=DEFAULT_DELAY_IPG_NS, delay_ipg_source='legacy candidate61 parameters (unchanged)',
                    bound=bound, pause=pause, legacy=True)
    if configured_delay_ipg_ns is not None:
        if type(configured_delay_ipg_ns) is not int or not DELAY_IPG_MIN_NS <= configured_delay_ipg_ns <= 4_000_000_000:
            raise ValueError('isolation.delay_ipg_ns must be an integer in 1..4 seconds')
        bound, pause = plan(configured_delay_ipg_ns)
        if not pause['upper_ok']:
            raise ValueError('configured delay IPG needs a %d ms c2 pause, above the endpoint maximum %d ms'
                             % (pause['pause_ms'], PAUSE_MAX_MS))
        if not pause['lower_ok']:
            raise ValueError('configured delay IPG drains the old READ tokens before the c2-ready snapshot')
        return dict(delay_ipg_ns=configured_delay_ipg_ns, delay_ipg_source='configured', bound=bound,
                    pause=maximum_pause(pause), legacy=False)
    for ipg in range(DEFAULT_DELAY_IPG_NS, DELAY_IPG_MIN_NS - 1, -DELAY_IPG_GRID_NS):
        bound, pause = plan(ipg)
        if pause['fits']:
            return dict(delay_ipg_ns=ipg, delay_ipg_source='derived: largest 250 ms grid IPG <= 2.5 s meeting both bounds',
                        bound=bound, pause=maximum_pause(pause), legacy=False)
    raise ValueError('no delay IPG in 1..2.5 s meets both the endpoint pause maximum and the old-token lower bound')


def drained(snapshot, population):
    """Every old token of every role, and nothing newer, has left the generator (first counter read)."""
    for role, prefix, _ in ROLES:
        entry = snapshot.get(prefix + '_app_before') or {}
        if (entry.get('pkt_counter'), entry.get('trigger_counter'), entry.get('batch_counter')) != \
                (population[role]['tokens'], population[role]['triggers'], population[role]['triggers']):
            return False
    return True


def overran(snapshot, population):
    """A generator counter beyond the old population: a new trigger arrived before the old batches drained."""
    for role, prefix, _ in ROLES:
        entry = snapshot.get(prefix + '_app_before') or {}
        for key, limit in (('pkt_counter', population[role]['tokens']), ('trigger_counter', population[role]['triggers']),
                           ('batch_counter', population[role]['triggers'])):
            if type(entry.get(key)) is int and entry[key] > limit:
                return True
    return False


def legacy_drained(snapshot):
    """The fixed candidate61 drain test the monitor used before 2026-10-15: exactly four tokens per app."""
    return snapshot.get('read_app_before', {}).get('pkt_counter') == 4 and \
        snapshot.get('operate_app_before', {}).get('pkt_counter') == 4


def cleanup_proof(anchor_ns, drained_ns, bound, anchor='vision: c1 master first_read_issued_ns'):
    """The drained poll must be observed (post-poll tick, same clock as the anchor) by anchor + bound."""
    failures = []
    if not isinstance(bound, dict) or type(bound.get('bound_ns')) is not int or bound['bound_ns'] <= 0:
        return dict(ok=False, failures=['cleanup bound: derivation missing'], elapsed_ns=None, bound=bound,
                    anchor=anchor)
    if type(anchor_ns) is not int or type(drained_ns) is not int or drained_ns < anchor_ns:
        failures.append('cleanup bound: missing or inverted anchor/drain times')
        elapsed = None
    else:
        elapsed = drained_ns - anchor_ns
        if elapsed > bound['bound_ns']:
            failures.append('cleanup bound exceeded: old tokens observed drained %d ns after the anchor, bound %d ns'
                            % (elapsed, bound['bound_ns']))
    return dict(ok=not failures, failures=failures, elapsed_ns=elapsed, bound=bound, anchor=anchor)


def restore_proof(drained_tick_ns, restored_ns):
    """IPG restore confirmed on Vision within RESTORE_ALLOWANCE of the drained poll's Vision tick."""
    if type(drained_tick_ns) is not int or type(restored_ns) is not int or restored_ns < drained_tick_ns:
        return dict(ok=False, failures=['restore: missing or inverted drain/restore ticks'], elapsed_ns=None)
    elapsed = restored_ns - drained_tick_ns
    failures = [] if elapsed <= RESTORE_ALLOWANCE_NS else [
        'restore took %d ns after the drained poll, allowance %d ns' % (elapsed, RESTORE_ALLOWANCE_NS)]
    return dict(ok=not failures, failures=failures, elapsed_ns=elapsed, allowance_ns=RESTORE_ALLOWANCE_NS)


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


def operate_rejection_proof(before, after, baseline, population=None):
    # pkt_counter records generator emission, not arrival at T. Prove the whole old OPERATE cohort rejected;
    # its emitted prefix may still be in flight.
    total = (population or LEGACY_POPULATION)['OPERATE']['tokens']
    first, last = raw_counts(before, 'after')['23'], raw_counts(after, 'before')['23']
    initial = baseline['outcomes'].get('RAW_OPERATE_TIMER_STALE')
    if type(initial) is not int or initial != 0:
        raise ValueError('dirty OPERATE rejection baseline')
    emitted = before['operate_app_after'].get('pkt_counter')
    completed = after['operate_app_before'].get('pkt_counter')
    if any(type(value) is not int or value < 0 for value in (first, last, initial, emitted, completed)):
        raise ValueError('missing OPERATE cohort counters')
    prefix_rejected = first - initial
    if completed != total or not 0 <= prefix_rejected <= emitted <= completed or last-initial != completed:
        raise ValueError('all %d tokens of the old OPERATE cohort must be rejected' % total)
    generated = completed - emitted
    pending = emitted - prefix_rejected
    rejected = last - first
    if rejected <= 0 or rejected != generated + pending:
        raise ValueError('old OPERATE generation and in-flight prefix do not conserve rejections')
    return dict(generated_during_pause=generated, prefix_inflight_rejected=pending,
                rejected_during_pause=rejected,total_old_operate_rejected=completed)


def full_run_rejections(before, after, quiet_end, population=None):
    """After c2/c3: raw timer rejections equal exactly the derived old population and none arose after drain."""
    pop = population or LEGACY_POPULATION
    read_stale, op_stale = pop['READ']['expected_raw_stale'], pop['OPERATE']['expected_raw_stale']
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
    if type(op_packets) is not int or op_packets != op_stale or delta['RAW_OPERATE_TIMER_STALE'] != op_packets:
        raise ValueError('raw OPERATE rejects must equal the completed old OPERATE cohort (%d)' % op_stale)
    if delta['RAW_READ_TIMER_STALE'] != read_stale:
        raise ValueError('raw READ timer rejection count must equal exactly the %d delayed c1 tokens' % read_stale)
    aggregate = sum(delta[name] for index, name in names.items() if index != '14')
    observed = after['outcomes']['OUT_TOKEN_STALE'] - before['outcomes']['OUT_TOKEN_STALE']
    if observed != aggregate:
        raise ValueError('ordinary stale aggregate differs from raw timer and blocker sum')
    return dict(expected_old_tokens=read_stale, raw_timer_rejections=read_stale,
                raw_operate_rejections=delta['RAW_OPERATE_TIMER_STALE'],
                stale_blocker_rejections=delta['STALE_BLOCKER'],
                strict_stale_total=aggregate, post_quiet_stale_rejections=0,
                old_epoch_cleanup=delta['index_14'], old_rejections_total=aggregate+delta['index_14'])


def require_marker(marker, pause_ms=PRE_READ_GRACE_MS):
    expected = dict(opens=1, pre_read_grace_ms=pause_ms, first_read_issued_ns=0)
    if not isinstance(marker, dict) or marker.get('tcp_open') is not True or any(
            type(marker.get(key)) is not int or marker[key] != value for key, value in expected.items()):
        raise ValueError('marker must prove one open, bounded%dms pause, and no issued READ' % pause_ms)
    ready = marker.get('pre_read_ready_ns')
    if type(ready) is not int or ready <= 0:
        raise ValueError('marker has no valid ready timestamp')
    return ready


def window_proof(marker, master, before, after, restored_vision_ns, population=None, cleanup=None,
                 delay_ipg_ns=DEFAULT_DELAY_IPG_NS, pause_ms=PRE_READ_GRACE_MS):
    """Old tokens arriving after c2 readiness drain exactly, and IPG is restored, before c2's first READ.

    Defaults are the candidate61 proof (one READ batch, 2.5 s delay, 10 s pause); population, delay_ipg_ns
    and pause_ms generalize it to the derived plan. cleanup (a cleanup_proof result) adds the bound.
    """
    pop = population or LEGACY_POPULATION
    read_tokens, op_tokens = pop['READ']['tokens'], pop['OPERATE']['tokens']
    pause_ns = pause_ms * 1_000_000
    failures, count, op_count = [], None, None
    try:
        ready = require_marker(marker, pause_ms)
        issued = master.get('first_read_issued_ns')
        if type(issued) is not int or master.get('pre_read_ready_ns') != ready or \
                master.get('pre_read_grace_ms') != pause_ms or issued < ready + pause_ns:
            failures.append('final master does not confirm the established pause before first READ')
        if type(restored_vision_ns) is not int or not ready <= restored_vision_ns < ready + pause_ns or \
                type(issued) is not int or restored_vision_ns >= issued:
            failures.append('READ IPG restore was not confirmed on Vision before pause deadline and first READ')
        if cleanup is not None and cleanup.get('ok') is not True:
            failures.extend(cleanup.get('failures') or ['cleanup bound proof failed'])
        for label, snapshot in (('before', before), ('after', after)):
            entries = [snapshot.get('read_app_' + suffix) for suffix in ('before', 'after')]
            if not all(isinstance(entry, dict) for entry in entries):
                raise ValueError(label + ': missing READ app counters')
            if entries[0] != entries[1]:
                failures.append(label + ': READ app changed during full bank snapshot')
            for entry in entries:
                values = [entry.get(key) for key in ('trigger_counter', 'batch_counter')]
                if label == 'after':
                    ok = all(type(v) is int and v == pop['READ']['triggers'] for v in values)
                else:   # c1's later READ-lane batches may still be queued at c2 readiness
                    ok = all(type(v) is int for v in values) and values[0] == values[1] and \
                        1 <= values[0] <= pop['READ']['triggers']
                if not ok:
                    failures.append(label + ': app counters do not prove exactly the old READ-lane batches')
                if entry.get('ipg') != delay_ipg_ns:
                    failures.append(label + ': actual READ delay differs from the configured delay IPG')
        old = before['read_app_after'].get('pkt_counter')
        new = after['read_app_before'].get('pkt_counter')
        if type(old) is not int or not 1 <= old < read_tokens or type(new) is not int or new != read_tokens:
            failures.append('counter interval does not prove old tokens arriving after new connection readiness')
        else:
            count = new - old
        for label, snapshot in (('before', before), ('after', after)):
            op = [snapshot.get('operate_app_' + suffix) for suffix in ('before', 'after')]
            if not all(isinstance(entry, dict) for entry in op) or op[0] != op[1]:
                raise ValueError(label + ': missing or changing OPERATE app counters')
            if any(type(entry.get(key)) is not int or entry[key] != pop['OPERATE']['triggers']
                   for entry in op for key in ('trigger_counter', 'batch_counter')):
                raise ValueError(label + ': OPERATE app must prove exactly the old OPERATE batches')
        old_op = before['operate_app_after'].get('pkt_counter')
        new_op = after['operate_app_before'].get('pkt_counter')
        if type(old_op) is not int or not 0 <= old_op <= op_tokens or type(new_op) is not int or new_op != op_tokens:
            raise ValueError('old OPERATE batch must finish before the quiet window ends')
        if before['operate_app_after'].get('ipg') != after['operate_app_before'].get('ipg'):
            raise ValueError('OPERATE app IPG changed during quiet window')
        counters = ('pkt_counter', 'trigger_counter', 'batch_counter') if pop['READ']['triggers'] > 1 \
            else ('pkt_counter',)
        for role in ('read', 'operate'):
            left = before[role + '_app_after']
            right = after[role + '_app_before']
            for entry in (left, right):
                check_population_config(pop, entry, role)
            if {k:v for k,v in left.items() if k not in counters} != \
                    {k:v for k,v in right.items() if k not in counters}:
                raise ValueError(role + ': app configuration changed during quiet window')
        op_count = new_op - old_op
    except (ValueError, KeyError, TypeError) as error:
        failures.append(str(error))
    return dict(ok=not failures, failures=failures, old_packets_during_pause=count, old_operate_packets_during_pause=op_count)


def _register(snapshot, name):
    entry = snapshot['registers'][name]
    values = [value for key, value in entry.items() if key not in ('action_name', 'is_default_entry')]
    if len(values) != 1 or not isinstance(values[0], list) or len(values[0]) != 1 or type(values[0][0]) is not int:
        raise ValueError('register %s is missing or not one integer' % name)
    return values[0][0]


AUTHORITY = (('N_epoch', 'p0.n_Ingress.epoch', 0x7fffffff), ('T_epoch', 'p1.t_Ingress.cur_epoch_reg', 0x7fffffff),
             ('owner_generation', 'p0.n_Ingress.owner', 0xffff), ('T_read_generation', 'p1.t_Ingress.gen_alloc_reg', None),
             ('T_operate_generation', 'p1.t_Ingress.op_gen_alloc_reg', None))


def authority(snapshot):
    """Current authority, owner and generations as one snapshot reads them (masked identity fields)."""
    if snapshot.get('valid') is not True or snapshot.get('errors') or snapshot.get('software_read_fallbacks'):
        raise ValueError('incomplete hardware snapshot')
    out = {}
    for key, name, mask in AUTHORITY:
        value = _register(snapshot, name)
        out[key] = value & mask if mask else value
    if 'p0.n_Ingress.work.work' in snapshot['registers']:
        out['N_work_generation'] = _register_field(snapshot, 'p0.n_Ingress.work.work', 'generation')
    return out


def _register_field(snapshot, name, field):
    keys = [key for key in snapshot['registers'][name] if key.endswith('.' + field)]
    if len(keys) != 1:
        raise ValueError('register %s has no single %s field' % (name, field))
    value = snapshot['registers'][name][keys[0]]
    if not isinstance(value, list) or len(value) != 1 or type(value[0]) is not int:
        raise ValueError('register %s.%s is not one integer' % (name, field))
    return value[0]


def expected_generations(lane_per_connection, operate_per_connection, lifecycle_per_connection):
    """T allocator values implied by the configured workload (generation_headroom.workload_reserve rows):
    at c2 readiness c1 is complete and c2 has only opened (one of its lifecycle bumps); after c3, three
    complete connections."""
    per = dict(T_read_generation=lane_per_connection + lifecycle_per_connection,
               T_operate_generation=operate_per_connection + lifecycle_per_connection)
    return dict(at_c2_ready={k: v + 1 for k, v in per.items()}, after_c3={k: 3 * v for k, v in per.items()},
                per_connection=per)


def quiet_poll_proof(before, polls, poll_vision_ns, first_read_issued_ns, expected_at_ready=None,
                     connection_generation=2):
    """Every poll is quiet (its post-poll Vision tick precedes c2's first READ) and authority is unchanged."""
    failures, observed = [], []
    if not isinstance(polls, list) or not polls or not isinstance(poll_vision_ns, list) or \
            len(poll_vision_ns) != len(polls):
        return dict(ok=False, failures=['poll series or its Vision ticks missing'], observed=observed)
    try:
        start = authority(before)
    except (KeyError, TypeError, ValueError) as error:
        return dict(ok=False, failures=['before: ' + str(error)], observed=observed)
    observed.append(dict(start, label='before'))
    if start['owner_generation'] != connection_generation:
        failures.append('before: owner is not the established current connection')
    for key, value in (expected_at_ready or {}).items():
        if start.get(key) != value:
            failures.append('before: %s=%s, workload implies %d at c2 readiness' % (key, start.get(key), value))
    for index, (poll, tick) in enumerate(zip(polls, poll_vision_ns)):
        label = 'poll%02d' % index
        if type(tick) is not int or type(first_read_issued_ns) is not int or tick >= first_read_issued_ns:
            failures.append(label + ': not proven quiet (Vision tick missing or not before c2 first READ)')
        try:
            current = authority(poll)
        except (KeyError, TypeError, ValueError) as error:
            failures.append(label + ': ' + str(error));continue
        observed.append(dict(current, label=label))
        if current != start:
            failures.append(label + ': authority changed while old tokens arrived')
    return dict(ok=not failures, failures=failures, observed=observed)


def post_traffic_authority(lifecycle_before, lifecycle_after, expected_after_c3, last_connection=3):
    """After c3: T generations equal exactly c1-c3's own workload from a zero baseline; owner is c3's."""
    failures = []
    try:
        start, end = authority(lifecycle_before), authority(lifecycle_after)
    except (KeyError, TypeError, ValueError) as error:
        return dict(ok=False, failures=['lifecycle: ' + str(error)], before=None, after=None)
    for key in expected_after_c3:
        if start[key] != 0:
            failures.append('lifecycle before: %s=%d, expected a zero baseline' % (key, start[key]))
        if end[key] != expected_after_c3[key]:
            failures.append('after c3: %s=%d, c1-c3 workload implies %d' % (key, end[key], expected_after_c3[key]))
    if end['owner_generation'] != last_connection:
        failures.append('after c3: owner connection generation %d, expected %d' % (end['owner_generation'],
                                                                                  last_connection))
    return dict(ok=not failures, failures=failures, before=start, after=end, expected=expected_after_c3)
