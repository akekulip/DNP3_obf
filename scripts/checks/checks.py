"""Current switch generator, snapshot and loop-port acceptance checks."""
import json

MAX_SBO_CYCLES=64
NO_J_CONTRACT="response_ready_ack_d_no_j_v3"
LOOP_ROLES=("n_ack_return","t_in","held_return")
RX,RX_GOOD="$OctetsReceived","$OctetsReceivedinGoodFrames"

def loop_roles(timing_contract=None):
    if timing_contract != NO_J_CONTRACT:
        raise ValueError("current switch checks require the D-only contract")
    return LOOP_ROLES

def allowed_gap(build):
    """Per-build allowed received-vs-good octet gap per loop role (default 0 = none allowed)."""
    return dict(build.get('allowed_loop_octet_gap', {}))


def max_token_stale(build):
    """Per-build bound on the OUT_TOKEN_STALE delta of a trial (default 0)."""
    return build.get('max_token_stale', 0)


def validate_max_token_stale(build, name):
    v = build.get('max_token_stale', 0)
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise ValueError('build %s: max_token_stale must be an integer >= 0' % name)


def validate_allowed_gap(build, name):
    for role, v in build.get('allowed_loop_octet_gap', {}).items():
        if role not in LOOP_ROLES:
            raise ValueError('build %s: allowed_loop_octet_gap role %r is not one of %s' % (name, role, LOOP_ROLES))
        if not isinstance(v, int) or isinstance(v, bool) or v < 0:
            raise ValueError('build %s: allowed_loop_octet_gap[%s] must be an integer >= 0' % (name, role))


def load_evidence_files(before=None, after=None, master=None, outstation=None, wire=None, timing=None, hold=None):
    """Read whichever evidence files exist; an unreadable one becomes None (and so a reported failure)."""
    out = {}
    for k, p in (('before', before), ('after', after), ('master', master), ('outstation', outstation),
                 ('wire', wire), ('timing', timing)) + ((('hold', hold),) if hold is not None else ()):
        try:
            value = json.load(open(p)) if p else None
            out[k] = value if isinstance(value, dict) else None
        except (OSError, ValueError):
            out[k] = None
    return out


def sbo_count(traffic):
    """SELECT/OPERATE pairs per connection: 0 without SBO, traffic.sbo_cycles when set, otherwise 1."""
    if not (traffic or {}).get('run_sbo', True):
        return 0
    return int((traffic or {}).get('sbo_cycles') or 1)


def sbo_select_only(traffic):
    """True only for an explicit traffic.sbo_select_only true (E4b): each of traffic.sbo_cycles guarded SELECTs is
    followed by READs and no OPERATE is planned. Absent = SELECT then OPERATE; any other value or shape is refused."""
    traffic = traffic or {}
    if 'sbo_select_only' not in traffic:
        return False
    if traffic['sbo_select_only'] is not True:
        raise ValueError('traffic.sbo_select_only must be true when present, got %r' % (traffic['sbo_select_only'],))
    if traffic.get('run_sbo', True) is not True or 'sbo_cycles' not in traffic:
        raise ValueError('traffic.sbo_select_only requires traffic.run_sbo and traffic.sbo_cycles')
    return True


def sbo_strict_cycle(traffic):
    """True only for an explicit traffic.sbo_strict_cycle true: [READ mixed, SELECT, OPERATE, READ integrity] x
    traffic.sbo_cycles on the mixed_full schedule. Absent = today's order; any other value or shape, or the key
    together with sbo_select_only, is refused."""
    traffic = traffic or {}
    if 'sbo_strict_cycle' not in traffic:
        return False
    if traffic['sbo_strict_cycle'] is not True:
        raise ValueError('traffic.sbo_strict_cycle must be true when present, got %r' % (traffic['sbo_strict_cycle'],))
    if traffic.get('run_sbo', True) is not True or 'sbo_cycles' not in traffic or \
            traffic.get('read_schedule') != 'mixed_full':
        raise ValueError('traffic.sbo_strict_cycle requires traffic.run_sbo, traffic.sbo_cycles and read_schedule '
                         'mixed_full')
    if 'sbo_select_only' in traffic:
        raise ValueError('traffic.sbo_strict_cycle is refused together with traffic.sbo_select_only')
    return True


def planned_controls(traffic):
    """Planned {SELECT, OPERATE} per connection: sbo_count of each, or sbo_count SELECTs and OPERATE 0 only when the
    config declares traffic.sbo_select_only."""
    sbo = sbo_count(traffic)
    return dict(SELECT=sbo, OPERATE=0 if sbo_select_only(traffic) else sbo)




def _loop_gap(before, after):
    """{role: (octet gap in the trial, error-or-None)}: delta of (received - received-in-good-frames)."""
    out = {}
    for role in LOOP_ROLES:
        try:
            a, b = after['loop_ports'][role], before['loop_ports'][role]
            gap = (a[RX] - a[RX_GOOD]) - (b[RX] - b[RX_GOOD])
            out[role] = (gap, None)
        except (KeyError, TypeError):
            out[role] = (None, 'loop-port counters for %s are missing or unreadable' % role)
    return out


def _mirror_checks(mx, arm, reads, sbo_count, b, a, k, fails, obs, max_stale=0, control_timed=False,
                   timing_contract=None, operate_count=None):
    """Generator counters (snapshot pktgen block, after minus before) on a build carrying the compiler-mirror
    fix: T on -> READ triggers == READs, READ packets == 2k per trigger, OPERATE triggers == SBOs, stale == 0;
    T off -> no generator activity at all (what the T-off silicon evidence shows). No-J contract: app1 (OPERATE)
    is retired and disabled; every admitted READ, SELECT and OPERATE triggers app0 (READ) once; an app1 block
    that is still reported must stay idle."""
    loop_roles(timing_contract)
    no_j = True
    try:
        d = {}
        for app in ('READ', 'OPERATE'):
            if no_j and app == 'OPERATE':
                reported = ('OPERATE' in b['pktgen'], 'OPERATE' in a['pktgen'])
                if not any(reported):
                    continue
                if not all(reported):
                    fails.append('no-J build: retired generator app1 (OPERATE) reported in only one snapshot')
                    return
            d[app] = {'triggers': a['pktgen'][app]['trigger_counter'] - b['pktgen'][app]['trigger_counter'],
                      'pkts': a['pktgen'][app]['pkt_counter'] - b['pktgen'][app]['pkt_counter']}
    except (KeyError, TypeError):
        fails.append('mirror_fix build: the snapshots carry no pktgen trigger/packet counters')
        return
    obs['pktgen'] = d
    sbo = sbo_count
    if arm['T']:
        if no_j:
            # SELECT and OPERATE both pass the common admission and its app0 trigger; app1 is disabled. A select-only
            # plan passes operate_count 0 (its SELECTs are admitted, no OPERATE is sent); None means one per SELECT.
            lane = reads + sbo + (sbo if operate_count is None else operate_count)
            want = {'READ': (lane, 2 * k * lane)}
            if 'OPERATE' in d:
                want['OPERATE'] = (0, 0)
        for app, (trig, pkts) in want.items():
            if d[app]['triggers'] != trig:
                fails.append('T on: %s trigger delta %d, expected %d' % (app, d[app]['triggers'], trig))
            if d[app]['pkts'] != pkts:
                fails.append('T on: generated %s packets delta %d, expected %d (2k = %d per trigger)'
                             % (app, d[app]['pkts'], pkts, 2 * k))
        obs['token_stale_bound'] = 'unknown: no switch telemetry in this build'
    else:
        for app in mx['T0']['zero_triggers']:
            if no_j and app not in d:
                continue
            if d[app]['triggers'] or d[app]['pkts']:
                fails.append('T off: %s trigger delta %d and packet delta %d, expected none (generator idle)'
                             % (app, d[app]['triggers'], d[app]['pkts']))


def evaluate_switch(exp, arm, reads, ev, allowed=None, mirror_k=None, max_stale=0, diagnostic=False,
                    sbo_count=1, complete_reads=None, piggyback_reads=0, control_timed=False,
                    piggyback_bound=False, piggyback_controls=0, gen_exhausted_outcome=None,
                    timing_contract=None, telemetry=False, operate_count=None):
    loop_roles(timing_contract)
    failures, observed = [], {'outcomes': 'no switch telemetry in this build'}
    if telemetry:
        failures.append('current build has no outcome telemetry; unsupported telemetry claim')
    for key in ('before', 'after'):
        if not ev.get(key):
            failures.append('missing evidence: %s snapshot' % key)
    before, after = ev.get('before'), ev.get('after')
    if before and after:
        if mirror_k is None:
            failures.append('current switch check requires generator K')
        else:
            _mirror_checks(exp['mirror_fix'], arm, reads, sbo_count, before, after, mirror_k,
                           failures, observed, timing_contract=timing_contract, operate_count=operate_count)
        gaps = _loop_gap(before, after)
        observed['loop_octet_gap'] = {role: gap for role, (gap, _) in gaps.items()}
        for role, (gap, error) in gaps.items():
            if error:
                failures.append(error)
            elif gap > (allowed or {}).get(role, 0):
                failures.append('loop port %s: %d received octets were not in good frames (allowed %d)' %
                                (role, gap, (allowed or {}).get(role, 0)))
    return failures, observed
