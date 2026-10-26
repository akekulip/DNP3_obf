"""Per-trial feature and outcome checks, computed from one trial's OWN evidence and enforced by the campaign gate.

  checks.evaluate(expectations, arm, fixture, reads, evidence, allowed_gap) -> (failures, observed)

`expectations` is the single table in campaign.json (`expectations`; README repeats it). `evidence` is a dict:
  before, after   the trial's counter snapshots (snapshot_counters.py): outcomes + loop_ports
  master          Vision master.json          outstation   Vision outstation.json
  wire            wire_check.analyze() / wire.json
  timing          clrt_check.analyze() / timing.json (summary per DNP3 function + per-exchange rows)
  hold            hold_check.analyze() / hold.json (per-OPERATE master-TX -> outstation-RX transit), optional
A missing or unreadable piece of evidence is a failure, never a crash and never a silent pass. Stdlib only.
"""
import json
import math
import statistics

LOOP_ROLES = ('n_ack_return', 't_in', 'hb_return', 'held_return')
RX, RX_GOOD = '$OctetsReceived', '$OctetsReceivedinGoodFrames'
SBO = ('SELECT', 'OPERATE')


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


MAX_SBO_CYCLES = 64


def sbo_count(traffic):
    """SELECT/OPERATE pairs per connection: 0 without SBO, traffic.sbo_cycles when set, otherwise 1."""
    if not (traffic or {}).get('run_sbo', True):
        return 0
    return int((traffic or {}).get('sbo_cycles') or 1)


def repeated_sbo_checks(master, outstation, cycles):
    """Per-cycle records of a repeated-SBO connection: one task callback per cycle with index 1 SUCCESS, the
    following READ matching the seed, and on the outstation exactly one SELECT then one OPERATE callback per
    cycle carrying that cycle's on-time (100 + cycle), in order, all SUCCESS, software handler only."""
    fails = []
    rows = (master or {}).get('cycles')
    if (master or {}).get('sbo_cycles') != cycles or not isinstance(rows, list) or len(rows) != cycles:
        fails.append('master did not report %d SBO cycle records (sbo_cycles=%r, records=%r)'
                     % (cycles, (master or {}).get('sbo_cycles'), len(rows) if isinstance(rows, list) else rows))
    for c, row in enumerate(rows if isinstance(rows, list) else []):
        want = {'cycle': c, 'on_time_ms': 100 + c, 'callbacks': 1, 'ok': True, 'index': 1, 'status': 0,
                'points': 1, 'read_matches_seed': True}
        bad = {k: row.get(k) for k, v in want.items() if row.get(k) != v}
        if bad:
            fails.append('SBO cycle %d: %r (expected %r)' % (c, bad, {k: want[k] for k in bad}))
    events = (outstation or {}).get('events')
    if not isinstance(events, list):
        return fails + ['outstation did not report per-callback events']
    # The handler counts OPERATEs delivered to its one wired point; with no output driver they actuate nothing.
    if ((outstation or {}).get('actuation'), (outstation or {}).get('output_driver')) != ('software_handler', 'none'):
        fails.append('outstation is not the software handler with no output driver')
    if (outstation or {}).get('wired_point_operates') != cycles:
        fails.append('outstation wired_point_operates=%r, expected %d' % ((outstation or {}).get('wired_point_operates'), cycles))
    want_kinds = ['SELECT', 'OPERATE'] * cycles
    if [e.get('kind') for e in events] != want_kinds:
        fails.append('outstation callbacks are not one SELECT then one OPERATE per cycle (%d events)' % len(events))
    else:
        for i, e in enumerate(events):
            if (e.get('index'), e.get('status'), e.get('on_time_ms')) != (1, 0, 100 + i // 2):
                fails.append('outstation %s callback %d: index=%r status=%r on_time_ms=%r' %
                             (e.get('kind'), i // 2, e.get('index'), e.get('status'), e.get('on_time_ms')))
    return fails


def first_packet_len(e):
    """Master-side length of a class response's first TCP segment under the declared construction (e = one class
    of read_classes.expectations): the image when the native is one segment; for a segmented class, the native
    first segment plus the added octets (the prefix frame travels with the native first frame)."""
    segments = e.get('native_segments') or [e['native']]
    return e['image'] if len(segments) == 1 else segments[0] + (e['image'] - e['native'])


def read_class_record_checks(master, expectation, read_points):
    """The master's per-READ records against the per-class expectation (read_classes.expectations): slot order,
    completion and fixture match of every READ, and with a schedule the endpoint's schedule/db, its append-only
    read_commands (function READ, class, native response size) and reads_per_class."""
    fails, m = [], master or {}
    classes, order = expectation['classes'], expectation['order']
    total = sum(e['count'] for e in classes.values())
    scheduled = expectation.get('schedule') is not None
    rs = m.get('reads')
    if not isinstance(rs, list) or len(rs) != total:
        fails.append('master reads records %r, expected %d' % (len(rs) if isinstance(rs, list) else rs, total))
        rs = []
    for i, r in enumerate(rs):
        want = order[i % len(order)]
        got = r.get('class', 'range' if not scheduled else None) if isinstance(r, dict) else None
        if got != want or r.get('completed') is not True or r.get('matches_seed') is not True or \
                (want == 'range' and r.get('points_received') != read_points):
            fails.append('READ %d: class %r completed %r matches %r points %r, expected %s%s'
                         % (i, got, r.get('completed') if isinstance(r, dict) else None,
                            r.get('matches_seed') if isinstance(r, dict) else None,
                            r.get('points_received') if isinstance(r, dict) else None, want,
                            ' with %d points' % read_points if want == 'range' else ''))
    if not scheduled:
        return fails
    for key in ('read_schedule', 'db'):
        if m.get(key) != expectation['schedule' if key == 'read_schedule' else 'db']:
            fails.append('master %s=%r, expected %r' % (key, m.get(key),
                                                         expectation['schedule' if key == 'read_schedule' else 'db']))
    commands = m.get('read_commands')
    if not isinstance(commands, list) or len(commands) != total:
        fails.append('master read_commands %r, expected %d records'
                     % (len(commands) if isinstance(commands, list) else commands, total))
        commands = []
    for i, c in enumerate(commands):
        want = order[i % len(order)]
        c = c if isinstance(c, dict) else {}
        if (c.get('slot'), c.get('class'), c.get('function_code')) != (i, want, 1) or \
                not all(c.get(k) is True for k in ('completed', 'success', 'matches_fixture')) or \
                c.get('response_link_octets') != classes[want]['native']:
            fails.append('read_commands[%d]: slot %r class %r function %r completed %r success %r fixture %r native '
                         '%r octets, expected slot %d %s READ at %d octets'
                         % (i, c.get('slot'), c.get('class'), c.get('function_code'), c.get('completed'),
                            c.get('success'), c.get('matches_fixture'), c.get('response_link_octets'), i, want,
                            classes[want]['native']))
    per = m.get('reads_per_class') if isinstance(m.get('reads_per_class'), dict) else {}
    for cls in set(per) | set(classes):
        count = classes[cls]['count'] if cls in classes else 0
        got = per.get(cls) or {'issued': 0, 'succeeded': 0}
        if got != {'issued': count, 'succeeded': count}:
            fails.append('reads_per_class[%s]=%r, expected %d issued and succeeded' % (cls, got, count))
    return fails


def read_padding_record_checks(master, padding):
    """The master's strict padding verdict, checked independently of its own matches_fixture: the endpoint must have
    been told exactly `padding` (class -> declared padding points; {} on an arm that pads nothing, which the endpoint
    reports as pad_expect 'none'), and every READ record must carry that class's declared count both as expected
    and as received."""
    fails, m = [], master or {}
    want = ','.join('%s=%d' % kv for kv in padding.items()) if padding else 'none'
    if m.get('pad_expect') != want:
        fails.append('master pad_expect=%r, expected %r' % (m.get('pad_expect'), want))
    commands = m.get('read_commands') if isinstance(m.get('read_commands'), list) else []
    if not commands:
        fails.append('master has no read_commands records to check the padding against')
    for i, c in enumerate(commands):
        c = c if isinstance(c, dict) else {}
        n = padding.get(c.get('class'), 0)
        if (c.get('padding_expected'), c.get('padding_points')) != (n, n):
            fails.append('read_commands[%d] %s: padding expected %r received %r, declared %d'
                         % (i, c.get('class'), c.get('padding_expected'), c.get('padding_points'), n))
    return fails


def read_class_timing_checks(summary, expectation):
    """clrt_check's READ by_class summary (a read_policy run): every declared class complete exactly count times at
    its first-segment length, and no READ outside the declared classes."""
    fails = []
    by_class = ((summary or {}).get('READ') or {}).get('by_class')
    if not isinstance(by_class, dict):
        return ['timing: READ by_class summary missing (clrt_check needs --read-policy)']
    for cls in sorted(set(by_class) - set(expectation['classes'])):
        fails.append('timing: READ class %s is not declared (%r)' % (cls, by_class[cls]))
    for cls, e in sorted(expectation['classes'].items()):
        item = by_class.get(cls) or {}
        want = [first_packet_len(e)]
        if item.get('logical_requests') != e['count'] or item.get('complete') != e['count'] or \
                item.get('resp_len') != want:
            fails.append('timing: READ %s logical=%r complete=%r resp_len=%r, expected %d at %s'
                         % (cls, item.get('logical_requests'), item.get('complete'), item.get('resp_len'),
                            e['count'], want))
    return fails


def application_checks(exp, padding, reads, ev, run_sbo=True, repeated=False, read_classes=None):
    """Endpoint semantics and per-function wire checks, shared by ordinary and reconnect trials. run_sbo is the
    number of SELECT/OPERATE pairs expected (a boolean means 0 or 1); repeated (from the configuration, not the
    endpoint's report) requires per-cycle records for every one of them. read_classes: the trial's per-class READ
    expectation (read_classes.expectations); the READ records and READ lengths are then checked per class."""
    fails = []
    m, o, w, t = (ev.get(k) for k in ('master', 'outstation', 'wire', 'timing'))
    for key, value in (('master', m), ('outstation', o), ('wire', w), ('timing', t)):
        if not isinstance(value, dict) or not value:
            fails.append('missing or malformed evidence: %s' % key)
    if isinstance(m, dict) and m:
        if m.get('success') is not True:
            fails.append('master did not succeed')
        if m.get('all_reads_match_seed') is not True:
            fails.append('master reports READ values that do not match the seed')
        if m.get('reads_completed') != reads or m.get('reads_requested') != reads:
            fails.append('master completed %s of %s READs, expected %d' % (m.get('reads_completed'), m.get('reads_requested'), reads))
        rs = m.get('reads')
        if read_classes is not None:
            fails += read_class_record_checks(m, read_classes, exp['common']['read_points'])
        elif not isinstance(rs, list) or len(rs) != reads or any(
                not isinstance(r, dict) or r.get('points_received') != exp['common']['read_points']
                or r.get('matches_seed') is not True or r.get('completed') is not True for r in rs):
            fails.append('READs did not return all %d seed values' % exp['common']['read_points'])
    if isinstance(o, dict) and o:
        if repeated or (isinstance(m, dict) and (m.get('sbo_cycles') or 0) > 0):
            fails += repeated_sbo_checks(m, o, int(run_sbo))
        for key in ('select_real', 'operate_real'):
            if o.get(key) != int(run_sbo):
                fails.append('outstation %s=%r, expected exactly %d real %s' %
                             (key, o.get(key), int(run_sbo), key.split('_')[0].upper()))
        for key in ('select_decoy', 'operate_decoy'):
            if o.get(key) != 0:
                fails.append('outstation saw a decoy or missing counter: %s=%r' % (key, o.get(key)))
    if isinstance(w, dict) and w:
        ri = w.get('returned_integrity')
        if not isinstance(ri, dict) or any(not isinstance(ri.get(k), list) for k in ('dnp3_crc_bad', 'tcp_checksum_bad')):
            fails.append('wire returned_integrity is missing or malformed')
        else:
            if ri['dnp3_crc_bad']:
                fails.append('returned frames with a bad DNP3 CRC: %s' % ri['dnp3_crc_bad'])
            if ri['tcp_checksum_bad']:
                fails.append('returned frames with a bad IP/TCP checksum: %s' % ri['tcp_checksum_bad'])
    if isinstance(t, dict) and t:
        summ = t.get('summary')
        if not isinstance(summ, dict):
            fails.append('timing summary is missing or malformed')
            return fails
        pad = exp['padding'][str(padding)]
        functions = [('READ', reads, pad['read_resp_len'])] + (
            [(kind, int(run_sbo), pad['sbo_resp_len']) for kind in SBO] if run_sbo else [])
        for kind, count, lengths in functions:
            item = summ.get(kind)
            if not isinstance(item, dict) or not item:
                fails.append('timing: no %s exchange extracted' % kind)
                continue
            if item.get('logical_requests') != count or item.get('complete') != count or item.get('incomplete') != 0:
                fails.append('timing: %s complete=%r incomplete=%r logical=%r, expected %d complete exchanges' %
                             (kind, item.get('complete'), item.get('incomplete'), item.get('logical_requests'), count))
            piggy = item.get('piggyback')
            if not isinstance(piggy, int) or isinstance(piggy, bool) or not 0 <= piggy <= count:
                fails.append('timing: %s piggyback count is missing or malformed' % kind)
            if item.get('req_crc_bad') != 0 or item.get('resp_crc_bad') != 0:
                fails.append('timing: %s DNP3 CRC failures or missing counts' % kind)
            if kind == 'READ' and read_classes is not None:
                fails += read_class_timing_checks(summ, read_classes)
            elif item.get('resp_len') != lengths:
                fails.append('%s response length %s on the master side, expected %s (padding %d)' %
                             (kind, item.get('resp_len'), lengths, padding))
        if not run_sbo and any(summ.get(kind, {}).get('logical_requests', 0) for kind in SBO):
            fails.append('timing: SBO exchanges occurred with run_sbo disabled')
    return fails


def _finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def visible_clrt(timing):
    """The CLRT (ACK -> response, clrt_check's clrt_us) the master side shows per DNP3 function, reported as data and
    never compared against a threshold: n, min, median, max and every value in microseconds over complete,
    non-piggybacked exchanges with a finite CLRT. Piggybacked exchanges have no separate CLRT and are counted apart."""
    out = {}
    for kind in ('READ',) + SBO:
        rows = [r for r in (timing or {}).get('exchanges', []) if isinstance(r, dict) and r.get('kind') == kind]
        values = sorted(r['clrt_us'] for r in rows
                        if r.get('complete') is True and not r.get('piggyback') and _finite(r.get('clrt_us')))
        out[kind] = dict(n=len(values), piggyback=sum(bool(r.get('piggyback')) for r in rows),
                         min_us=values[0] if values else None,
                         median_us=statistics.median(values) if values else None,
                         max_us=values[-1] if values else None, values_us=values)
    return out


def _delta_outcomes(before, after, timing_contract=None, require_no_bypass=False):
    recovery = ('OUT_REQ_DUP_DROP', 'OUT_REQ_DUP_FORWARD') if timing_contract == 'response_ready_ack_d_v2' else \
             ('OUT_ACK_FALLBACK', 'OUT_RESP_FALLBACK')
    required = ('OUT_ACK_COMMIT', 'OUT_RESP_RELEASE', 'OUT_OP_RELEASE', 'OUT_TOKEN_STALE') + recovery
    if require_no_bypass:
        required += ('OUT_REQ_BYPASS',)
    for snap in (before, after):
        for key in required:
            value = snap['outcomes'][key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise TypeError('required outcome is unreadable: %s' % key)
    return {k: (after['outcomes'].get(k) or 0) - ((before['outcomes'].get(k) or 0)) for k in after['outcomes']}


def stale_delta(before, after, diagnostic=False):
    """Production index 6 or the mandatory six-source sum on diagnostic builds."""
    if diagnostic or any(s.get('diag', {}).get('present') for s in (before, after)):
        if not all(s.get('diag', {}).get('present') for s in (before, after)):
            raise ValueError('diagnostic stale counters: snapshot build changed')
        try:
            delta = {str(i): after['diag']['stale'][str(i)] - before['diag']['stale'][str(i)]
                     for i in range(19, 25)}
        except (KeyError, TypeError):
            raise ValueError('diagnostic stale counters 19..24 are missing or unreadable')
        if any(v < 0 for v in delta.values()):
            raise ValueError('diagnostic stale counters decreased between snapshots')
        return sum(delta.values()), delta
    try:
        return after['outcomes']['OUT_TOKEN_STALE'] - before['outcomes']['OUT_TOKEN_STALE'], None
    except (KeyError, TypeError):
        raise ValueError('OUT_TOKEN_STALE counter is missing or unreadable')


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


def _mirror_checks(mx, arm, reads, sbo_count, b, a, k, fails, obs, max_stale=0, control_timed=False):
    """Generator counters (snapshot pktgen block, after minus before) on a build carrying the compiler-mirror
    fix: T on -> READ triggers == READs, READ packets == 2k per trigger, OPERATE triggers == SBOs, stale == 0;
    T off -> no generator activity at all (what the T-off silicon evidence shows)."""
    try:
        d = {}
        for app in ('READ', 'OPERATE'):
            d[app] = {'triggers': a['pktgen'][app]['trigger_counter'] - b['pktgen'][app]['trigger_counter'],
                      'pkts': a['pktgen'][app]['pkt_counter'] - b['pktgen'][app]['pkt_counter']}
    except (KeyError, TypeError):
        fails.append('mirror_fix build: the snapshots carry no pktgen trigger/packet counters')
        return
    obs['pktgen'] = d
    sbo = sbo_count
    if arm['T']:
        # control-timed builds (ctl_timing_01) admit each SELECT as a READ-lane request, which seeds READ blockers
        lane = reads + (sbo if control_timed else 0)
        want = {'READ': (lane, 2 * k * lane), 'OPERATE': (sbo, 2 * k * sbo)}
        for app, (trig, pkts) in want.items():
            if d[app]['triggers'] != trig:
                fails.append('T on: %s trigger delta %d, expected %d' % (app, d[app]['triggers'], trig))
            if d[app]['pkts'] != pkts:
                fails.append('T on: generated %s packets delta %d, expected %d (2k = %d per trigger)'
                             % (app, d[app]['pkts'], pkts, 2 * k))
        if not isinstance(obs.get('outcomes'), dict):
            obs['token_stale_bound'] = 'unknown: no switch telemetry in this build'
            return
        stale = (obs.get('outcomes') or {}).get('OUT_TOKEN_STALE') or 0
        # control-timed builds: the OPERATE opens the next READ-lane generation milliseconds after its SELECT's
        # response, so at most the SELECT's 2k blocker tokens are stranded and rejected as stale per cycle
        # (silicon ctl_timing_repeat_sbo_950_b1: 88 over 64 cycles, raw timer stale 0). Bound them explicitly.
        bound = max_stale + (2 * k * sbo if control_timed else 0)
        obs['token_stale_bound'] = bound
        if stale > bound:
            fails.append('T on, mirror_fix build: OUT_TOKEN_STALE delta %d exceeds the build bound %d'
                         % (stale, bound))
    else:
        for app in mx['T0']['zero_triggers']:
            if d[app]['triggers'] or d[app]['pkts']:
                fails.append('T off: %s trigger delta %d and packet delta %d, expected none (generator idle)'
                             % (app, d[app]['triggers'], d[app]['pkts']))


def evaluate(exp, arm, fixture, reads, ev, allowed=None, mirror_k=None, max_stale=0, diagnostic=False, run_sbo=True,
             repeated=False, control_timed=False, piggyback_bound=False, op_j_ns=None,
             gen_exhausted_outcome=None, read_classes=None):
    """mirror_k: the installer --k when the build is flagged mirror_fix (adds the generator-trigger checks), else None.

    CLRT is reported without a threshold. The READ piggyback fraction must identify the configured fixture.
    The software OPERATE hold check (op_j_ns given, timed arm with SBO, over ev['hold'] from hold_check.analyze
    of the trial's own captures) requires delivery and every transit >= op_j. Missing hold evidence fails.
    """
    allowed = allowed or {}
    fails, obs = [], {}
    need = [k for k in ('before', 'after', 'master', 'outstation', 'wire', 'timing') if not ev.get(k)]
    for k in need:
        fails.append('missing evidence: %s' % ('%s snapshot' % k if k in ('before', 'after') else k))
    fails += application_checks(exp, arm['padding'], reads, ev, run_sbo, repeated, read_classes)
    t = ev.get('timing')
    summary = t.get('summary', {}) if isinstance(t, dict) else {}
    summary = summary if isinstance(summary, dict) else {}
    rd = summary.get('READ', {})
    rd = rd if isinstance(rd, dict) else {}
    if isinstance(rd, dict) and isinstance(rd.get('complete'), int) and isinstance(rd.get('piggyback'), int):
        frac = rd['piggyback'] / rd['complete'] if rd['complete'] else 0.0
        obs['piggyback_fraction'] = round(frac, 4)
        lo, hi = exp['fixture'][fixture]['piggyback_fraction']
        if not lo <= frac <= hi:
            fails.append('piggyback fraction %.3f outside %s for fixture %s' % (frac, [lo, hi], fixture))
    if isinstance(t, dict):
        native = exp['native_len']
        first = {cls: (e.get('native_segments') or [e['native']])[0]
                 for cls, e in ((read_classes or {}).get('classes') or {}).items()}

        def native_of(e):        # per class: the native first segment of the exchange's own class
            if read_classes is not None and e['kind'] == 'READ':
                return first.get(e.get('read_class'), e['resp_len'])
            return native.get(e['kind'], e['resp_len'])
        obs['growth_bytes'] = sum(e['resp_len'] - native_of(e)
                                 for e in t.get('exchanges', []) if isinstance(e, dict) and e.get('resp_len'))
        pad = exp['padding'][str(arm['padding'])]
        if pad['growth'] == 'zero' and obs['growth_bytes'] != 0:
            fails.append('padding off but master-visible response growth is %d B' % obs['growth_bytes'])
        if pad['growth'] == 'positive' and obs['growth_bytes'] <= 0:
            fails.append('padding on but master-visible response growth is %d B (expected > 0)' % obs['growth_bytes'])
        obs['visible_clrt'] = visible_clrt(t)
    if op_j_ns is not None:
        import hold_check     # campaign-side only: checks.py is also deployed alone beside vision_candidate.py
        operate = summary.get('OPERATE') if isinstance(summary.get('OPERATE'), dict) else {}
        obs['operate_hold'] = hold_check.operate_hold(ev.get('hold'), op_j_ns, operate.get('complete'), int(run_sbo))
        obs['operate_hold']['gated'] = bool(arm['T'] and run_sbo)
        if obs['operate_hold']['gated'] and not obs['operate_hold']['pass']:
            fails.append('OPERATE hold: %s' % '; '.join(obs['operate_hold']['reasons']))

    switch_fails, switch_obs = evaluate_switch(
        exp, arm, reads, ev, allowed, mirror_k, max_stale, diagnostic,
        sbo_count=int(run_sbo), complete_reads=rd.get('complete'), piggyback_reads=rd.get('piggyback'),
        control_timed=control_timed, piggyback_bound=piggyback_bound, gen_exhausted_outcome=gen_exhausted_outcome,
        piggyback_controls=sum((summary.get(k) or {}).get('piggyback') or 0 for k in SBO if isinstance(summary.get(k), dict)))
    return fails + switch_fails, dict(obs, **switch_obs)


def evaluate_switch(exp, arm, reads, ev, allowed=None, mirror_k=None, max_stale=0, diagnostic=False,
                    sbo_count=1, complete_reads=None, piggyback_reads=0, control_timed=False, piggyback_bound=False,
                    piggyback_controls=0, gen_exhausted_outcome=None, timing_contract=None, telemetry=True):
    """Switch deltas for installed traffic; callers supply the number of installed READs and SBOs.

    Reconnect's unknown-port connection is native and contributes no installed generator/release counts.
    telemetry=False (c68: the build has no T outcomes or N count registers): the outcome expectations are skipped;
    the snapshot-presence, generator and loop-port checks, which read SDE and port state, still gate.
    """
    allowed = allowed or {}
    fails, obs = [], {}
    for key in ('before', 'after'):
        if not ev.get(key):
            fails.append('missing evidence: %s snapshot' % key)
    b, a = ev.get('before'), ev.get('after')
    require_no_bypass = bool(timing_contract == 'response_ready_ack_d_v2' and arm['T'] and
                             (reads > 0 or control_timed and sbo_count > 0))
    if a and b and not telemetry:
        obs['outcomes'] = 'no switch telemetry in this build'
    if a and b and telemetry:
        try:
            d = _delta_outcomes(b, a, timing_contract, require_no_bypass)
        except (KeyError, TypeError) as err:
            d = None
            fails.append('snapshots carry missing or unreadable outcomes: %s' % err)
        if d is not None:
            try:
                stale, sources = stale_delta(b, a, diagnostic)
                d['OUT_TOKEN_STALE'] = stale
                if sources is not None:
                    obs['stale_sources'] = sources
            except ValueError as err:
                fails.append(str(err))
                d['OUT_TOKEN_STALE'] = None
            if timing_contract == 'response_ready_ack_d_v2':
                obs.update(request_duplicates_dropped=d['OUT_REQ_DUP_DROP'],
                           request_duplicates_forwarded=d['OUT_REQ_DUP_FORWARD'])
                for key in ('OUT_REQ_DUP_DROP', 'OUT_REQ_DUP_FORWARD'):
                    if d[key] < 0:
                        fails.append('request duplicate counter decreased: %s=%s' % (key, d[key]))
            obs['outcomes'] = d
            obs['token_stale'] = d.get('OUT_TOKEN_STALE')      # unreadable evidence stays unknown
            # GEN_EXHAUSTED (T outcome 15 where the build declares it, build.gen_exhausted_outcome; snapshots name
            # it index_15): a request or OPERATE dropped because its generation allocator was exhausted. Never
            # silent: any such drop fails the trial, and so does a declared counter missing from the snapshots.
            # On other builds the index means something else (route_ab_01, stale_split_diag_01: a diagnostic RESP
            # re-wait counter), so it is not gated there and is recorded not_applicable.
            if gen_exhausted_outcome is None:
                obs['generation_exhausted'] = 'not_applicable'
            else:
                key = 'index_%d' % gen_exhausted_outcome
                exhausted = d.get('OUT_GEN_EXHAUSTED', d.get(key))
                obs['generation_exhausted'] = exhausted
                if not isinstance(exhausted, int) or isinstance(exhausted, bool):
                    fails.append('generation exhausted: the build declares outcome %d (OUT_GEN_EXHAUSTED) but the '
                                 'snapshots carry no readable %s' % (gen_exhausted_outcome, key))
                elif exhausted:
                    fails.append('generation exhausted: %s request/OPERATE drop(s) (OUT_GEN_EXHAUSTED)' % exhausted)
            if arm['T']:
                te = exp['T']['1']
                complete = complete_reads if isinstance(complete_reads, int) else reads
                piggy = piggyback_reads if isinstance(piggyback_reads, int) else 0
                # candidate61 times READ only; control-timed builds also time SELECT and OPERATE (each one ACK commit
                # and one release unless piggybacked); a piggyback-bound build releases piggybacked responses by the
                # bound (RESP_RELEASE) instead of the readiness fallback.
                controls = 2 * sbo_count if control_timed else 0
                piggy_ctl = (piggyback_controls if isinstance(piggyback_controls, int) else 0) if control_timed else 0
                piggy_all = piggy + piggy_ctl
                wanted = {'OUT_ACK_COMMIT': complete - piggy + controls - piggy_ctl,
                          'OUT_RESP_RELEASE': complete - piggy + controls - piggy_ctl + (piggy_all if piggyback_bound else 0),
                          'OUT_ACK_FALLBACK': 0, 'OUT_RESP_FALLBACK': 0 if piggyback_bound else piggy_all}
                if timing_contract == 'response_ready_ack_d_v2':
                    wanted.pop('OUT_ACK_FALLBACK')
                    wanted.pop('OUT_RESP_FALLBACK')
                    if require_no_bypass:
                        wanted['OUT_REQ_BYPASS'] = 0
                for k, count in wanted.items():
                    if d.get(k) != count:
                        fails.append('T on: %s=%s, expected %d (complete READs=%d, piggyback=%d)' %
                                     (k, d.get(k), count, complete, piggy))
                op_release = te['op_release_when_sbo'] * sbo_count
                if d.get('OUT_OP_RELEASE') != op_release:
                    fails.append('T on: OUT_OP_RELEASE=%s, expected %d' % (d.get('OUT_OP_RELEASE'),
                                                                         op_release))
            else:
                for k in set(exp['T']['0']['zero_outcomes']) | {'OUT_ACK_FALLBACK', 'OUT_RESP_FALLBACK'}:
                    if d.get(k):
                        fails.append('T off but %s=%s (expected 0)' % (k, d[k]))
    if a and b:
        if mirror_k is not None:
            _mirror_checks(exp['mirror_fix'], arm, reads, sbo_count, b, a, mirror_k, fails, obs, max_stale, control_timed)
        gaps = _loop_gap(b, a)
        obs['loop_octet_gap'] = {r: g for r, (g, e) in gaps.items()}
        for role, (g, err) in gaps.items():
            if err:
                fails.append(err)
            elif g > allowed.get(role, 0):
                fails.append('loop port %s: %d received octets were not in good frames (allowed %d)'
                             % (role, g, allowed.get(role, 0)))
    return fails, obs
