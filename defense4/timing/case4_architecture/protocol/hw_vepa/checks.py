"""Per-trial feature and outcome checks, computed from one trial's OWN evidence and enforced by the campaign gate.

  checks.evaluate(expectations, arm, fixture, reads, evidence, allowed_gap) -> (failures, observed)

`expectations` is the single table in campaign.json (`expectations`; README repeats it). `evidence` is a dict:
  before, after   the trial's counter snapshots (snapshot_counters.py): outcomes + loop_ports
  master          Vision master.json          outstation   Vision outstation.json
  wire            wire_check.analyze() / wire.json
  timing          clrt_check.analyze() / timing.json (summary per DNP3 function + per-exchange rows)
A missing or unreadable piece of evidence is a failure, never a crash and never a silent pass. Stdlib only.
"""
import json
import math

import clrt_check

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


def load_evidence_files(before=None, after=None, master=None, outstation=None, wire=None, timing=None):
    """Read whichever evidence files exist; an unreadable one becomes None (and so a reported failure)."""
    out = {}
    for k, p in (('before', before), ('after', after), ('master', master), ('outstation', outstation),
                 ('wire', wire), ('timing', timing)):
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


def application_checks(exp, padding, reads, ev, run_sbo=True, repeated=False):
    """Endpoint semantics and per-function wire checks, shared by ordinary and reconnect trials. run_sbo is the
    number of SELECT/OPERATE pairs expected (a boolean means 0 or 1); repeated (from the configuration, not the
    endpoint's report) requires per-cycle records for every one of them."""
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
        if not isinstance(rs, list) or len(rs) != reads or any(
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
            if item.get('resp_len') != lengths:
                fails.append('%s response length %s on the master side, expected %s (padding %d)' %
                             (kind, item.get('resp_len'), lengths, padding))
        if not run_sbo and any(summ.get(kind, {}).get('logical_requests', 0) for kind in SBO):
            fails.append('timing: SBO exchanges occurred with run_sbo disabled')
    return fails


def read_precision(timing, gap_ns):
    """READ-only absolute error using clrt_check's declared percentile convention."""
    excluded = dict(incomplete=0, piggyback=0, multiple_attempts=0, missing_clrt=0)
    errors, tails, total = [], [], 0
    for row in timing.get('exchanges', []):
        if not isinstance(row, dict) or row.get('kind') != 'READ':
            continue
        total += 1
        reason = ('incomplete' if row.get('complete') is not True else
                  'piggyback' if row.get('piggyback') else
                  'multiple_attempts' if row.get('attempts') != 1 else None)
        value = row.get('clrt_us')
        if reason is None and (not isinstance(value, (int, float)) or isinstance(value, bool) or not math.isfinite(value)):
            reason = 'missing_clrt'
        if reason:
            excluded[reason] += 1
            continue
        error = value - gap_ns / 1000.0
        errors.append(error)
        tails.append(dict(t_req=row.get('t_req'), clrt_us=value, error_us=error))
    absolute = clrt_check.stats([abs(e) for e in errors])
    return dict(gap_us=gap_ns / 1000.0, read_rows=total, eligible=len(errors), excluded=excluded,
                minimum_eligible=20, maximum_p99_absolute_error_us=100,
                absolute_error_us=absolute, signed_error_us=clrt_check.stats(errors),
                tails=sorted(tails, key=lambda row: abs(row['error_us']), reverse=True)[:5],
                **{'pass': len(errors) >= 20 and absolute is not None and absolute['p99'] <= 100})


def _delta_outcomes(before, after):
    for snap in (before, after):
        for key in ('OUT_ACK_COMMIT', 'OUT_ACK_FALLBACK', 'OUT_RESP_RELEASE', 'OUT_RESP_FALLBACK',
                    'OUT_OP_RELEASE', 'OUT_TOKEN_STALE'):
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
        stale = (obs.get('outcomes') or {}).get('OUT_TOKEN_STALE') or 0
        if stale > max_stale:
            fails.append('T on, mirror_fix build: OUT_TOKEN_STALE delta %d exceeds the build bound %d'
                         % (stale, max_stale))
    else:
        for app in mx['T0']['zero_triggers']:
            if d[app]['triggers'] or d[app]['pkts']:
                fails.append('T off: %s trigger delta %d and packet delta %d, expected none (generator idle)'
                             % (app, d[app]['triggers'], d[app]['pkts']))


def evaluate(exp, arm, fixture, reads, ev, allowed=None, mirror_k=None, max_stale=0, diagnostic=False, gap_ns=None, precision=True, run_sbo=True,
             repeated=False, control_timed=False, piggyback_bound=False):
    """mirror_k: the installer --k when the build is flagged mirror_fix (adds the generator-trigger checks), else None."""
    allowed = allowed or {}
    fails, obs = [], {}
    need = [k for k in ('before', 'after', 'master', 'outstation', 'wire', 'timing') if not ev.get(k)]
    for k in need:
        fails.append('missing evidence: %s' % ('%s snapshot' % k if k in ('before', 'after') else k))
    fails += application_checks(exp, arm['padding'], reads, ev, run_sbo, repeated)
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
        obs['growth_bytes'] = sum(e['resp_len'] - native.get(e['kind'], e['resp_len'])
                                 for e in t.get('exchanges', []) if isinstance(e, dict) and e.get('resp_len'))
        pad = exp['padding'][str(arm['padding'])]
        if pad['growth'] == 'zero' and obs['growth_bytes'] != 0:
            fails.append('padding off but master-visible response growth is %d B' % obs['growth_bytes'])
        if pad['growth'] == 'positive' and obs['growth_bytes'] <= 0:
            fails.append('padding on but master-visible response growth is %d B (expected > 0)' % obs['growth_bytes'])
        if gap_ns is not None:
            obs['read_precision'] = read_precision(t, gap_ns)
            obs['read_precision']['gated'] = bool(precision and arm['T'] and fixture == 'separate_ack')
            if obs['read_precision']['gated'] and not obs['read_precision']['pass']:
                fails.append('READ precision: eligible=%d (minimum20), p99 absolute CLRT error=%s us (maximum100)' %
                             (obs['read_precision']['eligible'], (obs['read_precision']['absolute_error_us'] or {}).get('p99')))

    switch_fails, switch_obs = evaluate_switch(
        exp, arm, reads, ev, allowed, mirror_k, max_stale, diagnostic,
        sbo_count=int(run_sbo), complete_reads=rd.get('complete'), piggyback_reads=rd.get('piggyback'),
        control_timed=control_timed, piggyback_bound=piggyback_bound,
        piggyback_controls=sum((summary.get(k) or {}).get('piggyback') or 0 for k in SBO if isinstance(summary.get(k), dict)))
    return fails + switch_fails, dict(obs, **switch_obs)


def evaluate_switch(exp, arm, reads, ev, allowed=None, mirror_k=None, max_stale=0, diagnostic=False,
                    sbo_count=1, complete_reads=None, piggyback_reads=0, control_timed=False, piggyback_bound=False,
                    piggyback_controls=0):
    """Switch deltas for installed traffic; callers supply the number of installed READs and SBOs.

    Reconnect's unknown-port connection is native and contributes no installed generator/release counts.
    """
    allowed = allowed or {}
    fails, obs = [], {}
    for key in ('before', 'after'):
        if not ev.get(key):
            fails.append('missing evidence: %s snapshot' % key)
    b, a = ev.get('before'), ev.get('after')
    if a and b:
        try:
            d = _delta_outcomes(b, a)
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
            obs['outcomes'] = d
            obs['token_stale'] = d.get('OUT_TOKEN_STALE')      # unreadable evidence stays unknown
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
