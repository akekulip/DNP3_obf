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
            out[k] = json.load(open(p)) if p else None
        except (OSError, ValueError):
            out[k] = None
    return out


def _delta_outcomes(before, after):
    return {k: (after['outcomes'].get(k) or 0) - ((before['outcomes'].get(k) or 0)) for k in after['outcomes']}


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


def _mirror_checks(mx, arm, reads, o, b, a, k, fails, obs, max_stale=0):
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
    sbo = 1 if (o and o.get('select_real') == 1 and o.get('operate_real') == 1) else 0
    if arm['T']:
        want = {'READ': (reads, 2 * k * reads), 'OPERATE': (sbo, 2 * k * sbo)}
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


def evaluate(exp, arm, fixture, reads, ev, allowed=None, mirror_k=None, max_stale=0):
    """mirror_k: the installer --k when the build is flagged mirror_fix (adds the generator-trigger checks), else None."""
    allowed = allowed or {}
    fails, obs = [], {}
    need = [k for k in ('before', 'after', 'master', 'outstation', 'wire', 'timing') if not ev.get(k)]
    for k in need:
        fails.append('missing evidence: %s' % ('%s snapshot' % k if k in ('before', 'after') else k))
    com = exp['common']

    m, o = ev.get('master'), ev.get('outstation')
    if m:
        if not m.get('success'):
            fails.append('master did not succeed')
        if not m.get('all_reads_match_seed'):
            fails.append('master reports READ values that do not match the seed')
        if m.get('reads_completed') != reads or m.get('reads_requested') != reads:
            fails.append('master completed %s of %s READs, expected %d' % (m.get('reads_completed'),
                                                                          m.get('reads_requested'), reads))
        bad = [i for i, r in enumerate(m.get('reads', []))
               if r.get('points_received') != com['read_points'] or not r.get('matches_seed') or not r.get('completed')]
        if bad or len(m.get('reads', [])) != reads:
            fails.append('READs %s did not return all %d seed values' % (bad[:10] or 'missing', com['read_points']))
    if o:
        for k in ('select_real', 'operate_real'):
            if o.get(k) != 1:
                fails.append('outstation %s=%r, expected exactly 1 real %s' % (k, o.get(k), k.split('_')[0].upper()))
        for k in ('select_decoy', 'operate_decoy'):
            if o.get(k):
                fails.append('outstation saw a decoy: %s=%r' % (k, o.get(k)))

    w = ev.get('wire')
    if w:
        ri = w.get('returned_integrity', {})
        if ri.get('dnp3_crc_bad'):
            fails.append('returned frames with a bad DNP3 CRC: %s' % ri['dnp3_crc_bad'])
        if ri.get('tcp_checksum_bad'):
            fails.append('returned frames with a bad IP/TCP checksum: %s' % ri['tcp_checksum_bad'])

    t = ev.get('timing')
    if t:
        summ = t.get('summary', {})
        rd = summ.get('READ')
        if not rd:
            fails.append('timing: no READ exchanges extracted')
        else:
            if rd['complete'] != reads or rd['incomplete']:
                fails.append('timing: %d READs complete (%d incomplete), expected %d'
                             % (rd['complete'], rd['incomplete'], reads))
            if rd['req_crc_bad'] or rd['resp_crc_bad']:
                fails.append('timing: READ DNP3 CRC failures req=%d resp=%d' % (rd['req_crc_bad'], rd['resp_crc_bad']))
            frac = rd['piggyback'] / rd['complete'] if rd['complete'] else 0.0
            obs['piggyback_fraction'] = round(frac, 4)
            lo, hi = exp['fixture'][fixture]['piggyback_fraction']
            if not lo <= frac <= hi:
                fails.append('piggyback fraction %.3f outside %s for fixture %s' % (frac, [lo, hi], fixture))
        pad = exp['padding'][str(arm['padding'])]
        for kind_, want in (('READ', pad['read_resp_len']),) + tuple((k, pad['sbo_resp_len']) for k in SBO):
            k = summ.get(kind_)
            if not k:
                fails.append('timing: no %s exchange extracted' % kind_)
            elif k['resp_len'] != want:
                fails.append('%s response length %s on the master side, expected %s (padding %d)'
                             % (kind_, k['resp_len'], want, arm['padding']))
        native = exp['native_len']
        obs['growth_bytes'] = sum(e['resp_len'] - native.get(e['kind'], e['resp_len'])
                                  for e in t.get('exchanges', []) if e.get('resp_len'))
        if pad['growth'] == 'zero' and obs['growth_bytes'] != 0:
            fails.append('padding off but master-visible response growth is %d B' % obs['growth_bytes'])
        if pad['growth'] == 'positive' and obs['growth_bytes'] <= 0:
            fails.append('padding on but master-visible response growth is %d B (expected > 0)' % obs['growth_bytes'])

    b, a = ev.get('before'), ev.get('after')
    if a and b:
        try:
            d = _delta_outcomes(b, a)
        except (KeyError, TypeError):
            d = None
            fails.append('snapshots carry no outcomes block')
        if d is not None:
            obs['outcomes'] = d
            obs['token_stale'] = d.get('OUT_TOKEN_STALE') or 0      # recorded for every trial, bounded per build
            if arm['T']:
                te = exp['T']['1']
                for k in ('OUT_ACK_COMMIT', 'OUT_RESP_RELEASE'):
                    if d.get(k) != reads:
                        fails.append('T on: %s=%s, expected %d (one per READ)' % (k, d.get(k), reads))
                sbo = bool(o and o.get('select_real') == 1 and o.get('operate_real') == 1)
                if sbo and d.get('OUT_OP_RELEASE') != te['op_release_when_sbo']:
                    fails.append('T on: OUT_OP_RELEASE=%s, expected %d' % (d.get('OUT_OP_RELEASE'),
                                                                         te['op_release_when_sbo']))
                if fixture in te['fallback_zero_fixtures']:
                    for k in ('OUT_ACK_FALLBACK', 'OUT_RESP_FALLBACK'):
                        if d.get(k):
                            fails.append('T on, on-time fixture %s: %s=%s, expected 0' % (fixture, k, d[k]))
            else:
                for k in exp['T']['0']['zero_outcomes']:
                    if d.get(k):
                        fails.append('T off but %s=%s (expected 0)' % (k, d[k]))
        if mirror_k is not None:
            _mirror_checks(exp['mirror_fix'], arm, reads, o, b, a, mirror_k, fails, obs, max_stale)
        gaps = _loop_gap(b, a)
        obs['loop_octet_gap'] = {r: g for r, (g, e) in gaps.items()}
        for role, (g, err) in gaps.items():
            if err:
                fails.append(err)
            elif g > allowed.get(role, 0):
                fails.append('loop port %s: %d received octets were not in good frames (allowed %d)'
                             % (role, g, allowed.get(role, 0)))
    return fails, obs
