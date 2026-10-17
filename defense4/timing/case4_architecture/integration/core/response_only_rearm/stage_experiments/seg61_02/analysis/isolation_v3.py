#!/usr/bin/env python3
"""Recompute a retained isolation block under acceptance version 3, as a separate file (review of 7637390c1).

  python3 isolation_v3.py RUN_DIR [RUN_DIR ...]      # writes RUN_DIR/isolation_v3.json for each
  python3 isolation_v3.py RUN_DIR --config CONFIG     # also binds the verdict to the block's own config: its sha256
                                                     # must be the run's config_file_sha256 and its
                                                     # acceptance_version this version, else the verdict is FAIL

Version 3 (rearm_01/hw/token_window.py: full_run_rejections_v3, drain_timing_v3) answers three questions apart:
  old_tokens_rejected   the old cohort was conserved: raw rejections equal the derived population, none after drain,
                        and stale-blocker retirements within the joint seeding bound;
  traffic_correct       every v1 component that judges the connections, restoration, quiet polls, bank isolation
                        and post-traffic authority, carried unchanged from the block's v1 verdict;
  cleanup_deadline      PASS / FAIL / INDETERMINATE from the switch poller's bracketed drain. Without a poller it is
                        INDETERMINATE: the v1 detection tick bounds detection, not the drain.
The v1 verdict is never modified. Each v1 failure is attributed to one named component through the explicit table
V1_FAILURE_COMPONENT. A failure matching no entry, or a v1 component missing from the verdict, blocks.
"""
import json
import re
import sys
from pathlib import Path

HW = Path(__file__).resolve().parents[5] / 'evidence/rearm_01/hw'
sys.path.insert(0, str(HW))
import token_window as tw  # noqa: E402

# v1 top-level failure prefix -> component, and which v3 judgement replaces it (None: carried unchanged)
V1_FAILURE_COMPONENT = (
    (r'^window: cleanup bound exceeded: ', 'cleanup', 'cleanup_deadline'),
    (r'^missing full-run rejection evidence: ', 'full_run', 'old_tokens_rejected'),
    (r'^switch: T on, mirror_fix build: OUT_TOKEN_STALE delta \d+ exceeds the build bound \d+$', 'switch_stale_bound',
     'old_tokens_rejected'),
)
TRAFFIC_COMPONENTS = ('restore', 'quiet_polls', 'bank_isolation', 'post_traffic_authority')


def one(path, pattern):
    found = sorted(Path(path).glob(pattern))
    if len(found) != 1:
        raise SystemExit('%s: expected one %s, found %d' % (path, pattern, len(found)))
    return found[0]


def binding(run, config):
    """The acceptance version a block was bound to, checked against the run's own record."""
    import hashlib
    record = json.loads((run / 'campaign_run.json').read_text())
    sha = hashlib.sha256(Path(config).read_bytes()).hexdigest()
    version = json.loads(Path(config).read_text()).get('acceptance_version')
    ok = sha == record.get('config_file_sha256') and version == tw.ACCEPTANCE_V3
    return dict(config=str(config), config_sha256=sha, run_config_sha256=record.get('config_file_sha256'),
                acceptance_version=version, ok=ok)


def recompute(run, config=None):
    run = Path(run)
    verdict_path = one(run, '*/*/*/isolation_verdict.json')
    trial = verdict_path.parent
    v1 = json.loads(verdict_path.read_text())
    window = json.loads((run / 'token_window_observer.json').read_text())
    window = window.get('window', window)
    before = json.loads(one(trial / 'snapshots', '*_before.json').read_text())
    after = json.loads(one(trial / 'snapshots', '*_after.json').read_text())
    quiet_end, population, bound = window['after'], window['population'], window['plan'].get('bound')
    control = bound is None
    out = dict(acceptance=tw.ACCEPTANCE_V3, run=run.name, mode='control' if control else 'isolation',
               v1_verdict_file=str(verdict_path.relative_to(run)), v1_ok=v1.get('ok'),
               v1_failures=v1.get('failures'))
    # attribute every v1 failure; unknown ones block
    attributed, unknown = [], []
    for failure in v1.get('failures') or []:
        hit = next(((c, q) for pattern, c, q in V1_FAILURE_COMPONENT if re.match(pattern, failure)), None)
        (attributed if hit else unknown).append(dict(failure=failure, component=hit[0] if hit else None,
                                                     replaced_by=hit[1] if hit else None))
    out['v1_failure_attribution'], out['unattributed_v1_failures'] = attributed, unknown
    # 1. old tokens rejected
    try:
        proof = tw.full_run_rejections_v3(before, after, quiet_end, population, control=control)
        blockers = proof['strict_stale_total'] - proof['raw_timer_rejections'] - proof['raw_operate_rejections']
        bounds = sorted({int(x) for x in re.findall(r'"token_stale_bound": (\d+)', verdict_path.read_text())})
        stale_bound_ok = len(bounds) == 1 and blockers <= bounds[0]
        out['old_tokens_rejected'] = dict(verdict=tw.V3_PASS if stale_bound_ok else tw.V3_FAIL, proof=proof,
                                          stale_blockers=blockers, token_stale_bound=bounds,
                                          note='checks.py bound applied to STALE_BLOCKER only')
    except ValueError as error:
        out['old_tokens_rejected'] = dict(verdict=tw.V3_FAIL, failure=str(error))
    # 2. subsequent traffic correct: carried v1 components, each present and ok
    missing = [c for c in TRAFFIC_COMPONENTS if not isinstance(v1.get(c), dict) or 'ok' not in v1[c]]
    # control mode writes no READ-IPG delay, so v1 records restore as not applicable (ok None); exactly that, and
    # only there, is accepted for restore
    na = {'restore'} if control else set()
    bad = [c for c in TRAFFIC_COMPONENTS if c not in missing
           and not (v1[c]['ok'] is True or (c in na and v1[c]['ok'] is None and not v1[c].get('failures')))]
    conns = window.get('connections') or v1.get('connections') or {}
    conn_bad = [k for k, x in (conns.items() if isinstance(conns, dict) else []) if not (isinstance(x, dict)
                and x.get('ok') is True)]
    if not conns:
        missing.append('connections')
    series = v1.get('vision_series_ok')
    out['traffic_correct'] = dict(
        verdict=tw.V3_PASS if not (missing or bad or conn_bad) and series is True and not unknown else tw.V3_FAIL,
        components={c: (v1.get(c) or {}).get('ok') for c in TRAFFIC_COMPONENTS}, connections_failed=conn_bad,
        vision_series_ok=series, missing_components=missing, unattributed_v1_failures=len(unknown))
    # 3. cleanup deadline
    poll = trial / 'diag_poll.jsonl'
    samples = [json.loads(line) for line in poll.read_text().splitlines() if line.strip()] if poll.is_file() else []
    if control:
        out['cleanup_deadline'] = dict(verdict='NOT_APPLICABLE', reason='control: no delayed cohort, no deadline')
    elif not samples:
        out['cleanup_deadline'] = dict(verdict=tw.V3_INDETERMINATE, reason='no switch poller in this block',
                                       v1_detection_elapsed_ns=(v1.get('cleanup') or {}).get('elapsed_ns'),
                                       v1_detection_bound_ns=((v1.get('cleanup') or {}).get('bound') or {}).get('bound_ns'))
    else:
        out['cleanup_deadline'] = tw.drain_timing_v3(samples, population, bound['emission_ns'],
                                                     bound['allowance']['trigger_latency_ns'],
                                                     (v1.get('cleanup') or {}).get('elapsed_ns'))
    states = [out['old_tokens_rejected']['verdict'], out['traffic_correct']['verdict'],
              out['cleanup_deadline']['verdict']]
    if config is not None:
        out['acceptance_binding'] = binding(run, config)
        if not out['acceptance_binding']['ok']:
            states.append(tw.V3_FAIL)
    out['verdict'] = tw.V3_FAIL if tw.V3_FAIL in states else tw.V3_INDETERMINATE if tw.V3_INDETERMINATE in states \
        else tw.V3_PASS
    (run / 'isolation_v3.json').write_text(json.dumps(out, indent=1) + '\n')
    return out


if __name__ == '__main__':
    args = sys.argv[1:]
    config = None
    if '--config' in args:
        i = args.index('--config')
        config, args = args[i + 1], args[:i] + args[i + 2:]
    for path in args:
        r = recompute(path, config)
        print(r['run'], r['mode'], '-> old_tokens', r['old_tokens_rejected']['verdict'], '| traffic',
              r['traffic_correct']['verdict'], '| cleanup', r['cleanup_deadline']['verdict'], '| overall', r['verdict'],
              '| unattributed', len(r['unattributed_v1_failures']))
