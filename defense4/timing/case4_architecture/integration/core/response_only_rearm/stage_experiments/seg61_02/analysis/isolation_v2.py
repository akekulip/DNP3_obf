#!/usr/bin/env python3
"""Recompute a retained isolation block under acceptance version 2, as a separate file.

  python3 isolation_v2.py RUN_DIR [RUN_DIR ...]      # writes RUN_DIR/isolation_v2.json for each

Version 2 is defined in rearm_01/hw/token_window.py: full_run_rejections_v2 and drain_timing_v2. The block's own
isolation_verdict.json, written under version 1, is never modified. Version 2 replaces only those two judgements and
reports every other v1 component as it was recorded (copied, not re-derived).
"""
import json
import sys
from pathlib import Path

HW = Path(__file__).resolve().parents[5] / 'evidence/rearm_01/hw'
sys.path.insert(0, str(HW))
import token_window as tw  # noqa: E402


def one(path, pattern):
    found = sorted(Path(path).glob(pattern))
    if len(found) != 1:
        raise SystemExit('%s: expected one %s, found %d' % (path, pattern, len(found)))
    return found[0]


def recompute(run):
    run = Path(run)
    verdict_path = one(run, '*/*/*/isolation_verdict.json')
    trial = verdict_path.parent
    v1 = json.loads(verdict_path.read_text())
    window = json.loads((run / 'token_window_observer.json').read_text())
    window = window.get('window', window)
    before = json.loads(one(trial / 'snapshots', '*_before.json').read_text())
    after = json.loads(one(trial / 'snapshots', '*_after.json').read_text())
    quiet_end, population, bound = window['after'], window['population'], window['plan'].get('bound')
    control = bound is None                     # the matched control delays nothing, so it plans no cleanup bound
    result = dict(acceptance=tw.ACCEPTANCE_V2, run=run.name, v1_verdict_file=str(verdict_path.relative_to(run)),
                  v1_ok=v1.get('ok'), v1_failures=v1.get('failures'))
    try:
        result['rejections'] = dict(ok=True, **tw.full_run_rejections_v2(before, after, quiet_end, population,
                                                                          control=control))
    except ValueError as error:
        result['rejections'] = dict(ok=False, failure=str(error))
    poll = trial / 'diag_poll.jsonl'
    samples = [json.loads(line) for line in poll.read_text().splitlines() if line.strip()] if poll.is_file() else []
    samples = [x for x in samples if not x.get('summary')]
    if control:
        result['drain'] = dict(acceptance=tw.ACCEPTANCE_V2, verdict='not_applicable',
                               reason='control: no delayed cohort, so no cleanup bound')
    else:
        result['drain'] = tw.drain_timing_v2(samples, bound['emission_ns'], bound['allowance']['trigger_latency_ns'],
                                             (v1.get('cleanup') or {}).get('elapsed_ns'))
    # checks.py's build bound (max_stale + 2k per SBO, recorded as token_stale_bound) budgets the blockers an SBO
    # strands; v1 compared it with all of OUT_TOKEN_STALE, raw old-cohort rejections included. v2 keeps the bound's
    # value and applies it to stale-blocker retirements only; the raw cohort is conserved separately above.
    bounds = sorted({int(x) for x in __import__('re').findall(r'"token_stale_bound": (\d+)', verdict_path.read_text())})
    blockers = after['outcomes']['STALE_BLOCKER'] - before['outcomes']['STALE_BLOCKER']
    result['build_stale_bound_v2'] = dict(ok=len(bounds) == 1 and blockers <= bounds[0], stale_blockers=blockers,
                                          token_stale_bound=bounds[0] if len(bounds) == 1 else bounds,
                                          basis='checks.py bound, applied to STALE_BLOCKER only')
    v1_rejection_or_cleanup = [f for f in v1.get('failures') or []
                               if 'rejection' in f or 'cleanup bound' in f or 'OUT_TOKEN_STALE' in f]
    other = [f for f in v1.get('failures') or [] if f not in v1_rejection_or_cleanup]
    cleanup_v1_ok = (v1.get('cleanup') or {}).get('ok')
    drain = result['drain']['verdict']
    if drain == 'not_applicable':
        cleanup_ok, basis = True, 'control: not applicable'
    elif drain == 'unobserved':
        cleanup_ok, basis = bool(cleanup_v1_ok), 'v1 detection bound (no poller)'
    else:
        cleanup_ok, basis = drain == 'consistent', 'switch-side drain'
    result['mode'] = 'control' if control else 'isolation'
    result['cleanup_v2'] = dict(ok=cleanup_ok, basis=basis)
    result['other_v1_failures'] = other
    result['ok'] = bool(result['rejections']['ok'] and cleanup_ok and result['build_stale_bound_v2']['ok']
                        and not other)
    out = run / 'isolation_v2.json'
    out.write_text(json.dumps(result, indent=1) + '\n')
    return result


if __name__ == '__main__':
    for path in sys.argv[1:]:
        r = recompute(path)
        print(r['run'], 'v1 ok', r['v1_ok'], '-> v2 ok', r['ok'], r['rejections'].get('failure', ''),
              r['drain']['verdict'], r['other_v1_failures'])
