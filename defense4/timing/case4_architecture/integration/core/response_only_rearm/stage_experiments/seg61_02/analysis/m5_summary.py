#!/usr/bin/env python3
"""Per-block, per-arm verdicts of the ctl_timing m5 silicon runs (PLAN_m5.md S4), from retained evidence.

  python3 m5_summary.py -o m5_silicon_summary.json                    # report only, always exits 0
  python3 m5_summary.py --strict --prefix ctl_m6_ --require RUN_ID [RUN_ID ...] \
      [--expect-stale RUN_ID ...] -o out.json                         # aggregate gate, exits 1 on any reason

As m4_summary.py, plus N's contention counters: for every trial, the before/after deltas of count_busy (0 busy
drop, 1 busy pass, 2 retry lap, 3 retry exhaustion, 4 stale retry) and count_term[0] (retried duplicate aborted),
read from the snapshots' n_counters. The contention gate is that every trial shows zero busy drops, zero
exhaustion and zero stale retries; a trial whose snapshots lack n_counters FAILS the gate (never assumed zero).
Timing tails beyond 100 us are listed with their exchange index; the index-127 outlier stays unexcluded.

Strict mode (W1). Every required run (default: every run matching --prefix; none found is itself a failure) is
checked and every reason is recorded in the output JSON ('reasons'); the exit code is 1 if there is any reason:
  * the run directory is missing; campaign_run.json or restore_verify.json is missing or unreadable;
  * the runner's block outcome is not ok, a runner restore step failed, or restore_verify.json ok is not true;
  * the block is incomplete: per fixture (effective.fixture.modes) the recorded arm sequence must equal the
    block's arm order (campaign_run.json effective.evaluation.arm_order, recorded at run time; otherwise the
    block config hw/config/<run>.json or <run minus _NN>.json 'arms', whose sha256 must match the recorded
    config_file_sha256), and every arm must hold at least trials.trials_per_arm trials;
  * a recorded trial lacks trial.json, its ok is not true, or (purpose 'qualification') any qualification
    verdict is 'rejected';
  * artifacts: a scenario trial (trial.json has 'scenario') needs scenario.json, whose ok must not be false;
    any other trial needs standards_verdict.json (ok true), standards.json (no objective status 'fail') and
    profile_verdict.json (result.conformant true);
  * counters: snapshots/<trial>_before.json and _after.json must both carry n_counters with integer count_busy
    (at least 5 cells) and count_term (at least 1 cell) of equal lengths.

Counter expectations.  Ordinary trial: count_busy[0] (busy drop), [3] (exhaustion) and [4] (stale retry) deltas
are all 0.  Stale-token isolation trial (run named in --expect-stale, or evaluation purpose
'stale_source_characterization'): [0] and [3] are still 0, because the stale-token design
(integration/evidence/rearm_01/hw/token_window.py) drains c1's old GENERATOR tokens before c2's first READ and
rejects them in T's raw timer-stale cells (RAW_INDICES 23/24, OUT_TOKEN_STALE), which N's count_busy does not
count; nothing in that design admits an N busy drop or an exhausted retry budget.  [4] (stale retry) is ALLOWED
and reported, never required: the block reconnects on the same tuple (c1 -> c2 -> c3), and
ctl_timing_01/DESIGN.md (amendment 2 and 'Known costs') states that a retry captured before a master RST or a
same-tuple reconnect is refused as stale and counted in count_busy[4], the safe direction.  In addition the
token_window gates recorded in trial.json observed must hold: bank_isolation.ok and old_token_window.ok true and
an integer old_rejection_delta.  No retained stale-token run (ctl_m4_stale_tokens_950_01,
candidate61_stale_tokens_950_02) carries n_counters, so none of them can pass strict mode.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

from m4_summary import RUNS, objective_view, tails

GATED = {0: 'busy_drop', 3: 'retry_exhaustion', 4: 'stale_retry'}
STALE_GATED = {0: 'busy_drop', 3: 'retry_exhaustion'}
STALE_PURPOSE = 'stale_source_characterization'
CONFIGS = RUNS.parent.parent / 'hw/config'


def counter_delta(snapshots, label):
    try:
        before = json.loads((snapshots / ('%s_before.json' % label)).read_text())['n_counters']
        after = json.loads((snapshots / ('%s_after.json' % label)).read_text())['n_counters']
    except (OSError, KeyError, ValueError):
        return None
    out = {}
    for name in ('count_busy', 'count_term'):
        out[name] = [None if a is None or b is None else b - a for a, b in zip(before[name], after[name])]
    return out


def contention_gate(delta):
    if delta is None:
        return {'ok': False, 'failures': ['n_counters missing from the trial snapshots']}
    busy = delta['count_busy']
    failures = ['%s %s' % (name, busy[i]) for i, name in GATED.items() if busy[i] != 0]
    return {'ok': not failures, 'failures': failures, 'retry_laps': busy[2],
            'retried_duplicates_aborted': delta['count_term'][0]}


def trial_view(d):
    tr = json.loads((d / 'trial.json').read_text()) if (d / 'trial.json').is_file() else {}
    sv = json.loads((d / 'standards_verdict.json').read_text()) if (d / 'standards_verdict.json').is_file() else {}
    art = json.loads((d / 'standards.json').read_text()) if (d / 'standards.json').is_file() else {}
    timed = tails(d / 'timing.json') if 'timing_only' in str(d) or 'combined' in str(d) else None
    delta = counter_delta(d / 'snapshots', d.name)
    return {'trial': d.name, 'ok': tr.get('ok'), 'qualification': sv.get('qualification'),
            'objectives': objective_view(art), 'failures': tr.get('failures'), 'clrt_tails_timed_arm': timed,
            'n_counter_delta': delta, 'contention_gate': contention_gate(delta)}


def run_view(root):
    rv = json.loads((root / 'restore_verify.json').read_text()) if (root / 'restore_verify.json').is_file() else {}
    trials = [trial_view(p.parent) for p in sorted(root.glob('*/*/*/trial.json'))]
    return {'run': root.name, 'restore_verified': rv.get('ok'), 'restore_failures': rv.get('failures'),
            'contention_gate_ok': bool(trials) and all(t['contention_gate']['ok'] for t in trials),
            'trials': trials}


# ---------------------------------------------------------------- strict mode

def _load(path):
    """(value, None) or (None, reason); a missing or unreadable file is a reason, never an empty default."""
    if not path.is_file():
        return None, 'missing artifact %s' % path.name
    try:
        return json.loads(path.read_text()), None
    except (OSError, ValueError) as exc:
        return None, 'unreadable artifact %s: %s' % (path.name, exc)


def strict_counters(snapshots, label):
    """(delta, None) from validated n_counters, or (None, reason)."""
    sides = {}
    for side in ('before', 'after'):
        snap, err = _load(snapshots / ('%s_%s.json' % (label, side)))
        if err:
            return None, 'snapshot: ' + err
        nc = snap.get('n_counters') if isinstance(snap, dict) else None
        if not isinstance(nc, dict):
            return None, 'snapshot %s lacks n_counters' % side
        for name, minimum in (('count_busy', 5), ('count_term', 1)):
            cells = nc.get(name)
            if (not isinstance(cells, list) or len(cells) < minimum
                    or any(type(v) is not int for v in cells)):
                return None, 'snapshot %s n_counters.%s invalid: %r' % (side, name, cells)
        sides[side] = nc
    delta = {}
    for name in ('count_busy', 'count_term'):
        b, a = sides['before'][name], sides['after'][name]
        if len(b) != len(a):
            return None, 'n_counters.%s length differs before/after (%d/%d)' % (name, len(b), len(a))
        delta[name] = [y - x for x, y in zip(b, a)]
    return delta, None


def counter_reasons(delta, stale):
    busy = delta['count_busy']
    gated = STALE_GATED if stale else GATED
    return ['%s delta %d (expected 0%s)' % (name, busy[i], ', stale-token trial' if stale else '')
            for i, name in gated.items() if busy[i] != 0]


def _rejected(qualification):
    values = qualification.values() if isinstance(qualification, dict) else [qualification]
    return any(v == 'rejected' for v in values)


def expected_arms(root, rec, config_dir):
    """(arm order, None) or (None, reason): the run-time record first, then the block config."""
    order = ((rec.get('effective') or {}).get('evaluation') or {}).get('arm_order')
    if isinstance(order, list) and order:
        return order, None
    for name in (root.name, re.sub(r'_\d\d$', '', root.name)):
        path = config_dir / ('%s.json' % name)
        if path.is_file():
            recorded = rec.get('config_file_sha256')
            if recorded and hashlib.sha256(path.read_bytes()).hexdigest() != recorded:
                return None, 'block config %s changed since the run (sha256 differs from config_file_sha256)' \
                    % path.name
            cfg, err = _load(path)
            if err:
                return None, err
            return [a.get('name') for a in cfg.get('arms') or []], None
    return None, 'no arm order: effective.evaluation.arm_order absent and no block config for %s' % root.name


def strict_trial(trial_dir, label, purpose, stale):
    reasons = []
    tr, err = _load(trial_dir / 'trial.json')
    if err:
        return [err]
    if tr.get('ok') is not True:
        reasons.append('trial ok=%r: %s' % (tr.get('ok'), tr.get('failures')))
    if purpose == 'qualification' and _rejected(tr.get('qualification')):
        reasons.append('qualification rejected: %s' % (tr.get('qualification'),))
    if 'scenario' in tr:
        sc, err = _load(trial_dir / 'scenario.json')
        if err:
            reasons.append(err)
        elif isinstance(sc, dict) and 'ok' in sc and sc['ok'] is not True:
            reasons.append('scenario ok=%r' % sc['ok'])
    else:
        sv, err = _load(trial_dir / 'standards_verdict.json')
        if err:
            reasons.append(err)
        else:
            if sv.get('ok') is not True:
                reasons.append('standards verdict ok=%r: %s' % (sv.get('ok'), sv.get('failures')))
            if purpose == 'qualification' and _rejected(sv.get('qualification')):
                reasons.append('standards qualification rejected')
        art, err = _load(trial_dir / 'standards.json')
        if err:
            reasons.append(err)
        else:
            failed = sorted(k for k, v in objective_view(art).items() if v['status'] == 'fail')
            if failed:
                reasons.append('objective verdict fail: %s' % ', '.join(failed))
        pv, err = _load(trial_dir / 'profile_verdict.json')
        if err:
            reasons.append(err)
        elif ((pv.get('result') or {}).get('conformant')) is not True:
            reasons.append('profile verdict not conformant: %s' % ((pv.get('result') or {}).get('failures'),))
    if stale:
        obs = tr.get('observed') or {}
        for gate in ('bank_isolation', 'old_token_window'):
            if (obs.get(gate) or {}).get('ok') is not True:
                reasons.append('stale-token gate %s not ok: %s' % (gate, (obs.get(gate) or {}).get('failures')))
        if type(obs.get('old_rejection_delta')) is not int:
            reasons.append('stale-token old_rejection_delta missing')
    delta, err = strict_counters(trial_dir / 'snapshots', label)
    reasons.extend([err] if err else counter_reasons(delta, stale))
    return reasons


def strict_run(root, expect_stale, config_dir):
    if not root.is_dir():
        return ['missing run']
    reasons = []
    rec, err = _load(root / 'campaign_run.json')
    rv, err_rv = _load(root / 'restore_verify.json')
    if err_rv:
        reasons.append(err_rv)
    elif rv.get('ok') is not True:
        reasons.append('restore_verify ok=%r: %s' % (rv.get('ok'), rv.get('failures')))
    if err:
        return reasons + [err]
    if rec.get('ok') is not True:
        reasons.append('runner block ok=%r: %s' % (rec.get('ok'), rec.get('failure')))
    if not rec.get('restore') or not all(s.get('ok') is True for s in rec['restore']):
        reasons.append('runner restore step failed or absent')
    effective = rec.get('effective') or {}
    purpose = (effective.get('evaluation') or {}).get('purpose')
    stale = root.name in expect_stale or purpose == STALE_PURPOSE
    order, err = expected_arms(root, rec, config_dir)
    arms = rec.get('arms') or []
    if err:
        reasons.append(err)
    else:
        modes = (effective.get('fixture') or {}).get('modes') or sorted({a.get('fixture') for a in arms})
        for fixture in modes:
            got = [a.get('arm') for a in arms if a.get('fixture') == fixture]
            if got != order:
                reasons.append('incomplete block: fixture %s arms %s, expected %s' % (fixture, got, order))
        stray = sorted({str(a.get('fixture')) for a in arms} - set(modes))
        if stray:
            reasons.append('arms recorded for unconfigured fixtures %s' % stray)
    per_arm = (effective.get('trials') or {}).get('trials_per_arm', 1)
    for arm in arms:
        trials = arm.get('trials') or []
        if len(trials) < per_arm:
            reasons.append('incomplete arm %s/%s: %d trials, expected at least %d'
                           % (arm.get('fixture'), arm.get('arm'), len(trials), per_arm))
        for t in trials:
            label = t.get('label')
            for r in strict_trial(root / str(arm.get('fixture')) / str(arm.get('arm')) / str(label),
                                  label, purpose, stale):
                reasons.append('%s: %s' % (label, r))
    return reasons


def strict_main(a, runs, config_dir):
    required = a.require or sorted(p.name for p in runs.glob(a.prefix + '*'))
    expect_stale = set(a.expect_stale or [])
    reasons = [] if required else [{'run': None, 'reason': 'no run matches prefix %s' % a.prefix}]
    views = []
    for run_id in required:
        for r in strict_run(runs / run_id, expect_stale, config_dir):
            reasons.append({'run': run_id, 'reason': r})
        if (runs / run_id).is_dir():
            views.append(run_view(runs / run_id))
    ok = not reasons
    out = {'mode': 'strict', 'ok': ok, 'prefix': a.prefix, 'required': required,
           'expect_stale': sorted(expect_stale), 'reasons': reasons, 'runs': views}
    Path(a.output).write_text(json.dumps(out, indent=1, default=str) + '\n')
    for r in reasons:
        print('FAIL %s: %s' % (r['run'], r['reason']))
    print('strict: %s (%d runs, %d reasons)' % ('PASS' if ok else 'FAIL', len(required), len(reasons)))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--prefix', default='ctl_m5_')
    ap.add_argument('--strict', action='store_true', help='aggregate gate: exit 1 and record every reason')
    ap.add_argument('--require', nargs='+', metavar='RUN_ID', help='strict: runs that must exist and pass')
    ap.add_argument('--expect-stale', nargs='+', metavar='RUN_ID', help='strict: stale-token isolation runs')
    ap.add_argument('--runs-dir', type=Path, default=RUNS, help=argparse.SUPPRESS)
    ap.add_argument('--config-dir', type=Path, default=CONFIGS, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.strict:
        return strict_main(a, a.runs_dir, a.config_dir)
    if a.require or a.expect_stale:
        ap.error('--require and --expect-stale need --strict')
    out = [run_view(root) for root in sorted(a.runs_dir.glob(a.prefix + '*'))]
    Path(a.output).write_text(json.dumps(out, indent=1, default=str) + '\n')
    for run in out:
        print(run['run'], 'restore_verified=%s contention_gate_ok=%s' % (run['restore_verified'], run['contention_gate_ok']))
        for t in run['trials']:
            print('   %-60s ok=%-5s %-16s retries=%s %s' % (t['trial'][-60:], t['ok'], t['qualification'],
                  t['contention_gate'].get('retry_laps'), t['contention_gate']['failures'] or ''))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
