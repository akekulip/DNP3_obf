#!/usr/bin/env python3
"""Per-block, per-arm verdicts of the ctl_timing m5 silicon runs (PLAN_m5.md S4), from retained evidence.

  python3 m5_summary.py -o m5_silicon_summary.json                    # report only, always exits 0
  python3 m5_summary.py --strict --require RUN_ID [RUN_ID ...] [--prefix ctl_m6_] \
      [--expect-stale RUN_ID ...] [--measurement-only RUN_ID ...] -o out.json   # aggregate gate, exit 1 on any reason

As m4_summary.py, plus N's contention counters: for every trial, the before/after deltas of count_busy (0 busy
drop, 1 busy pass, 2 retry lap, 3 retry exhaustion, 4 stale retry) and count_term[0] (retried duplicate aborted),
read from the snapshots' n_counters. The contention gate is that every trial shows zero busy drops, zero
exhaustion and zero stale retries; a trial whose snapshots lack n_counters FAILS the gate (never assumed zero).
Timing tails beyond 100 us are listed with their exchange index; the index-127 outlier stays unexcluded.

Strict mode (W1). The required set is exactly --require (mandatory; a prefix alone is an argument error). A given
--prefix is only a filter that must agree: a required run not matching it is an argument error, as is an
--expect-stale or --measurement-only name outside the required set. Every required run is checked, every reason
is recorded in the output JSON ('reasons', always written), and the exit code is 1 if there is any reason:
  * the run directory is missing; any JSON artifact read is missing, unreadable or not a JSON object;
  * the runner's block outcome is not ok or a runner restore step failed or is absent; restore_verify.json ok is
    not true, or its run_root does not name the run's own directory (resolved, or the same path below the
    repository's defense4/ directory in another checkout);
  * evaluation purpose is not one of qualification, timing_precision_characterization,
    stale_source_characterization;
  * the block is incomplete: effective.fixture.modes must be a non-empty list, and per mode the recorded arm
    sequence must equal the block's arm order -- campaign_run.json effective.evaluation.arm_order (non-empty) if
    recorded, otherwise the block config hw/config/<run>.json or <run minus _NN>.json 'arms' (non-empty), which
    needs a recorded config_file_sha256 that matches; neither is ever derived from the recorded arms. Arms for
    unconfigured fixtures fail. effective.trials.trials_per_arm must be an integer >= 1 and every recorded arm
    must hold at least that many trials; every recorded trial needs a label;
  * a trial directory on disk (<fixture>/<arm>/<label>) is not among campaign_run.json's recorded trials;
  * a recorded trial lacks trial.json or its ok is not true;
  * qualification verdicts: every recorded verdict (trial.json qualification, each standards_verdict.json
    qualification) must be 'qualified' or 'measurement_only'; a missing verdict fails when the purpose is
    qualification. A qualification-purpose run must hold at least one 'qualified' verdict unless it is named in
    --measurement-only;
  * artifacts of an ordinary trial, and of every c*/ connection directory of a scenario trial:
    standards_verdict.json ok true, profile_verdict.json result.conformant true, and standards.json
    observed.objectives a non-empty mapping in which an objective with required true has status 'pass' and any
    other has 'pass' or 'not_applicable' (deferred, fail or anything else fails). A timed objective (name
    *_precision, status not not_applicable) must record gap_us, maximum_p99_absolute_error_us, minimum_eligible
    and p99_convention in its evidence;
  * thresholds: wherever trial.json, standards.json or standards_verdict.json (trial or c*/) records them,
    gap_us must be 950, maximum_p99_absolute_error_us 100, minimum_eligible 20, and p99_convention the nearest-rank
    convention ('nearest rank: ceil(0.99 n)-th smallest ...');
  * a scenario trial (trial.json has 'scenario') needs scenario.json with ok true, every entry of its
    'connections' (list or mapping) with ok true, and at least one c*/ connection directory;
  * counters: snapshots/<trial>_before.json and _after.json must both carry n_counters with integer count_busy
    (at least 5 cells) and count_term (at least 1 cell) of equal lengths.

Counter expectations.  Ordinary trial: count_busy[0] (busy drop), [3] (exhaustion) and [4] (stale retry) deltas
are all 0.  Stale-token isolation trial (only a run named in --expect-stale; a named run must have purpose
'stale_source_characterization' and a run with that purpose must be named, else either is a reason): [0] and [3]
are still 0, because the stale-token design (integration/evidence/rearm_01/hw/token_window.py) drains c1's old
GENERATOR tokens before c2's first READ and rejects them in T's raw timer-stale cells (RAW_INDICES 23/24,
OUT_TOKEN_STALE), which N's count_busy does not count; nothing in that design admits an N busy drop or an
exhausted retry budget.  [4] (stale retry) is ALLOWED and reported, never required: the block reconnects on the same tuple (c1 -> c2 -> c3), and
ctl_timing_01/DESIGN.md (amendment 2 and 'Known costs') states that a retry captured before a master RST or a
same-tuple reconnect is refused as stale and counted in count_busy[4], the safe direction.  In addition the
token_window gates recorded in trial.json observed must hold: bank_isolation.ok and old_token_window.ok true and
an integer old_rejection_delta > 0.  No retained stale-token run (ctl_m4_stale_tokens_950_01,
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

QUALIFICATION_VALUES = ('qualified', 'measurement_only')
PURPOSES = ('qualification', 'timing_precision_characterization', STALE_PURPOSE)
THRESHOLDS = {'gap_us': 950, 'maximum_p99_absolute_error_us': 100, 'minimum_eligible': 20}
P99_CONVENTION = 'nearest rank: ceil(0.99 n)-th smallest'
CONNECTION_DIR = re.compile(r'c\d+$')


def _load(path):
    """(dict, None) or (None, reason); a missing, unreadable or non-object file is a reason, never a default."""
    if not path.is_file():
        return None, 'missing artifact %s' % path.name
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        return None, 'unreadable artifact %s: %s' % (path.name, exc)
    if not isinstance(value, dict):
        return None, 'artifact %s is not a JSON object (%s)' % (path.name, type(value).__name__)
    return value, None


def _dict(value):
    return value if isinstance(value, dict) else {}


def strict_counters(snapshots, label):
    """(delta, None) from validated n_counters, or (None, reason)."""
    sides = {}
    for side in ('before', 'after'):
        snap, err = _load(snapshots / ('%s_%s.json' % (label, side)))
        if err:
            return None, 'snapshot: ' + err
        nc = snap.get('n_counters')
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


def verdict_reasons(source, holder, purpose, verdicts):
    """Whitelist every recorded qualification verdict; collect them in verdicts."""
    if 'qualification' not in holder:
        return ['%s lacks a qualification verdict' % source] if purpose == 'qualification' else []
    q = holder['qualification']
    if isinstance(q, dict):
        if not q:
            return ['%s qualification is empty' % source]
        items = [('%s %s' % (source, k), v) for k, v in sorted(q.items())]
    else:
        items = [(source, q)]
    reasons = []
    for where, v in items:
        verdicts.append(v)
        if not (isinstance(v, str) and v in QUALIFICATION_VALUES):
            reasons.append('qualification %s: %s=%r (accepted: %s)'
                           % ('rejected' if v == 'rejected' else 'not accepted', where, v,
                              ', '.join(QUALIFICATION_VALUES)))
    return reasons


def threshold_reasons(source, value, gap_us=950):
    """Every recorded threshold must be the m5 one: 950 us gap (or the run's declared --expected-gap), 100 us p99
    maximum, 20 eligible, nearest rank."""
    out = []
    wanted = dict(THRESHOLDS, gap_us=gap_us)

    def walk(o, path):
        if isinstance(o, dict):
            for key, want in wanted.items():
                if key in o and (type(o[key]) not in (int, float) or o[key] != want):
                    out.append('threshold %s%s.%s=%r (expected %r)' % (source, path, key, o[key], want))
            if 'p99_convention' in o:
                conv = o['p99_convention']
                if not (isinstance(conv, str) and conv.startswith(P99_CONVENTION)):
                    out.append('threshold %s%s.p99_convention=%r (expected %r...)'
                               % (source, path, conv, P99_CONVENTION))
            for k, v in o.items():
                walk(v, '%s.%s' % (path, k))
        elif isinstance(o, list):
            for i, v in enumerate(o):
                walk(v, '%s[%d]' % (path, i))
    walk(value, '')
    return out


def objective_reasons(art):
    """standards.json objectives: required ones must pass, the rest pass or be not_applicable; a timed
    (*_precision, applicable) objective must carry its full threshold record."""
    objectives = _dict(art.get('observed')).get('objectives')
    if not isinstance(objectives, dict) or not objectives:
        return ['standards.json has no objectives mapping']
    reasons = []
    for name, block in sorted(objectives.items()):
        if not isinstance(block, dict):
            reasons.append('objective %s is not an object' % name)
            continue
        required, status = block.get('required'), block.get('status')
        if type(required) is not bool:
            reasons.append('objective %s required=%r (expected true or false)' % (name, required))
        elif required and status != 'pass':
            reasons.append('required objective %s status %r (expected pass)' % (name, status))
        elif not required and status not in ('pass', 'not_applicable'):
            reasons.append('objective %s status %r (not required: expected pass or not_applicable)'
                           % (name, status))
        if name.endswith('_precision') and status != 'not_applicable':
            evidence = _dict(block.get('evidence'))
            missing = [k for k in list(THRESHOLDS) + ['p99_convention'] if k not in evidence]
            if missing:
                reasons.append('timed objective %s lacks threshold record %s' % (name, ', '.join(missing)))
    return reasons


def artifact_reasons(d, purpose, verdicts, gap_us=950):
    """standards_verdict, standards objectives and profile verdict of one trial or one scenario connection."""
    reasons = []
    sv, err = _load(d / 'standards_verdict.json')
    if err:
        reasons.append(err)
    else:
        if sv.get('ok') is not True:
            reasons.append('standards verdict ok=%r: %s' % (sv.get('ok'), sv.get('failures')))
        reasons.extend(verdict_reasons('standards_verdict.json', sv, purpose, verdicts))
        reasons.extend(threshold_reasons('standards_verdict.json', sv, gap_us))
    art, err = _load(d / 'standards.json')
    if err:
        reasons.append(err)
    else:
        reasons.extend(objective_reasons(art))
        reasons.extend(threshold_reasons('standards.json', art, gap_us))
    pv, err = _load(d / 'profile_verdict.json')
    if err:
        reasons.append(err)
    elif _dict(pv.get('result')).get('conformant') is not True:
        reasons.append('profile verdict not conformant: %s' % (_dict(pv.get('result')).get('failures'),))
    return reasons


def scenario_reasons(trial_dir, purpose, verdicts, gap_us=950):
    reasons = []
    sc, err = _load(trial_dir / 'scenario.json')
    if err:
        reasons.append(err)
    else:
        if sc.get('ok') is not True:
            reasons.append('scenario ok=%r' % (sc.get('ok'),))
        if 'connections' in sc:
            conns = sc['connections']
            entries = (sorted(conns.items()) if isinstance(conns, dict)
                       else list(enumerate(conns)) if isinstance(conns, list) else None)
            if entries is None:
                reasons.append('scenario connections is neither a list nor a mapping')
            for key, c in entries or []:
                if not isinstance(c, dict) or c.get('ok') is not True:
                    name = c.get('name', key) if isinstance(c, dict) else key
                    reasons.append('scenario connection %s ok=%r: %s' % (
                        name, _dict(c).get('ok'), _dict(c).get('failures')))
    cdirs = sorted(p for p in trial_dir.iterdir() if p.is_dir() and CONNECTION_DIR.match(p.name))
    if not cdirs:
        reasons.append('scenario trial has no c*/ connection directory')
    for c in cdirs:
        reasons.extend('%s/%s' % (c.name, r) for r in artifact_reasons(c, purpose, verdicts, gap_us))
    return reasons


def expected_arms(root, rec, config_dir):
    """(arm order, None) or (None, reason): the run-time record first, then the block config; never the
    recorded arms."""
    evaluation = _dict(_dict(rec.get('effective')).get('evaluation'))
    order = evaluation.get('arm_order')
    if order is not None:
        if isinstance(order, list) and order and all(isinstance(a, str) for a in order):
            return order, None
        return None, 'recorded effective.evaluation.arm_order invalid or empty: %r' % (order,)
    for name in (root.name, re.sub(r'_\d\d$', '', root.name)):
        path = config_dir / ('%s.json' % name)
        if path.is_file():
            recorded = rec.get('config_file_sha256')
            if not recorded:
                return None, 'arm order from block config %s but campaign_run.json lacks config_file_sha256' \
                    % path.name
            if hashlib.sha256(path.read_bytes()).hexdigest() != recorded:
                return None, 'block config %s changed since the run (sha256 differs from config_file_sha256)' \
                    % path.name
            cfg, err = _load(path)
            if err:
                return None, err
            arms = cfg.get('arms')
            names = [a.get('name') for a in arms if isinstance(a, dict)] if isinstance(arms, list) else []
            if not names or len(names) != len(arms) or not all(isinstance(n, str) and n for n in names):
                return None, 'block config %s arms invalid or empty: %r' % (path.name, arms)
            return names, None
    return None, 'no arm order: effective.evaluation.arm_order absent and no block config for %s' % root.name


def strict_trial(trial_dir, label, purpose, stale, verdicts, gap_us=950):
    reasons = []
    tr, err = _load(trial_dir / 'trial.json')
    if err:
        return [err]
    if tr.get('ok') is not True:
        reasons.append('trial ok=%r: %s' % (tr.get('ok'), tr.get('failures')))
    reasons.extend(verdict_reasons('trial.json', tr, purpose, verdicts))
    reasons.extend(threshold_reasons('trial.json', tr, gap_us))
    if 'scenario' in tr:
        reasons.extend(scenario_reasons(trial_dir, purpose, verdicts, gap_us))
    else:
        reasons.extend(artifact_reasons(trial_dir, purpose, verdicts, gap_us))
    if stale:
        obs = _dict(tr.get('observed'))
        for gate in ('bank_isolation', 'old_token_window'):
            if _dict(obs.get(gate)).get('ok') is not True:
                reasons.append('stale-token gate %s not ok: %s' % (gate, _dict(obs.get(gate)).get('failures')))
        delta = obs.get('old_rejection_delta')
        if type(delta) is not int:
            reasons.append('stale-token old_rejection_delta missing')
        elif delta <= 0:
            reasons.append('stale-token old_rejection_delta %d (expected > 0)' % delta)
    delta, err = strict_counters(trial_dir / 'snapshots', label)
    reasons.extend([err] if err else counter_reasons(delta, stale))
    return reasons


def block_reasons(root, rec, effective, config_dir):
    """Completeness: configured fixtures x expected arm order, trials_per_arm; returns (reasons, arms, need)."""
    reasons = []
    modes = _dict(effective.get('fixture')).get('modes')
    if not (isinstance(modes, list) and modes and all(isinstance(m, str) and m for m in modes)):
        reasons.append('effective.fixture.modes missing or empty: %r' % (modes,))
        modes = None
    order, err = expected_arms(root, rec, config_dir)
    if err:
        reasons.append(err)
    arms = rec.get('arms')
    if not isinstance(arms, list):
        reasons.append('campaign_run.json arms is not a list: %r' % (arms,))
        arms = []
    if any(not isinstance(a, dict) for a in arms):
        reasons.append('campaign_run.json arms holds a non-object entry')
        arms = [a for a in arms if isinstance(a, dict)]
    if modes is not None and order is not None:
        for fixture in modes:
            got = [a.get('arm') for a in arms if a.get('fixture') == fixture]
            if got != order:
                reasons.append('incomplete block: fixture %s arms %s, expected %s' % (fixture, got, order))
    if modes is not None:
        stray = sorted({str(a.get('fixture')) for a in arms} - set(modes))
        if stray:
            reasons.append('arms recorded for unconfigured fixtures %s' % stray)
    per_arm = _dict(effective.get('trials')).get('trials_per_arm')
    if type(per_arm) is not int or per_arm < 1:
        reasons.append('effective.trials.trials_per_arm missing or invalid: %r (expected an integer >= 1)'
                       % (per_arm,))
        per_arm = 1
    return reasons, arms, per_arm


def strict_run(root, expect_stale, measurement_only, config_dir, gap_us=950):
    if not root.is_dir():
        return ['missing run']
    reasons = []
    rec, err = _load(root / 'campaign_run.json')
    rv, err_rv = _load(root / 'restore_verify.json')
    if err_rv:
        reasons.append(err_rv)
    else:
        if rv.get('ok') is not True:
            reasons.append('restore_verify ok=%r: %s' % (rv.get('ok'), rv.get('failures')))
        run_root = rv.get('run_root')
        if not isinstance(run_root, str) or not run_root:
            reasons.append('restore_verify.json lacks run_root')
        elif not _same_run(run_root, root):
            reasons.append('restore_verify run_root %s is not this run' % run_root)
    if err:
        return reasons + [err]
    if rec.get('ok') is not True:
        reasons.append('runner block ok=%r: %s' % (rec.get('ok'), rec.get('failure')))
    restore = rec.get('restore')
    if not isinstance(restore, list) or not restore or not all(_dict(s).get('ok') is True for s in restore):
        reasons.append('runner restore step failed or absent')
    effective = _dict(rec.get('effective'))
    purpose = _dict(effective.get('evaluation')).get('purpose')
    if not (isinstance(purpose, str) and purpose in PURPOSES):
        reasons.append('evaluation purpose %r not one of %s' % (purpose, ', '.join(PURPOSES)))
    stale = root.name in expect_stale
    if purpose == STALE_PURPOSE and not stale:
        reasons.append('purpose %s but the run is not named in --expect-stale' % STALE_PURPOSE)
    if stale and purpose != STALE_PURPOSE:
        reasons.append('named in --expect-stale but purpose is %r' % (purpose,))
    block, arms, per_arm = block_reasons(root, rec, effective, config_dir)
    reasons.extend(block)
    recorded, verdicts = set(), []
    for arm in arms:
        trials = arm.get('trials')
        trials = trials if isinstance(trials, list) else []
        if len(trials) < per_arm:
            reasons.append('incomplete arm %s/%s: %d trials, expected at least %d'
                           % (arm.get('fixture'), arm.get('arm'), len(trials), per_arm))
        for t in trials:
            label = _dict(t).get('label')
            if not isinstance(label, str) or not label:
                reasons.append('arm %s/%s records a trial without a label: %r'
                               % (arm.get('fixture'), arm.get('arm'), t))
                continue
            trial_dir = root / str(arm.get('fixture')) / str(arm.get('arm')) / label
            recorded.add(trial_dir)
            for r in strict_trial(trial_dir, label, purpose, stale, verdicts, gap_us):
                reasons.append('%s: %s' % (label, r))
    for d in sorted(p for p in root.glob('*/*/*') if p.is_dir()):
        if d not in recorded:
            reasons.append('trial directory on disk not recorded in campaign_run.json: %s' % d.relative_to(root))
    if purpose == 'qualification' and root.name not in measurement_only and 'qualified' not in verdicts:
        reasons.append('qualification run has no qualified verdict (not named in --measurement-only)')
    return reasons


def _same_run(recorded, root):
    """The recorded run_root names this run: equal after resolving, or (another checkout of the repository) the
    same path below the repository's defense4/ directory, so a clean worktree reads its own retained records."""
    a, b = Path(recorded).resolve(), Path(root).resolve()
    if a == b:
        return True
    pa, pb = a.parts, b.parts
    return 'defense4' in pa and 'defense4' in pb and pa[pa.index('defense4'):] == pb[pb.index('defense4'):]


def _gap_arg(text):
    run, sep, us = text.partition('=')
    if not sep or not run or not us.isdigit() or int(us) <= 0:
        raise argparse.ArgumentTypeError('expected RUN_ID=US, got %r' % text)
    return run, int(us)


def strict_main(a, runs, config_dir):
    required = a.require
    expect_stale = set(a.expect_stale or [])
    measurement_only = set(a.measurement_only or [])
    expected_gap = dict(a.expected_gap or [])
    reasons, views = [], []
    for run_id in required:
        root = runs / run_id
        try:
            run_reasons = strict_run(root, expect_stale, measurement_only, config_dir, expected_gap.get(root.name, 950))
        except Exception as exc:  # the gate must always write its record; an unforeseen shape is a reason
            run_reasons = ['strict check raised %s: %s' % (type(exc).__name__, exc)]
        reasons.extend({'run': run_id, 'reason': r} for r in run_reasons)
        if root.is_dir():
            try:
                views.append(run_view(root))
            except Exception as exc:  # report view of malformed evidence; recorded, never fatal
                views.append({'run': run_id, 'view_error': '%s: %s' % (type(exc).__name__, exc)})
                reasons.append({'run': run_id, 'reason': 'report view raised %s: %s' % (type(exc).__name__, exc)})
    ok = not reasons
    out = {'mode': 'strict', 'ok': ok, 'prefix': a.prefix, 'required': required,
           'expect_stale': sorted(expect_stale), 'measurement_only': sorted(measurement_only),
           'reasons': reasons, 'runs': views}
    Path(a.output).write_text(json.dumps(out, indent=1, default=str) + '\n')
    for r in reasons:
        print('FAIL %s: %s' % (r['run'], r['reason']))
    print('strict: %s (%d runs, %d reasons)' % ('PASS' if ok else 'FAIL', len(required), len(reasons)))
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-o', '--output', required=True)
    ap.add_argument('--prefix', help='report: runs to list (default ctl_m5_); strict: every required run must match')
    ap.add_argument('--strict', action='store_true', help='aggregate gate: exit 1 and record every reason')
    ap.add_argument('--require', nargs='+', metavar='RUN_ID', help='strict: runs that must exist and pass')
    ap.add_argument('--expect-stale', nargs='+', metavar='RUN_ID', help='strict: stale-token isolation runs')
    ap.add_argument('--measurement-only', nargs='+', metavar='RUN_ID',
                    help='strict: qualification runs allowed to carry only measurement_only verdicts')
    ap.add_argument('--expected-gap', nargs='+', metavar='RUN_ID=US', type=_gap_arg,
                    help='strict: a run whose block config prescribes another gap than 950 us (declared, never read '
                         'from the evidence); the run must be required')
    ap.add_argument('--runs-dir', type=Path, default=RUNS, help=argparse.SUPPRESS)
    ap.add_argument('--config-dir', type=Path, default=CONFIGS, help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    if a.strict:
        if not a.require:
            ap.error('--strict needs --require RUN_ID [RUN_ID ...]; a prefix does not define the required set')
        if a.prefix is not None:
            off = [r for r in a.require if not r.startswith(a.prefix)]
            if off:
                ap.error('required runs do not match --prefix %s: %s' % (a.prefix, ' '.join(off)))
        for flag, names in (('--expect-stale', a.expect_stale), ('--measurement-only', a.measurement_only),
                            ('--expected-gap', [run for run, _us in a.expected_gap or []])):
            extra = sorted(set(names or []) - set(a.require))
            if extra:
                ap.error('%s names runs not in --require: %s' % (flag, ' '.join(extra)))
        return strict_main(a, a.runs_dir, a.config_dir)
    if a.require or a.expect_stale or a.measurement_only or a.expected_gap:
        ap.error('--require, --expect-stale and --measurement-only need --strict')
    prefix = a.prefix if a.prefix is not None else 'ctl_m5_'
    out = [run_view(root) for root in sorted(a.runs_dir.glob(prefix + '*'))]
    Path(a.output).write_text(json.dumps(out, indent=1, default=str) + '\n')
    for run in out:
        print(run['run'], 'restore_verified=%s contention_gate_ok=%s' % (run['restore_verified'], run['contention_gate_ok']))
        for t in run['trials']:
            print('   %-60s ok=%-5s %-16s retries=%s %s' % (t['trial'][-60:], t['ok'], t['qualification'],
                  t['contention_gate'].get('retry_laps'), t['contention_gate']['failures'] or ''))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
