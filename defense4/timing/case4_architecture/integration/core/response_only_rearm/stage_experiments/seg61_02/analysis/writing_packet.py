#!/usr/bin/env python3
"""Writing package for the 72d85875b directive, regenerated offline from retained evidence.

  python3 writing_packet.py [-o ../evidence/writing_packet_72d85875b]

Reads only retained inputs (silicon run directories under evidence/hw_campaigns, the ctl_timing_01 build
directories with their compile and model records) and writes, into the package directory:
  qualification_table.json / .md   one row per gate: PASS, FAIL or PENDING, candidate identity, run IDs, paths
  timing_errors.csv                per run, arm and transaction kind: n, signed mean and sample SD of
                                   CLRT - gap, nearest-rank p99 and maximum of |CLRT - gap| (timed arms; every
                                   sample kept, the index-127 tail included)
  costs.csv                        internal loop-port frames and octets, re-waits and pktgen seeds per exchange
  external_growth.csv              native versus master-visible response lengths per kind
  stages.csv                       per build: compiler, N/E/T stages, mirror guard, E/T identity
  model.csv                        per build: counted model driver passes bound to source and driver SHA
  fig_timing_error.{pdf,png}       p99 and maximum absolute CLRT error per block (timed arms), 100 us bound
  evidence_index.json              sha256 of every input read and every output written, and this command
CLAIMS.md (claims-to-evidence) is hand-written and only checked to exist. A required input that is missing
fails the run (exit 1) and nothing is written; optional successor (m6) inputs are reported PENDING.
"""
import argparse
import csv
import hashlib
import json
import math
import os
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
S = HERE.parent
sys.path.insert(0, str(HERE))
import repeat_sbo_report as rsr  # noqa: E402
import cost_report as cr  # noqa: E402

RUNS = S / 'evidence/hw_campaigns'
CT = S.parent / 'ctl_timing_01'
BUILDS = {'m4': CT / 'evidence/m4_01', 'm5': CT / 'evidence/m5_10'}
GAP_US, P99_BOUND_US, IMAGE_LEN = 950.0, 100.0, 61
NATIVE_LEN = {'READ': 49, 'SELECT': 37, 'OPERATE': 37}

# gate -> run IDs per candidate (the run-ID stem; '_NN' attempts are all listed, the last decides)
FAMILIES = (
    ('recovery: graceful persistence', 'persistence_graceful_950'),
    ('recovery: RST persistence', 'persistence_rst_950'),
    ('recovery: protected reconnect', 'reconnect_950'),
    ('recovery: single loss (measurement only)', 'loss_core_950'),
    ('recovery: held OPERATE', 'held_operate_350'),
    ('timing: repeated-SBO qualification b1', 'qual_repeat_sbo_950_b1'),
    ('timing: repeated-SBO qualification b2', 'qual_repeat_sbo_950_b2'),
    ('timing: repeated-SBO qualification b3', 'qual_repeat_sbo_950_b3'),
    ('timing: piggyback qualification b1', 'qual_piggyback_950_b1'),
    ('timing: piggyback qualification b2', 'qual_piggyback_950_b2'),
    ('timing: piggyback qualification b3', 'qual_piggyback_950_b3'),
    ('timing: characterization b1 (measurement only)', 'char_repeat_sbo_950_b1'),
    ('timing: characterization b2 (measurement only)', 'char_repeat_sbo_950_b2'),
    ('timing: characterization b3 (measurement only)', 'char_repeat_sbo_950_b3'),
    ('isolation: quiet new incarnation followed by traffic', 'stale_iso20_950'),
)
REQUIRED_M5 = [stem for _gate, stem in FAMILIES if stem != 'stale_iso20_950']


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def attempts(prefix, stem):
    return sorted(p for p in RUNS.glob('%s%s*' % (prefix, stem))
                  if p.is_dir() and p.name[len(prefix) + len(stem):] in ('',) or
                  (p.name[len(prefix) + len(stem):].startswith('_') and p.name[len(prefix) + len(stem) + 1:].isdigit()))


def load(path, inputs):
    inputs.add(Path(path))
    return json.loads(Path(path).read_text())


def run_verdict(root, inputs):
    """PASS / FAIL for one retained run directory, with the reasons."""
    reasons = []
    rec = load(root / 'campaign_run.json', inputs)
    rv = root / 'restore_verify.json'
    if not rv.is_file():
        reasons.append('restore_verify.json missing')
    elif load(rv, inputs).get('ok') is not True:
        reasons.append('restore not verified')
    retry_laps = 0
    trials = 0
    for arm in rec.get('arms', []):
        for tr in arm.get('trials', []):
            trials += 1
            d = root / arm['fixture'] / arm['arm'] / tr['label']
            t = load(d / 'trial.json', inputs) if (d / 'trial.json').is_file() else None
            if t is None:
                reasons.append('%s: trial.json missing' % tr['label'])
                continue
            if t.get('ok') is not True:
                reasons.append('%s: trial not ok' % tr['label'])
            q = json.dumps(t.get('qualification', '')) + json.dumps((t.get('observed') or {}).get('qualification', ''))
            if '"rejected"' in q:
                reasons.append('%s: qualification rejected' % tr['label'])
            for when in ('before', 'after'):
                snap = d / 'snapshots' / ('%s_%s.json' % (tr['label'], when))
                if snap.is_file():
                    inputs.add(snap)
            try:
                b = json.loads((d / 'snapshots' / ('%s_before.json' % tr['label'])).read_text())['n_counters']
                a = json.loads((d / 'snapshots' / ('%s_after.json' % tr['label'])).read_text())['n_counters']
                retry_laps += a['count_busy'][2] - b['count_busy'][2]
            except (OSError, KeyError, IndexError, ValueError):
                pass
    if trials == 0:
        reasons.append('no recorded trial')
    if rec.get('ok') is False:
        reasons.append('runner block not ok')
    return ('PASS' if not reasons else 'FAIL'), reasons, retry_laps


def qualification(candidates, inputs):
    rows = []
    for name, prefix in candidates:
        any_retry = 0
        for gate, stem in FAMILIES:
            runs = attempts(prefix, stem)
            if not runs:
                rows.append(dict(candidate=name, gate=gate, status='PENDING', runs=[], reasons=['not run'],
                                 evidence=[]))
                continue
            verdicts = [run_verdict(r, inputs) for r in runs]
            any_retry += sum(v[2] for v in verdicts)
            rows.append(dict(candidate=name, gate=gate, status=verdicts[-1][0], runs=[r.name for r in runs],
                             reasons={r.name: v[1] for r, v in zip(runs, verdicts) if v[1]},
                             evidence=[os.path.relpath(r, S.parents[7]) for r in runs]))
        rows.append(dict(candidate=name, gate='contention: nonzero silicon retry activity',
                         status='PASS' if any_retry > 0 else 'PENDING', runs=[], evidence=[],
                         reasons=[] if any_retry else ['retry laps 0 in every retained run (count_busy[2])']))
        rows.append(dict(candidate=name, gate='isolation: active-traffic overlap', status='PENDING', runs=[],
                         evidence=[], reasons=['source/model test only; no silicon schedule demonstrated']))
    return rows


def nearest(values, q):
    v = sorted(values)
    return v[max(0, math.ceil(q * len(v)) - 1)] if v else None


def timing(runs, inputs):
    rows = []
    for root in runs:
        rec = load(root / 'campaign_run.json', inputs)
        gap = rec['effective']['timing_params_ns']['gap'] / 1000.0
        for arm in rec['arms']:
            for tr in arm['trials']:
                d = root / arm['fixture'] / arm['arm'] / tr['label']
                if not (d / 'timing.json').is_file():
                    continue
                inputs.add(d / 'timing.json')
                t = rsr.trial_cycles(d, gap if arm.get('T') else 0.0)
                values = {'READ': list(t['read_error_us']) if arm.get('T') else [], 'SELECT': [], 'OPERATE': []}
                for r in t['rows']:
                    for kind in ('select', 'operate'):
                        x = r[kind]
                        if arm.get('T') and isinstance(x.get('clrt_us'), (int, float)) and not x.get('piggyback'):
                            values[kind.upper()].append(x['clrt_us'] - gap)
                for kind, err in values.items():
                    if not err:
                        continue
                    ab = [abs(e) for e in err]
                    rows.append(dict(run=root.name, fixture=arm['fixture'], arm=arm['arm'], kind=kind, n=len(err),
                                     signed_mean_us=round(statistics.mean(err), 2),
                                     sd_us=round(statistics.stdev(err), 2) if len(err) > 1 else None,
                                     p99_abs_us=nearest(ab, 0.99), max_abs_us=max(ab),
                                     p99_within_bound=nearest(ab, 0.99) <= P99_BOUND_US))
    return rows


def costs(runs, inputs):
    out = cr.report(runs)
    for r in runs:
        for p in r.glob('*/*/*/snapshots/*.json'):
            inputs.add(p)
    return [dict(run=x['run'], fixture=x['fixture'], arm=x['arm'], trial_ok=x['trial_ok'],
                 **{k: v for k, v in (x.get('per_exchange') or {}).items()}) for x in out['runs'] if 'error' not in x]


def stages(inputs):
    rows = []
    for name, build in BUILDS.items():
        review = build / 'resource_review.json'
        if not review.is_file():
            continue
        r = load(review, inputs)
        for compile_name, c in r['compiles'].items():
            st = c.get('stages') or {}
            rows.append(dict(build=build.name, milestone=name, compile=compile_name, compiler=c.get('compiler'),
                             exit_code=c.get('exit_code'), N=st.get('N'), E=st.get('E'), T=st.get('T'),
                             mirror_guard=c.get('mirror_guard'), E_byte_identical=r.get('E_byte_identical'),
                             source_sha256=r.get('candidate_sha256')))
    return rows


def models(inputs):
    rows = []
    for name, build in BUILDS.items():
        summary = build / 'model_summary.json'
        if not summary.is_file():
            continue
        s = load(summary, inputs)
        counted = set(next((v for k, v in s.items() if k.startswith('counted_passes')), {}).values())
        # ctl_timing_01/model_summary.py summaries: a blocked build counts nothing, whatever earlier attempts passed
        qualification = s.get('qualification', 'hand_summary')
        if 'qualification' in s:
            counted = set(s['latest_by_driver'].values()) if qualification == 'model_gate_passed' else set()
        for r in s.get('runs', []):                       # every attempt, failed ones included
            rows.append(dict(build=build.name, milestone=name, driver=r.get('driver') or r['run'].split('_')[1],
                             build_qualification=qualification,
                             run=r['run'], counted=r['run'] in counted, passed=r.get('passed'),
                             total=r.get('total'), exit_code=r.get('exit_code'),
                             failed='; '.join(r.get('failed') or []), source_sha256=r.get('source_sha256'),
                             driver_sha256=r.get('driver_sha256')))
    return rows


def growth():
    return [dict(kind=k, native_octets=n, master_visible_octets=IMAGE_LEN, growth_octets=IMAGE_LEN - n)
            for k, n in NATIVE_LEN.items()]


def write_csv(path, rows):
    if not rows:
        path.write_text('')
        return
    keys = list(dict.fromkeys(k for r in rows for k in r))
    with open(path, 'w', newline='') as f:
        w = csv.DictWriter(f, keys)
        w.writeheader()
        w.writerows(rows)


def figure(rows, out):
    import matplotlib
    matplotlib.use('Agg')
    matplotlib.rcParams.update({'font.family': 'serif', 'font.size': 8, 'pdf.fonttype': 42, 'svg.hashsalt': 'wp',
                                'path.simplify': False})
    import matplotlib.pyplot as plt
    timed = [r for r in rows if r['fixture'] == 'separate_ack' and r['arm'] == 'combined']
    if not timed:
        return []
    labels = ['%s\n%s' % (r['run'].replace('ctl_', '').replace('_950', ''), r['kind']) for r in timed]
    fig, ax = plt.subplots(figsize=(7.16, 2.6))
    x = range(len(timed))
    ax.bar([i - 0.2 for i in x], [r['p99_abs_us'] for r in timed], 0.4, label='nearest-rank p99 |error|')
    ax.bar([i + 0.2 for i in x], [r['max_abs_us'] for r in timed], 0.4, label='maximum |error|')
    ax.axhline(P99_BOUND_US, color='k', lw=0.8, ls='--', label='p99 bound 100 us')
    ax.set_yscale('log')
    ax.set_ylabel('|CLRT - 950 us| (us)')
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=90, fontsize=5)
    ax.legend(fontsize=6, frameon=False)
    fig.tight_layout()
    paths = []
    for ext in ('pdf', 'png'):
        p = out / ('fig_timing_error.%s' % ext)
        fig.savefig(p, dpi=300, metadata={'CreationDate': None} if ext == 'pdf' else {'Software': None})
        paths.append(p)
    plt.close(fig)
    return paths


def table_md(rows):
    lines = ['| candidate | gate | status | runs | reasons |', '|---|---|---|---|---|']
    for r in rows:
        reasons = r['reasons'] if isinstance(r['reasons'], list) else ['%s: %s' % (k, '; '.join(v)) for k, v in
                                                                         r['reasons'].items()]
        lines.append('| %s | %s | %s | %s | %s |' % (r['candidate'], r['gate'], r['status'], ', '.join(r['runs']),
                                                     '; '.join(reasons).replace('|', '/')))
    return '\n'.join(lines) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('-o', '--out', type=Path, default=S / 'evidence/writing_packet_72d85875b')
    ap.add_argument('--successor', default='m6_07', help='ctl_timing_01 build directory of the m6 successor')
    a = ap.parse_args(argv)
    BUILDS['m6'] = CT / 'evidence' / a.successor
    missing = [stem for stem in REQUIRED_M5 if not attempts('ctl_m5_', stem)]
    missing += [str(p) for p in (BUILDS['m5'] / 'resource_review.json', BUILDS['m5'] / 'model_summary.json',
                                 a.out / 'CLAIMS.md') if not p.is_file()]
    if missing:
        sys.stderr.write('missing required input: %s\n' % ', '.join(missing))
        return 1
    inputs = set()
    succ = BUILDS['m6'] / 'response_only.p4'
    candidates = [('m5_10 (b758c981)', 'ctl_m5_'),
                  ('%s (%s)' % (a.successor, sha(succ)[:8] if succ.is_file() else 'not built'), 'ctl_m6_')]
    qual = qualification(candidates, inputs)
    runs = sorted({p for _n, prefix in candidates for p in RUNS.glob(prefix + '*') if p.is_dir()})
    timed = timing([r for r in runs if 'repeat_sbo' in r.name or 'piggyback' in r.name], inputs)
    out = a.out
    (out / 'qualification_table.json').write_text(json.dumps(qual, indent=1) + '\n')
    (out / 'qualification_table.md').write_text(table_md(qual))
    write_csv(out / 'timing_errors.csv', timed)
    write_csv(out / 'costs.csv', costs([r for r in runs if 'repeat_sbo' in r.name or 'piggyback' in r.name], inputs))
    write_csv(out / 'external_growth.csv', growth())
    write_csv(out / 'stages.csv', stages(inputs))
    write_csv(out / 'model.csv', models(inputs))
    figs = figure(timed, out)
    inputs.add(out / 'CLAIMS.md')
    outputs = [out / n for n in ('qualification_table.json', 'qualification_table.md', 'timing_errors.csv',
                                 'costs.csv', 'external_growth.csv', 'stages.csv', 'model.csv')] + figs
    root = S.parents[7]

    def rel(p):
        return os.path.relpath(p, root)
    index = {'command': 'python3 %s' % Path(__file__).resolve().relative_to(root),
             'prerequisites': 'Python 3 with matplotlib; no compiler, model or hardware is needed (compile and model '
                              'records are read, not rerun)',
             'inputs': {rel(p): sha(p) for p in sorted(inputs)},
             'outputs': {rel(p): sha(p) for p in outputs}}
    (out / 'evidence_index.json').write_text(json.dumps(index, indent=1) + '\n')
    pending = sum(r['status'] == 'PENDING' for r in qual)
    failed = sum(r['status'] == 'FAIL' for r in qual)
    print('wrote %s: %d gates (%d FAIL, %d PENDING), %d timing rows, %d inputs hashed'
          % (out, len(qual), failed, pending, len(timed), len(inputs)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
