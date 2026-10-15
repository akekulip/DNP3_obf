#!/usr/bin/env python3
"""Independent post-block restoration check (run after every hardware block, including a failed one).

  python3 restore_verify.py --config CFG --run-root EVIDENCE_DIR [--vision-baseline FILE]

Read-only on both hosts. Passes only when all of these hold:
  1. the runner's own restore record (campaign_run.json or series record) lists every step ok, and every
     required step is present: cold swap to the production launch script, $PORT replay, relay slot (when the
     config restores one), Vision restore and the ping;
  2. the switch is running the configured production program (observe_program.py, read-only);
  3. a fresh read-only live_snapshot.py of that program equals the block's own pre-run snapshot on every table
     except the counter tables in VOLATILE (all 399 others, $PORT included, matched exactly on 2026-10-15);
  4. Vision's `vision_run.py state` equals the recorded baseline (source pruning, namespace TCP profile, route,
     fixture qdisc);
  5. a fresh ping through the restored path succeeds.
Writes restore_verify.json beside the evidence; exit 0 only when every check passes.
"""
import argparse
import glob
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
VOLATILE = frozenset({'$PORT_STAT', 'log_tbl_counter', 'tbl_dbg_counter', 'tf1.log_tbl_counter'})
BASELINE = HERE / 'restore_baseline/vision_state_20261015.txt'
REQUIRED_STEPS = ('cold-swap bf_switchd back to the observed production program',
                  'replay the pre-run $PORT snapshot on the production program',
                  'Vision: fixture off, namespace profile and NIC flag restored',
                  'ping through the restored switch path')


def ssh(host, cmd, timeout=180):
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', host, cmd],
                          capture_output=True, text=True, timeout=timeout)


def run_record(root):
    """The runner's record that carries the restore list (campaign_run.json, or a series/isolation record)."""
    for path in [root / 'campaign_run.json'] + sorted(Path(p) for p in glob.glob(str(root / '*.json'))):
        try:
            data = json.loads(path.read_text())
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get('restore'), list):
            return path, data
    return None, None


def compare_snapshots(pre, post):
    errors = []
    if pre.get('program') != post.get('program'):
        errors.append('program %r != pre-run %r' % (post.get('program'), pre.get('program')))
    if post.get('errors'):
        errors.append('post snapshot read errors: %s' % str(post['errors'])[:300])
    a, b = pre.get('tables', {}), post.get('tables', {})
    if set(a) != set(b):
        errors.append('table sets differ: %s' % sorted(set(a) ^ set(b))[:20])
    differ = sorted(k for k in set(a) & set(b) - VOLATILE
                    if json.dumps(a[k], sort_keys=True) != json.dumps(b[k], sort_keys=True))
    if differ:
        errors.append('tables differ from the pre-run snapshot: %s' % differ[:20])
    return errors, len(set(a) & set(b) - VOLATILE)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--config', required=True)
    ap.add_argument('--run-root', required=True)
    ap.add_argument('--vision-baseline', default=str(BASELINE))
    a = ap.parse_args(argv)
    cfg = json.loads(Path(a.config).read_text())
    root = Path(a.run_root)
    hosts, prod = cfg['hosts'], cfg['production']
    R, V = hosts['switch_remote_dir'], hosts['vision_run_dir']
    out = {'time': time.time(), 'run_root': str(root), 'checks': {}}
    fails = []

    path, record = run_record(root)
    if record is None:
        fails.append('no runner restore record under %s' % root)
    else:
        steps = record['restore']
        labels = [s.get('step') for s in steps]
        bad = [s for s in steps if not s.get('ok')]
        required = list(REQUIRED_STEPS) + (['reinstall the relay slot'] if prod.get('relay_slot') else [])
        missing = [r for r in required if r not in labels]
        out['checks']['runner_restore'] = {'record': str(path), 'steps': steps, 'missing': missing}
        if bad:
            fails.append('runner restore step(s) failed: %s' % [s.get('step') for s in bad])
        if missing:
            fails.append('runner restore step(s) missing: %s' % missing)

    r = ssh(hosts['switch'], 'python3 %s/aux/observe_program.py' % R)
    try:
        observed = json.loads([l for l in r.stdout.splitlines() if l.startswith('{')][-1])
    except (IndexError, ValueError):
        observed = {'error': (r.stdout + r.stderr)[-300:]}
    out['checks']['program'] = observed
    if observed.get('program') != prod['program']:
        fails.append('switch runs %r, production is %r' % (observed.get('program'), prod['program']))

    pre_files = sorted(root.glob('*_prerun.json'))
    if len(pre_files) != 1:
        fails.append('expected one pre-run snapshot in %s, found %d' % (root, len(pre_files)))
    else:
        remote = '/tmp/restore_verify_%s.json' % root.name
        r = ssh(hosts['switch'], 'python3 %s/aux/live_snapshot.py %s %s >/dev/null && cat %s' %
                (R, prod['program'], remote, remote), timeout=600)
        try:
            post = json.loads(r.stdout)
        except ValueError:
            post = None
            fails.append('post-restore snapshot unreadable: %s' % (r.stderr or r.stdout)[-300:])
        if post is not None:
            (root / 'restore_verify_postrun.json').write_text(json.dumps(post) + '\n')
            errors, compared = compare_snapshots(json.loads(pre_files[0].read_text()), post)
            out['checks']['snapshot'] = {'pre': pre_files[0].name, 'tables_compared': compared,
                                         'volatile_ignored': sorted(VOLATILE), 'errors': errors}
            fails.extend(errors)

    r = ssh(hosts['vision'], 'sudo -n python3 %s/vision_run.py state' % V)
    want = Path(a.vision_baseline).read_text()
    out['checks']['vision_state'] = {'rc': r.returncode, 'state': r.stdout, 'baseline': a.vision_baseline}
    if r.returncode or r.stdout != want:
        fails.append('Vision state differs from the baseline (rc %d): %s' % (r.returncode, r.stdout[-300:]))

    pg = prod['ping']
    r = ssh(hosts['vision'], 'ping -c %d -I %s %s' % (pg['count'] + 1, pg['src'], pg['dst']))
    out['checks']['ping'] = {'rc': r.returncode, 'tail': r.stdout[-200:]}
    if r.returncode:
        fails.append('ping through the restored path failed (rc %d)' % r.returncode)

    out.update(ok=not fails, failures=fails)
    (root / 'restore_verify.json').write_text(json.dumps(out, indent=1, default=str) + '\n')
    print(json.dumps({'ok': out['ok'], 'failures': fails}))
    return 0 if not fails else 1


if __name__ == '__main__':
    sys.exit(main())
