#!/usr/bin/env python3
"""Run one campaign with exactly one Vision NIC coalescing factor changed, restoring it afterwards (Gate 5, tails).

  DEFENSE4_HW_AUTHORIZED=1 python3 tail_factor.py --config CFG --run-id ID --arms off,timing_only \
      --fixtures separate_ack --set tx-frames-irq=64 [--apply]

The candidate campaign itself is unchanged (same config, traffic and restore). Around it this records Vision's
`ethtool -c` for the parent NIC, applies one `ethtool -C` change, verifies it by read-back, runs the campaign, and
in every case restores each changed field to its recorded value and verifies that read-back too. A control run
uses --set none. The record (before, requested, applied, restored, campaign rc) is written beside the run's
evidence as tail_factor.json. Without --apply it prints the plan only.
"""
import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VISION = 'decps@10.10.54.19'
NIC = 'enp59s0f0np0'
FIELDS = {'adaptive-rx': 'Adaptive RX', 'adaptive-tx': 'TX', 'rx-usecs': 'rx-usecs', 'tx-usecs': 'tx-usecs',
          'tx-frames-irq': 'tx-frames-irq'}


def ssh(cmd, check=True):
    r = subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', VISION, cmd],
                       capture_output=True, text=True, timeout=60)
    if check and r.returncode:
        raise RuntimeError('vision: %s -> rc %d %s' % (cmd, r.returncode, r.stderr.strip()))
    return r.stdout


def read_coalesce():
    out = ssh('ethtool -c %s' % NIC)
    values = {}
    for line in out.splitlines():
        if line.startswith('Adaptive RX:'):
            parts = line.split()
            values['adaptive-rx'], values['adaptive-tx'] = parts[2], parts[4]
        else:
            name, _, value = line.partition(':')
            if name.strip() in ('rx-usecs', 'tx-usecs', 'tx-frames-irq'):
                values[name.strip()] = value.strip()
    missing = [k for k in FIELDS if k not in values]
    if missing:
        raise RuntimeError('ethtool -c lacks %s' % missing)
    return values


def set_coalesce(changes):
    args = ' '.join('%s %s' % (k, v) for k, v in changes.items())
    ssh("sudo -n python3 -c %s" % shlex.quote(
        "import subprocess,sys; sys.exit(subprocess.run(['ethtool','-C','%s'] + %r).returncode)"
        % (NIC, args.split())))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--config', required=True)
    ap.add_argument('--run-id', required=True)
    ap.add_argument('--arms', required=True)
    ap.add_argument('--fixtures', default='separate_ack')
    ap.add_argument('--set', required=True, help="FIELD=VALUE[,FIELD=VALUE] or 'none' for the control run")
    ap.add_argument('--apply', action='store_true')
    a = ap.parse_args(argv)
    changes = {} if a.set == 'none' else dict(item.split('=', 1) for item in a.set.split(','))
    unknown = [k for k in changes if k not in FIELDS]
    if unknown:
        raise SystemExit('unknown coalescing field(s) %s; allowed %s' % (unknown, sorted(FIELDS)))
    campaign = [sys.executable, '-u', str(HERE / 'candidate_campaign.py'), 'run', '--config', a.config,
                '--run-id', a.run_id, '--arms', a.arms, '--fixtures', a.fixtures] + (['--apply'] if a.apply else [])
    record = {'nic': NIC, 'requested': changes, 'campaign': campaign}
    record['before'] = read_coalesce()
    if not a.apply:
        print(json.dumps(record, indent=1))
        return 0
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        raise SystemExit('DEFENSE4_HW_AUTHORIZED=1 required')
    rc, restore_ok = None, False
    try:
        if changes:
            set_coalesce(changes)
        record['applied'] = read_coalesce()
        wrong = {k: (v, record['applied'][k]) for k, v in changes.items() if record['applied'][k] != v}
        if wrong:
            raise RuntimeError('read-back differs from the requested factor: %s' % wrong)
        rc = subprocess.run(campaign).returncode
    finally:
        try:
            if changes:
                set_coalesce({k: record['before'][k] for k in changes})
            record['restored'] = read_coalesce()
            restore_ok = record['restored'] == record['before']
        except (RuntimeError, subprocess.SubprocessError) as error:
            record['restore_error'] = str(error)
        record.update(campaign_rc=rc, restore_ok=restore_ok)
        cfg = json.load(open(a.config))
        root = HERE.parents[4] / cfg['evidence_dir'] / a.run_id
        root.mkdir(parents=True, exist_ok=True)
        (root / 'tail_factor.json').write_text(json.dumps(record, indent=1) + '\n')
        print(json.dumps({k: record.get(k) for k in ('requested', 'campaign_rc', 'restore_ok')}))
    return 0 if rc == 0 and restore_ok else 1


if __name__ == '__main__':
    raise SystemExit(main())
