#!/usr/bin/env python3
"""
Highest-N multi-CROB Select-Before-Operate sweep (rig orchestration).

Drives the master on ``cfg.MASTER_IP`` and the outstation on ``cfg.OUTSTATION_IP``
over SSH. For each N it starts a FRESH ``--control-test`` outstation with N control
points, captures a per-N ``.pcapng`` with dumpcap, runs one SBO of N CROBs, pulls the
outstation JSON evidence + master JSON + PCAP back, and validates the PCAP with
``analyze_multicrob_pcap.py``.

A run PASSES iff: master exit 0, master task_completion == SUCCESS, outstation
final_state_matches_expected, and the PCAP analyzer passes for N.

Nmax discovery: test the mandatory points; the ascending sequence gives the first
failure; binary-search the boundary between the last consecutive pass and the first
failure; then re-run Nmax three times. Writes reports/sweep_manifest.csv.

This characterises ONE controlled configuration (the exact OpenDNP3 build, hosts,
point count, and fragment settings in use) -- it is NOT a universal DNP3 maximum.

Usage: run from the harness dir on the dev box that can SSH to both rig hosts.
"""
import argparse
import csv
import json
import os
import subprocess
import sys
import time

HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HARNESS_DIR)
import lab_config as cfg

MANDATORY_POINTS = [1, 2, 4, 8, 16, 18, 19, 32, 64, 128]
REMOTE_DIR = '~/dnp3_multicrob_harness'
IFACE = 'eno1'


def _ssh_base(user, host, extra=()):
    return ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', *extra, '%s@%s' % (user, host)]


def ssh(user, host, cmd, timeout=120):
    r = subprocess.run(_ssh_base(user, host) + [cmd], capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def ssh_detached(user, host, cmd, timeout=20):
    # -f backgrounds ssh; DEVNULL local streams so the forked child never holds a pipe.
    subprocess.run(_ssh_base(user, host, extra=['-f']) + [cmd],
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=timeout)


def pull(user, host, remote_glob, local_dir):
    subprocess.run(['rsync', '-az', '%s@%s:%s' % (user, host, remote_glob), local_dir + '/'],
                   capture_output=True, text=True, timeout=60)


def deploy(user):
    for host in (cfg.MASTER_IP, cfg.OUTSTATION_IP):
        subprocess.run(['rsync', '-az', '--exclude', 'logs/', '--exclude', 'captures/',
                        '--exclude', '__pycache__/', HARNESS_DIR + '/',
                        '%s@%s:%s/' % (user, host, REMOTE_DIR)],
                       capture_output=True, text=True, timeout=120)


def stop_outstation(user):
    ssh(user, cfg.OUTSTATION_IP,
        "fuser -k 20000/tcp 2>/dev/null; pkill -f 'run_[o]utstation.py' 2>/dev/null; "
        "pkill -f dumpcap 2>/dev/null; true")


def wait_ready(user, logrel, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        _, out, _ = ssh(user, cfg.OUTSTATION_IP,
                        "grep -qs 'CONTROL-TEST mode ENABLED' %s/%s && echo READY" % (REMOTE_DIR, logrel))
        if 'READY' in out:
            return True
        time.sleep(0.5)
    return False


def run_one(user, n, results_dir):
    run_id = 'sweep_n%d' % n
    pcap_rel = 'captures/sweep/multicrob_n%d.pcapng' % n
    olog = 'logs/outstation/ctrl_%s.log' % run_id
    ojson = 'logs/outstation/multicrob_%s.json' % run_id
    mjson = 'logs/master/multicrob_master_%s.json' % run_id

    stop_outstation(user); time.sleep(1)
    # Clear stale artifacts (local + remote) so a silently-failed pull can never let
    # this run be scored against a previous run's evidence.
    for p in (os.path.join(HARNESS_DIR, pcap_rel), os.path.join(HARNESS_DIR, ojson),
              os.path.join(HARNESS_DIR, mjson), os.path.join(results_dir, 'analyze_n%d.json' % n)):
        try:
            os.remove(p)
        except OSError:
            pass
    ssh(user, cfg.OUTSTATION_IP, "cd %s && mkdir -p captures/sweep logs/outstation logs/master && rm -f %s %s"
        % (REMOTE_DIR, pcap_rel, ojson))
    ssh(user, cfg.MASTER_IP, "cd %s && rm -f %s" % (REMOTE_DIR, mjson))
    ssh_detached(user, cfg.OUTSTATION_IP,
                 "cd %s && dumpcap -i %s -f 'tcp port 20000' -w %s > logs/dumpcap_%s.log 2>&1"
                 % (REMOTE_DIR, IFACE, pcap_rel, run_id))
    time.sleep(2.5)
    ssh(user, cfg.OUTSTATION_IP,
        "cd %s && fuser -k 20000/tcp 2>/dev/null; sleep 1; nohup python3 run_outstation.py "
        "--control-test --control-point-count %d --run-id %s > %s 2>&1 </dev/null & echo $!"
        % (REMOTE_DIR, n, run_id, olog))
    if not wait_ready(user, olog):
        stop_outstation(user)
        return {'n': n, 'pass': False, 'note': 'outstation not ready'}

    rc, _, _ = ssh(user, cfg.MASTER_IP,
                   "cd %s && python3 run_master.py --action multi-crob-sbo --crob-count %d --run-id %s"
                   % (REMOTE_DIR, n, run_id), timeout=120)
    time.sleep(1.5)
    ssh(user, cfg.OUTSTATION_IP, "pkill -f dumpcap 2>/dev/null; true"); time.sleep(1.0)

    # pull artifacts
    pull(user, cfg.OUTSTATION_IP, '%s/%s' % (REMOTE_DIR, pcap_rel), os.path.join(HARNESS_DIR, 'captures/sweep'))
    pull(user, cfg.OUTSTATION_IP, '%s/%s' % (REMOTE_DIR, ojson), os.path.join(HARNESS_DIR, 'logs/outstation'))
    pull(user, cfg.MASTER_IP, '%s/%s' % (REMOTE_DIR, mjson), os.path.join(HARNESS_DIR, 'logs/master'))
    stop_outstation(user)

    local_pcap = os.path.join(HARNESS_DIR, pcap_rel)
    local_ojson = os.path.join(HARNESS_DIR, ojson)
    local_mjson = os.path.join(HARNESS_DIR, mjson)

    out_ev = _load_json(local_ojson)
    mas_ev = _load_json(local_mjson)
    analyze_json = os.path.join(results_dir, 'analyze_n%d.json' % n)
    ana_rc = subprocess.run([sys.executable, os.path.join(HARNESS_DIR, 'analyze_multicrob_pcap.py'),
                             '--pcap', local_pcap, '--expected-n', str(n), '--json', analyze_json],
                            capture_output=True, text=True)
    ana = _load_json(analyze_json)

    task_ok = (mas_ev or {}).get('task_completion') == 'SUCCESS'
    out_ok = bool((out_ev or {}).get('final_state_matches_expected'))
    ana_ok = bool((ana or {}).get('pass'))
    passed = (rc == 0) and task_ok and out_ok and ana_ok
    sel = (ana or {}).get('select') or {}
    op = (ana or {}).get('operate') or {}
    return {
        'n': n, 'master_exit': rc, 'task_completion': (mas_ev or {}).get('task_completion'),
        'outstation_final_matches': out_ok, 'analyze_pass': ana_ok, 'pass': passed,
        'pcap': pcap_rel, 'select_link_frames': sel.get('data_link_frames'),
        'operate_link_frames': op.get('data_link_frames'),
        'sbo_round_trip_sec': (mas_ev or {}).get('sbo_round_trip_sec'),
        'note': '' if passed else 'FAIL: %s' % ((ana or {}).get('failures') or 'see JSON'),
    }


def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def write_manifest(path, records, nmax, first_fail, repeats):
    cols = ['n', 'master_exit', 'task_completion', 'outstation_final_matches', 'analyze_pass',
            'pass', 'select_link_frames', 'operate_link_frames', 'sbo_round_trip_sec', 'pcap', 'note']
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['# multi-CROB SBO highest-N sweep; config: OpenDNP3 rig %s(master)/%s(outstation), '
                    'db_size default, one SBO per N' % (cfg.MASTER_IP, cfg.OUTSTATION_IP)])
        w.writerow(['# Nmax=%s (last passing N); first_fail=%s; Nmax not a universal DNP3 maximum'
                    % (nmax, first_fail)])
        w.writerow(cols)
        for rec in records:
            w.writerow([rec.get(c, '') for c in cols])
        for i, rec in enumerate(repeats, 1):
            row = [rec.get(c, '') for c in cols]
            row[-1] = 'Nmax repeat %d/3; %s' % (i, rec.get('note', ''))
            w.writerow(row)


def main():
    ap = argparse.ArgumentParser(description='Highest-N multi-CROB SBO rig sweep.')
    ap.add_argument('--user', default=os.environ.get('RIG_USER', 'decps'), help='SSH user for the rig hosts.')
    ap.add_argument('--points', default=None, help='Comma-separated N points (default: mandatory set).')
    ap.add_argument('--no-deploy', action='store_true', help='Skip the rsync deploy step.')
    args = ap.parse_args()

    points = [int(x) for x in args.points.split(',')] if args.points else list(MANDATORY_POINTS)
    results_dir = os.path.join(HARNESS_DIR, 'reports', 'sweep')
    os.makedirs(results_dir, exist_ok=True)

    if not args.no_deploy:
        print('Deploying to %s and %s ...' % (cfg.MASTER_IP, cfg.OUTSTATION_IP))
        deploy(args.user)

    records = []
    by_n = {}
    for n in sorted(points):
        print('--- N=%d ---' % n, flush=True)
        rec = run_one(args.user, n, results_dir)
        print('    N=%d pass=%s exit=%s task=%s out_match=%s ana=%s frames(sel/op)=%s/%s' % (
            n, rec.get('pass'), rec.get('master_exit'), rec.get('task_completion'),
            rec.get('outstation_final_matches'), rec.get('analyze_pass'),
            rec.get('select_link_frames'), rec.get('operate_link_frames')), flush=True)
        records.append(rec); by_n[n] = rec

    # first failure along the ascending sequence; last consecutive pass before it
    ascending = sorted(by_n)
    first_fail = next((n for n in ascending if not by_n[n]['pass']), None)
    passes = [n for n in ascending if by_n[n]['pass']]
    last_pass = max(passes) if passes else 0

    if first_fail is not None:
        lo = max([n for n in passes if n < first_fail], default=0)
        hi = first_fail
        print('First failure at N=%d; binary-searching (%d, %d)...' % (first_fail, lo, hi), flush=True)
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if mid not in by_n:
                print('--- N=%d (binary search) ---' % mid, flush=True)
                rec = run_one(args.user, mid, results_dir)
                print('    N=%d pass=%s' % (mid, rec.get('pass')), flush=True)
                records.append(rec); by_n[mid] = rec
            if by_n[mid]['pass']:
                lo = mid
            else:
                hi = mid
        nmax = lo
    else:
        nmax = last_pass
        print('No failure up to N=%d (Nmax >= %d for this config).' % (max(ascending), nmax), flush=True)

    print('Re-running Nmax=%d three times...' % nmax, flush=True)
    repeats = []
    for i in range(3):
        rec = run_one(args.user, nmax, results_dir)
        print('    Nmax=%d repeat %d/3 pass=%s' % (nmax, i + 1, rec.get('pass')), flush=True)
        repeats.append(rec)

    manifest = os.path.join(HARNESS_DIR, 'reports', 'sweep_manifest.csv')
    write_manifest(manifest, records, nmax, first_fail, repeats)
    print('\nNmax=%s (first_fail=%s). Manifest -> %s' % (nmax, first_fail, manifest))
    stop_outstation(args.user)
    return 0


if __name__ == '__main__':
    sys.exit(main())
