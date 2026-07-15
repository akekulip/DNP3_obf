#!/usr/bin/env python3
"""
Boundary-index CROB experiment (rig orchestration).

Runs two fixed Select-Before-Operate cases on the rig to DISTINGUISH a per-request
operation-count limit (``TOO_MANY_OPS``, the earlier N=17 result) from a
nonexistent-output-index rejection (``OUT_OF_RANGE``):

  * valid   K=5, N=5 -- indexes 0..4 all exist -> expect all SUCCESS, OPERATE sent.
  * invalid K=5, N=6 -- index 5 does not exist -> characterise (do NOT assume) the
                        SELECT-response status for index 5 and whether OPERATE fires.

For each case it starts a FRESH ``--control-test`` outstation with K points on
``cfg.OUTSTATION_IP``, captures a per-case ``.pcapng`` with dumpcap, runs one SBO of
N CROBs from the master on ``cfg.MASTER_IP``, pulls the PCAP + master/outstation JSON
back, and runs ``analyze_multicrob_pcap.py`` (all-success mode for the valid case,
boundary-index mode for the invalid case). Stale local+remote artifacts are cleared
before each case so an old file can never produce a false success.

This is a different experiment from the highest-N sweep, so it is a separate script.
It does NOT change ``maxControlsPerRequest`` and never modifies the replay/split/READ
paths. Software-only: no index maps to any physical output. It characterises ONE
OpenDNP3 configuration; it is NOT a universal DNP3 result.

Usage (from the harness dir on the dev box that can SSH to both rig hosts):
    python3 run_crob_boundary_index_test.py --user decps
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

DEFAULT_REMOTE_DIR = '~/dnp3_multicrob_harness'
DEFAULT_IFACE = 'eno1'


# --------------------------------------------------------------------------- #
# SSH / rsync helpers (same patterns as run_multicrob_sweep.py)
# --------------------------------------------------------------------------- #
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


def pull(user, host, remote_path, local_dir):
    subprocess.run(['rsync', '-az', '%s@%s:%s' % (user, host, remote_path), local_dir + '/'],
                   capture_output=True, text=True, timeout=60)


def deploy(user, remote_dir):
    for host in (cfg.MASTER_IP, cfg.OUTSTATION_IP):
        subprocess.run(['rsync', '-az', '--exclude', 'logs/', '--exclude', 'captures/',
                        '--exclude', '__pycache__/', HARNESS_DIR + '/',
                        '%s@%s:%s/' % (user, host, remote_dir)],
                       capture_output=True, text=True, timeout=120)


def stop_outstation(user, remote_dir):
    ssh(user, cfg.OUTSTATION_IP,
        "fuser -k 20000/tcp 2>/dev/null; pkill -f 'run_[o]utstation.py' 2>/dev/null; "
        "pkill -f dumpcap 2>/dev/null; true")


def wait_ready(user, remote_dir, logrel, timeout=25):
    end = time.time() + timeout
    while time.time() < end:
        _, out, _ = ssh(user, cfg.OUTSTATION_IP,
                        "grep -qs 'CONTROL-TEST mode ENABLED' %s/%s && echo READY" % (remote_dir, logrel))
        if 'READY' in out:
            return True
        time.sleep(0.5)
    return False


def _load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# One boundary case, end to end
# --------------------------------------------------------------------------- #
def run_case(user, remote_dir, iface, case):
    """Run one case (fresh outstation + capture + SBO + pull + analyze). Returns a record."""
    run_id = case['run_id']
    k, n = case['k'], case['n']
    pcap_rel = os.path.join('captures', 'boundary', '%s.pcapng' % case['pcap_stem'])
    olog = 'logs/outstation/ctrl_%s.log' % run_id
    ojson_rel = 'logs/outstation/multicrob_%s.json' % run_id
    mjson_rel = 'logs/master/multicrob_master_%s.json' % run_id

    local_pcap = os.path.join(HARNESS_DIR, pcap_rel)
    local_ojson = os.path.join(HARNESS_DIR, ojson_rel)
    local_mjson = os.path.join(HARNESS_DIR, mjson_rel)
    analyze_json = os.path.join(HARNESS_DIR, 'reports', 'boundary', 'analyze_%s.json' % case['tag'])

    stop_outstation(user, remote_dir)
    time.sleep(1)
    # Clear stale local + remote artifacts so a silently-failed pull can never let this
    # case be scored against a previous run's evidence.
    for p in (local_pcap, local_ojson, local_mjson, analyze_json):
        try:
            os.remove(p)
        except OSError:
            pass
    for d in (os.path.dirname(local_pcap), os.path.dirname(local_ojson),
              os.path.dirname(local_mjson), os.path.dirname(analyze_json)):
        os.makedirs(d, exist_ok=True)
    ssh(user, cfg.OUTSTATION_IP,
        "cd %s && mkdir -p captures/boundary logs/outstation logs/master && rm -f %s %s"
        % (remote_dir, pcap_rel, ojson_rel))
    ssh(user, cfg.MASTER_IP, "cd %s && rm -f %s" % (remote_dir, mjson_rel))

    ssh_detached(user, cfg.OUTSTATION_IP,
                 "cd %s && dumpcap -i %s -f 'tcp port 20000' -w %s > logs/dumpcap_%s.log 2>&1"
                 % (remote_dir, iface, pcap_rel, run_id))
    time.sleep(2.5)
    ssh(user, cfg.OUTSTATION_IP,
        "cd %s && fuser -k 20000/tcp 2>/dev/null; sleep 1; nohup python3 run_outstation.py "
        "--control-test --control-point-count %d --run-id %s > %s 2>&1 </dev/null & echo $!"
        % (remote_dir, k, run_id, olog))
    if not wait_ready(user, remote_dir, olog):
        stop_outstation(user, remote_dir)
        return {'case_name': case['name'], 'configured_points': k, 'sent_crobs': n,
                'note': 'FAIL: outstation not ready', 'pcap_path': pcap_rel}

    rc, _, _ = ssh(user, cfg.MASTER_IP,
                   "cd %s && python3 run_master.py --action multi-crob-sbo --crob-count %d --run-id %s"
                   % (remote_dir, n, run_id), timeout=120)
    time.sleep(1.5)
    ssh(user, cfg.OUTSTATION_IP, "pkill -f dumpcap 2>/dev/null; true")
    time.sleep(1.0)

    pull(user, cfg.OUTSTATION_IP, '%s/%s' % (remote_dir, pcap_rel), os.path.dirname(local_pcap))
    pull(user, cfg.OUTSTATION_IP, '%s/%s' % (remote_dir, ojson_rel), os.path.dirname(local_ojson))
    pull(user, cfg.MASTER_IP, '%s/%s' % (remote_dir, mjson_rel), os.path.dirname(local_mjson))
    stop_outstation(user, remote_dir)

    # Analyze the pulled PCAP locally; mode depends on the case.
    ana_cmd = [sys.executable, os.path.join(HARNESS_DIR, 'analyze_multicrob_pcap.py'),
               '--pcap', local_pcap, '--expected-n', str(n), '--mode', case['mode'],
               '--json', analyze_json]
    if case['mode'] == 'boundary-index':
        ana_cmd += ['--configured-points', str(k), '--expect-operate', 'either']
    subprocess.run(ana_cmd, capture_output=True, text=True)

    out_ev = _load_json(local_ojson) or {}
    mas_ev = _load_json(local_mjson) or {}
    ana = _load_json(analyze_json) or {}
    sel_resp = ana.get('select_response') or {}

    return {
        'case_name': case['name'],
        'configured_points': k,
        'sent_crobs': n,
        'master_exit': rc,
        'master_task_completion': mas_ev.get('task_completion'),
        'outstation_select_seen': out_ev.get('select_seen'),
        'outstation_select_success': out_ev.get('select_success'),
        'outstation_operate_seen': out_ev.get('operate_seen'),
        'outstation_operate_success': out_ev.get('operate_success'),
        'outstation_rejected_indexes': out_ev.get('rejected_indexes'),
        'outstation_final_state_matches_expected': out_ev.get('final_state_matches_expected'),
        'analyzer_pass': ana.get('pass'),
        'analyzer_classification': ana.get('classification',
                                           'all_success' if ana.get('pass') else 'unclassified'),
        'first_rejected_index': sel_resp.get('first_rejected_index'),
        'first_rejected_status_name': sel_resp.get('first_rejected_status_name'),
        'operate_sent': ana.get('operate_sent', bool(ana.get('operate'))),
        'pcap_path': pcap_rel,
        'analyzer_json': os.path.relpath(analyze_json, HARNESS_DIR),
        'outstation_json': ojson_rel,
        'master_json': mjson_rel,
        'note': case['note'],
    }


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
MANIFEST_COLS = [
    'case_name', 'configured_points', 'sent_crobs', 'master_exit', 'master_task_completion',
    'outstation_select_seen', 'outstation_select_success', 'outstation_operate_seen',
    'outstation_operate_success', 'outstation_rejected_indexes',
    'outstation_final_state_matches_expected', 'analyzer_pass', 'analyzer_classification',
    'first_rejected_index', 'first_rejected_status_name', 'operate_sent', 'pcap_path',
    'analyzer_json', 'outstation_json', 'master_json', 'note',
]


def _cell(value):
    if value is None:
        return ''
    if isinstance(value, (list, dict)):
        return json.dumps(value)
    return value


def write_manifest(path, records):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['# boundary-index CROB experiment; config: OpenDNP3 rig %s(master)/%s(outstation); '
                    'software-only; NOT a universal DNP3 result' % (cfg.MASTER_IP, cfg.OUTSTATION_IP)])
        w.writerow(MANIFEST_COLS)
        for rec in records:
            w.writerow([_cell(rec.get(c)) for c in MANIFEST_COLS])


def write_results_md(path, records):
    L = []
    L.append('# Boundary-Index CROB Experiment\n')
    L.append('## Purpose\n')
    L.append('This experiment distinguishes an OpenDNP3 operation-count limit '
             '(`TOO_MANY_OPS`, the earlier N=17 result) from a nonexistent-output-index '
             'rejection (`OUT_OF_RANGE`). Both stop controls from applying, but for '
             'different reasons; the SELECT-response per-index `CommandStatus` on the wire '
             'tells them apart.\n')
    L.append('## Method\n')
    L.append('- Object type fixed: Group 12 Variation 1 CROB.\n'
             '- One SBO command set, one object header, qualifier `0x28`, Count = N.\n'
             '- Outstation configured with only K valid software-only output points (indexes 0..K-1).\n'
             '- Master sends N CROBs (indexes 0..N-1); N can equal K or exceed K.\n'
             '- Correctness is the logical SELECT/OPERATE content and per-index status (PCAP + '
             'outstation JSON), never TCP packet count. Task-level master SUCCESS is NOT proof '
             'that any output changed.\n')
    L.append('## Observation plan (observe and report -- statuses are not assumed)\n')
    L.append('- **Valid K=5, N=5:** all indexes exist -> expect all SELECT statuses SUCCESS, OPERATE '
             'sent (the valid baseline).\n'
             '- **Invalid K=5, N=6:** index 5 does not exist -> observe and report the returned '
             'per-index SELECT-response CommandStatus for index 5 and whether OPERATE is sent. The '
             'status is whatever the outstation application returns; this harness does not assume it '
             'will be OUT_OF_RANGE.\n'
             '- **Earlier N=17 result (for contrast):** `TOO_MANY_OPS` came from the per-request '
             'operation-count limit (`maxControlsPerRequest`), not a nonexistent index.\n'
             '- The returned CommandStatus originates in the outstation application control-point '
             'backend; OpenDNP3 does not validate a control index natively (see `run_outstation.py`).\n')
    L.append('## Observed results\n')
    if not records:
        L.append('_No cases were run._\n')
    for rec in records:
        L.append('### %s\n' % rec.get('case_name'))
        L.append('- configured points K = %s ; CROBs sent N = %s\n'
                 % (rec.get('configured_points'), rec.get('sent_crobs')))
        L.append('- master exit = %s ; task_completion = %s (task-level only)\n'
                 % (rec.get('master_exit'), rec.get('master_task_completion')))
        L.append('- outstation: select_seen=%s select_success=%s operate_seen=%s operate_success=%s\n'
                 % (rec.get('outstation_select_seen'), rec.get('outstation_select_success'),
                    rec.get('outstation_operate_seen'), rec.get('outstation_operate_success')))
        L.append('- outstation rejected_indexes = %s ; final_state_matches_expected = %s\n'
                 % (rec.get('outstation_rejected_indexes'),
                    rec.get('outstation_final_state_matches_expected')))
        L.append('- analyzer: pass=%s classification=`%s` operate_sent=%s\n'
                 % (rec.get('analyzer_pass'), rec.get('analyzer_classification'),
                    rec.get('operate_sent')))
        L.append('- first rejected: index=%s status=%s\n'
                 % (rec.get('first_rejected_index'), rec.get('first_rejected_status_name')))
        L.append('- artifacts: `%s`, `%s`, outstation `%s`, master `%s`\n'
                 % (rec.get('pcap_path'), rec.get('analyzer_json'),
                    rec.get('outstation_json'), rec.get('master_json')))
    L.append('## Scope / interpretation\n')
    L.append('Software-only; no index maps to any physical output. Invalid-index padding is NOT '
             'implemented. This experiment only characterises how OpenDNP3 responds when a '
             'multi-CROB SBO command set includes a nonexistent output index -- i.e. whether '
             'invalid-index CROBs can be considered later as a padding candidate and what '
             'response-side evidence they produce. Results are for this exact OpenDNP3 '
             'build/host/config; they are not a universal DNP3 result.\n')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write('\n'.join(L) + '\n')


def build_cases(valid_points, invalid_extra, only):
    k = valid_points
    n_invalid = k + invalid_extra
    cases = []
    if only in ('valid', 'both'):
        cases.append({
            'name': 'valid_k%d_n%d' % (k, k), 'tag': 'valid_k%d_n%d' % (k, k),
            'run_id': 'boundary_valid_k%d_n%d' % (k, k),
            'pcap_stem': 'crob_boundary_valid_k%d_n%d' % (k, k),
            'k': k, 'n': k, 'mode': 'all-success',
            'note': 'baseline: all %d indexes exist -> expect all SUCCESS + OPERATE' % k,
        })
    if only in ('invalid', 'both'):
        cases.append({
            'name': 'invalid_k%d_n%d' % (k, n_invalid), 'tag': 'invalid_k%d_n%d' % (k, n_invalid),
            'run_id': 'boundary_invalid_k%d_n%d' % (k, n_invalid),
            'pcap_stem': 'crob_boundary_invalid_k%d_n%d' % (k, n_invalid),
            'k': k, 'n': n_invalid, 'mode': 'boundary-index',
            'note': 'boundary: index %d does not exist -> characterise rejection + whether OPERATE fires'
                    % (n_invalid - 1),
        })
    return cases


def main():
    ap = argparse.ArgumentParser(description='Boundary-index CROB experiment (valid K=N vs invalid N>K).')
    ap.add_argument('--user', default=os.environ.get('RIG_USER', 'decps'), help='SSH user for the rig hosts.')
    ap.add_argument('--valid-points', type=int, default=5, help='K: valid simulated output points (default 5).')
    ap.add_argument('--invalid-extra', type=int, default=1,
                    help='Extra CROBs beyond K for the invalid case (default 1 -> N=K+1).')
    ap.add_argument('--iface', default=DEFAULT_IFACE, help='Capture interface on the outstation host.')
    ap.add_argument('--remote-dir', default=DEFAULT_REMOTE_DIR, help='Harness dir on the rig hosts.')
    ap.add_argument('--no-deploy', action='store_true', help='Skip the rsync deploy step.')
    ap.add_argument('--only', choices=['valid', 'invalid', 'both'], default='both',
                    help='Which case(s) to run (default both).')
    args = ap.parse_args()

    if args.valid_points < 1:
        ap.error('--valid-points must be >= 1')
    if args.invalid_extra < 1:
        ap.error('--invalid-extra must be >= 1')

    reports_dir = os.path.join(HARNESS_DIR, 'reports', 'boundary')
    os.makedirs(reports_dir, exist_ok=True)

    if not args.no_deploy:
        print('Deploying to %s and %s ...' % (cfg.MASTER_IP, cfg.OUTSTATION_IP), flush=True)
        deploy(args.user, args.remote_dir)

    cases = build_cases(args.valid_points, args.invalid_extra, args.only)
    records = []
    for case in cases:
        print('--- case: %s (K=%d, N=%d, mode=%s) ---' % (case['name'], case['k'], case['n'], case['mode']),
              flush=True)
        rec = run_case(args.user, args.remote_dir, args.iface, case)
        records.append(rec)
        print('    exit=%s task=%s analyzer_pass=%s classification=%s first_rejected=%s/%s operate_sent=%s'
              % (rec.get('master_exit'), rec.get('master_task_completion'), rec.get('analyzer_pass'),
                 rec.get('analyzer_classification'), rec.get('first_rejected_index'),
                 rec.get('first_rejected_status_name'), rec.get('operate_sent')), flush=True)

    manifest = os.path.join(reports_dir, 'boundary_index_manifest.csv')
    results_md = os.path.join(reports_dir, 'boundary_index_results.md')
    write_manifest(manifest, records)
    write_results_md(results_md, records)
    stop_outstation(args.user, args.remote_dir)
    print('\nManifest -> %s\nResults  -> %s' % (manifest, results_md), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
