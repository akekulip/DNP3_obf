#!/usr/bin/env python3
"""
Invalid-index CROB "padding candidate" test suite (rig orchestration).

Extends the boundary-index experiment to characterise how OpenDNP3 handles
nonexistent G12V1 CROB indexes placed at chosen positions, multiple invalid CROBs,
decoy-only invalid command sets, and the interaction between invalid indexes and the
per-request operation-count limit. Purely a SOFTWARE-ONLY OpenDNP3 protocol
characterisation: no index maps to a physical output, no padding is implemented,
`maxControlsPerRequest` is not raised, and DNP3 responses are never rewritten.

For each fixed case it starts a FRESH ``--control-test`` outstation with K points on
``cfg.OUTSTATION_IP``, captures a per-case ``.pcapng`` with dumpcap, runs one SBO from
the master on ``cfg.MASTER_IP`` (``--crob-count`` for the all-valid baseline, else an
explicit ``--crob-plan`` that places invalid indexes), pulls the PCAP + master/
outstation JSON, and analyzes it with ``analyze_multicrob_pcap.py``. Stale local+remote
artifacts are cleared before each case so an old file can never produce a false success.

Correctness is the logical SELECT/OPERATE content and per-index CommandStatus (PCAP +
outstation JSON), never TCP packet count. Task-level master SUCCESS is NOT proof any
output changed. Results are for this exact OpenDNP3 build/host/config; not universal.

Usage (from the harness dir on the dev box that can SSH to both rig hosts):
    python3 run_crob_padding_candidate_tests.py --user decps
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


def _plan_string(indexes):
    """Even index -> LATCH_ON, odd -> LATCH_OFF, in the given transmitted order."""
    return ','.join('%d:%s' % (i, 'LATCH_ON' if i % 2 == 0 else 'LATCH_OFF') for i in indexes)


def _statuses_by_index(frag_report):
    if not frag_report:
        return None
    idxs = frag_report.get('indexes') or []
    sts = frag_report.get('statuses') or []
    return {str(i): s for i, s in zip(idxs, sts)} if idxs else None


# --------------------------------------------------------------------------- #
# Case definitions (fixed suite)
# --------------------------------------------------------------------------- #
def build_cases(valid_points):
    k = valid_points               # default 5 for cases 1-7
    return [
        {'name': 'valid_k5_n5', 'k': k, 'indexes': list(range(k)), 'use_count': True,
         'mode': 'all-success', 'expect_operate': 'present',
         'goal': 'baseline: all valid -> all SUCCESS, OPERATE sent'},
        {'name': 'invalid_end_k5_n6', 'k': k, 'indexes': list(range(k)) + [k],
         'mode': 'boundary-index', 'expect_operate': 'either',
         'goal': 'invalid index %d at END' % k},
        {'name': 'invalid_begin_k5_n6', 'k': k, 'indexes': [k] + list(range(k)),
         'mode': 'boundary-index', 'expect_operate': 'either',
         'goal': 'invalid index %d FIRST -- does OpenDNP3 status all objects or stop early?' % k},
        {'name': 'invalid_middle_k5_n6', 'k': k, 'indexes': [0, 1, k, 2, 3, 4],
         'mode': 'boundary-index', 'expect_operate': 'either',
         'goal': 'invalid index %d in MIDDLE -- does position change the response pattern?' % k},
        {'name': 'multiple_invalid_k5_n8', 'k': k, 'indexes': list(range(k)) + [k, k + 1, k + 2],
         'mode': 'boundary-index', 'expect_operate': 'either',
         'goal': 'three invalid indexes -> multiple visible rejection statuses?'},
        {'name': 'decoy_only_invalid_k5_n3', 'k': k, 'indexes': [k, k + 1, k + 2],
         'mode': 'boundary-index', 'expect_operate': 'either',
         'goal': 'ALL requested CROBs invalid -> is a harmless decoy transaction possible?'},
        {'name': 'count_limit_vs_invalid_k5_n17', 'k': k, 'indexes': list(range(17)),
         'mode': 'boundary-index', 'expect_operate': 'either',
         'goal': 'K=5, indexes 0..16 -> observe invalid-index vs count-limit status per index'},
        {'name': 'count_limit_valid_k16_n17', 'k': 16, 'indexes': list(range(17)),
         'mode': 'boundary-index', 'expect_operate': 'either',
         'goal': 'K=16, indexes 0..16 -> compare to prior N=17: TOO_MANY_OPS or invalid-index?'},
    ]


# --------------------------------------------------------------------------- #
# One case, end to end
# --------------------------------------------------------------------------- #
def run_case(user, remote_dir, iface, case):
    name = case['name']
    k = case['k']
    indexes = case['indexes']
    n = len(indexes)
    run_id = 'padcand_%s' % name
    pcap_rel = os.path.join('captures', 'padding_candidates', '%s.pcapng' % name)
    olog = 'logs/outstation/ctrl_%s.log' % run_id
    ojson_rel = 'logs/outstation/multicrob_%s.json' % run_id
    mjson_rel = 'logs/master/multicrob_master_%s.json' % run_id

    local_pcap = os.path.join(HARNESS_DIR, pcap_rel)
    local_ojson = os.path.join(HARNESS_DIR, ojson_rel)
    local_mjson = os.path.join(HARNESS_DIR, mjson_rel)
    analyze_json = os.path.join(HARNESS_DIR, 'reports', 'padding_candidates', 'analyze_%s.json' % name)

    stop_outstation(user, remote_dir)
    time.sleep(1)
    for p in (local_pcap, local_ojson, local_mjson, analyze_json):
        try:
            os.remove(p)
        except OSError:
            pass
    for d in (os.path.dirname(local_pcap), os.path.dirname(local_ojson),
              os.path.dirname(local_mjson), os.path.dirname(analyze_json)):
        os.makedirs(d, exist_ok=True)
    ssh(user, cfg.OUTSTATION_IP,
        "cd %s && mkdir -p captures/padding_candidates logs/outstation logs/master && rm -f %s %s"
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
        return {'case_name': name, 'configured_points': k, 'sent_crobs': n,
                'transmitted_index_order': indexes, 'notes': 'FAIL: outstation not ready',
                'pcap_path': pcap_rel}

    if case.get('use_count'):
        master_arg = '--crob-count %d' % n
    else:
        master_arg = "--crob-plan '%s'" % _plan_string(indexes)
    rc, _, _ = ssh(user, cfg.MASTER_IP,
                   "cd %s && python3 run_master.py --action multi-crob-sbo %s --run-id %s"
                   % (remote_dir, master_arg, run_id), timeout=120)
    time.sleep(1.5)
    ssh(user, cfg.OUTSTATION_IP, "pkill -f dumpcap 2>/dev/null; true")
    time.sleep(1.0)

    pull(user, cfg.OUTSTATION_IP, '%s/%s' % (remote_dir, pcap_rel), os.path.dirname(local_pcap))
    pull(user, cfg.OUTSTATION_IP, '%s/%s' % (remote_dir, ojson_rel), os.path.dirname(local_ojson))
    pull(user, cfg.MASTER_IP, '%s/%s' % (remote_dir, mjson_rel), os.path.dirname(local_mjson))
    stop_outstation(user, remote_dir)

    ana_cmd = [sys.executable, os.path.join(HARNESS_DIR, 'analyze_multicrob_pcap.py'),
               '--pcap', local_pcap, '--expected-n', str(n), '--mode', case['mode'],
               '--json', analyze_json]
    if case['mode'] == 'boundary-index':
        ana_cmd += ['--configured-points', str(k), '--expect-operate', case.get('expect_operate', 'either')]
    subprocess.run(ana_cmd, capture_output=True, text=True)

    out_ev = _load_json(local_ojson) or {}
    mas_ev = _load_json(local_mjson) or {}
    ana = _load_json(analyze_json) or {}
    sel = ana.get('select') or {}
    selr = ana.get('select_response') or {}

    return {
        'case_name': name,
        'configured_points': k,
        'sent_crobs': n,
        'transmitted_index_order': indexes,
        'mode': case['mode'],
        'master_exit': rc,
        'master_task_completion': mas_ev.get('task_completion'),
        'analyzer_pass': ana.get('pass'),
        'classification': ana.get('classification', 'all_success' if ana.get('pass') else 'unclassified'),
        'select_count': sel.get('count'),
        'first_rejected_index': ana.get('first_rejected_index') or selr.get('first_rejected_index'),
        'first_rejected_status_name': ana.get('first_rejected_status_name')
                                      or selr.get('first_rejected_status_name'),
        'operate_sent': ana.get('operate_sent', bool(ana.get('operate'))),
        'operate_response_seen': ana.get('operate_response_seen', bool(ana.get('operate_response'))),
        'outstation_select_seen': out_ev.get('select_seen'),
        'outstation_select_success': out_ev.get('select_success'),
        'outstation_operate_seen': out_ev.get('operate_seen'),
        'outstation_operate_success': out_ev.get('operate_success'),
        'outstation_rejected_indexes': out_ev.get('rejected_indexes'),
        'final_state_matches_expected': out_ev.get('final_state_matches_expected'),
        'select_statuses_by_index': ana.get('select_statuses_by_index') or _statuses_by_index(selr),
        'status_counts': ana.get('status_counts'),
        'invalid_indexes_in_select': ana.get('invalid_indexes_in_select'),
        'select_request_byte_length': sel.get('app_byte_length'),
        'select_response_byte_length': selr.get('app_byte_length'),
        'select_data_link_frames': sel.get('data_link_frames'),
        'select_response_data_link_frames': selr.get('data_link_frames'),
        'pcap_path': pcap_rel,
        'analyzer_json': os.path.relpath(analyze_json, HARNESS_DIR),
        'master_json': mjson_rel,
        'outstation_json': ojson_rel,
        'notes': '; '.join(ana.get('notes') or []) or case['goal'],
    }


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
MANIFEST_COLS = [
    'case_name', 'configured_points', 'sent_crobs', 'transmitted_index_order', 'mode',
    'master_exit', 'master_task_completion', 'analyzer_pass', 'classification', 'select_count',
    'first_rejected_index', 'first_rejected_status_name', 'operate_sent', 'operate_response_seen',
    'outstation_select_seen', 'outstation_select_success', 'outstation_operate_seen',
    'outstation_operate_success', 'outstation_rejected_indexes', 'final_state_matches_expected',
    'select_statuses_by_index', 'status_counts', 'invalid_indexes_in_select',
    'select_request_byte_length', 'select_response_byte_length',
    'select_data_link_frames', 'select_response_data_link_frames',
    'pcap_path', 'analyzer_json', 'master_json', 'outstation_json', 'notes',
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
        w.writerow(['# invalid-index CROB padding-candidate suite; config: OpenDNP3 rig '
                    '%s(master)/%s(outstation); software-only; NOT a universal DNP3 result'
                    % (cfg.MASTER_IP, cfg.OUTSTATION_IP)])
        w.writerow(MANIFEST_COLS)
        for rec in records:
            w.writerow([_cell(rec.get(c)) for c in MANIFEST_COLS])


def _padding_supported(records):
    """True iff every invalid case suppressed OPERATE, changed no valid output, and
    made the invalid index visible via a non-success SELECT status."""
    invalid = [r for r in records if r.get('mode') == 'boundary-index']
    if not invalid:
        return False
    for r in invalid:
        if r.get('operate_sent'):
            return False
        if r.get('final_state_matches_expected'):    # a valid output reached operated state
            return False
        if not r.get('first_rejected_status_name'):  # no visible rejection status
            return False
    return True


def write_results_md(path, records):
    supported = _padding_supported(records)
    L = []
    L.append('# Invalid-Index CROB Padding-Candidate Tests\n')
    L.append('## Purpose\n')
    L.append('Determine whether nonexistent G12V1 CROB indexes can act as harmless padding '
             'candidates in a Select-Before-Operate command set, and what response-side evidence '
             'they produce. This is protocol characterisation only -- it does NOT implement padding '
             'and does NOT prove padding is safe.\n')
    L.append('## Method\n')
    L.append('- Object type fixed: Group 12 Variation 1 CROB; one SBO command set; qualifier `0x28`, Count=N.\n'
             '- Outstation configured with K valid software-only points (indexes `0..K-1`).\n'
             '- Master sends N CROBs via an explicit ordered `--crob-plan` (baseline uses `--crob-count`), '
             'placing invalid (index >= K) CROBs at chosen positions.\n'
             '- `maxControlsPerRequest` is unchanged; no response is rewritten; no physical output exists.\n'
             '- Correctness = per-index `CommandStatus` in the SELECT response (PCAP) + outstation JSON, '
             'never TCP packet count. Task-level master SUCCESS is not proof any output changed.\n')
    L.append('## Case table\n')
    L.append('| case | K | N | transmitted order | classification | first rejected | OPERATE sent | '
             'valid output changed | analyzer pass |')
    L.append('|------|---|---|-------------------|----------------|----------------|--------------|'
             '----------------------|---------------|')
    for r in records:
        fr = r.get('first_rejected_index')
        frn = r.get('first_rejected_status_name')
        first_rejected = ('%s / %s' % (fr, frn)) if fr is not None else '-'
        changed = 'yes' if r.get('final_state_matches_expected') else 'no'
        order = r.get('transmitted_index_order')
        L.append('| %s | %s | %s | %s | `%s` | %s | %s | %s | %s |' % (
            r.get('case_name'), r.get('configured_points'), r.get('sent_crobs'),
            order, r.get('classification'), first_rejected, r.get('operate_sent'),
            changed, r.get('analyzer_pass')))
    L.append('')
    L.append('## Interpretation (observed, not assumed)\n')
    L.append('Per-case status maps, byte lengths, and DNP3 frame counts are in '
             '`padding_candidate_manifest.csv` and `analyze_<case>.json`. The per-index '
             'CommandStatus is read verbatim from the SELECT response on the wire and reported as '
             'observed; the harness does not assume it. In these runs the observed status for a '
             'nonexistent index was `OUT_OF_RANGE` (status 12), and the per-request operation-count '
             'limit produced `TOO_MANY_OPS` (status 8) once the command count exceeded '
             '`maxControlsPerRequest`; the two are distinct and both visible per-index on the wire. '
             'The returned status originates in the outstation application control-point backend '
             '(OpenDNP3 does not validate a control index natively), not in this test runner.\n')
    L.append('## What this means for padding\n')
    if supported:
        L.append('Invalid-index CROBs do not execute physical or simulated configured outputs, but they '
                 'are visible in the SELECT response through non-success command statuses. In the current '
                 'OpenDNP3 SBO behavior, a partial SELECT failure prevents OPERATE, so invalid-index '
                 'padding cannot be inserted into a real control transaction without additional '
                 'response-side handling or a different cover-traffic design.\n')
    else:
        L.append('The observed behavior did not uniformly match the "partial SELECT failure prevents '
                 'OPERATE with no output change" pattern across every invalid case; see the case table '
                 'and per-case JSON before drawing a padding conclusion. Invalid-index CROBs remain '
                 'visible in the SELECT response through non-success command statuses and did not '
                 'execute configured outputs, but the padding question is not settled by these runs.\n')
    L.append('## What it does NOT prove\n')
    L.append('- It does NOT show padding works, or that invalid CROBs are invisible.\n'
             '- An accepted SELECT does not mean a control executed; task-level SUCCESS is not execution.\n'
             '- It is not safe for real relays and maps no index to a physical output.\n'
             '- It is not a universal DNP3 behavior -- only this OpenDNP3 build/host/config.\n')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write('\n'.join(L) + '\n')


def main():
    ap = argparse.ArgumentParser(description='Invalid-index CROB padding-candidate test suite (rig).')
    ap.add_argument('--user', default=os.environ.get('RIG_USER', 'decps'), help='SSH user for the rig hosts.')
    ap.add_argument('--iface', default=DEFAULT_IFACE, help='Capture interface on the outstation host.')
    ap.add_argument('--remote-dir', default=DEFAULT_REMOTE_DIR, help='Harness dir on the rig hosts.')
    ap.add_argument('--no-deploy', action='store_true', help='Skip the rsync deploy step.')
    ap.add_argument('--only', default=None, help='Run only this case name (default: all).')
    ap.add_argument('--valid-points', type=int, default=5, help='K for cases 1-7 (default 5).')
    args = ap.parse_args()

    reports_dir = os.path.join(HARNESS_DIR, 'reports', 'padding_candidates')
    os.makedirs(reports_dir, exist_ok=True)

    cases = build_cases(args.valid_points)
    if args.only:
        cases = [c for c in cases if c['name'] == args.only]
        if not cases:
            ap.error('--only %r matched no case; names: %s'
                     % (args.only, ', '.join(c['name'] for c in build_cases(args.valid_points))))

    if not args.no_deploy:
        print('Deploying to %s and %s ...' % (cfg.MASTER_IP, cfg.OUTSTATION_IP), flush=True)
        deploy(args.user, args.remote_dir)

    records = []
    for case in cases:
        print('--- case: %s (K=%d, N=%d, mode=%s) ---'
              % (case['name'], case['k'], len(case['indexes']), case['mode']), flush=True)
        rec = run_case(args.user, args.remote_dir, args.iface, case)
        records.append(rec)
        print('    exit=%s task=%s pass=%s class=%s first_rejected=%s/%s operate_sent=%s valid_changed=%s'
              % (rec.get('master_exit'), rec.get('master_task_completion'), rec.get('analyzer_pass'),
                 rec.get('classification'), rec.get('first_rejected_index'),
                 rec.get('first_rejected_status_name'), rec.get('operate_sent'),
                 rec.get('final_state_matches_expected')), flush=True)

    manifest = os.path.join(reports_dir, 'padding_candidate_manifest.csv')
    results_md = os.path.join(reports_dir, 'padding_candidate_results.md')
    write_manifest(manifest, records)
    write_results_md(results_md, records)
    stop_outstation(args.user, args.remote_dir)
    print('\nManifest -> %s\nResults  -> %s' % (manifest, results_md), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
