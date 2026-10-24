#!/usr/bin/env python3
"""Independent post-block restoration check (run after every hardware block, including a failed one).

  python3 restore_verify.py --config CFG --run-root EVIDENCE_DIR [--vision-baseline FILE]

Read-only on both hosts. Passes only when all of these hold:
  1. the runner's own restore record (campaign_run.json or series record) lists every step ok, and every
     required step is present: cold swap to the production launch script, $PORT replay, relay slot (when the
     config restores one), Vision restore and the ping;
  2. the switch is running the configured production program (observe_program.py, read-only);
  3. a fresh read-only live_snapshot.py of that program equals the block's own pre-run snapshot on every table
     except the counter tables in VOLATILE (all 399 others, $PORT included, matched exactly on 2026-10-15),
     with the packet, drop and occupancy statistics in STATISTICS removed from entry data first;
  4. Vision's `vision_run.py state` equals the recorded baseline (source pruning, namespace TCP profile, route,
     fixture qdisc);
  5. a fresh ping through the restored path succeeds;
  6. Vision's parent NIC RX interrupt moderation (`ethtool -c`, adaptive RX and rx-usecs) equals the recorded
     baseline -- the RX-coalescing host diagnostic (Philip, 2026-10-22) is never left in place;
  7. Vision's effective CPU latency constraint (/dev/cpu_dma_latency) equals the recorded baseline and no
     CPU-latency hold helper is running -- the CPU-latency host diagnostic is never left in place.
Writes restore_verify.json beside the evidence; exit 0 only when every check passes.
"""
import argparse
import glob
import hashlib
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
VOLATILE = frozenset({'$PORT_STAT', 'log_tbl_counter', 'tbl_dbg_counter', 'tf1.log_tbl_counter'})
# Packet, drop and buffer-occupancy statistics in entry data. A cold swap zeroes them, so they differ from a
# pre-run snapshot taken after background traffic (2026-10-19); every key, action and other field is compared.
STATISTICS = frozenset({'$COUNTER_SPEC_PKTS', '$COUNTER_SPEC_BYTES', 'drop_count_packets', 'drop_count_bytes',
                        'usage_cells', 'watermark_cells', 'shared_pool_usage_cells', 'guaranteed_min_usage_cells'})
BASELINE = HERE / 'restore_baseline/vision_state_20261015.txt'
RX_COALESCE_BASELINE = HERE / 'restore_baseline/vision_rx_coalesce_20261022.json'
CPU_LATENCY_BASELINE = HERE / 'restore_baseline/vision_cpu_dma_latency_20261022.json'


def offload_failures(ethtool_text, baseline):
    """Compare a fresh NIC feature read with the independently retained pre-capture baseline."""
    sys.path.insert(0, str(HERE.parents[3] / 'protocol/hw_vepa'))
    import capture_observation
    expected = baseline.get('features') or {}
    if baseline.get('interface') != capture_observation.PARENT or type(expected.get('gro')) is not bool or any(
            key not in capture_observation.MANAGED_OFFLOADS or type(value) is not bool for key, value in expected.items()):
        return ['physical receive-offload baseline missing or malformed']
    features = capture_observation.parse_ethtool_features(ethtool_text)
    actual = {key: value for key, value in features.items() if key in capture_observation.MANAGED_OFFLOADS}
    if actual != expected:
        return ['Vision receive offloads differ from pre-capture baseline: actual %r, baseline %r' % (actual, expected)]
    return []
# read-only: the effective constraint, and any helper still running (its command line carries this marker)
def cpu_latency_probe(device='/dev/cpu_dma_latency'):
    """Read-only probe source: the effective constraint, then -- after closing its own descriptor -- whether any
    process still holds the device open (fuser -s; the probe's own sudo/sh parents never hold it)."""
    return ('import os, struct, subprocess; fd = os.open(%r, os.O_RDONLY); '
            'v = struct.unpack("i", os.read(fd, 4))[0]; os.close(fd); '
            'h = subprocess.run(["fuser", "-s", %r]).returncode == 0; '
            'print("value", v, "helpers", int(h))' % (device, device))


CPU_LATENCY_PROBE = cpu_latency_probe()
REQUIRED_STEPS = ('cold-swap bf_switchd back to the observed production program',
                  'replay the pre-run $PORT snapshot on the production program',
                  'Vision: fixture off, namespace profile and NIC flag restored',
                  'ping through the restored switch path')


def rx_coalesce_failures(ethtool_text, baseline):
    """[failure] unless `ethtool -c` reports the baseline's adaptive RX and rx-usecs."""
    import re
    adaptive = re.search(r'^Adaptive RX:\s*(on|off)\b', ethtool_text or '', re.M)
    usecs = re.search(r'^rx-usecs:\s*(\d+)\s*$', ethtool_text or '', re.M)
    if not adaptive or not usecs:
        return ['Vision RX coalescing unreadable: %s' % (ethtool_text or '')[-200:]]
    got = (adaptive.group(1), int(usecs.group(1)))
    want = (baseline['adaptive_rx'], baseline['rx_usecs'])
    return [] if got == want else ['Vision RX coalescing adaptive %s rx-usecs %d, baseline adaptive %s rx-usecs %d'
                                   % (got + want)]


def cpu_latency_failures(probe_output, baseline):
    """[failure] unless the probe reports the baseline constraint and no helper."""
    import re
    m = re.search(r'value (-?\d+) helpers (\d+)', probe_output or '')
    if not m:
        return ['Vision CPU latency unreadable: %s' % (probe_output or '')[-200:]]
    fails = []
    if int(m.group(1)) != baseline['value']:
        fails.append('Vision CPU latency constraint %s, baseline %d' % (m.group(1), baseline['value']))
    if int(m.group(2)):
        fails.append('Vision /dev/cpu_dma_latency is still held open by a process')
    return fails


def ssh(host, cmd, timeout=180):
    return subprocess.run(['ssh', '-o', 'BatchMode=yes', '-o', 'IdentityAgent=none',
                           '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
                           '-o', 'ConnectTimeout=8', host, cmd],
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


def without_statistics(table):
    if not isinstance(table, dict) or not isinstance(table.get('entries'), list):
        return table
    entries = [dict(e, data={k: v for k, v in e['data'].items() if k not in STATISTICS})
               if isinstance(e, dict) and isinstance(e.get('data'), dict) else e for e in table['entries']]
    return dict(table, entries=entries)


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
                    if json.dumps(without_statistics(a[k]), sort_keys=True)
                    != json.dumps(without_statistics(b[k]), sort_keys=True))
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

    if cfg.get('endpoint_profile') == 'sel751':
        baseline_path = root / 'vision_offload_baseline.json'
        try:
            raw = baseline_path.read_bytes()
            offload_base = json.loads(raw)
            if record is None or hashlib.sha256(raw).hexdigest() != record.get('vision_offload_baseline_sha256'):
                raise ValueError('retained receive-offload baseline differs from runner pre-capture identity')
            r = ssh(hosts['vision'], 'ethtool -k %s' % shlex.quote(offload_base['interface']))
            errors = offload_failures(r.stdout if not r.returncode else '', offload_base)
            out['checks']['vision_receive_offloads'] = dict(rc=r.returncode, ethtool=r.stdout,
                                                           baseline=str(baseline_path), failures=errors)
            fails.extend(errors)
            if 'iptables' in offload_base:
                observed = ssh(hosts['vision'], 'sudo -n /usr/bin/python3 %s/relay_loss.py --snapshot' % shlex.quote(V))
                actual = json.loads(next(line for line in reversed(observed.stdout.splitlines()) if line.startswith('{')))
                errors = []
                if observed.returncode or actual.get('pending_owner') is not False or actual.get('chains') != offload_base['iptables']:
                    errors.append('physical host firewall/owned loss state differs from campaign baseline')
                out['checks']['vision_physical_loss_restoration'] = dict(rc=observed.returncode, actual=actual,
                                                                        baseline=offload_base['iptables'], failures=errors)
                fails.extend(errors)
        except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
            fails.append('physical receive-offload restoration unverified: ' + str(error))

    rx_base = json.loads(RX_COALESCE_BASELINE.read_text())
    r = ssh(hosts['vision'], 'ethtool -c %s' % rx_base['interface'])
    rx_fail = rx_coalesce_failures(r.stdout if not r.returncode else '', rx_base)
    out['checks']['vision_rx_coalescing'] = {'rc': r.returncode, 'ethtool': r.stdout, 'baseline': str(RX_COALESCE_BASELINE),
                                             'failures': rx_fail}
    fails.extend(rx_fail)

    cpu_base = json.loads(CPU_LATENCY_BASELINE.read_text())
    r = ssh(hosts['vision'], 'sudo -n python3 -c %s' % shlex.quote(CPU_LATENCY_PROBE))
    cpu_fail = cpu_latency_failures(r.stdout if not r.returncode else '', cpu_base)
    out['checks']['vision_cpu_latency'] = {'rc': r.returncode, 'probe': r.stdout, 'stderr': r.stderr[-300:],
                                           'baseline': str(CPU_LATENCY_BASELINE),
                                           'failures': cpu_fail}
    fails.extend(cpu_fail)

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
