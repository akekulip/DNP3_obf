#!/usr/bin/env python3
"""Drive one software-endpoint run through the switch from this workstation and collect its evidence.

  run.py deploy
  run.py setup | restore
  run.py run LABEL --master-port P --reads N --out EVIDENCE_DIR [--enable 0|1] [--no-forwarding]

`deploy` copies the switch tools to /home/decps/hw_vepa on the switch and vision_run.py to Vision.
`setup` / `restore` set or undo the namespace TCP profile and the NIC source-pruning flag on Vision; `restore`
also reinstalls the relay slot on the switch.
`run` installs the tuple for master port P in slot 0 (padding policy --enable; --no-forwarding leaves the port-9
forwarding row out), reads the switch counters, runs the endpoints on Vision, reads the counters again, copies
the run directory into EVIDENCE_DIR/LABEL and runs wire_check.py and clrt_check.py on the captures. Use a new
master port for each run: the previous tuple stays in TIME-WAIT for 60 s after its master closes.

A `run` FAILS (nonzero exit) if the endpoint returns nonzero, an expected artifact is missing, or the wire or
clrt extractor reports a checksum, mapping or extraction failure -- all evidence is still written first. A
`--no-forwarding` run is a declared negative control: it passes only if the endpoint fails in the expected way
(the master cannot connect), and the extractor verdicts are recorded but not gated.
"""
import argparse
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SWITCH, VISION = 'decps@10.10.54.81', 'decps@10.10.54.19'
SW_DIR, V_RUN = '/home/decps/hw_vepa', '/home/decps/pad58b_20261011'
PY = os.environ.get('RESEARCH_PYTHON', sys.executable)


def ssh(host, cmd, timeout=600, check=True):
    r = subprocess.run(['ssh', '-o', 'BatchMode=yes', host, cmd], capture_output=True, text=True, timeout=timeout)
    if check and r.returncode:
        sys.exit('FAILED on %s: %s\n%s\n%s' % (host, cmd, r.stdout[-2000:], r.stderr[-2000:]))
    return r


def last_json(text):
    return json.loads([l for l in text.splitlines() if l.startswith('{')][-1])


def counters():
    return last_json(ssh(SWITCH, 'python3 %s/switch_counters.py' % SW_DIR).stdout)


def reg(snap, name, field=None):
    r = snap['regs'][name]
    return r[[k for k in r if field is None or k.endswith(field)][0]][0]


def outcome(s, code):
    return int(s['outcome'].get(str(code), 0))


def evaluate(expect_fail, vision_rc, vision_result, wire_rc, clrt_rc, artifacts_present):
    """Decide whether a run passed. Returns (ok, failures).

    expect_fail marks a declared negative control (--no-forwarding): it passes only when the endpoint fails
    in the way the endpoint runner declared (vision sets result['ok'] := master connect failed), and the
    extractor return codes are not gated. A normal run requires a clean endpoint and clean extractors."""
    fails = []
    result_ok = bool(vision_result.get('ok')) if isinstance(vision_result, dict) else False
    if expect_fail:
        if vision_rc != 0 or not result_ok:
            fails.append('negative control did not fail in the declared way (vision_rc=%s, result_ok=%s)'
                         % (vision_rc, result_ok))
    else:
        if vision_rc != 0:
            fails.append('endpoint returned nonzero (vision_rc=%s)' % vision_rc)
        if not result_ok:
            detail = vision_result.get('error', 'master_rc=%s' % vision_result.get('master_rc')) \
                if isinstance(vision_result, dict) else str(vision_result)
            fails.append('endpoint run not ok (%s)' % detail)
    for name, present in sorted(artifacts_present.items()):
        if not present:
            fails.append('missing expected artifact: %s' % name)
    if not expect_fail:
        if wire_rc != 0:
            fails.append('wire extractor reported a checksum/mapping/extraction failure (rc=%s)' % wire_rc)
        if clrt_rc != 0:
            fails.append('clrt extractor reported a CRC/extraction failure (rc=%s)' % clrt_rc)
    return (not fails), fails


def vision_cmd(label, master_port, reads, rng, gap_ms, start_delay_ms=0, start_seed=0, connect_must_fail=False,
               drop=None, scenario=None, reconnect_port=None):
    """The Vision-side command for one run; shared by `run` here so the flags cannot drift from vision_run.py."""
    return ('sudo python3 %s/vision_run.py run %s --master-port %d --reads %d --range %d --gap-ms %d '
            '--start-delay-ms %d --start-seed %d%s%s%s' % (
                V_RUN, label, master_port, reads, rng, gap_ms, start_delay_ms, start_seed,
                ' --connect-must-fail' if connect_must_fail else '', ' --drop %s' % drop if drop else '',
                ' --scenario %s --reconnect-port %d' % (scenario, reconnect_port) if scenario else ''))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=('deploy', 'setup', 'restore', 'casea', 'run'))
    ap.add_argument('label', nargs='?')
    ap.add_argument('--master-port', type=int)
    ap.add_argument('--reads', type=int, default=10)
    ap.add_argument('--enable', type=int, choices=(0, 1), default=1)
    ap.add_argument('--no-forwarding', action='store_true')
    ap.add_argument('--range', type=int, choices=(8, 16), default=16)
    ap.add_argument('--gap-ms', type=int, default=0)
    ap.add_argument('--start-delay-ms', type=int, default=0)
    ap.add_argument('--start-seed', type=int, default=0)
    ap.add_argument('--delay-ms', type=int, default=25)
    ap.add_argument('--out')
    a = ap.parse_args(argv)

    if a.mode == 'deploy':
        ssh(SWITCH, 'mkdir -p ' + SW_DIR)
        files = [os.path.join(HERE, f) for f in ('switch_slot.py', 'switch_counters.py')] + [os.path.join(HERE, '..', 'response_path_cp.py')]
        subprocess.run(['scp', '-q'] + files + ['%s:%s/' % (SWITCH, SW_DIR)], check=True)
        subprocess.run(['scp', '-q', os.path.join(HERE, 'vision_run.py'), '%s:%s/' % (VISION, V_RUN)], check=True)
        print(ssh(SWITCH, 'sha256sum %s/*.py' % SW_DIR).stdout + ssh(VISION, 'sha256sum %s/vision_run.py' % V_RUN).stdout)
        return 0
    if a.mode == 'casea':            # run.py casea on|off [--delay-ms D]: see vision_run.py
        print(ssh(VISION, 'sudo python3 %s/vision_run.py casea %s --delay-ms %d' % (V_RUN, a.label, a.delay_ms)).stdout)
        return 0
    if a.mode in ('setup', 'restore'):
        print(ssh(VISION, 'sudo python3 %s/vision_run.py %s' % (V_RUN, a.mode)).stdout)
        if a.mode == 'restore':
            print(last_json(ssh(SWITCH, 'python3 %s/switch_slot.py relay' % SW_DIR).stdout))
        return 0

    if not (a.label and a.master_port and a.out):
        ap.error('run needs LABEL, --master-port and --out')
    dest = os.path.join(a.out, a.label)
    os.makedirs(dest)
    slot = last_json(ssh(SWITCH, 'python3 %s/switch_slot.py vepa --master-port %d --enable %d%s' %
                         (SW_DIR, a.master_port, a.enable, ' --no-forwarding' if a.no_forwarding else '')).stdout)
    before = counters()
    v = ssh(VISION, vision_cmd(a.label, a.master_port, a.reads, a.range, a.gap_ms, a.start_delay_ms, a.start_seed,
                               a.no_forwarding), check=False)
    after = counters()
    subprocess.run(['scp', '-q', '%s:%s/runs/%s/*' % (VISION, V_RUN, a.label), dest + '/'], check=True)
    for stale in ('stop', 'stop.master'):
        if os.path.exists(os.path.join(dest, stale)):
            os.remove(os.path.join(dest, stale))
    json.dump({'slot': slot, 'before': before, 'after': after}, open(os.path.join(dest, 'switch.json'), 'w'), indent=1)

    out_pcap, in_pcap = os.path.join(dest, 'out.pcap'), os.path.join(dest, 'in.pcap')
    wire = subprocess.run([PY, os.path.join(HERE, 'wire_check.py'), out_pcap, in_pcap],
                          capture_output=True, text=True)
    open(os.path.join(dest, 'wire.json'), 'w').write(wire.stdout if wire.stdout.strip() else
                                                     json.dumps({'error': wire.stderr[-800:]}))
    clrt = subprocess.run([PY, os.path.join(HERE, 'clrt_check.py'), out_pcap, in_pcap,
                           '--json', os.path.join(dest, 'timing.json')], capture_output=True, text=True)
    if not os.path.exists(os.path.join(dest, 'timing.json')):
        open(os.path.join(dest, 'timing.json'), 'w').write(json.dumps({'error': clrt.stderr[-800:]}))

    vision_result = last_json(v.stdout) if '{' in v.stdout else {'error': (v.stdout + v.stderr)[-500:]}
    summary = {'vision': vision_result,
               'commit_delta': outcome(after, 1) - outcome(before, 1), 'arm_map_delta': outcome(after, 13) - outcome(before, 13),
               'translate_delta': outcome(after, 2) - outcome(before, 2), 'rev_translate_delta': outcome(after, 9) - outcome(before, 9),
               'growth_bytes': (reg(after, 'acct', '.lo') - reg(after, 'front')) & 0xffffffff, 'unacked': reg(after, 'acct', '.hi'),
               'dev9_rx_delta': after['ports']['9']['rx'] - before['ports']['9']['rx'],
               'dev9_tx_delta': after['ports']['9']['tx'] - before['ports']['9']['tx'],
               'wire_rc': wire.returncode, 'clrt_rc': clrt.returncode}
    artifacts = {'out.pcap': os.path.exists(out_pcap), 'in.pcap': os.path.exists(in_pcap),
                 'wire.json': os.path.exists(os.path.join(dest, 'wire.json')),
                 'timing.json': os.path.exists(os.path.join(dest, 'timing.json'))}
    ok, fails = evaluate(a.no_forwarding, v.returncode, vision_result, wire.returncode, clrt.returncode, artifacts)
    summary['expect_fail'] = a.no_forwarding
    summary['run_ok'] = ok
    summary['failures'] = fails
    json.dump(summary, open(os.path.join(dest, 'summary.json'), 'w'), indent=1)
    print(json.dumps(summary, indent=1))
    if not ok:
        sys.stderr.write('RUN FAILED: %s\n' % '; '.join(fails))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
