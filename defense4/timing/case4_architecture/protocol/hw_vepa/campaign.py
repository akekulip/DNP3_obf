#!/usr/bin/env python3
"""Single entry point for the response-only four-arm hardware campaign.

  campaign.py validate [--config campaign.json]
  campaign.py plan     [--config campaign.json]        # the full ordered runbook, substituted from the config
  campaign.py run      [--config campaign.json] --apply # execute it (hardware; gated, see below)

One JSON config (campaign.json) is the single documented source for endpoints, port map, build/binary
hashes, feature bits (T on/off via the live install, padding on/off via the selected build), timing
parameters, K / service config, fixture delay/jitter, trial counts, traffic schedule, loss settings and
seeds. `plan` turns it into the exact, ordered command sequence with no undocumented manual step, tying
together:

  * the reviewed composite installer under core/response_only/hw/ -- make_conf.py, restore_ports.py,
    bringup_composite.py, set_enabled.py, snapshot_counters.py, bringup_teardown.py. This file CALLS those
    scripts by their documented invocations (hw/README.md); it does not reimplement any installer logic.
  * the endpoint runner vision_run.py (traffic + capture on Vision);
  * independent verification and extraction, wire_check.py and clrt_check.py, run on the captures;
  * restoration, via bringup_teardown.py and restore_ports.py.

Feature bits map to the real mechanism: T on/off is a live `set_enabled.py --enabled 0|1` toggle on one
install (Timing OFF vs Obfuscated); padding on/off is a build property, so a padding change selects the
other build and reinstalls. `plan` therefore groups the arms by build, installs each build once, and
toggles T per block to avoid needless reinstalls.

`run --apply` executes the plan and requires DEFENSE4_HW_AUTHORIZED=1; it also refuses to start while any
build hash in the config is still a placeholder, so a real campaign cannot run against an unbound build.
Physical relay OPERATE remains attended-only and is out of this unattended path.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run as runner  # noqa: E402  (ssh/host constants and the endpoint-run helpers)

# where the hw installer scripts live on the switch, relative to the copied source tree (hw/README.md)
HW = 'src/integration/core/response_only/hw'
REQUIRED = ('endpoints', 'hosts', 'ports_map', 'builds', 'arms', 'timing_params_ns', 'service',
            'fixture', 'trials', 'traffic', 'loss', 'seeds', 'evidence_dir')
PLACEHOLDER = '<sha256 from manifest.json>'


def load_config(path):
    cfg = json.load(open(path))
    missing = [k for k in REQUIRED if k not in cfg]
    if missing:
        raise ValueError('config missing required sections: %s' % ', '.join(missing))
    t = cfg['timing_params_ns']
    if not (t['da'] < t['readiness'] <= t['cap']):
        raise ValueError('timing params must satisfy da < readiness <= cap (got da=%d readiness=%d cap=%d)'
                         % (t['da'], t['readiness'], t['cap']))
    if not cfg['arms']:
        raise ValueError('no arms defined')
    for a in cfg['arms']:
        for k in ('name', 'T', 'padding', 'build'):
            if k not in a:
                raise ValueError('arm %r missing %r' % (a, k))
        if a['build'] not in cfg['builds']:
            raise ValueError('arm %r references unknown build %r' % (a['name'], a['build']))
        if a['T'] not in (0, 1) or a['padding'] not in (0, 1):
            raise ValueError('arm %r: T and padding are 0/1 feature bits' % a['name'])
    if cfg['trials']['trials_per_arm'] < 1 or cfg['trials']['reads_per_trial'] < 1:
        raise ValueError('trials_per_arm and reads_per_trial must be >= 1')
    return cfg


def warnings(cfg):
    """Non-fatal advisories that encode known traps (returned, not raised)."""
    w = []
    fixture_ns = int(cfg['fixture']['delay_ms'] * 1_000_000)
    if fixture_ns >= cfg['timing_params_ns']['readiness']:
        w.append('fixture delay %d ms >= T readiness %d ns: the child response arrives after the readiness '
                 'deadline, so the normal commit/release path cannot be observed (defect D). Lower the '
                 'fixture delay or raise readiness.' % (cfg['fixture']['delay_ms'], cfg['timing_params_ns']['readiness']))
    for name, b in cfg['builds'].items():
        if any(v == PLACEHOLDER for v in b.get('hashes', {}).values()):
            w.append('build %r still has placeholder hashes; `run` will refuse until they are filled.' % name)
    return w


def _install_steps(cfg, build_name):
    b = cfg['builds'][build_name]
    e, pm, t = cfg['endpoints'], cfg['ports_map'], cfg['timing_params_ns']
    R = cfg['hosts']['switch_remote_dir']
    expects = ' '.join('--expect %s=%s' % (rel, h) for rel, h in b['hashes'].items()
                       if rel in ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin'))
    endpoint_args = (
        '--master-ip %s --master-port %d --master-dev %d --relay-ip %s --relay-port %d --relay-dev %d '
        '--read-dst 0x%04x --read-src 0x%04x' % (
            e['master_ip'], cfg['traffic']['master_port'], pm['master_dev'], e['outstation_ip'],
            e['outstation_port'], pm['relay_dev'], e['read_dst'], e['read_src']))
    t_args = '--t-da %d --t-readiness %d --t-cap %d --t-gap %d --t-op-j %d --k %d' % (
        t['da'], t['readiness'], t['cap'], t['gap'], t['op_j'], cfg['service']['k'])
    comp = '%s/%s/bringup_composite.py --build-out %s/out %s %s %s' % (R, HW, R, expects, endpoint_args, t_args)
    return [
        ('switch', 'conf from the loaded build',
         'python3 %s/%s/make_conf.py %s/out --remote-dir %s/out --pcie %s -o %s/response_only_hw.conf'
         % (R, HW, R, R, b['pcie'], R)),
        ('switch', 'launch bf_switchd on the composite build (rehearsed restore in place)',
         'see hw/README.md run-order step 2 (SDE=%s); refuse if bf_switchd is already up' % b['sde']),
        ('switch', 'enable the front-panel ports from the live snapshot',
         'python3 framework/control/restore_ports.py %s %s --apply --wait 35' % (cfg['program'], cfg['ports_snapshot'])),
        ('switch', 'composite install dry-run (prints the ports it will loop)', comp),
        ('switch', 'composite install apply (loopback first, apps enabled last)',
         'DEFENSE4_HW_AUTHORIZED=1 ' + comp + ' --apply --enable-pktgen --manifest-out %s/bringup_manifest.json' % R),
        ('switch', 'counter snapshot before the blocks',
         'python3 %s/%s/snapshot_counters.py --build-out %s/out --ports %s -o %s/before_%s.json'
         % (R, HW, R, cfg['ports_map']['stat_ports'], R, build_name)),
    ]


def _arm_steps(cfg, arm):
    R = cfg['hosts']['switch_remote_dir']
    V = runner.V_RUN
    reads, trials = cfg['trials']['reads_per_trial'], cfg['trials']['trials_per_arm']
    tr = cfg['traffic']
    steps = [('switch', 'select T for arm %s (0=Timing OFF, 1=Obfuscated)' % arm['name'],
              'python3 %s/%s/set_enabled.py --manifest %s/bringup_manifest.json --enabled %d'
              % (R, HW, R, arm['T']))]
    if cfg['fixture'].get('casea'):
        steps.append(('vision', 'arm %s: emulate the relay separate-ACK + delayed response' % arm['name'],
                      'sudo python3 %s/vision_run.py casea on --delay-ms %d' % (V, cfg['fixture']['delay_ms'])))
    for i in range(trials):
        label = '%s_t%d' % (arm['name'], i)
        steps += [
            ('vision', 'arm %s trial %d: traffic + capture' % (arm['name'], i),
             'sudo python3 %s/vision_run.py run %s --master-port %d --reads %d --range %d --gap-ms %d'
             % (V, label, cfg['traffic']['master_port'], reads, tr['range'], tr['gap_ms'])),
            ('workstation', 'arm %s trial %d: copy evidence' % (arm['name'], i),
             'scp -q %s:%s/runs/%s/* %s/%s/' % (runner.VISION, V, label, cfg['evidence_dir'], label)),
            ('workstation', 'arm %s trial %d: independent wire verification' % (arm['name'], i),
             'python3 %s/wire_check.py %s/%s/out.pcap %s/%s/in.pcap --json %s/%s/wire.json'
             % (HERE, cfg['evidence_dir'], label, cfg['evidence_dir'], label, cfg['evidence_dir'], label)),
            ('workstation', 'arm %s trial %d: per-exchange timing extraction' % (arm['name'], i),
             'python3 %s/clrt_check.py %s/%s/out.pcap %s/%s/in.pcap --json %s/%s/timing.json'
             % (HERE, cfg['evidence_dir'], label, cfg['evidence_dir'], label, cfg['evidence_dir'], label)),
        ]
    return steps


def plan(cfg):
    steps = [('workstation', 'copy the switch tools and vision_run.py to their hosts',
              'python3 %s/run.py deploy' % HERE),
             ('vision', 'set the namespace TCP profile and NIC source-pruning (snapshots prior state)',
              'python3 %s/run.py setup' % HERE)]
    # group arms by build so each build is installed once
    by_build = {}
    for a in cfg['arms']:
        by_build.setdefault(a['build'], []).append(a)
    for build_name, arms in by_build.items():
        steps += _install_steps(cfg, build_name)
        for a in arms:
            steps += _arm_steps(cfg, a)
        R = cfg['hosts']['switch_remote_dir']
        steps += [
            ('switch', 'counter snapshot after the blocks on build %s' % build_name,
             'python3 %s/%s/snapshot_counters.py --build-out %s/out --ports %s -o %s/after_%s.json'
             % (R, HW, R, cfg['ports_map']['stat_ports'], R, build_name)),
            ('switch', 'teardown the composite on build %s (loopback off last)' % build_name,
             'python3 %s/%s/bringup_teardown.py --manifest %s/bringup_manifest.json --apply' % (R, HW, R)),
        ]
    steps += [('vision', 'restore the namespace profile and the NIC flag', 'python3 %s/run.py restore' % HERE),
              ('switch', 'production port restore (rehearsed cold restart)',
               'python3 framework/control/restore_ports.py %s %s --apply --wait 35'
               % (cfg['program'], cfg['ports_snapshot']))]
    return steps


def render(steps):
    return '\n'.join('[%-11s] %s\n              $ %s' % (host, label, cmd) for host, label, cmd in steps)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=('validate', 'plan', 'run'))
    ap.add_argument('--config', default=os.path.join(HERE, 'campaign.json'))
    ap.add_argument('--apply', action='store_true', help='required for run: actually execute the plan')
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    warns = warnings(cfg)
    for w in warns:
        sys.stderr.write('WARNING: %s\n' % w)
    if a.mode == 'validate':
        print('config OK: %d arms over %d build(s), %d trials/arm'
              % (len(cfg['arms']), len({x['build'] for x in cfg['arms']}), cfg['trials']['trials_per_arm']))
        return 0
    steps = plan(cfg)
    if a.mode == 'plan':
        print(render(steps))
        return 0
    # run
    if not a.apply:
        sys.exit('run needs --apply to execute the plan; use `plan` to see it first')
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        sys.exit('run needs DEFENSE4_HW_AUTHORIZED=1 (this is a hardware campaign)')
    bad = [n for n, b in cfg['builds'].items() if any(v == PLACEHOLDER for v in b.get('hashes', {}).values())]
    if bad:
        sys.exit('refusing to run: builds with placeholder hashes: %s' % ', '.join(bad))
    sys.exit('run execution is intentionally not wired in this session (no hardware contact); the plan '
             'above is the authoritative sequence for the lead to execute with authorization')


if __name__ == '__main__':
    sys.exit(main())
