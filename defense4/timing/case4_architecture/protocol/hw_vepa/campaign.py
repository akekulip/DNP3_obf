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
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run as runner  # noqa: E402  (ssh/host constants and the endpoint-run helpers)

# where the hw installer scripts live on the switch, relative to the copied source tree (hw/README.md)
HW = 'src/integration/core/response_only/hw'
ARCH = os.path.abspath(os.path.join(HERE, '..', '..'))      # case4_architecture: every config path is relative to it
REQUIRED = ('endpoints', 'endpoint', 'hosts', 'ports_map', 'builds', 'arms', 'timing_params_ns', 'service',
            'shaping', 'fixture', 'trials', 'traffic', 'loss', 'seeds', 'evidence_dir', 'production',
            'ports_snapshot')
BUILD_HASHED = ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin')   # what bringup_composite --expect requires
ROLES = ('ack', 'resp', 'op')
HEX64 = re.compile(r'[0-9a-f]{64}')
HEX40 = re.compile(r'[0-9a-f]{40}')


def path_of(rel):
    return rel if os.path.isabs(rel) else os.path.join(ARCH, rel)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


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
    validate_profile(cfg)
    return cfg


def validate_profile(cfg):
    """The hardware profile the campaign may run: the 8-bit-range READ, a positive K, non-negative shaping
    rates, and no fixture jitter (vision_run.py has no way to apply it)."""
    if cfg['traffic']['range'] != 8:
        raise ValueError('traffic.range must be 8 (the 20-byte 8-bit-range READ profile); got %r'
                         % cfg['traffic']['range'])
    if cfg['service']['k'] < 1:
        raise ValueError('service.k must be >= 1 (installer --k is 2*k tokens)')
    sh = cfg['shaping']
    for group in ('hold_pps', 'block_pps'):
        for r in ROLES:
            v = sh[group].get(r)
            if not isinstance(v, int) or isinstance(v, bool) or v < 0:
                raise ValueError('shaping.%s.%s must be an integer >= 0 (0 = unshaped), got %r' % (group, r, v))
    bb = sh.get('block_burst')
    if bb is not None and (not isinstance(bb, int) or isinstance(bb, bool) or bb < 1):
        raise ValueError('shaping.block_burst must be null (installer default) or an integer >= 1')
    if cfg['fixture'].get('jitter_ms', 0) != 0:
        raise ValueError('fixture.jitter_ms must be 0: vision_run.py does not implement jitter')


def shaping_args(cfg):
    """The installer/snapshot shaping flags, always explicit so a run's requested rates are never implicit."""
    sh = cfg['shaping']
    parts = ['--shape-%s-pps %d' % (r, sh['hold_pps'][r]) for r in ROLES]
    parts += ['--shape-%s-blk-pps %d' % (r, sh['block_pps'][r]) for r in ROLES]
    if sh.get('block_burst') is not None:
        parts.append('--block-burst %d' % sh['block_burst'])
    return ' '.join(parts)


def check_bindings(cfg):
    """Every identity error that must stop a run (empty list = bound). Offline: reads each build's compile
    manifest.json and hashes the files under out_dir. A config hash must be null (filled from the manifest)
    or a 64-hex sha256 equal to the manifest; the files on disk must equal the manifest. A placeholder or
    malformed value is an error, not a warning."""
    errs = []
    for name in sorted({a['build'] for a in cfg['arms']}):
        b = cfg['builds'][name]
        mpath = path_of(b.get('manifest', ''))
        try:
            want = json.load(open(mpath))['artifact_sha256']
        except (OSError, ValueError, KeyError) as e:
            errs.append('build %s: cannot read the compile manifest %s (%s)' % (name, mpath, e))
            continue
        for rel in BUILD_HASHED:
            slot = b.get('hashes', {}).get(rel)
            if slot is not None and not (isinstance(slot, str) and HEX64.fullmatch(slot)):
                errs.append('build %s: hashes[%s]=%r is a placeholder or not a sha256 (use null to fill it from '
                            'the manifest)' % (name, rel, slot))
                continue
            if rel not in want:
                errs.append('build %s: the compile manifest has no artifact_sha256 for %s' % (name, rel))
                continue
            if slot is not None and slot != want[rel]:
                errs.append('build %s: hashes[%s] disagrees with the compile manifest (%s vs %s)'
                            % (name, rel, slot, want[rel]))
            f = os.path.join(path_of(b['out_dir']), rel)
            got = sha256_file(f) if os.path.isfile(f) else 'missing'
            if got != want[rel]:
                errs.append('build %s: %s on disk is %s but the compile manifest records %s'
                            % (name, rel, got, want[rel]))
    ep = cfg['endpoint']
    for k in ('binary_sha256', 'lib_sha256'):
        if not (isinstance(ep.get(k), str) and HEX64.fullmatch(ep[k])):
            errs.append('endpoint.%s is not pinned (%r); it cannot be derived offline, pin it with: %s'
                        % (k, ep.get(k), ep.get('_pin_with', 'sha256sum on Vision')))
    if not (isinstance(ep.get('opendnp3_commit'), str) and HEX40.fullmatch(ep['opendnp3_commit'])):
        errs.append('endpoint.opendnp3_commit is not a 40-hex commit id')
    return errs


def bind_builds(cfg):
    """{build: {rel: sha256}} verified against the manifest and the files; raises ValueError listing every
    problem. Null config slots come back filled from the manifest."""
    errs = [e for e in check_bindings(cfg) if not e.startswith('endpoint.')]
    if errs:
        raise ValueError('; '.join(errs))
    out = {}
    for name in sorted({a['build'] for a in cfg['arms']}):
        want = json.load(open(path_of(cfg['builds'][name]['manifest'])))['artifact_sha256']
        out[name] = {rel: want[rel] for rel in BUILD_HASHED}
    return out


def warnings(cfg):
    """Non-fatal advisories that encode known traps (returned, not raised)."""
    w = []
    fixture_ns = int(cfg['fixture']['delay_ms'] * 1_000_000)
    if fixture_ns >= cfg['timing_params_ns']['readiness']:
        w.append('fixture delay %d ms >= T readiness %d ns: the child response arrives after the readiness '
                 'deadline, so the normal commit/release path cannot be observed (defect D). Lower the '
                 'fixture delay or raise readiness.' % (cfg['fixture']['delay_ms'], cfg['timing_params_ns']['readiness']))
    return w


def _install_steps(cfg, build_name):
    b = cfg['builds'][build_name]
    e, pm, t = cfg['endpoints'], cfg['ports_map'], cfg['timing_params_ns']
    R = cfg['hosts']['switch_remote_dir']
    bound = {rel: b['hashes'].get(rel) or json.load(open(path_of(b['manifest'])))['artifact_sha256'][rel]
             for rel in BUILD_HASHED}
    expects = ' '.join('--expect %s=%s' % (rel, h) for rel, h in bound.items())
    endpoint_args = (
        '--master-ip %s --master-port %d --master-dev %d --relay-ip %s --relay-port %d --relay-dev %d '
        '--read-dst 0x%04x --read-src 0x%04x' % (
            e['master_ip'], cfg['traffic']['master_port'], pm['master_dev'], e['outstation_ip'],
            e['outstation_port'], pm['relay_dev'], e['read_dst'], e['read_src']))
    t_args = '--t-da %d --t-readiness %d --t-cap %d --t-gap %d --t-op-j %d --k %d' % (
        t['da'], t['readiness'], t['cap'], t['gap'], t['op_j'], cfg['service']['k']) + ' ' + shaping_args(cfg)
    comp = '%s/%s/bringup_composite.py --build-out %s/out %s %s %s' % (R, HW, R, expects, endpoint_args, t_args)
    return [
        ('switch', 'conf from the loaded build',
         'python3 %s/%s/make_conf.py %s/out --remote-dir %s/out --pcie %s -o %s/response_only_hw.conf'
         % (R, HW, R, R, b['pcie'], R)),
        ('switch', 'launch bf_switchd on the composite build (rehearsed restore in place)',
         'see hw/README.md run-order step 2 (SDE=%s); refuse if bf_switchd is already up' % b['sde']),
        ('switch', 'enable the front-panel ports from the live snapshot',
         'python3 framework/control/restore_ports.py %s %s --apply --wait 35' % (cfg['program'], os.path.basename(cfg['ports_snapshot']))),
        ('switch', 'composite install dry-run (prints the ports it will loop)', comp),
        ('switch', 'composite install apply (loopback first, apps enabled last)',
         'DEFENSE4_HW_AUTHORIZED=1 ' + comp + ' --apply --enable-pktgen --manifest-out %s/bringup_manifest.json' % R),
        ('switch', 'counter snapshot before the blocks',
         'python3 %s/%s/snapshot_counters.py --build-out %s/out --ports %s %s -o %s/before_%s.json'
         % (R, HW, R, cfg['ports_map']['stat_ports'], shaping_args(cfg), R, build_name)),
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
             'python3 %s/%s/snapshot_counters.py --build-out %s/out --ports %s %s -o %s/after_%s.json'
             % (R, HW, R, cfg['ports_map']['stat_ports'], shaping_args(cfg), R, build_name)),
            ('switch', 'teardown the composite on build %s (loopback off last)' % build_name,
             'python3 %s/%s/bringup_teardown.py --manifest %s/bringup_manifest.json --apply' % (R, HW, R)),
        ]
    steps += [('vision', 'restore the namespace profile and the NIC flag', 'python3 %s/run.py restore' % HERE),
              ('switch', 'production port restore (rehearsed cold restart)',
               'python3 framework/control/restore_ports.py %s %s --apply --wait 35'
               % (cfg['program'], os.path.basename(cfg['ports_snapshot'])))]
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
        errs = check_bindings(cfg)
        for e in errs:
            sys.stderr.write('UNBOUND: %s\n' % e)
        if errs:
            print('config structure OK but %d binding error(s); `run` will refuse' % len(errs))
            return 1
        print('config OK and bound: %d arms over %d build(s), %d trials/arm'
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
    bad = check_bindings(cfg)
    if bad:
        sys.exit('refusing to run, unbound identity: %s' % '; '.join(bad))
    sys.exit('run execution is intentionally not wired in this session (no hardware contact); the plan '
             'above is the authoritative sequence for the lead to execute with authorization')


if __name__ == '__main__':
    sys.exit(main())
