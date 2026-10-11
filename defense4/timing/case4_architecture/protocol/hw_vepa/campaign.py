#!/usr/bin/env python3
"""Single entry point for the response-only four-arm hardware campaign.

  campaign.py validate [--config campaign.json]
  campaign.py plan     [--config campaign.json] [--arms a,b]   # print the exact commands `run` would execute
  campaign.py run      [--config campaign.json] [--arms a,b] --apply [--dry-run]

One JSON config (campaign.json) is the single source for endpoints, port map, build identity, feature bits,
timing, K, shaping, fixture, trials and restoration. `run` and `plan` are the SAME orchestration
(`Campaign.execute`) over a different runner: `plan` uses DryRunner, which records and prints every command
and executes none, so the reviewed command list is exactly what `run` emits. Nothing is a prose instruction.

`run --apply` (requires DEFENSE4_HW_AUTHORIZED=1) does, in order:
  1. refuses unless every build's hashes equal its compile manifest.json and the files on disk, the endpoint
     binary/lib identity is pinned, and every requested arm's feature bits are expressible by the installer;
  2. Vision: deploys vision_run.py, verifies its sha256 and the endpoint binary/lib sha256 against the pins,
     sets the namespace TCP profile and NIC flag, switches on the separate-ACK fixture;
  3. per install group (arms sharing a build and padding value): rsyncs the build and the installer source to
     the switch, checks the PCI vendor, makes the conf, cold-swaps bf_switchd to the composite
     (switch_swap.sh), replays the front-panel ports (restore_ports.py), dry-runs then applies the composite
     installer (bringup_composite.py, with K, timing and every shaping rate from the config);
  4. per arm: set_enabled.py for T, a before snapshot (snapshot_counters.py), the trials (vision_run.py run,
     scp, wire_check.py, clrt_check.py, gated by run.evaluate), an after snapshot, snapshots copied back;
  5. per group: bringup_teardown.py;
  6. in a finally block, whatever happened: Vision casea off and profile restore, teardown of any install
     still standing, cold swap back to the production launch script and restore_ports.py for production.
The first failed step or trial stops the campaign (fail-fast); the restore still runs; the exit status is
nonzero if any step, trial or restore step failed. campaign_run.json records the effective parameters, the
bound hashes, the observed endpoint identity, per-trial verdicts and the ACHIEVED (hardware-quantized)
shaping rates read back in each after-snapshot.

T on/off is a live toggle on one install. Padding on/off is the E conn policy row written at install time
(see campaign.json _notes); the installer flag that writes it is outstanding, so padding-off arms are refused
until it exists. Physical relay OPERATE remains attended-only and is out of this unattended path.
"""
import argparse
import collections
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import run as runner  # noqa: E402  (evaluate(): the reviewed per-run gate)
import vision_run as vr  # noqa: E402  (the Vision-side paths the endpoint runner itself uses)

# where the hw installer scripts live on the switch, relative to the copied source tree (hw/README.md)
HW = 'src/integration/core/response_only/hw'
RESPONSE_ONLY = 'integration/core/response_only'
Result = collections.namedtuple('Result', 'rc out err')
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
    if cfg['hosts'].get('vision_run_dir') != vr.HOME:
        raise ValueError('hosts.vision_run_dir must equal vision_run.HOME (%s): the endpoint runner uses its own '
                         'constant' % vr.HOME)
    if cfg['fixture'].get('jitter_ms', 0) != 0:
        raise ValueError('fixture.jitter_ms must be 0: vision_run.py does not implement jitter')


def shaping_args(cfg, burst=True):
    """The installer/snapshot shaping flags, always explicit so a run's requested rates are never implicit.
    burst=False for snapshot_counters.py, which records the requested rates but has no --block-burst."""
    sh = cfg['shaping']
    parts = ['--shape-%s-pps %d' % (r, sh['hold_pps'][r]) for r in ROLES]
    parts += ['--shape-%s-blk-pps %d' % (r, sh['block_pps'][r]) for r in ROLES]
    if burst and sh.get('block_burst') is not None:
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


class StepFailed(Exception):
    pass


class ShellRunner:
    """The real process boundary: ssh to the switch/Vision, a local subprocess for everything else."""
    dry = False

    def __init__(self, hosts):
        self.hosts = hosts

    def run(self, where, cmd, cwd=None, timeout=3600, label=None):
        argv = ['ssh', '-o', 'BatchMode=yes', self.hosts[where], cmd] if where in ('switch', 'vision') \
            else shlex.split(cmd)
        try:
            p = subprocess.run(argv, capture_output=True, text=True, cwd=cwd, timeout=timeout)
        except subprocess.TimeoutExpired:
            return Result(124, '', 'timed out after %ds' % timeout)
        return Result(p.returncode, p.stdout, p.stderr)


class DryRunner:
    """Records and prints every command; executes none. Used by `plan` and `run --dry-run`."""
    dry = True

    def __init__(self):
        self.calls = []

    def run(self, where, cmd, cwd=None, timeout=None, label=None):
        self.calls.append((where, cmd))
        print('[%-11s] %s\n              $ %s' % (where, label or '', cmd))
        return Result(0, '', '')


def default_installer_flags(flag):
    """Does hw/bringup_composite.py (the reviewed installer) accept `flag`? Read from its source."""
    src = open(os.path.join(ARCH, RESPONSE_ONLY, 'hw', 'bringup_composite.py')).read()
    return ("'%s'" % flag) in src or ('"%s"' % flag) in src


def q(x):
    return shlex.quote(str(x))


class Campaign:
    def __init__(self, cfg, runner_, run_id, arms=None, installer_flags=None, out=print):
        self.cfg, self.rn, self.run_id, self.out = cfg, runner_, run_id, out
        self.installer_has = installer_flags or (lambda flag: default_installer_flags(flag))
        names = [a['name'] for a in cfg['arms']]
        want = arms or names
        unknown = [n for n in want if n not in names]
        if unknown:
            raise ValueError('unknown arm(s) %s; the config defines %s' % (unknown, names))
        self.arms = [a for a in cfg['arms'] if a['name'] in want]
        self.R = cfg['hosts']['switch_remote_dir']
        self.V = vr.HOME
        self.root = os.path.join(path_of(cfg['evidence_dir']), run_id)
        self.record = {'run_id': run_id, 'ok': False, 'failure': None, 'arms': [], 'restore': [], 'groups': []}
        self.switch_touched = False
        self.standing = []            # manifests of installs not yet torn down
        self.vision_touched = False

    # ---- groups, gates, bound identity ------------------------------------------------------------------
    def groups(self):
        """[(build, padding, [arms])] in config order: one cold launch + install per group."""
        out, index = [], {}
        for a in self.arms:
            k = (a['build'], a['padding'])
            if k not in index:
                index[k] = len(out)
                out.append((a['build'], a['padding'], []))
            out[index[k]][2].append(a)
        return out

    def blocked(self):
        """Why a requested arm cannot be run by the reviewed installer today (empty = nothing blocks)."""
        flag = self.cfg.get('padding_installer_flag', '--pad-enable')
        if any(a['padding'] == 0 for a in self.arms) and not self.installer_has(flag):
            names = [a['name'] for a in self.arms if a['padding'] == 0]
            return ['arm(s) %s need the padding policy row off, but hw/bringup_composite.py has no %s flag '
                    '(TODO hw/ owner); run the padding-on arms with --arms' % (names, flag)]
        return []

    def preflight(self):
        """Everything that must stop a real run; `plan` prints the same list as banners and carries on."""
        return check_bindings(self.cfg) + self.blocked()

    # ---- step plumbing ------------------------------------------------------------------------------------
    def step(self, where, label, cmd, cwd=None, check=True, timeout=3600):
        r = self.rn.run(where, cmd, cwd=cwd, timeout=timeout, label=label)
        if not self.rn.dry:
            self.out('[%s] %s -> rc %d' % (where, label, r.rc))
        if check and r.rc != 0:
            raise StepFailed('%s failed (rc %d) on %s: %s | %s' % (label, r.rc, where, cmd[:300],
                                                                   (r.err or r.out)[-400:].strip()))
        return r

    def switch_cmd(self, script, args):
        return 'python3 %s/%s/%s %s' % (self.R, HW, script, args)

    def hw_env(self, cmd):
        return 'DEFENSE4_HW_AUTHORIZED=1 ' + cmd

    # ---- the flow -------------------------------------------------------------------------------------------
    def execute(self):
        dry = self.rn.dry
        errs = self.preflight()
        if errs and not dry:
            for e in errs:
                sys.stderr.write('REFUSED: %s\n' % e)
            self.record['failure'] = 'refused: ' + '; '.join(errs)
            return 1
        for e in errs:
            self.out('BLOCKED/UNBOUND (a real run refuses): %s' % e)
        try:
            self.bound = bind_builds(self.cfg)
        except ValueError:
            if not dry:
                raise
            self.bound = {n: {r: (self.cfg['builds'][n]['hashes'].get(r) or '<UNBOUND>') for r in BUILD_HASHED}
                          for n in {a['build'] for a in self.arms}}
        if not dry:
            os.makedirs(self.root)
        failed = False
        try:
            self.preflight_vision()
            for build, padding, arms in self.groups():
                self.run_group(build, padding, arms)
        except (StepFailed, ValueError, OSError) as e:
            failed = True
            self.record['failure'] = str(e)
            sys.stderr.write('CAMPAIGN FAILED: %s\n' % e)
        finally:
            restore_ok = self.restore()
            self.finish(dry)
        self.record['ok'] = (not failed) and restore_ok
        if not dry:
            self.finish(dry)
        return 0 if self.record['ok'] else 1

    def preflight_vision(self):
        c, ep, V = self.cfg, self.cfg['endpoint'], self.V
        host = c['hosts']['vision']
        self.vision_touched = True
        self.step('local', 'deploy vision_run.py to Vision',
                  'scp -q %s %s:%s/' % (q(os.path.join(HERE, 'vision_run.py')), host, V))
        r = self.step('vision', 'verify the deployed vision_run.py identity', 'sha256sum %s/vision_run.py' % V)
        self.check_hash(r, sha256_file(os.path.join(HERE, 'vision_run.py')), 'vision_run.py on Vision')
        r = self.step('vision', 'verify the endpoint binary identity', 'sha256sum %s' % vr.BIN)
        self.check_hash(r, ep['binary_sha256'], 'endpoint binary %s' % vr.BIN)
        r = self.step('vision', 'verify the endpoint lib/ identity',
                      'cd %s && find . -type f | sort | xargs sha256sum | sha256sum' % vr.LIB)
        self.check_hash(r, ep['lib_sha256'], 'endpoint lib %s' % vr.LIB)
        self.record['endpoint_observed'] = {'binary_sha256': ep['binary_sha256'], 'lib_sha256': ep['lib_sha256'],
                                            'vision_run_sha256': sha256_file(os.path.join(HERE, 'vision_run.py'))}
        self.step('vision', 'namespace TCP profile and NIC source-pruning (snapshots prior state)',
                  'sudo python3 %s/vision_run.py setup' % V)
        fx = c['fixture']
        if fx.get('casea'):
            self.step('vision', 'separate-ACK + delayed-response fixture on (emulated relay)',
                      'sudo python3 %s/vision_run.py casea on --delay-ms %d' % (V, fx['delay_ms']))

    def check_hash(self, result, want, what):
        if self.rn.dry:
            return
        got = (result.out.split() or ['<none>'])[0]
        if got != want:
            raise StepFailed('%s: sha256 %s does not match the pinned %s' % (what, got, want))

    def run_group(self, build, padding, arms):
        c, R = self.cfg, self.R
        b, tag = c['builds'][build], '%s_pad%d' % (build, padding)
        out_remote, conf = '%s/out_%s' % (R, build), '%s/response_only_hw_%s.conf' % (R, tag)
        manifest, log = '%s/bringup_manifest_%s_%s.json' % (R, self.run_id, tag), '%s/switchd_%s_%s.log' % (R, self.run_id, tag)
        aux, snapname = R + '/aux', os.path.basename(c['ports_snapshot'])
        host = c['hosts']['switch']
        self.switch_touched = False
        self.step('switch', 'make remote directories', 'mkdir -p %s %s/src %s/snap' % (aux, R, R))
        self.step('local', 'copy the build out/ to the switch',
                  'rsync -a %s/ %s:%s/' % (q(path_of(b['out_dir'])), host, out_remote))
        self.step('local', 'copy the installer source tree to the switch', 'rsync -aR --exclude __pycache__ '
                  '%s/cp.py %s/port_map.py %s/hw protocol/response_path_cp.py %s:%s/src/'
                  % (RESPONSE_ONLY, RESPONSE_ONLY, RESPONSE_ONLY, host, R), cwd=ARCH)
        self.step('local', 'copy restore_ports.py, the port snapshot and the swap/launch scripts',
                  'scp -q %s %s %s %s %s:%s/' % (
                      q(os.path.join(ARCH, '..', 'framework', 'control', 'restore_ports.py')),
                      q(path_of(c['ports_snapshot'])), q(os.path.join(HERE, 'switch_swap.sh')),
                      q(os.path.join(HERE, 'launch_composite.sh')), host, aux))
        self.step('switch', 'PCI vendor must be Barefoot/Intel (0x1d1c)',
                  'test "$(cat /sys/bus/pci/devices/%s/vendor)" = 0x1d1c' % b['pcie'])
        self.step('switch', 'make the bf_switchd conf for this build',
                  'python3 %s/%s/make_conf.py %s --remote-dir %s --pcie %s -o %s'
                  % (R, HW, out_remote, out_remote, b['pcie'], conf))
        self.switch_touched = True
        self.step('switch', 'cold-swap bf_switchd to the composite (stop, launch, wait for :50052, no device_add error)',
                  'bash %s/switch_swap.sh %s %s/launch_composite.sh %s %s' % (aux, log, aux, conf, b['sde']))
        self.step('switch', 'replay the front-panel $PORT entries from the live snapshot',
                  'python3 %s/restore_ports.py %s %s/%s --apply --wait 35' % (aux, c['program'], aux, snapname))
        comp = self.installer_cmd(build, padding, out_remote)
        self.step('switch', 'composite install dry-run (hash check, name check, ports it will loop)', comp)
        self.standing.append(manifest)
        self.step('switch', 'composite install apply (loopback first, apps enabled last)',
                  self.hw_env(comp + ' --apply --enable-pktgen --manifest-out %s' % manifest))
        self.record['groups'].append({'build': build, 'padding': padding, 'arms': [a['name'] for a in arms],
                                      'manifest': manifest})
        for arm in arms:
            self.run_arm(arm, build, out_remote, manifest)
        self.step('switch', 'teardown the composite (generator and T off, rows out, loopback off last)',
                  self.hw_env(self.switch_cmd('bringup_teardown.py', '--manifest %s --apply' % manifest)))
        self.standing.remove(manifest)
        self.step('local', 'copy the bring-up manifest back',
                  'scp -q %s:%s %s/' % (host, manifest, q(self.root)), check=False)

    def installer_cmd(self, build, padding, out_remote):
        c = self.cfg
        e, pm, t = c['endpoints'], c['ports_map'], c['timing_params_ns']
        expects = ' '.join('--expect %s=%s' % (rel, h) for rel, h in sorted(self.bound[build].items()))
        pad = ''
        flag = c.get('padding_installer_flag', '--pad-enable')
        if self.installer_has(flag):
            pad = ' %s %d' % (flag, padding)
        return ('python3 %s/%s/bringup_composite.py --build-out %s %s --master-ip %s --master-port %d --master-dev %d '
                '--relay-ip %s --relay-port %d --relay-dev %d --read-dst 0x%04x --read-src 0x%04x '
                '--t-da %d --t-readiness %d --t-cap %d --t-gap %d --t-op-j %d --k %d %s%s'
                % (self.R, HW, out_remote, expects, e['master_ip'], c['traffic']['master_port'], pm['master_dev'],
                   e['outstation_ip'], e['outstation_port'], pm['relay_dev'], e['read_dst'], e['read_src'],
                   t['da'], t['readiness'], t['cap'], t['gap'], t['op_j'], c['service']['k'],
                   shaping_args(c), pad))

    def snapshot(self, out_remote, name):
        return self.step('switch', 'counter snapshot %s' % name, self.hw_env(self.switch_cmd(
            'snapshot_counters.py', '--build-out %s --ports %s %s -o %s/snap/%s.json'
            % (out_remote, self.cfg['ports_map']['stat_ports'], shaping_args(self.cfg, burst=False), self.R, name))))

    def run_arm(self, arm, build, out_remote, manifest):
        c, host = self.cfg, self.cfg['hosts']['switch']
        n, tr = arm['name'], c['traffic']
        base = '%s_%s' % (self.run_id, n)
        rec = {'arm': n, 'T': arm['T'], 'padding': arm['padding'], 'build': build, 'trials': [],
               'achieved_shaping': None}
        self.record['arms'].append(rec)
        arm_dir = os.path.join(self.root, n)
        self.step('switch', 'arm %s: select T (0=Timing OFF, 1=Obfuscated)' % n, self.hw_env(self.switch_cmd(
            'set_enabled.py', '--manifest %s --enabled %d' % (manifest, arm['T']))))
        self.snapshot(out_remote, base + '_before')
        for i in range(c['trials']['trials_per_arm']):
            label = '%s_t%d' % (base, i)
            dest = os.path.join(arm_dir, label)
            trial = {'label': label, 'ok': False, 'failures': []}
            rec['trials'].append(trial)
            v = self.step('vision', 'arm %s trial %d: traffic + capture' % (n, i),
                          'sudo python3 %s/vision_run.py run %s --master-port %d --reads %d --range %d --gap-ms %d'
                          % (self.V, label, tr['master_port'], c['trials']['reads_per_trial'], tr['range'],
                             tr['gap_ms']), check=False)
            if not self.rn.dry:
                os.makedirs(dest)
            self.step('local', 'arm %s trial %d: copy evidence' % (n, i), 'scp -q %s:%s/runs/%s/* %s/'
                      % (c['hosts']['vision'], self.V, label, q(dest)), check=not self.rn.dry)
            w = self.step('local', 'arm %s trial %d: independent wire verification' % (n, i),
                          '%s %s/wire_check.py %s %s --json %s' % (runner.PY, q(HERE), q(dest + '/out.pcap'),
                                                                    q(dest + '/in.pcap'), q(dest + '/wire.json')),
                          check=False)
            k = self.step('local', 'arm %s trial %d: per-exchange timing extraction' % (n, i),
                          '%s %s/clrt_check.py %s %s --json %s' % (runner.PY, q(HERE), q(dest + '/out.pcap'),
                                                                    q(dest + '/in.pcap'), q(dest + '/timing.json')),
                          check=False)
            if self.rn.dry:
                continue
            try:
                result = json.loads([l for l in v.out.splitlines() if l.startswith('{')][-1])
            except (IndexError, ValueError):
                result = {'error': (v.out + v.err)[-500:]}
            artifacts = {f: os.path.exists(os.path.join(dest, f)) for f in ('out.pcap', 'in.pcap', 'wire.json',
                                                                            'timing.json')}
            ok, fails = runner.evaluate(False, v.rc, result, w.rc, k.rc, artifacts)
            trial.update(ok=ok, failures=fails, vision=result, wire_rc=w.rc, clrt_rc=k.rc)
            json.dump(trial, open(os.path.join(dest, 'trial.json'), 'w'), indent=1, default=str)
            if not ok:
                raise StepFailed('arm %s trial %d failed: %s' % (n, i, '; '.join(fails)))
        self.snapshot(out_remote, base + '_after')
        snapdir = os.path.join(arm_dir, 'snapshots')
        if not self.rn.dry:
            os.makedirs(snapdir)
        self.step('local', 'arm %s: copy the before/after snapshots back' % n,
                  'scp -q %s:%s/snap/%s_before.json %s:%s/snap/%s_after.json %s/'
                  % (host, self.R, base, host, self.R, base, q(snapdir)), check=not self.rn.dry)
        if not self.rn.dry:
            snap = json.load(open(os.path.join(snapdir, '%s_after.json' % base)))
            rec['achieved_shaping'] = snap.get('shaping')

    # ---- restoration: best effort, every step attempted, every failure recorded -------------------------------
    def restore(self):
        c, R = self.cfg, self.R
        ok = True

        def attempt(where, label, cmd):
            nonlocal ok
            try:
                r = self.rn.run(where, cmd, timeout=1800, label=label)
                bad = r.rc != 0
            except Exception as e:                      # a restore step must never stop the later ones
                r, bad = Result(1, '', str(e)), True
            self.record['restore'].append({'step': label, 'rc': r.rc, 'ok': not bad})
            if not self.rn.dry:
                self.out('[restore:%s] %s -> rc %d' % (where, label, r.rc))
            if bad:
                ok = False
                sys.stderr.write('RESTORE STEP FAILED: %s (rc %d) %s\n' % (label, r.rc, (r.err or r.out)[-300:]))

        if self.vision_touched:
            attempt('vision', 'Vision: fixture off, namespace profile and NIC flag restored',
                    'sudo python3 %s/vision_run.py restore' % self.V)
        for manifest in list(self.standing):
            attempt('switch', 'teardown the composite still installed', self.hw_env(
                self.switch_cmd('bringup_teardown.py', '--manifest %s --apply' % manifest)))
        if self.switch_touched:
            p, aux = c['production'], R + '/aux'
            attempt('switch', 'cold-swap bf_switchd back to the production launch script',
                    'bash %s/switch_swap.sh %s/switchd_production_%s.log %s' % (aux, R, self.run_id, p['launch_script']))
            attempt('switch', 'replay production $PORT entries',
                    'python3 %s/restore_ports.py %s %s/%s --apply --wait 35'
                    % (aux, p['program'], aux, os.path.basename(c['ports_snapshot'])))
        return ok

    def finish(self, dry):
        if dry:
            return
        c = self.cfg
        self.record['effective'] = {
            'timing_params_ns': c['timing_params_ns'], 'k': c['service']['k'],
            'shaping_requested': c['shaping'], 'fixture': c['fixture'], 'trials': c['trials'],
            'traffic': c['traffic'], 'ports_map': c['ports_map'], 'endpoints': c['endpoints']}
        self.record['builds'] = getattr(self, 'bound', None)
        self.record['time'] = time.time()
        json.dump(self.record, open(os.path.join(self.root, 'campaign_run.json'), 'w'), indent=1, default=str)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=('validate', 'plan', 'run'))
    ap.add_argument('--config', default=os.path.join(HERE, 'campaign.json'))
    ap.add_argument('--arms', help='comma-separated arm names to run (default: all arms in the config)')
    ap.add_argument('--run-id', default=None)
    ap.add_argument('--apply', action='store_true', help='required for run: actually execute on hardware')
    ap.add_argument('--dry-run', action='store_true', help='run: print the commands instead (same as plan)')
    a = ap.parse_args(argv)
    cfg = load_config(a.config)
    for w in warnings(cfg):
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
    run_id = a.run_id or time.strftime('c%Y%m%dT%H%M%S')
    arms = a.arms.split(',') if a.arms else None
    if a.mode == 'plan' or a.dry_run:
        return Campaign(cfg, DryRunner(), run_id, arms).execute()
    if not a.apply:
        sys.exit('run needs --apply to execute on hardware; use `plan` (or --dry-run) to see the commands first')
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        sys.exit('run needs DEFENSE4_HW_AUTHORIZED=1 (this is a hardware campaign)')
    bad = check_bindings(cfg)
    if bad:
        sys.exit('refusing to run, unbound identity: %s' % '; '.join(bad))
    return Campaign(cfg, ShellRunner(cfg['hosts']), run_id, arms).execute()


if __name__ == '__main__':
    sys.exit(main())
