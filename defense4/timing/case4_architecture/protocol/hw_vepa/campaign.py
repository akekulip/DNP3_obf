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
     binary/lib identity is pinned, the master-port range covers every connection, and the installer accepts
     every requested arm's feature bits;
  2. Vision (read-only identity): deploys vision_run.py and verifies its sha256 and the endpoint binary/lib
     sha256 against the pins;
  3. switch (read-only): copies the tools and builds, reads the running program from ps and REFUSES unless it is
     the configured production program, and snapshots its $PORT table for every later replay;
  4. Vision: namespace TCP profile and NIC flag;
  5. for each fixture (separate_ack = casea on, piggyback = casea off), for each arm, for each trial (one
     connection per arm in trial_mode one_connection) a COLD bring-up on a NEW master port from
     traffic.master_port_range: switch_swap.sh, restore_ports.py, bringup_composite.py dry-run then apply
     (K, timing, shaping preset, --pad-enable), set_enabled.py for T, before snapshot, vision_run.py run, scp,
     wire_check.py, clrt_check.py (gated by run.evaluate), after snapshot copied back, bringup_teardown.py;
  6. in a finally block, whatever happened: tear down any install still standing, cold-swap to the production
     launch script, restore_ports.py on the pre-run snapshot, reinstall the relay slot, Vision restore, then a
     ping that must succeed.
The first failed step or trial stops the campaign (fail-fast); the restore still runs; the exit status is
nonzero if any step, trial or restore step failed. campaign_run.json records the effective parameters (preset,
fixture, K, timing), the bound hashes, the observed endpoint identity and pre-run program, per-trial verdicts
and the ACHIEVED (hardware-quantized) shaping rates read back in each after-snapshot.

T on/off is a live toggle on one install. Padding on/off is the E conn policy row written at install time
(see campaign.json _notes); the installer flag that writes it is outstanding, so padding-off arms are refused
until it exists. Physical relay OPERATE remains attended-only and is out of this unattended path.
"""
import argparse
import collections
import hashlib
import importlib.util
import json
import os
import re
import shlex
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import checks  # noqa: E402
import loss  # noqa: E402
import read_classes  # noqa: E402  (per-class READ declarations: builds[b].read_images, traffic.read_schedule/db)
import run as runner  # noqa: E402  (evaluate(): the reviewed per-run gate)
import standards  # noqa: E402
import vision_run as vr  # noqa: E402  (the Vision-side paths the endpoint runner itself uses)

# where the hw installer scripts live on the switch, relative to the copied source tree (hw/README.md)
HW = 'src/integration/core/response_only/hw'
RESPONSE_ONLY = 'integration/core/response_only'
Result = collections.namedtuple('Result', 'rc out err')
ARCH = os.path.abspath(os.path.join(HERE, '..', '..'))      # case4_architecture: every config path is relative to it
CHECK_CAPTURE = os.path.join(ARCH, 'integration', 'core', 'response_only_rearm', 'stage_experiments',
                             'read_reencode_01', 'check_capture.py')
REQUIRED = ('endpoints', 'endpoint', 'hosts', 'ports_map', 'builds', 'arms', 'timing_params_ns', 'service',
            'shaping', 'fixture', 'trials', 'traffic', 'loss', 'seeds', 'evidence_dir', 'production', 'expectations')
# bringup_composite --expect: the first three are required by the installer; p1/response_only.bfa is the file its
# mirror-defect guard reads (out/p1/*.bfa), pinned here to tie the checked file to the loaded binaries.
BUILD_HASHED = ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin', 'p1/response_only.bfa')
ROLES = ('ack', 'resp', 'op')
FIXTURES = ('separate_ack', 'piggyback')
LADDER = (0, 58, 232, 930, 3723, 14892, 59570, 238281)   # the TM shaper realizes only these PPS values (0 = off)
HEX64 = re.compile(r'[0-9a-f]{64}')
HEX40 = re.compile(r'[0-9a-f]{40}')
# observed key of each timing objective -> its failure prefix (checks.OBJECTIVE_PREFIXES)
OBJECTIVE_KEYS = {'read_precision': 'READ precision:', 'select_precision': 'SELECT precision:',
                  'operate_precision': 'OPERATE precision:', 'piggyback_latency': 'PIGGYBACK latency:',
                  'operate_hold': 'OPERATE hold:'}
LOSS_OBJECTIVES_EXEMPT = 'loss/recovery trial: timing objectives are not evaluated'
RECONNECT_OBJECTIVES_EXEMPT = 'reconnect %s: timing objectives beyond READ precision are not evaluated'
RUNNER_OBJECTIVES_EXEMPT = 'this runner evaluates no timing objectives beyond READ precision'
# host-observed CLRT precision misses only (not J hold, piggyback latency, or any correctness gate)
PRECISION_PREFIXES = ('READ precision:', 'SELECT precision:', 'OPERATE precision:')


def precision_only_soft(record, evaluation):
    """True when a block's only failures are host-observed CLRT precision threshold misses that the runner already
    accepted as timing-characterization continuations, AND the config explicitly reports host precision instead of
    gating it (evaluation.host_precision_gated is False; Philip, 2026-10-18, evaluation option 1). Any other failure,
    including a J-hold or piggyback miss, stays a hard failure."""
    if evaluation.get('host_precision_gated') is not False or \
            evaluation.get('purpose') != 'timing_precision_characterization':
        return False
    soft = [t for a in record.get('arms', []) for t in a.get('trials', []) if t.get('ok') is False]
    return bool(soft) and all((t.get('continuation') or {}).get('allowed') is True and t.get('failures') and
                              all(f.startswith(PRECISION_PREFIXES) for f in t['failures']) for t in soft)


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
    if 'pb' in t and not (isinstance(t['pb'], int) and not isinstance(t['pb'], bool) and t['op_j'] < t['pb'] < t['readiness']):
        raise ValueError('timing_params_ns.pb (piggyback bound, ctl_timing builds only) must be an int in op_j < pb < readiness')
    if any(b.get('piggyback_bound') for b in cfg.get('builds', {}).values()) and 'pb' not in t:
        raise ValueError('a piggyback_bound build requires timing_params_ns.pb')
    for name, b in cfg.get('builds', {}).items():
        g = b.get('gen_exhausted_outcome')
        if g is not None and not (isinstance(g, int) and not isinstance(g, bool) and 0 <= g < 32):
            raise ValueError('build %s: gen_exhausted_outcome must be the T outcome index (int 0..31) declaring '
                             'GEN_EXHAUSTED, or absent' % name)
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


def validate_read_classes(cfg):
    """endpoint.binary, traffic.read_schedule/db and every arm's per-class READ declaration, before anything runs: a
    schedule on an arm whose build declares no read_images/read_images_by_db, or a padded arm whose build does not
    support a scheduled class, is refused here, never run against a native expectation. Loss presets
    identify packets by one READ request/response length, so they do not carry a READ-class schedule."""
    traffic = cfg['traffic']
    if 'binary' in cfg['endpoint'] and (not isinstance(cfg['endpoint']['binary'], str) or
                                        not re.fullmatch(r'[A-Za-z0-9_.-]+', cfg['endpoint']['binary']) or
                                        cfg['endpoint']['binary'] in ('.', '..')):
        raise ValueError('endpoint.binary must be a file name beside vision_run.py ([A-Za-z0-9_.-]+), got %r'
                         % (cfg['endpoint']['binary'],))
    for key in ('read_schedule', 'db'):
        if key in traffic and not isinstance(traffic[key], str):
            raise ValueError('traffic.%s must be a string' % key)
    try:
        name, _classes, db = read_classes.schedule_and_db(cfg)
        presets = cfg.get('loss', {}).get('presets')
        if name is not None and presets:
            # A READ-class schedule with a loss preset is allowed only for a single-frame READ-response selector
            # whose length exists as one link frame on this database. The 247-byte selector (read_resp_247) covers
            # base class0/integrity without distinguishing them; on the large database those classes are segmented
            # (292 + 85), so no 247-byte single-frame response exists and read_resp_247 is refused (NOT_EXERCISED).
            single_frame = {sum(segs) for segs in read_classes.NATIVE_SEGMENTS.get(db, {}).values() if len(segs) == 1}
            for pname, entries in presets.items():
                for e in entries:
                    if e['class'] not in loss.READ_RESP_LEN:
                        raise ValueError('traffic.read_schedule with a loss preset is supported only for the '
                                         'single-frame READ-response selectors %s; preset %s targets %r'
                                         % (sorted(loss.READ_RESP_LEN), pname, e['class']))
                    _sel, reason = loss.read_resp_class(e['class'], single_frame)
                    if reason:
                        raise ValueError('traffic.read_schedule with loss preset %s: %s' % (pname, reason))
        # the READ count one unit (connection) actually carries; one_connection runs every trial of an arm on one
        reads = cfg['trials']['reads_per_trial'] * (cfg['trials']['trials_per_arm']
                                                    if cfg.get('trial_mode') == 'one_connection' else 1)
        for arm in cfg.get('arms', []):
            standards.read_class_expectations(cfg, arm, {'reads': reads})
    except read_classes.ReadClassError as error:
        raise ValueError(str(error))


def validate_profile(cfg):
    """The hardware profile the campaign may run: the 8-bit-range READ, a positive K, non-negative shaping
    rates, and fixture jitter only with a netem distribution on the separate_ack fixture."""
    for key, default in (('read_pause_ms', 25), ('close_grace_ms', 0)):
        value = cfg['traffic'].get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 5000:
            raise ValueError('traffic.%s must be an integer in 0..5000' % key)
    if not isinstance(cfg['traffic'].get('run_sbo', True), bool):
        raise ValueError('traffic.run_sbo must be boolean')
    if 'sbo_cycles' in cfg['traffic']:
        cycles = cfg['traffic']['sbo_cycles']
        if not isinstance(cycles, int) or isinstance(cycles, bool) or not 1 <= cycles <= checks.MAX_SBO_CYCLES:
            raise ValueError('traffic.sbo_cycles must be an integer in 1..%d' % checks.MAX_SBO_CYCLES)
        if cfg['traffic'].get('run_sbo', True) is not True:
            raise ValueError('traffic.sbo_cycles requires traffic.run_sbo')
        if cfg['trials']['reads_per_trial'] < cycles + 1:
            raise ValueError('trials.reads_per_trial counts every READ and must be >= sbo_cycles + 1')
        if cfg.get('loss', {}).get('presets'):
            raise ValueError('traffic.sbo_cycles is not supported with loss presets (unsupported shape)')
    validate_read_classes(cfg)
    quality = cfg.get('evaluation', {})
    if quality.get('purpose', 'qualification') not in ('qualification', 'stale_source_characterization',
                                                      'timing_precision_characterization'):
        raise ValueError('evaluation.purpose must be qualification, stale_source_characterization, '
                         'or timing_precision_characterization')
    if not isinstance(quality.get('read_precision', True), bool):
        raise ValueError('evaluation.read_precision must be boolean')
    if quality.get('read_precision') is False and quality.get('purpose') != 'stale_source_characterization':
        raise ValueError('only explicit stale_source_characterization may disable READ precision qualification')
    for name, scenario in cfg.get('scenarios', {}).items():
        if scenario.get('policy', 'characterize') not in ('characterize', 'protected'):
            raise ValueError('scenario %s: policy must be characterize or protected' % name)
    if cfg['traffic']['range'] != 8:
        raise ValueError('traffic.range must be 8 (the 20-byte 8-bit-range READ profile); got %r'
                         % cfg['traffic']['range'])
    if cfg['service']['k'] < 1:
        raise ValueError('service.k must be >= 1 (installer --k is 2*k tokens)')
    sh = cfg['shaping']
    if sh.get('preset') not in sh.get('presets', {}):
        raise ValueError('shaping.preset %r is not one of %s' % (sh.get('preset'), sorted(sh.get('presets', {}))))
    for name, p in sh['presets'].items():
        for group in ('hold_pps', 'block_pps'):
            for r in ROLES:
                v = p[group].get(r)
                if not isinstance(v, int) or isinstance(v, bool) or v not in LADDER:
                    raise ValueError('shaping preset %s: %s.%s=%r is not an exact shaper ladder value %s (0 = off)'
                                     % (name, group, r, v, LADDER))
        bb = p.get('block_burst')
        if bb is not None and (not isinstance(bb, int) or isinstance(bb, bool) or bb < 1):
            raise ValueError('shaping preset %s: block_burst must be null (installer default) or an integer >= 1'
                             % name)
    if cfg.get('trial_mode') not in ('per_trial_cold', 'one_connection'):
        raise ValueError("trial_mode must be 'per_trial_cold' or 'one_connection', got %r" % cfg.get('trial_mode'))
    pr = cfg['traffic'].get('master_port_range', {})
    if not (isinstance(pr.get('first'), int) and isinstance(pr.get('last'), int)
            and 1024 <= pr['first'] <= pr['last'] <= 65535):
        raise ValueError('traffic.master_port_range needs integer first <= last within 1024..65535, got %r' % pr)
    for name, b in cfg['builds'].items():
        checks.validate_allowed_gap(b, name)
        checks.validate_max_token_stale(b, name)
        if not isinstance(b.get('mirror_fix', False), bool):
            raise ValueError('build %s: mirror_fix must be true or false' % name)
    exp = cfg['expectations']
    for k in ('common', 'native_len', 'padding', 'T', 'fixture'):
        if k not in exp:
            raise ValueError('expectations.%s is missing' % k)
    modes = cfg['fixture'].get('modes')
    if not modes or any(m not in FIXTURES for m in modes) or len(set(modes)) != len(modes):
        raise ValueError('fixture.modes must be a non-empty list of distinct values from %s, got %r' % (FIXTURES, modes))
    if 'separate_ack' in modes and not cfg['fixture'].get('delay_ms', 0) > 0:
        raise ValueError('fixture.delay_ms must be > 0 for the separate_ack fixture')
    sd = cfg['traffic'].get('start_delay_ms', 0)
    if not isinstance(sd, int) or isinstance(sd, bool) or sd < 0:
        raise ValueError('traffic.start_delay_ms must be an integer >= 0')
    validate_paired_blocks(cfg)
    validate_loss_and_scenarios(cfg)
    jitter, distribution = cfg['fixture'].get('jitter_ms', 0), cfg['fixture'].get('distribution')
    if not isinstance(jitter, int) or isinstance(jitter, bool) or not 0 <= jitter <= 20:
        raise ValueError('fixture.jitter_ms must be an integer in 0..20, got %r' % (jitter,))
    if jitter and (distribution not in vr.DISTRIBUTIONS or 'separate_ack' not in modes):
        raise ValueError('fixture.jitter_ms needs fixture.distribution in %s and the separate_ack fixture'
                         % (vr.DISTRIBUTIONS,))
    if not jitter and distribution is not None:
        raise ValueError('fixture.distribution is only meaningful with fixture.jitter_ms > 0')


def resolve_shaping(cfg, preset=None):
    """The effective requested shaping: {'preset', 'hold_pps', 'block_pps', 'block_burst'}."""
    sh = cfg['shaping']
    name = preset or sh['preset']
    if name not in sh['presets']:
        raise ValueError('unknown shaping preset %r; the config defines %s' % (name, sorted(sh['presets'])))
    p = sh['presets'][name]
    return {'preset': name, 'hold_pps': dict(p['hold_pps']), 'block_pps': dict(p['block_pps']),
            'block_burst': p.get('block_burst')}


def validate_loss_and_scenarios(cfg):
    lc = cfg['loss']
    mr = lc.get('max_recovery_s', 5.0)
    if not isinstance(mr, (int, float)) or isinstance(mr, bool) or mr <= 0:
        raise ValueError('loss.max_recovery_s must be a positive number of seconds')
    for pname, entries in lc.get('presets', {}).items():
        if not entries:
            raise ValueError('loss.presets.%s must list at least one {class, n}' % pname)
        for e in entries:
            if set(e) != {'class', 'n'} or not isinstance(e['n'], int) or isinstance(e['n'], bool):
                raise ValueError('loss.presets.%s: each entry needs exactly class and integer n, got %r' % (pname, e))
            loss.parse_drop('%s:%d' % (e['class'], e['n']), cfg['trials']['reads_per_trial'])
    names = [a['name'] for a in cfg['arms']]
    for sname, sc in cfg.get('scenarios', {}).items():
        if sname != 'reconnect':
            raise ValueError('scenarios.%s: only "reconnect" is implemented' % sname)
        if sc.get('arm') not in names or sc.get('fixture') not in FIXTURES:
            raise ValueError('scenarios.%s needs a configured arm and a fixture from %s' % (sname, FIXTURES))
        off = sc.get('reconnect_port_offset')
        if not isinstance(off, int) or isinstance(off, bool) or off < 1:
            raise ValueError('scenarios.%s.reconnect_port_offset must be an integer >= 1' % sname)
        if cfg['traffic']['master_port_range']['last'] + off > 65535:
            raise ValueError('scenarios.%s: reconnect port would exceed 65535' % sname)


def validate_paired_blocks(cfg):
    names = [a['name'] for a in cfg['arms']]
    for bname, blk in cfg.get('paired_blocks', {}).items():
        where = 'paired_blocks.%s' % bname
        if blk.get('arm') not in names:
            raise ValueError('%s.arm %r is not one of %s' % (where, blk.get('arm'), names))
        if blk.get('fixture') not in FIXTURES:
            raise ValueError('%s.fixture must be one of %s' % (where, FIXTURES))
        pr = blk.get('presets')
        if not (isinstance(pr, list) and len(pr) == 2 and pr[0] != pr[1]
                and all(p in cfg['shaping']['presets'] for p in pr)):
            raise ValueError('%s.presets must be two distinct shaping presets (A, B) from %s'
                             % (where, sorted(cfg['shaping']['presets'])))
        if not isinstance(blk.get('repeats', 1), int) or blk.get('repeats', 1) < 1:
            raise ValueError('%s.repeats must be an integer >= 1' % where)
        if not blk.get('conditions'):
            raise ValueError('%s.conditions must be a non-empty list' % where)
        for cnd in blk['conditions']:
            if set(cnd) != {'delay_ms', 'gap_ms', 'start_delay_ms', 'seed'} or \
                    any(not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in cnd.values()):
                raise ValueError('%s: each condition needs integer delay_ms, gap_ms, start_delay_ms, seed >= 0, got %r'
                                 % (where, cnd))
            if blk['fixture'] == 'separate_ack' and cnd['delay_ms'] < 1:
                raise ValueError('%s: separate_ack needs delay_ms >= 1' % where)


def shaping_args(cfg, burst=True, preset=None):
    """The installer/snapshot shaping flags, always explicit so a run's requested rates are never implicit.
    burst=False for snapshot_counters.py, which records the requested rates but has no --block-burst."""
    sh = resolve_shaping(cfg, preset)
    parts = ['--shape-%s-pps %d' % (r, sh['hold_pps'][r]) for r in ROLES]
    parts += ['--shape-%s-blk-pps %d' % (r, sh['block_pps'][r]) for r in ROLES]
    if burst and sh['block_burst'] is not None:
        parts.append('--block-burst %d' % sh['block_burst'])
    return ' '.join(parts)


def selected_builds(cfg, arms=None, all_builds=False):
    return sorted(cfg['builds'] if all_builds else {a['build'] for a in (cfg['arms'] if arms is None else arms)})


def check_bindings(cfg, arms=None, all_builds=False):
    """Every identity error that must stop a run (empty list = bound). Offline: reads each build's compile
    manifest.json and hashes the files under out_dir. A config hash must be null (filled from the manifest)
    or a 64-hex sha256 equal to the manifest; the files on disk must equal the manifest. A placeholder or
    malformed value is an error, not a warning."""
    errs = []
    for name in selected_builds(cfg, arms, all_builds):
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


def bind_builds(cfg, arms=None):
    """{build: {rel: sha256}} verified against the manifest and the files; raises ValueError listing every
    problem. Null config slots come back filled from the manifest."""
    errs = [e for e in check_bindings(cfg, arms) if not e.startswith('endpoint.')]
    if errs:
        raise ValueError('; '.join(errs))
    out = {}
    for name in selected_builds(cfg, arms):
        want = json.load(open(path_of(cfg['builds'][name]['manifest'])))['artifact_sha256']
        out[name] = {rel: want[rel] for rel in BUILD_HASHED}
    return out


def warnings(cfg):
    """Non-fatal advisories that encode known traps (returned, not raised)."""
    w = []
    fx = cfg['fixture']
    if 'separate_ack' in fx.get('modes', FIXTURES):
        need_ns = int((fx['delay_ms'] + fx.get('readiness_margin_ms', 0)) * 1_000_000)
        if need_ns >= cfg['timing_params_ns']['readiness']:
            w.append('fixture delay %s ms + %s ms margin >= T readiness %d ns: the child response arrives after the '
                     'readiness deadline (or too close to it), so the normal commit/release path cannot be '
                     'observed (defect D). Lower the fixture delay or raise readiness.'
                     % (fx['delay_ms'], fx.get('readiness_margin_ms', 0), cfg['timing_params_ns']['readiness']))
    for bname, blk in cfg.get('paired_blocks', {}).items():
        if blk['fixture'] != 'separate_ack':
            continue
        for cnd in blk['conditions']:
            if int((cnd['delay_ms'] + fx.get('readiness_margin_ms', 0)) * 1_000_000) >= cfg['timing_params_ns']['readiness']:
                w.append('paired_blocks.%s condition delay %d ms + margin >= T readiness: the child response misses '
                         'the readiness deadline (defect D)' % (bname, cnd['delay_ms']))
    return w


class StepFailed(Exception):
    def __init__(self, msg, result=None):
        super().__init__(msg)
        self.result = result


class ShellRunner:
    """The real process boundary: ssh to the switch/Vision, a local subprocess for everything else."""
    dry = False

    def __init__(self, hosts):
        self.hosts = hosts

    def run(self, where, cmd, cwd=None, timeout=3600, label=None):
        detached_ssh = ['-o', 'BatchMode=yes', '-o', 'IdentityAgent=none',
                        '-o', 'ControlMaster=no', '-o', 'ControlPath=none']
        argv = ['ssh'] + detached_ssh + [self.hosts[where], cmd] if where in ('switch', 'vision') \
            else shlex.split(cmd)
        if argv and argv[0] == 'scp':
            argv[1:1] = detached_ssh
        try:
            p = subprocess.run(argv, capture_output=True, text=True, cwd=cwd, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            def partial(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
            return Result(124, partial(error.stdout), partial(error.stderr) + '\ntimed out after %ds' % timeout)
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


def switch_tools():
    """[(local path, name)]: every tool the campaign runs on the switch, deployed into <switch_remote_dir>/aux."""
    fw = os.path.join(ARCH, '..', 'framework', 'control')
    return [(os.path.join(fw, 'restore_ports.py'), 'restore_ports.py'),
            (os.path.join(fw, 'live_snapshot.py'), 'live_snapshot.py'),
            (os.path.join(HERE, 'observe_program.py'), 'observe_program.py'),
            (os.path.join(HERE, 'switch_slot.py'), 'switch_slot.py'),
            (os.path.join(HERE, '..', 'response_path_cp.py'), 'response_path_cp.py'),
            (os.path.join(HERE, 'switch_swap.sh'), 'switch_swap.sh'),
            (os.path.join(HERE, 'launch_composite.sh'), 'launch_composite.sh')]


def installer_sources():
    """[local path]: the installer source files deployed to <switch_remote_dir>/src at their repo-relative path
    (rsync -R from case4_architecture), so `import X` resolves on the switch exactly as in the repo. hw/ goes whole."""
    ro = os.path.join(ARCH, RESPONSE_ONLY)
    return [os.path.join(ro, 'cp.py'), os.path.join(ro, 'port_map.py'), os.path.join(ro, 'check_mirror_select.py'),
            os.path.join(ARCH, 'protocol', 'response_path_cp.py')]


def installer_hw_files():
    hw = os.path.join(ARCH, RESPONSE_ONLY, 'hw')
    return sorted(os.path.join(hw, f) for f in os.listdir(hw) if f.endswith('.py'))


class Campaign:
    def __init__(self, cfg, runner_, run_id, arms=None, installer_flags=None, out=print, fixtures=None, paired=None,
                 loss=None, scenario=None, reconnect_policy=None, config_path=None):
        self.cfg, self.rn, self.run_id, self.out = cfg, runner_, run_id, out
        self.installer_has = installer_flags or (lambda flag: default_installer_flags(flag))
        names = [a['name'] for a in cfg['arms']]
        want = arms or names
        unknown = [n for n in want if n not in names]
        if unknown:
            raise ValueError('unknown arm(s) %s; the config defines %s' % (unknown, names))
        self.paired = paired
        self.loss_preset, self.scenario = loss, scenario
        self.reconnect_policy = reconnect_policy or cfg.get('scenarios', {}).get('reconnect', {}).get('policy', 'characterize')
        if self.reconnect_policy not in ('characterize', 'protected'):
            raise ValueError('reconnect policy must be characterize or protected')
        self.config_sha256 = hashlib.sha256(json.dumps(cfg, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.config_file_sha256 = sha256_file(config_path) if config_path else None
        self.runner_identity = {name: sha256_file(os.path.join(HERE, name)) for name in
                                ('campaign.py', 'checks.py', 'vision_run.py', 'clrt_check.py', 'wire_check.py',
                                 'hold_check.py', 'read_classes.py')}
        self.soft_failures = []
        if loss is not None and loss not in cfg['loss'].get('presets', {}):
            raise ValueError('unknown loss preset %r; the config defines %s' % (loss, sorted(cfg['loss'].get('presets', {}))))
        if scenario is not None:
            if 'sbo_cycles' in cfg['traffic']:
                raise ValueError('scenario %r is not supported with traffic.sbo_cycles (unsupported shape)' % scenario)
            if 'read_schedule' in cfg['traffic']:
                raise ValueError('scenario %r is not supported with traffic.read_schedule (unsupported shape)' % scenario)
            if scenario not in cfg.get('scenarios', {}):
                raise ValueError('unknown scenario %r; the config defines %s' % (scenario, sorted(cfg.get('scenarios', {}))))
            want = [cfg['scenarios'][scenario]['arm']]
        if paired is not None:
            if paired not in cfg.get('paired_blocks', {}):
                raise ValueError('unknown paired block %r; the config defines %s'
                                 % (paired, sorted(cfg.get('paired_blocks', {}))))
            want = [cfg['paired_blocks'][paired]['arm']]
        self.arms = [a for a in cfg['arms'] if a['name'] in want]
        modes = cfg['fixture']['modes']
        self.fixtures = ([cfg['paired_blocks'][paired]['fixture']] if paired is not None else
                         [cfg['scenarios'][scenario]['fixture']] if scenario is not None else (fixtures or list(modes)))
        bad = [f for f in self.fixtures if f not in modes and paired is None]
        if bad:
            raise ValueError('unknown or unconfigured fixture(s) %s; fixture.modes is %s' % (bad, modes))
        self.R = cfg['hosts']['switch_remote_dir']
        self.V = cfg['hosts'].get('vision_run_dir', '/home/decps/pad58b_20261011')
        self.prerun = '%s/snap/%s_prerun.json' % (self.R, run_id)
        self.root = os.path.join(path_of(cfg['evidence_dir']), run_id)
        self.record = {'run_id': run_id, 'ok': False, 'failure': None, 'arms': [], 'restore': [], 'bringups': [], 'collections': []}
        self.switch_touched = False
        self.standing = []            # manifests of installs not yet torn down
        self.vision_touched = False

    def standards_context(self, trial, arm, connection_id=None, unbound_native=False):
        build = self.cfg['builds'].get(arm['build'], {})
        return {
            'config': self.cfg,
            'run_record': dict(self.record, run_id=self.run_id, config_sha256=self.config_sha256,
                               builds=getattr(self, 'bound', None) or {}),
            'trial': trial,
            'connection_id': connection_id or 'primary',
            'arm': arm,
            'candidate_source_sha256': build.get('source_sha256') or build.get('strict_source_sha256'),
            'checker_files': [os.path.join(HERE, name) for name in
                              ('wire_check.py', 'clrt_check.py', 'checks.py', 'standards.py',
                               'capture_boundary.py', 'hold_check.py', 'read_classes.py')] + [CHECK_CAPTURE] + [
                                   os.path.join(os.path.dirname(CHECK_CAPTURE), name)
                                   for name in ('capture.py', 'dnp3_std.py', 'profile_check.py')],
            'unbound_native': unbound_native,
            'packet_boundary_required': bool(build.get('profile') == 'candidate61' or
                                             build.get('packet_boundary_required') or
                                             self.cfg.get('standards', {}).get('packet_boundary_required')),
        }

    def precision_required(self, arm, fixture):
        """The trial claims a READ timing target: timed arm, separate-ACK fixture, precision enabled."""
        return bool(arm.get('T') and fixture == 'separate_ack' and
                    self.cfg.get('evaluation', {}).get('read_precision', True))

    def hold_analyzer(self, out_pcap, in_pcap, master_port, outstation_port):
        """The validator's recomputation of the OPERATE hold from the bound captures (hold_check.analyze)."""
        import hold_check
        return hold_check.analyze(out_pcap, in_pcap, master_port, outstation_port)

    def objective_blocks(self, trial, arm, observed, exempt=None, connection_id=None, unbound_native=False):
        """observed.objectives for the standards artifact: SELECT/OPERATE precision, piggyback latency and the
        OPERATE hold, each required exactly when standards.objective_requirements says so for this trial's
        context (the validator re-derives the same requirement). exempt: a code-path declaration (loss, reconnect)
        that the trial evaluates none of them; an objective the build/arm/fixture would require is then recorded
        exempted, and the trial is measurement_only at best."""
        context = self.standards_context(trial, arm, connection_id, unbound_native)
        context['objectives_exempt'] = exempt
        purpose = self.cfg.get('evaluation', {}).get('purpose', 'qualification')
        bounds = standards.objective_bounds(self.cfg)
        return {name: standards.objective_block(name, required, (observed or {}).get(name), purpose, reason, bounds,
                                                exempted)
                for name, (required, reason, exempted) in standards.objective_requirements(context).items()}

    def standards_observed(self, ev, failures, *, transport_ok, select_ok, operate_ok, aggregate_ok,
                           precision_required, precision=None, precision_reason=None, checker_result=None,
                           objectives=None):
        # The timing objectives (READ precision and checks.OBJECTIVE_PREFIXES) are gated by their own failure
        # entries (soft in timing characterization); they are not standards properties, so an objective-only
        # failure must not re-enter here as a hard standards failure. They are serialized separately as
        # observed.precision and observed.objectives and drive the qualification verdict.
        if failures and all(str(f).startswith(checks.OBJECTIVE_PREFIXES) for f in failures):
            failures, aggregate_ok = [], True
        purpose = self.cfg.get('evaluation', {}).get('purpose', 'qualification')
        observed = {
            'timing': ev.get('timing'),
            'checker_result': checker_result,
            'failures': failures,
            'transport_ok': transport_ok,
            'select_authorizes_operate': select_ok,
            'operate_success': operate_ok,
            'aggregate_verdict': aggregate_ok,
            'precision': standards.precision_block(precision_required, precision, purpose, precision_reason),
        }
        if objectives is not None:        # None: a caller that evaluates no objectives keeps the pre-objective shape
            observed['objectives'] = objectives
        return observed

    def standards_captures(self, dest, captures):
        merged = dict(captures or {})
        boundary_files = {
            'capture_offloads': 'capture_offloads.json',
            'calibration_expected': 'calibration_expected.json',
            'calibration_in': 'calibration_in.pcap',
            'calibration_out': 'calibration_out.pcap',
            'calibration_result': 'calibration_result.json',
            'run_result': 'result.json',
            'hold': 'hold.json',          # hold_check output, hashed into the artifact's capture identity
        }
        for name, filename in boundary_files.items():
            path = os.path.join(dest, filename)
            if os.path.exists(path):
                merged[name] = {'path': path}
        return merged

    def qualify_capture_arg(self, arm):
        build = self.cfg.get('builds', {}).get(arm.get('build'), {})
        required = (build.get('profile') == 'candidate61' or build.get('packet_boundary_required') or
                    self.cfg.get('standards', {}).get('packet_boundary_required'))
        return ' --qualify-capture' if required else ''

    def _load_standards_checker(self):
        spec = importlib.util.spec_from_file_location('dnp3_standards_check_capture', CHECK_CAPTURE)
        module = importlib.util.module_from_spec(spec)
        sys.path.insert(0, os.path.dirname(CHECK_CAPTURE))
        try:
            spec.loader.exec_module(module)
        finally:
            try:
                sys.path.remove(os.path.dirname(CHECK_CAPTURE))
            except ValueError:
                pass
        return module

    def run_standards_checker(self, dest, trial, arm, connection_id=None, unbound_native=False, master_port=None):
        master_port = master_port if master_port is not None else trial.get('master_port')
        context = self.standards_context(trial, arm, connection_id, unbound_native)
        expected = standards.expected_identity(context)['expected']
        lengths = {kind: values[0] for kind, values in expected['lengths'].items()}
        per_class = {'read_classes': expected['read_classes']} if 'read_classes' in expected else {}
        try:
            raw = self._load_standards_checker().check(
                dest,
                outstation_port=self.cfg['endpoints']['outstation_port'],
                master_port=master_port,
                expected_lengths=lengths,
                require_handshake=True, **per_class)
        except SystemExit as error:
            raw = {'conformant': False, 'failures': ['SystemExit: %s' % error],
                   'verdicts': [], 'run_dir': dest}
        except Exception as error:
            raw = {'conformant': False, 'failures': [str(error)], 'verdicts': [], 'run_dir': dest}
        result = dict(raw)
        result['require_handshake'] = True
        result['outstation_port'] = self.cfg['endpoints']['outstation_port']
        result['master_port'] = master_port if master_port is not None else result.get('master_port')
        result['expected_lengths'] = expected['lengths']
        result['expected_counts'] = expected['counts']
        if per_class:
            result['expected_read_classes'] = expected['read_classes']
        result['raw_result'] = raw
        result['result_sha256'] = hashlib.sha256(
            json.dumps(raw, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()
        return result

    def validate_standards_file(self, dest, trial, arm, captures, observed, connection_id=None, unbound_native=False,
                                precision_exempt=None, master_port=None, objectives_exempt=None):
        """precision_exempt: a code-path declaration (e.g. a loss trial) that this trial claims no READ timing
        target although its arm is timed; the validator derives the requirement from this context, not from the
        artifact. master_port: the commanded port (default the trial's), which the profile verdict must match."""
        if self.rn.dry:
            return []
        context = self.standards_context(trial, arm, connection_id, unbound_native)
        if (observed or {}).get('objectives') is None:
            # a runner that evaluates no timing objectives (rearm_01 external/isolation/series): the artifact is
            # still v3, with every objective the build would claim recorded exempted (measurement_only at best)
            objectives_exempt = objectives_exempt or RUNNER_OBJECTIVES_EXEMPT
            observed = dict(observed or {}, objectives=self.objective_blocks(
                trial, arm, None, objectives_exempt, connection_id, unbound_native))
        context['precision_exempt'] = precision_exempt
        context['objectives_exempt'] = objectives_exempt
        context['master_port'] = master_port if master_port is not None else trial.get('master_port')
        captures = self.standards_captures(dest, captures)
        artifact = standards.build_standards_artifact(context, captures, observed)
        path = os.path.join(dest, 'standards.json')
        with open(path, 'w') as f:
            json.dump(artifact, f, indent=1, default=str)
        result = standards.validate_standards(path, context, captures, hold_analyzer=self.hold_analyzer)
        failures = ['standards: ' + failure for failure in result['failures']]
        if standards.profile_required(context):
            profile = self.validate_profile_file(dest, context, captures, artifact['expected']['lengths'],
                                                 context['master_port'])
            result['profile'] = profile
            failures += ['profile: ' + failure for failure in profile['failures']]
            if not profile['ok']:
                result['qualification'] = 'rejected'
        if result.get('qualification') == 'rejected' and not failures:
            # conformant, but the timing claim is not supported (e.g. missing precision evidence): never silent
            blocks = [result.get('precision') or {}] + list(((observed or {}).get('objectives') or {}).values())
            reasons = [r for b in blocks if isinstance(b, dict) and b.get('status') != 'pass'
                       for r in (b.get('reasons') or []) if b.get('status') != 'not_applicable']
            failures.append('qualification: rejected: %s' % '; '.join(reasons or ['precision status fail']))
        with open(os.path.join(dest, 'standards_verdict.json'), 'w') as f:
            json.dump(result, f, indent=1, default=str)
        trial.setdefault('qualification', {})[connection_id or 'trial'] = result.get('qualification')
        return failures

    def validate_profile_file(self, dest, context, captures, lengths, master_port):
        """Every response attempt against the exact candidate61 (or native) image, bound to this trial."""
        checker = os.path.join(os.path.dirname(CHECK_CAPTURE), 'profile_check.py')
        try:
            module = self._load_profile_checker()
            classes = standards.expected_identity(context)['expected'].get('read_classes')
            raw = module.check(dest, master_port, lengths, self.cfg['endpoints']['outstation_port'],
                               **({'read_classes': classes} if classes is not None else {}))
        except Exception as error:                        # fail closed; the run still restores
            raw = {'conformant': False, 'failures': ['profile checker error: %s' % error]}
        path = os.path.join(dest, 'profile_verdict.json')
        with open(path, 'w') as f:
            json.dump(standards.build_profile_artifact(context, captures, raw, checker), f, indent=1, default=str)
        return standards.validate_profile(path, context, captures, checker)

    def _load_profile_checker(self):
        path = os.path.join(os.path.dirname(CHECK_CAPTURE), 'profile_check.py')
        spec = importlib.util.spec_from_file_location('dnp3_profile_check', path)
        module = importlib.util.module_from_spec(spec)
        sys.path.insert(0, os.path.dirname(CHECK_CAPTURE))
        try:
            spec.loader.exec_module(module)
        finally:
            try:
                sys.path.remove(os.path.dirname(CHECK_CAPTURE))
            except ValueError:
                pass
        return module

    # ---- groups, gates, bound identity ------------------------------------------------------------------
    def _padded_suffix(self, arm, cls=None):
        """'@LEN' for builds whose padded response is not 58 octets (loss.parse_drop), else ''. A READ drop class
        uses the build's read_image_len when its READ image differs from the control image."""
        build = self.cfg['builds'][arm['build']]
        image = build.get('image_len', 58)
        read = read_classes.range_image_len(build, image)      # read_images['range'], else read_image_len
        if cls is not None and (str(cls).startswith('read_') or str(cls).startswith('master_ack')):
            image = read          # a READ class, or the master's ACK of the first padded frontier (a READ)
        elif cls is not None and read != image and str(cls).endswith('_resp_padded'):
            return '@%d/%d' % (image, read)
        return '' if image == 58 else '@%d' % image

    def units(self):
        """[unit dict]: one cold bring-up and one connection each, with its own recorded conditions.
        per_trial_cold: every trial of every arm (fixture-major); one_connection: one per arm carrying all of its
        READs. A paired block instead lists, per condition and repeat, presets A and B under IDENTICAL conditions,
        the order alternating between consecutive pairs."""
        c, t = self.cfg, self.cfg['trials']
        out = []
        base = {'delay_ms': c['fixture']['delay_ms'], 'gap_ms': c['traffic']['gap_ms'],
                'start_delay_ms': c['traffic'].get('start_delay_ms', 0)}
        if self.paired is not None:
            blk = c['paired_blocks'][self.paired]
            arm = self.arms[0]
            pair = 0
            for _rep in range(blk.get('repeats', 1)):
                for cnd in blk['conditions']:
                    order = list(blk['presets']) if pair % 2 == 0 else list(reversed(blk['presets']))
                    for preset in order:
                        out.append({'fixture': blk['fixture'], 'arm': arm, 'i': len(out), 'reads': t['reads_per_trial'],
                                    'preset': preset, 'pair': pair, 'order': order, 'condition': dict(cnd),
                                    'delay_ms': cnd['delay_ms'], 'gap_ms': cnd['gap_ms'],
                                    'start_delay_ms': cnd['start_delay_ms'], 'start_seed': cnd['seed']})
                    pair += 1
            return out
        if self.loss_preset is not None or self.scenario is not None:
            for fx in self.fixtures:
                for arm in self.arms:
                    i = 0
                    entries = ([None] if self.scenario else c['loss']['presets'][self.loss_preset])
                    for e in entries:
                        out.append(dict(base, fixture=fx, arm=arm, i=i, preset=None, pair=None, reads=t['reads_per_trial'],
                                        start_seed=c['seeds']['rng_seed'] + len(out),
                                        drop=('%s:%d' % (e['class'], e['n']) + self._padded_suffix(arm, e['class'])) if e else None,
                                        scenario=self.scenario))
                        i += 1
            return out
        one = c['trial_mode'] == 'one_connection'
        for fx in self.fixtures:
            for arm in self.arms:
                for i in range(1 if one else t['trials_per_arm']):
                    out.append(dict(base, fixture=fx, arm=arm, i=i, preset=None, pair=None,
                                    reads=t['reads_per_trial'] * (t['trials_per_arm'] if one else 1),
                                    start_seed=c['seeds']['rng_seed'] + len(out)))
        return out

    def label(self, unit):
        """The run label (and Vision run directory name) of a unit; unique within a campaign and, through the
        run id, across campaigns."""
        return '%s_%s_%s_t%d' % (self.run_id, unit['fixture'], unit['arm']['name'], unit['i'])

    def ports(self):
        pr = self.cfg['traffic']['master_port_range']
        return list(range(pr['first'], pr['last'] + 1))

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
        errs = check_bindings(self.cfg, self.arms) + self.blocked()
        labels = [self.label(u) for u in self.units()]
        if len(set(labels)) != len(labels):
            errs.append('run labels are not unique (a Vision run directory cannot be reused)')
        if os.path.exists(self.root):
            errs.append('evidence directory %s already exists; use a new --run-id' % self.root)
        if len(self.units()) > len(self.ports()):
            errs.append('%d connections need %d distinct master ports but traffic.master_port_range has %d'
                        % (len(self.units()), len(self.units()), len(self.ports())))
        return errs

    # ---- step plumbing ------------------------------------------------------------------------------------
    def step(self, where, label, cmd, cwd=None, check=True, timeout=3600):
        r = self.rn.run(where, cmd, cwd=cwd, timeout=timeout, label=label)
        if not self.rn.dry:
            self.out('[%s] %s -> rc %d' % (where, label, r.rc))
        if check and r.rc != 0:
            raise StepFailed('%s failed (rc %d) on %s: %s | %s' % (label, r.rc, where, cmd[:300],
                                                                   (r.err or r.out)[-400:].strip()), r)
        return r

    def switch_cmd(self, script, args):
        return 'python3 %s/%s/%s %s' % (self.R, HW, script, args)

    def hw_env(self, cmd):
        return 'DEFENSE4_HW_AUTHORIZED=1 ' + cmd

    def endpoint_controls(self):
        controls = {key: self.cfg['traffic'].get(key, default) for key, default in
                    (('read_pause_ms', 25), ('run_sbo', True), ('close_grace_ms', 0))}
        if 'sbo_cycles' in self.cfg['traffic']:          # only the repeated-SBO endpoint knows this control
            controls['sbo_cycles'] = self.cfg['traffic']['sbo_cycles']
        for key in ('read_schedule', 'db'):               # only the read-schedule endpoint knows these
            if key in self.cfg['traffic']:
                controls[key] = self.cfg['traffic'][key]
        return controls

    def endpoint_control_args(self):
        return ''.join(' --%s %s' % (key.replace('_', '-'), value if isinstance(value, str) else int(value))
                       for key, value in self.endpoint_controls().items())

    def endpoint_binary_name(self):
        """The endpoint file on Vision: endpoint.binary when configured, else the pad58b endpoint."""
        return self.cfg['endpoint'].get('binary', os.path.basename(vr.BIN))

    def endpoint_binary_arg(self):
        return ' --endpoint-binary %s' % q(self.cfg['endpoint']['binary']) if 'binary' in self.cfg['endpoint'] else ''

    def read_policy_arg(self, trial, arm):
        """clrt_check --read-policy for a build with a per-class READ declaration, else ''."""
        expectation = standards.read_class_expectations(self.cfg, arm, trial)
        if expectation is None:
            return ''
        return ' --read-policy %s' % q(json.dumps({'classes': expectation['classes']}, sort_keys=True,
                                                    separators=(',', ':')))

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
            self.bound = bind_builds(self.cfg, self.arms)
        except ValueError:
            if not dry:
                raise
            self.bound = {n: {r: (self.cfg['builds'][n]['hashes'].get(r) or '<UNBOUND>') for r in BUILD_HASHED}
                          for n in {a['build'] for a in self.arms}}
        if not dry:
            os.makedirs(self.root)
        failed = False
        try:
            self.deploy()
            self.switch_toolkit()
            self.vision_setup()
            current = None
            for unit, port in zip(self.units(), self.ports()):
                key = (unit['fixture'], unit['delay_ms'])
                if key != current:
                    self.set_fixture(unit['fixture'], unit['delay_ms'])
                    current = key
                self.run_unit(unit, port)
        except (StepFailed, ValueError, OSError) as e:
            failed = True
            self.record['failure'] = str(e)
            sys.stderr.write('CAMPAIGN FAILED: %s\n' % e)
        finally:
            restore_ok = self.restore()
            self.finish(dry)
        self.record['ok'] = (not failed) and restore_ok and not self.soft_failures
        if self.soft_failures:
            self.record['soft_failures'] = self.soft_failures
        # record['ok'] keeps its strict meaning; gate_ok says the block passed every gate it is configured to apply
        precision_reported = (not failed) and restore_ok and bool(self.soft_failures) and \
            precision_only_soft(self.record, self.cfg.get('evaluation', {}))
        self.record['gate_ok'] = bool(self.record['ok'] or precision_reported)
        if precision_reported:
            self.record['host_precision_reported_not_gated'] = True
        if not dry:
            self.finish(dry)
        return 0 if self.record['gate_ok'] else 1

    def vision_identity(self):
        """Read-only identity checks on Vision (the only change is copying vision_run.py)."""
        ep, V = self.cfg['endpoint'], self.V
        files = ('vision_run.py', 'loss.py', 'capture_observation.py', 'wire_check.py')
        self.step('local', 'deploy Vision run/capture helpers to Vision',
                  'scp -q %s %s:%s/' % (' '.join(q(os.path.join(HERE, f)) for f in files),
                                        self.cfg['hosts']['vision'], V))
        r = self.step('vision', 'verify deployed Vision helper sha256 values',
                      'sha256sum ' + ' '.join('%s/%s' % (V, f) for f in files))
        if not self.rn.dry:
            got = {l.split()[1].rsplit('/', 1)[-1]: l.split()[0] for l in r.out.splitlines() if len(l.split()) == 2}
            for f in files:
                want = sha256_file(os.path.join(HERE, f))
                if got.get(f) != want:
                    raise StepFailed('%s on Vision has sha256 %s, expected %s' % (f, got.get(f), want))
        binary, lib = V + '/' + self.endpoint_binary_name(), V + '/lib'
        r = self.step('vision', 'verify the endpoint binary identity', 'sha256sum %s' % q(binary))
        self.check_hash(r, ep['binary_sha256'], 'endpoint binary %s' % binary)
        r = self.step('vision', 'verify the endpoint lib/ identity',
                      'cd %s && find . -type f | sort | xargs sha256sum | sha256sum' % lib)
        self.check_hash(r, ep['lib_sha256'], 'endpoint lib %s' % lib)
        labels = [self.label(u) for u in self.units()]
        self.step('vision', 'no run directory for any of these labels may exist yet (vision_run refuses to reuse one)',
                  'for l in %s; do test ! -e %s/runs/$l || { echo "EXISTS $l"; exit 1; }; done'
                  % (' '.join(labels), self.V))
        helper_hashes = {f: sha256_file(os.path.join(HERE, f)) for f in files}
        self.record['endpoint_observed'] = {'binary_sha256': ep['binary_sha256'], 'lib_sha256': ep['lib_sha256'],
                                            'binary_path': binary, 'lib_path': lib,
                                            'vision_helper_sha256': helper_hashes,
                                            'vision_run_sha256': helper_hashes['vision_run.py'],
                                            'loss_sha256': helper_hashes['loss.py']}

    def deploy_switch(self):
        """Copy every tool and build into the configured switch directory and verify each tool's sha256 there.
        Nothing the campaign runs lives anywhere else."""
        c, R, host = self.cfg, self.R, self.cfg['hosts']['switch']
        aux = R + '/aux'
        self.step('switch', 'make remote directories', 'mkdir -p %s %s/src %s/snap' % (aux, R, R))
        tools = switch_tools()
        self.step('local', 'copy the switch tools (ports, snapshot, observe, relay slot, swap/launch) into aux',
                  'scp -q %s %s:%s/' % (' '.join(q(p) for p, _n in tools), host, aux))
        rel = [os.path.relpath(p, ARCH) for p in installer_sources()]
        self.step('local', 'copy the installer source tree to the switch (repo-relative paths)',
                  'rsync -aR --exclude __pycache__ %s %s/hw %s:%s/src/' % (' '.join(rel), RESPONSE_ONLY, host, R),
                  cwd=ARCH)
        for build in sorted({a['build'] for a in self.arms}):
            self.step('local', 'copy build %s out/ to the switch' % build, 'rsync -a %s/ %s:%s/'
                      % (q(path_of(c['builds'][build]['out_dir'])), host, '%s/out_%s' % (R, build)))
        src = [(p, '%s/src/%s' % (R, os.path.relpath(p, ARCH))) for p in installer_sources() + installer_hw_files()]
        want = [(p, '%s/%s' % (aux, n)) for p, n in tools] + src
        r = self.step('switch', 'verify every deployed tool and installer source file by sha256',
                      'sha256sum ' + ' '.join(remote for _p, remote in want))
        if not self.rn.dry:
            got = {l.split()[1]: l.split()[0] for l in r.out.splitlines() if len(l.split()) == 2}
            for path, remote in want:
                if got.get(remote) != sha256_file(path):
                    raise StepFailed('deployed %s on the switch has sha256 %s, expected %s'
                                     % (remote, got.get(remote), sha256_file(path)))

    def deploy(self):
        self.vision_identity()
        self.deploy_switch()

    def deploy_only(self):
        """The `deploy` mode: put the tools in place and verify them; changes no switch or Vision state."""
        try:
            errs = check_bindings(self.cfg, self.arms)
            if errs and not self.rn.dry:
                raise StepFailed('refusing to deploy, unbound identity: %s' % '; '.join(errs))
            self.deploy()
            return 0
        except (StepFailed, OSError) as e:
            sys.stderr.write('DEPLOY FAILED: %s\n' % e)
            return 1

    def switch_toolkit(self):
        """Observe (read-only) which program is running, refuse unless it is the configured production program,
        and snapshot its $PORT table for every later replay."""
        c, R, host = self.cfg, self.R, self.cfg['hosts']['switch']
        aux = R + '/aux'
        prod = c['production']
        r = self.step('switch', 'observe the running program (read-only, from ps)',
                      'python3 %s/observe_program.py' % aux)
        observed = prod['program']
        if not self.rn.dry:
            try:
                observed = json.loads([l for l in r.out.splitlines() if l.startswith('{')][-1])['program']
            except (IndexError, ValueError, KeyError):
                raise StepFailed('cannot read the running program from observe_program.py: %s' % (r.out + r.err)[-300:])
            self.record['pre_run_program'] = observed
            if observed != prod['program']:
                raise StepFailed('refusing: the switch is running program %r but the configured production program '
                                 'is %r; nothing was changed' % (observed, prod['program']))
        self.step('switch', 'snapshot the running program\'s $PORT table (read-only) for every later replay',
                  'python3 %s/live_snapshot.py %s %s' % (aux, observed, self.prerun))
        self.step('local', 'copy the pre-run snapshot back',
                  'scp -q %s:%s %s/' % (host, self.prerun, q(self.root)), check=not self.rn.dry)

    def vision_setup(self):
        V = self.V
        self.vision_touched = True
        self.step('vision', 'namespace TCP profile and NIC source-pruning (snapshots prior state)',
                  'sudo python3 %s/vision_run.py setup' % V)

    def set_fixture(self, fixture, delay_ms):
        """separate_ack: the emulated relay (separate ACK, delayed response); piggyback: fixture off."""
        if fixture == 'separate_ack':
            jitter = self.cfg['fixture'].get('jitter_ms', 0)
            spread = (' --jitter-ms %d --distribution %s' % (jitter, self.cfg['fixture']['distribution'])
                      if jitter else '')
            self.step('vision', 'fixture separate_ack: casea on, response delayed %d ms%s' % (delay_ms, spread),
                      'sudo python3 %s/vision_run.py casea on --delay-ms %d%s' % (self.V, delay_ms, spread))
        else:
            self.step('vision', 'fixture piggyback: casea off (ACK rides on the response)',
                      'sudo python3 %s/vision_run.py casea off' % self.V)

    def check_hash(self, result, want, what):
        if self.rn.dry:
            return
        got = (result.out.split() or ['<none>'])[0]
        if got != want:
            raise StepFailed('%s: sha256 %s does not match the pinned %s' % (what, got, want))

    def arm_record(self, fixture, arm):
        for rec in self.record['arms']:
            if rec['arm'] == arm['name'] and rec['fixture'] == fixture:
                return rec
        rec = {'fixture': fixture, 'arm': arm['name'], 'T': arm['T'], 'padding': arm['padding'], 'build': arm['build'], 'trials': [],
               'achieved_shaping': None}
        self.record['arms'].append(rec)
        return rec

    def run_unit(self, unit, port):
        """One cold bring-up and one connection: swap, ports, install, T, snapshot, traffic, then ALWAYS the
        collection phase (after snapshot, teardown, logs, manifest, endpoint outputs), then the verdict."""
        c, R = self.cfg, self.R
        fixture, arm, i, reads, preset = unit['fixture'], unit['arm'], unit['i'], unit['reads'], unit['preset']
        aux, build, tr = R + '/aux', arm['build'], c['traffic']
        b = c['builds'][build]
        n, out_remote = arm['name'], '%s/out_%s' % (R, build)
        label = self.label(unit)
        conf = '%s/response_only_hw_%s.conf' % (R, label)
        manifest, log = '%s/bringup_manifest_%s.json' % (R, label), '%s/switchd_%s.log' % (R, label)
        rec = self.arm_record(fixture, arm)
        trial = {'fixture': fixture, 'label': label, 'master_port': port, 'reads': reads, 'ok': False, 'failures': [],
                 'max_token_stale': checks.max_token_stale(b), 'reconnect_policy': self.reconnect_policy,
                 'diagnostic': b.get('diagnostic', False),
                 'preset': preset or c['shaping']['preset'],
                 'conditions': {k: unit[k] for k in ('delay_ms', 'gap_ms', 'start_delay_ms', 'start_seed')}}
        rec['trials'].append(trial)
        pair = None
        if unit['pair'] is not None:
            pairs = self.record.setdefault('pairs', [])
            if not pairs or pairs[-1]['pair'] != unit['pair']:
                pairs.append({'pair': unit['pair'], 'condition': unit['condition'], 'order': unit['order'],
                              'labels': [], 'ok': False})
            pair = pairs[-1]
            pair['labels'].append(label)
        dest = os.path.join(self.root, fixture, n, label)
        if not self.rn.dry:
            os.makedirs(os.path.join(dest, 'snapshots'))
        err, v, state = None, None, {'installed': False, 'ran': False, 'before': False, 'after': False}
        try:
            self.step('switch', '%s: PCI vendor must be Barefoot/Intel (0x1d1c)' % label,
                      'test "$(cat /sys/bus/pci/devices/%s/vendor)" = 0x1d1c' % b['pcie'])
            self.step('switch', '%s: make the bf_switchd conf for this build' % label,
                      'python3 %s/%s/make_conf.py %s --remote-dir %s --pcie %s -o %s'
                      % (R, HW, out_remote, out_remote, b['pcie'], conf))
            self.switch_touched = True
            self.step('switch', '%s: cold-swap bf_switchd to the composite (stop, launch, wait for :50052)' % label,
                      'bash %s/switch_swap.sh %s %s/launch_composite.sh %s %s' % (aux, log, aux, conf, b['sde']))
            self.step('switch', '%s: replay the pre-run $PORT snapshot' % label,
                      'python3 %s/restore_ports.py %s %s --apply --wait 35' % (aux, c['program'], self.prerun))
            comp = self.installer_cmd(build, arm['padding'], out_remote, port, preset)
            self.step('switch', '%s: composite install dry-run (hash check, name check, ports it will loop)' % label,
                      comp)
            self.standing.append(manifest)
            state['installed'] = True
            r = self.step('switch', '%s: composite install apply (loopback first, apps enabled last)' % label,
                          self.hw_env(comp + ' --apply --enable-pktgen --manifest-out %s' % manifest))
            self.save(dest, 'install.log', r)
            self.record['bringups'].append({'label': label, 'fixture': fixture, 'arm': n, 'trial': i,
                                            'master_port': port, 'padding': arm['padding'], 'T': arm['T'],
                                            'manifest': manifest})
            self.step('switch', '%s: select T (0=Timing OFF, 1=Obfuscated)' % label, self.hw_env(self.switch_cmd(
                'set_enabled.py', '--manifest %s --enabled %d' % (manifest, arm['T']))))
            self.snapshot(out_remote, label + '_before', preset=preset)
            state['before'] = True
            state['ran'] = True
            v = self.step('vision', '%s: traffic + capture on master port %d' % (label, port),
                          runner.vision_cmd(label, port, reads, tr['range'], unit['gap_ms'], unit['start_delay_ms'],
                                            unit['start_seed'], drop=unit.get('drop'), scenario=unit.get('scenario'),
                                            reconnect_port=(port + c['scenarios'][unit['scenario']]['reconnect_port_offset']
                                                            if unit.get('scenario') else None)
                                            ).replace(runner.V_RUN, self.V) + self.endpoint_control_args()
                          + self.endpoint_binary_arg() + self.qualify_capture_arg(arm), check=False)
            self.save(dest, 'vision_run.out', v)
            state['after'] = True
            self.snapshot(out_remote, label + '_after', check=False, preset=preset)
        except (StepFailed, OSError) as e:
            err = e
            if isinstance(e, StepFailed) and e.result is not None:
                self.save(dest, 'install.log' if state['installed'] and not state['before'] else 'failed_step.log',
                          e.result)
        self.collect_unit(label, dest, out_remote, manifest, log, state, preset)
        if err is not None:
            raise err
        if unit.get('scenario'):
            self.verdict_scenario(trial, label, dest, v, arm)
        elif unit.get('drop'):
            self.verdict_loss(trial, rec, label, dest, v, arm, fixture, unit, port)
        else:
            self.verdict(trial, rec, label, dest, v, arm, fixture)
        if pair is not None:
            pair['ok'] = len(pair['labels']) == 2 and all(
                t['ok'] for a in self.record['arms'] for t in a['trials'] if t['label'] in pair['labels'])

    def save(self, dest, name, result):
        """Write a command's captured output next to the evidence (local, best effort)."""
        if self.rn.dry or result is None:
            return
        try:
            with open(os.path.join(dest, name), 'w') as f:
                f.write(result.out + ('\n--- stderr ---\n' + result.err if result.err else ''))
        except OSError:
            pass

    def collect(self, label, what, where, cmd):
        """One independent best-effort collection step, recorded with ok/error whatever happens."""
        entry = {'unit': label, 'what': what, 'ok': False, 'error': None}
        try:
            r = self.rn.run(where, cmd, timeout=900, label='%s: collect %s' % (label, what))
            entry['ok'] = r.rc == 0
            if r.rc != 0:
                entry['error'] = 'rc %d: %s' % (r.rc, (r.err or r.out)[-300:].strip())
        except Exception as e:
            entry['error'] = '%s: %s' % (type(e).__name__, e)
        self.record['collections'].append(entry)
        if not self.rn.dry and not entry['ok']:
            sys.stderr.write('COLLECTION FAILED: %s %s: %s\n' % (label, what, entry['error']))
        return entry

    def collect_unit(self, label, dest, out_remote, manifest, log, state, preset=None):
        """Runs after success AND failure, before any restore: tear the install down (output kept), then fetch
        everything the unit produced. Every step is independent of the others."""
        R, host, vhost = self.R, self.cfg['hosts']['switch'], self.cfg['hosts']['vision']
        if state['installed']:
            if not state['after']:                  # the failure came before the normal after-snapshot
                state['after'] = True
                try:
                    self.snapshot(out_remote, label + '_after', check=False, preset=preset)
                except Exception:
                    pass
            entry = {'unit': label, 'what': 'teardown', 'ok': False, 'error': None}
            try:
                r = self.rn.run('switch', self.hw_env(self.switch_cmd('bringup_teardown.py',
                                '--manifest %s --apply' % manifest)), timeout=1800,
                                label='%s: teardown the composite (generator and T off, rows out, loopback off last)'
                                % label)
                self.save(dest, 'teardown.log', r)
                entry['ok'] = r.rc == 0
                if r.rc != 0:
                    entry['error'] = 'rc %d: %s' % (r.rc, (r.err or r.out)[-300:].strip())
                else:
                    self.standing.remove(manifest)
            except Exception as e:
                entry['error'] = '%s: %s' % (type(e).__name__, e)
            self.record['collections'].append(entry)
        fetch = lambda f: 'scp -q %s:%s %s/' % (host, f, q(dest))
        snapdir = q(os.path.join(dest, 'snapshots'))
        if state['before']:
            self.collect(label, 'before snapshot', 'local',
                         'scp -q %s:%s/snap/%s_before.json %s/' % (host, R, label, snapdir))
        if state['after']:
            self.collect(label, 'after snapshot', 'local',
                         'scp -q %s:%s/snap/%s_after.json %s/' % (host, R, label, snapdir))
        if state['ran']:
            self.collect(label, 'vision run directory', 'local', 'scp -qr %s:%s/runs/%s/* %s/'
                         % (vhost, self.V, label, q(dest)))
        self.collect(label, 'switch log', 'local', fetch(log))
        if state['installed']:
            self.collect(label, 'bring-up manifest', 'local', fetch(manifest))

    def verdict(self, trial, rec, label, dest, v, arm, fixture):
        """The gate: independent wire verification, timing extraction and run.evaluate over the collected files."""
        w = self.step('local', '%s: independent wire verification' % label,
                      '%s %s/wire_check.py %s %s --json %s' % (runner.PY, q(HERE), q(dest + '/out.pcap'),
                                                                q(dest + '/in.pcap'), q(dest + '/wire.json')),
                      check=False)
        k = self.step('local', '%s: per-exchange timing extraction' % label,
                      '%s %s/clrt_check.py %s %s --json %s' % (runner.PY, q(HERE), q(dest + '/out.pcap'),
                                                                q(dest + '/in.pcap'), q(dest + '/timing.json'))
                      + self.read_policy_arg(trial, arm), check=False)
        # OPERATE hold J from the same two captures (master-side TX to outstation-side RX), bound to this trial
        self.step('local', '%s: OPERATE hold transit extraction' % label,
                  '%s %s/hold_check.py %s %s --master-port %d --outstation-port %d --json %s'
                  % (runner.PY, q(HERE), q(dest + '/out.pcap'), q(dest + '/in.pcap'), trial['master_port'],
                     self.cfg['endpoints']['outstation_port'], q(dest + '/hold.json')), check=False)
        if self.rn.dry:
            return
        try:
            result = json.loads([l for l in v.out.splitlines() if l.startswith('{')][-1])
        except (IndexError, ValueError):
            result = {'error': (v.out + v.err)[-500:]}
        artifacts = {f: os.path.exists(os.path.join(dest, f)) for f in ('out.pcap', 'in.pcap', 'wire.json',
                                                                        'timing.json')}
        ok, fails = runner.evaluate(False, v.rc, result, w.rc, k.rc, artifacts)
        trial.update(ok=ok, failures=fails, vision=result, wire_rc=w.rc, clrt_rc=k.rc)
        snapdir = os.path.join(dest, 'snapshots')
        ev = checks.load_evidence_files(
            before=os.path.join(snapdir, '%s_before.json' % label), after=os.path.join(snapdir, '%s_after.json' % label),
            master=os.path.join(dest, 'master.json'), outstation=os.path.join(dest, 'outstation.json'),
            wire=os.path.join(dest, 'wire.json'), timing=os.path.join(dest, 'timing.json'),
            hold=os.path.join(dest, 'hold.json'))
        if ev['after']:
            trial['achieved_shaping'] = rec['achieved_shaping'] = ev['after'].get('shaping')
        cfail, obs = checks.evaluate(self.cfg['expectations'], arm, fixture, trial['reads'], ev,
                                     checks.allowed_gap(self.cfg['builds'][arm['build']]),
                                     self.cfg['service']['k'] if self.cfg['builds'][arm['build']].get('mirror_fix') else None,
                                     checks.max_token_stale(self.cfg['builds'][arm['build']]),
                                     diagnostic=self.cfg['builds'][arm['build']].get('diagnostic', False),
                                     gap_ns=self.cfg['timing_params_ns']['gap'],
                                     precision=self.cfg.get('evaluation', {}).get('read_precision', True),
                                     run_sbo=checks.sbo_count(self.cfg['traffic']),
                                     repeated='sbo_cycles' in self.cfg['traffic'],
                                     control_timed=bool(self.cfg['builds'][arm['build']].get('control_timed')),
                                     piggyback_bound=bool(self.cfg['builds'][arm['build']].get('piggyback_bound')),
                                     pb_ns=self.cfg['timing_params_ns'].get('pb'),
                                     op_j_ns=self.cfg['timing_params_ns'].get('op_j'),
                                     gen_exhausted_outcome=self.cfg['builds'][arm['build']].get('gen_exhausted_outcome'),
                                     read_classes=standards.read_class_expectations(self.cfg, arm, trial))
        cfail += self.endpoint_control_checks(ev['master'])
        trial['observed'] = obs
        ok, fails = ok and not cfail, fails + cfail
        outstation = ev.get('outstation') or {}
        run_sbo = checks.sbo_count(self.cfg['traffic'])
        std_fail = self.validate_standards_file(
            dest, trial, arm, {'out': {'path': os.path.join(dest, 'out.pcap')},
                               'in': {'path': os.path.join(dest, 'in.pcap')}},
            self.standards_observed(
                ev, list(fails), transport_ok=(w.rc == 0),
                select_ok=(not run_sbo) or outstation.get('select_real') == run_sbo,
                operate_ok=(not run_sbo) or outstation.get('operate_real') == run_sbo,
                aggregate_ok=ok, precision_required=self.precision_required(arm, fixture),
                precision=obs.get('read_precision'),
                precision_reason=('arm %s has no timing target (T=0)' % arm['name'] if not arm.get('T') else
                                  'fixture %s: READ CLRT undefined or precision disabled' % fixture), checker_result=self.run_standards_checker(dest, trial, arm),
                objectives=self.objective_blocks(trial, arm, obs)))
        fails += std_fail
        ok = ok and not std_fail
        trial.update(ok=ok, failures=fails)
        purpose = self.cfg.get('evaluation', {}).get('purpose', 'qualification')
        timing_continue = False
        if purpose == 'timing_precision_characterization':
            # continue only past timing-objective threshold misses over sufficient evidence (each failed objective
            # is gated and has its minimum sample / complete observation); anything else is a hard gate failure
            precision = obs.get('read_precision') or {}
            p99 = precision.get('p99_nearest_rank_abs_error_us')        # the value the READ gate uses
            failed = {key for key, prefix in OBJECTIVE_KEYS.items() if any(f.startswith(prefix) for f in fails)}
            read_ok = ('read_precision' not in failed or (
                precision.get('gated') and precision.get('eligible', 0) >= 20
                and isinstance(p99, (int, float)) and p99 > 100))
            timing_continue = bool(fails and all(f.startswith(checks.OBJECTIVE_PREFIXES) for f in fails) and read_ok
                                   and all((obs.get(key) or {}).get('gated') and (obs.get(key) or {}).get('sufficient')
                                           for key in failed - {'read_precision'}))
            trial['continuation'] = {'purpose': purpose, 'allowed': timing_continue,
                                     'reason': ('READ p99 absolute error threshold only'
                                                if timing_continue and failed == {'read_precision'} else
                                                'timing objective thresholds only: %s' % ', '.join(sorted(failed))
                                                if timing_continue else
                                                'hard gate failure' if fails else 'trial passed')}
        json.dump(trial, open(os.path.join(dest, 'trial.json'), 'w'), indent=1, default=str)
        if not ok:
            if purpose == 'stale_source_characterization' or timing_continue:
                self.soft_failures.append(label)
                kind = 'TIMING CHARACTERIZATION' if timing_continue else 'DIAGNOSTIC'
                sys.stderr.write('%s TRIAL %s: %s\n' % (kind, label, '; '.join(fails)))
            else:
                raise StepFailed('%s failed: %s' % (label, '; '.join(fails)))

    def endpoint_control_checks(self, master):
        fails = []
        controls = self.endpoint_controls()
        # The frozen binary predates these JSON fields. Explicit control profiles and any binary
        # reporting controls must expose all three fields; omitted default controls stay compatible.
        if any(key in self.cfg['traffic'] or key in (master or {}) for key in controls):
            for key, value in controls.items():
                if not master or master.get(key) != value:
                    fails.append('master effective %s=%r, expected %r' %
                                 (key, (master or {}).get(key), value))
        return fails

    def _vision_json(self, v):
        try:
            return json.loads([l for l in v.out.splitlines() if l.startswith('{')][-1])
        except (IndexError, ValueError, AttributeError):
            return {'error': ((v.out if v else '') + (v.err if v else ''))[-500:]}

    def _baseline_completion_s(self, fixture, arm_name):
        vals = []
        for a in self.record['arms']:
            if a['fixture'] == fixture and a['arm'] == arm_name:
                vals += [t['master_completion_s'] for t in a['trials'] if t.get('master_completion_s') and t.get('ok')
                         and not t.get('loss') and not t.get('scenario')]
        return sorted(vals)[len(vals) // 2] if vals else None

    def verdict_loss(self, trial, rec, label, dest, v, arm, fixture, unit, port):
        """Gate for a trial with one deterministic drop. A failed recovery is RECORDED (trial not ok, campaign goes
        on to the next trial); only infrastructure failures stop the campaign."""
        w = self.step('local', '%s: independent wire verification' % label,
                      '%s %s/wire_check.py %s %s --json %s' % (runner.PY, q(HERE), q(dest + '/out.pcap'),
                                                                q(dest + '/in.pcap'), q(dest + '/wire.json')),
                      check=False)
        k = self.step('local', '%s: per-exchange timing extraction' % label,
                      '%s %s/clrt_check.py %s %s --json %s' % (runner.PY, q(HERE), q(dest + '/out.pcap'),
                                                                q(dest + '/in.pcap'), q(dest + '/timing.json')),
                      check=False)
        if self.rn.dry:
            return
        c = self.cfg
        result = self._vision_json(v)
        snapdir = os.path.join(dest, 'snapshots')
        ev = checks.load_evidence_files(
            before=os.path.join(snapdir, '%s_before.json' % label), after=os.path.join(snapdir, '%s_after.json' % label),
            master=os.path.join(dest, 'master.json'), outstation=os.path.join(dest, 'outstation.json'),
            wire=os.path.join(dest, 'wire.json'), timing=os.path.join(dest, 'timing.json'))
        if ev['after']:
            trial['achieved_shaping'] = rec['achieved_shaping'] = ev['after'].get('shaping')
        spec = loss.parse_drop(unit['drop'], trial['reads'])
        try:
            ident = loss.identify(os.path.join(dest, 'out.pcap'), os.path.join(dest, 'in.pcap'), spec, port,
                                  c['endpoints']['outstation_port'])
        except Exception as e:                       # an unreadable capture is a recorded failure, not a crash
            ident = {'identified': False, 'candidates': None, 'packet': None, 'error': str(e)}
        base = self._baseline_completion_s(fixture, arm['name'])
        build = c['builds'][arm['build']]
        arm = dict(arm, control_padding=build.get('control_padding', True), image_len=build.get('image_len', 58),
                   read_image_len=read_classes.range_image_len(build, build.get('image_len', 58)))
        fails, res = loss.evaluate_loss(arm, trial['reads'], c['loss'].get('max_recovery_s', 5.0), spec,
                                        result.get('loss'), ident, ev['master'], ev['outstation'], ev['wire'],
                                        ev['timing'], c['expectations'], base)
        for f in ('out.pcap', 'in.pcap', 'wire.json', 'timing.json', 'master.json', 'outstation.json'):
            if not os.path.exists(os.path.join(dest, f)):
                fails.append('missing expected artifact: %s' % f)
        # infrastructure checks that still apply: snapshot evidence, stale bound, loop-port gaps
        _f, obs = checks.evaluate(c['expectations'], arm, fixture, trial['reads'], ev,
                                  checks.allowed_gap(c['builds'][arm['build']]),
                                  c['service']['k'] if c['builds'][arm['build']].get('mirror_fix') else None,
                                  checks.max_token_stale(c['builds'][arm['build']]),
                                  diagnostic=c['builds'][arm['build']].get('diagnostic', False),
                                  run_sbo=checks.sbo_count(c['traffic']),
                                  # a control-timed build's SELECT strands bounded blocker tokens (2k per SBO cycle)
                                  control_timed=bool(build.get('control_timed')),
                                  piggyback_bound=bool(build.get('piggyback_bound')),
                                  gen_exhausted_outcome=c['builds'][arm['build']].get('gen_exhausted_outcome'))
        fails += [f for f in _f if f.startswith(('loop port', 'missing evidence: before', 'missing evidence: after',
                                                 'generation exhausted'))
                  or 'OUT_TOKEN_STALE' in f or 'diagnostic stale' in f]
        if ev['master'] and ev['master'].get('issued_ns') and ev['master'].get('completed_ns'):
            trial['master_completion_s'] = round((ev['master']['completed_ns'] - ev['master']['issued_ns']) / 1e9, 3)
        outstation = ev.get('outstation') or {}
        run_sbo = checks.sbo_count(self.cfg['traffic'])
        fails += self.validate_standards_file(
            dest, trial, arm, {'out': {'path': os.path.join(dest, 'out.pcap')},
                               'in': {'path': os.path.join(dest, 'in.pcap')}},
            self.standards_observed(
                ev, list(fails), transport_ok=(w.rc == 0),
                select_ok=(not run_sbo) or outstation.get('select_real') == run_sbo,
                operate_ok=(not run_sbo) or outstation.get('operate_real') == run_sbo,
                aggregate_ok=not fails, precision_required=False,
                precision_reason='loss/recovery trial: READ precision is not evaluated',
                checker_result=self.run_standards_checker(dest, trial, arm),
                objectives=self.objective_blocks(trial, arm, None, LOSS_OBJECTIVES_EXEMPT)),
            precision_exempt='loss/recovery trial: READ precision is not evaluated',
            objectives_exempt=LOSS_OBJECTIVES_EXEMPT)
        trial.update(ok=not fails, failures=fails, vision=result, wire_rc=w.rc, clrt_rc=k.rc, loss=res, observed=obs)
        json.dump(trial, open(os.path.join(dest, 'trial.json'), 'w'), indent=1, default=str)
        if fails:
            self.soft_failures.append(label)
            sys.stderr.write('LOSS TRIAL %s: %s\n' % (label, '; '.join(fails)))

    def verdict_scenario(self, trial, label, dest, v, arm):
        """Reconnect scenario: analyse c1..c3 separately. c1 must succeed and carry the arm's response lengths; c2
        (a port the switch has no rows for) must complete natively; c3 (the installed tuple again) is characterized or protected according to the effective policy."""
        conns = ('c1', 'c2', 'c3')
        rcs = {}
        for cn in conns:
            d = '%s/%s' % (dest, cn)
            rcs[cn] = (
                self.step('local', '%s/%s: independent wire verification' % (label, cn),
                          '%s %s/wire_check.py %s %s --json %s' % (runner.PY, q(HERE), q(d + '/out.pcap'),
                                                                    q(d + '/in.pcap'), q(d + '/wire.json')), check=False),
                self.step('local', '%s/%s: per-exchange timing extraction' % (label, cn),
                          '%s %s/clrt_check.py %s %s --json %s' % (runner.PY, q(HERE), q(d + '/out.pcap'),
                                                                    q(d + '/in.pcap'), q(d + '/timing.json')), check=False))
        if self.rn.dry:
            return
        result = self._vision_json(v)
        vc = result.get('connections', {})
        out, fails = {}, []
        run_sbo = checks.sbo_count(self.cfg['traffic'])
        reconnect_offset = self.cfg['scenarios'][self.scenario]['reconnect_port_offset']   # c2's commanded port
        for cn in conns:
            d = os.path.join(dest, cn)
            e = checks.load_evidence_files(master=os.path.join(d, 'master.json'),
                                           outstation=os.path.join(d, 'outstation.json'),
                                           wire=os.path.join(d, 'wire.json'), timing=os.path.join(d, 'timing.json'))
            summary = (e['timing'] or {}).get('summary') or {}
            summary = summary if isinstance(summary, dict) else {}
            rd = summary.get('READ') or {}
            rd = rd if isinstance(rd, dict) else {}
            lengths = {kind: item.get('resp_len') for kind, item in summary.items() if isinstance(item, dict)}
            lens = sorted({length for values in lengths.values() if isinstance(values, list) for length in values
                           if isinstance(length, int) and not isinstance(length, bool)})
            m, ent = e['master'] or {}, vc.get(cn, {})
            padded = arm['padding'] if cn != 'c2' else 0
            connection_failures = checks.application_checks(self.cfg['expectations'], padded, trial['reads'], e, run_sbo)
            connection_failures += self.endpoint_control_checks(m)
            precision = checks.read_precision_gate(e['timing'] or {}, self.cfg['timing_params_ns']['gap'])
            precision['gated'] = bool(self.reconnect_policy == 'protected' and cn != 'c2' and arm['T'] and
                                      trial.get('fixture', self.fixtures[0]) == 'separate_ack' and
                                      self.cfg.get('evaluation', {}).get('read_precision', True))
            if precision['gated'] and not precision['pass']:
                connection_failures.append('READ precision did not qualify: eligible%d, p99 absolute error%s us' %
                                           (precision['eligible'], precision['p99_nearest_rank_abs_error_us']))
            exempt = (None if precision['gated'] or cn == 'c2' else
                      'reconnect %s: READ precision not gated (policy %s)' % (cn, self.reconnect_policy))
            for tool, status in zip(('wire', 'clrt'), rcs[cn]):
                if status.rc:
                    connection_failures.append('%s extractor rc=%d' % (tool, status.rc))
            if not (cn in vc and ent.get('ok') and ent.get('master_rc') == 0 and not ent.get('master_timeout')):
                connection_failures.append('connection did not complete successfully')
            outstation = e.get('outstation') or {}
            std_fail = self.validate_standards_file(
                d, trial, arm, {'out': {'path': os.path.join(d, 'out.pcap')},
                                'in': {'path': os.path.join(d, 'in.pcap')}},
                self.standards_observed(
                    e, list(connection_failures), transport_ok=(rcs[cn][0].rc == 0),
                    select_ok=(not run_sbo) or outstation.get('select_real') == run_sbo,
                    operate_ok=(not run_sbo) or outstation.get('operate_real') == run_sbo,
                    aggregate_ok=not connection_failures,
                    precision_required=precision['gated'], precision=precision,
                    precision_reason=exempt or 'reconnect %s: no READ timing target' % cn,
                    checker_result=self.run_standards_checker(
                        d, trial, arm, cn, cn == 'c2',
                        master_port=(None if trial.get('master_port') is None else
                                     trial['master_port'] + (reconnect_offset if cn == 'c2' else 0))),
                    objectives=self.objective_blocks(trial, arm, None, RECONNECT_OBJECTIVES_EXEMPT % cn, cn,
                                                     cn == 'c2')),
                connection_id=cn, unbound_native=(cn == 'c2'), precision_exempt=exempt,
                objectives_exempt=RECONNECT_OBJECTIVES_EXEMPT % cn,
                master_port=(None if trial.get('master_port') is None else
                             trial['master_port'] + (reconnect_offset if cn == 'c2' else 0)))
            connection_failures.extend(std_fail)
            out[cn] = {'role': ent.get('role'), 'master_port': ent.get('master_port'), 'ran': ent.get('ran', cn in vc),
                       'vision_ok': bool(ent.get('ok')), 'connect_ok': ent.get('master_rc') == 0,
                       'master_rc': ent.get('master_rc'), 'master_timeout': bool(ent.get('master_timeout')),
                       'source_port_wait': ent.get('source_port_wait'),
                       'error': ent.get('error'), 'completed': bool(m.get('success') and m.get('reads_completed') == trial['reads']),
                       'reads_completed': m.get('reads_completed'), 'resp_lens': lens, 'response_lengths': lengths,
                       'padded': 58 in lens, 'retransmitted': rd.get('retransmitted'),
                       'complete': rd.get('complete'), 'incomplete': rd.get('incomplete'), 'piggyback': rd.get('piggyback'),
                       'wire_rc': rcs[cn][0].rc, 'clrt_rc': rcs[cn][1].rc,
                       'failures': connection_failures, 'ok': not connection_failures, 'read_precision': precision}
            if cn != 'c3' or self.reconnect_policy == 'protected':
                prefix = '%s%s' % (cn, ' native connection' if cn == 'c2' else '')
                fails.extend('%s: %s' % (prefix, failure) for failure in connection_failures)
        if v.rc or not result.get('ok'):
            fails.append('vision reconnect runner did not succeed (rc=%d)' % v.rc)
        out['c3']['comparable'] = bool(out['c1']['ok'] and out['c2']['ok'] and out['c3']['ran'])
        out['c3']['note'] = ('not comparable: an earlier connection prerequisite failed or c3 did not run' if
                             not out['c3']['comparable'] else
                             'protected: endpoint, extractor and aggregate switch gates apply without switch reset' if
                             self.reconnect_policy == 'protected' else 'characterization only; c3 failures are retained')
        switch_obs, switch_fails = {}, []
        if self.reconnect_policy == 'protected':
            build = self.cfg['builds'][arm['build']]
            snapdir = os.path.join(dest, 'snapshots')
            snapshots = checks.load_evidence_files(
                before=os.path.join(snapdir, '%s_before.json' % label),
                after=os.path.join(snapdir, '%s_after.json' % label))
            # c1 and c3 use the installed tuple; c2 must pass natively and adds no T counters.
            switch_fails, switch_obs = checks.evaluate_switch(
                self.cfg['expectations'], arm, 2 * trial['reads'], snapshots, checks.allowed_gap(build),
                self.cfg['service']['k'] if build.get('mirror_fix') else None,
                checks.max_token_stale(build), diagnostic=build.get('diagnostic', False),
                sbo_count=2 * run_sbo, gen_exhausted_outcome=build.get('gen_exhausted_outcome'),
                control_timed=bool(build.get('control_timed')), piggyback_bound=bool(build.get('piggyback_bound')),
                complete_reads=sum(out[cn]['complete'] for cn in ('c1', 'c3') if isinstance(out[cn]['complete'], int)),
                piggyback_reads=sum(out[cn]['piggyback'] for cn in ('c1', 'c3') if isinstance(out[cn]['piggyback'], int)))
            fails.extend('switch: %s' % failure for failure in switch_fails)
        trial.update(ok=not fails, failures=fails, vision=result,
                     scenario={'policy': self.reconnect_policy, 'connections': out,
                               'switch_observed': switch_obs, 'switch_failures': switch_fails,
                               'installed_connections_expected': 2, 'unknown_native_connections_expected': 1})
        json.dump(trial, open(os.path.join(dest, 'trial.json'), 'w'), indent=1, default=str)
        if fails:
            self.soft_failures.append(label)
            sys.stderr.write('RECONNECT TRIAL %s: %s\n' % (label, '; '.join(fails)))

    def installer_cmd(self, build, padding, out_remote, port, preset=None):
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
                % (self.R, HW, out_remote, expects, e['master_ip'], port, pm['master_dev'],
                   e['outstation_ip'], e['outstation_port'], pm['relay_dev'], e['read_dst'], e['read_src'],
                   t['da'], t['readiness'], t['cap'], t['gap'], t['op_j'], c['service']['k'],
                   shaping_args(c, preset=preset), pad)
                + (' --t-pb %d' % t['pb'] if t.get('pb') is not None else ''))

    def snapshot(self, out_remote, name, check=True, preset=None):
        return self.step('switch', 'counter snapshot %s' % name, check=check, cmd=self.hw_env(self.switch_cmd(
            'snapshot_counters.py', '--build-out %s --ports %s %s -o %s/snap/%s.json'
            % (out_remote, self.cfg['ports_map']['stat_ports'], shaping_args(self.cfg, burst=False, preset=preset), self.R, name))))

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

        for manifest in list(self.standing):
            attempt('switch', 'teardown the composite still installed', self.hw_env(
                self.switch_cmd('bringup_teardown.py', '--manifest %s --apply' % manifest)))
        p, aux = c['production'], R + '/aux'
        if self.switch_touched:
            attempt('switch', 'cold-swap bf_switchd back to the observed production program',
                    'bash %s/switch_swap.sh %s/switchd_production_%s.log %s' % (aux, R, self.run_id, p['launch_script']))
            attempt('switch', 'replay the pre-run $PORT snapshot on the production program',
                    'python3 %s/restore_ports.py %s %s --apply --wait 35' % (aux, p['program'], self.prerun))
            if p.get('relay_slot'):
                attempt('switch', 'reinstall the relay slot', 'python3 %s/switch_slot.py relay' % aux)
        if self.vision_touched:
            attempt('vision', 'Vision: fixture off, namespace profile and NIC flag restored',
                    'sudo python3 %s/vision_run.py restore' % self.V)
        if self.vision_touched or self.switch_touched:
            pg = p['ping']
            attempt('vision', 'ping through the restored switch path',
                    'ping -c %d -I %s %s' % (pg['count'], pg['src'], pg['dst']))
        return ok

    def finish(self, dry):
        if dry:
            return
        c = self.cfg
        self.record['effective'] = {
            'timing_params_ns': c['timing_params_ns'], 'k': c['service']['k'],
            'shaping_requested': resolve_shaping(c), 'fixture': c['fixture'], 'trials': c['trials'],
            'traffic': dict(c['traffic'], **self.endpoint_controls()), 'ports_map': c['ports_map'], 'endpoints': c['endpoints'],
            'evaluation': dict({'purpose': 'qualification', 'read_precision': True}, **c.get('evaluation', {})),
            'reconnect_policy': self.reconnect_policy,
            'max_token_stale': {name: checks.max_token_stale(c['builds'][name]) for name in selected_builds(c, self.arms)},
            'endpoint_identity': c['endpoint'], 'vision_run_dir': self.V}
        self.record['config_sha256'] = self.config_sha256
        self.record['config_file_sha256'] = self.config_file_sha256
        self.record['source_identity'] = {
            'runner_files': self.runner_identity,
            'build_sources': {}}
        for name in selected_builds(c, self.arms):
            manifest = json.load(open(path_of(c['builds'][name]['manifest'])))
            self.record['source_identity']['build_sources'][name] = {
                key: manifest.get(key) for key in ('source_sha256', 'source_files', 'compiler_sha256')}
        self.record['builds'] = getattr(self, 'bound', None)
        self.record['paired_block'] = self.paired
        self.record['time'] = time.time()
        json.dump(self.record, open(os.path.join(self.root, 'campaign_run.json'), 'w'), indent=1, default=str)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=('validate', 'plan', 'deploy', 'run', 'report'))
    ap.add_argument('--config', default=os.path.join(HERE, 'campaign.json'))
    ap.add_argument('--arms', help='comma-separated arm names to run (default: all arms in the config)')
    ap.add_argument('--run-dir', help='report: a campaign run directory (contains campaign_run.json)')
    ap.add_argument('--run-id', default=None)
    ap.add_argument('--fixtures', help='comma-separated fixtures to run (default: fixture.modes)')
    ap.add_argument('--loss', help='run the named loss preset: one deterministic drop per entry, each its own cold bring-up')
    ap.add_argument('--scenario', help='run the named scenario (reconnect)')
    ap.add_argument('--reconnect-policy', choices=('characterize', 'protected'), help='default characterize; protected gates c3 without a switch reset')
    ap.add_argument('--paired', help='run the named paired_blocks entry: presets A/B, identical conditions, alternating order')
    ap.add_argument('--preset', help='shaping preset from campaign.json (default: shaping.preset)')
    ap.add_argument('--apply', action='store_true', help='required for run: actually execute on hardware')
    ap.add_argument('--dry-run', action='store_true', help='run: print the commands instead (same as plan)')
    ap.add_argument('--all-builds', action='store_true', help='validate: audit every configured build, including unused historical builds')
    a = ap.parse_args(argv)
    if a.mode == 'report':
        if not a.run_dir:
            sys.exit('report needs --run-dir')
        import report
        print(report.render(a.run_dir), end='')
        return 0
    cfg = load_config(a.config)
    if a.preset:
        cfg['shaping']['preset'] = a.preset
        validate_profile(cfg)
    for w in warnings(cfg):
        sys.stderr.write('WARNING: %s\n' % w)
    if a.all_builds and a.mode != 'validate':
        ap.error('--all-builds is an explicit validate audit')
    run_id = a.run_id or time.strftime('c%Y%m%dT%H%M%S')
    arms = a.arms.split(',') if a.arms else None
    fixtures = a.fixtures.split(',') if a.fixtures else None
    selected = Campaign(cfg, DryRunner(), run_id, arms, fixtures=fixtures, paired=a.paired, loss=a.loss, scenario=a.scenario, reconnect_policy=a.reconnect_policy, config_path=a.config)
    if a.mode == 'validate':
        errs = check_bindings(cfg, selected.arms, all_builds=a.all_builds)
        for e in errs:
            sys.stderr.write('UNBOUND: %s\n' % e)
        if errs:
            print('config structure OK but %d binding error(s); `run` will refuse' % len(errs))
            return 1
        print('config OK and bound: %d arms over %d build(s), %d trials/arm'
              % (len(selected.arms), len(selected_builds(cfg, selected.arms, a.all_builds)), cfg['trials']['trials_per_arm']))
        return 0
    if a.mode == 'deploy':
        runner_ = DryRunner() if a.dry_run else ShellRunner(cfg['hosts'])
        if not a.dry_run:
            bad = check_bindings(cfg, selected.arms)
            if bad:
                sys.exit('refusing to deploy, unbound identity: %s' % '; '.join(bad))
        return Campaign(cfg, runner_, run_id, arms, fixtures=fixtures, paired=a.paired, loss=a.loss, scenario=a.scenario, reconnect_policy=a.reconnect_policy, config_path=a.config).deploy_only()
    if a.mode == 'plan' or a.dry_run:
        return Campaign(cfg, DryRunner(), run_id, arms, fixtures=fixtures, paired=a.paired, loss=a.loss, scenario=a.scenario, reconnect_policy=a.reconnect_policy, config_path=a.config).execute()
    if not a.apply:
        sys.exit('run needs --apply to execute on hardware; use `plan` (or --dry-run) to see the commands first')
    if os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
        sys.exit('run needs DEFENSE4_HW_AUTHORIZED=1 (this is a hardware campaign)')
    bad = check_bindings(cfg, selected.arms)
    if bad:
        sys.exit('refusing to run, unbound identity: %s' % '; '.join(bad))
    return Campaign(cfg, ShellRunner(cfg['hosts']), run_id, arms, fixtures=fixtures, paired=a.paired, loss=a.loss, scenario=a.scenario, reconnect_policy=a.reconnect_policy, config_path=a.config).execute()


if __name__ == '__main__':
    sys.exit(main())
