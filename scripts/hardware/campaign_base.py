"""Current SEL-751 block engine: guarded deployment, receiver checks and verified restoration."""
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
from pathlib import Path
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE, str(Path(HERE).parent / 'checks')]
import checks
import loss
import runner
import standards
import endpoint_profiles
from pathlib import Path
validate_endpoint_profile = endpoint_profiles.validate
RELAY_PYTHON = 'sudo -n /usr/bin/python3'
import vision_run as vr
HW = 'src/scripts/hardware'
RESPONSE_ONLY = 'scripts/hardware'
Result = collections.namedtuple('Result', 'rc out err')
ARCH = str(Path(HERE).resolve().parents[1])
REQUIRED = ('endpoints', 'endpoint', 'hosts', 'ports_map', 'builds', 'arms', 'timing_params_ns', 'service', 'shaping', 'fixture', 'trials', 'traffic', 'loss', 'seeds', 'evidence_dir', 'production', 'expectations')
BUILD_HASHED = ('bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin', 'p1/response_only.bfa')
ROLES = ('ack', 'resp')
FIXTURES = ('physical_relay',)
LADDER = (0, 58, 232, 930, 3723, 14892, 59570, 238281)
HEX64 = re.compile('[0-9a-f]{64}')
DIAG_MIRROR_KEYS = ('state', 'copy_port', 'capture_interface', 'build_label', 'source_sha256')

def validate_diag_mirror(cfg, arms):
    """A diagnostic-mirror block (c72_diag_mirror only) declares purpose 'diagnostic' and a complete label that names
    the selected build, its compiled copy port and a capture interface other than the master NIC."""
    dm = cfg['diag_mirror']
    if cfg.get('purpose') != 'diagnostic':
        raise ValueError("diag_mirror requires purpose 'diagnostic', not %r: refusing the diagnostic block"
                         % cfg.get('purpose'))
    missing = [key for key in DIAG_MIRROR_KEYS if not isinstance(dm, dict) or key not in dm]
    if missing:
        raise ValueError('diag_mirror is missing ' + ', '.join(missing))
    if dm['state'] not in ('on', 'off'):
        raise ValueError('diag_mirror state must be on or off, got %r' % dm['state'])
    interface = dm['capture_interface']
    if not isinstance(interface, str) or not vr.MIRROR_IFACE.fullmatch(interface) or interface == vr.PARENT:
        raise ValueError('diag_mirror capture_interface %r is not a separate interface name' % (interface,))
    if not isinstance(dm['build_label'], str) or not re.fullmatch('[A-Za-z0-9_.-]+', dm['build_label']):
        raise ValueError('diag_mirror build_label must be a plain name')
    if not isinstance(dm['source_sha256'], str) or not HEX64.fullmatch(dm['source_sha256']):
        raise ValueError('diag_mirror source_sha256 must be a sha256')
    stat_ports = str(cfg['ports_map'].get('stat_ports')).split(',')
    if type(dm['copy_port']) is not int or str(dm['copy_port']) not in stat_ports:
        raise ValueError('diag_mirror copy port %r must be one of ports_map.stat_ports' % (dm['copy_port'],))
    import diag_mirror_sessions
    for name in selected_builds(cfg, arms):
        build = cfg['builds'][name]
        if build.get('source_sha256') != dm['source_sha256']:
            raise ValueError('diag_mirror source_sha256 does not name selected build %s (%s)'
                             % (name, build.get('source_sha256')))
        try:
            port = diag_mirror_sessions.load(path_of(build['out_dir']))['copy_port']
        except (OSError, ValueError) as error:
            raise ValueError('diag_mirror build %s has no diagnostic constants: %s' % (name, error))
        if port != dm['copy_port']:
            raise ValueError('diag_mirror copy port %d differs from build %s copy port %d'
                             % (dm['copy_port'], name, port))

def relay_checker_files():
    return [str(p) for p in sorted((Path(HERE).parent / 'checks').glob('*.py'))] + [str(Path(HERE) / name) for name in ('relay_master.py', 'relay_loss.py', 'loss.py')] + [str(p) for p in sorted((Path(HERE) / 'active_harness').glob('*.py'))]

def path_of(rel):
    return rel if os.path.isabs(rel) else os.path.join(ARCH, rel)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()

def load_config(path):
    cfg = json.loads(Path(path).read_text())
    missing = [key for key in REQUIRED if key not in cfg]
    if missing:
        raise ValueError('config missing required sections: ' + ', '.join(missing))
    validate_endpoint_profile(cfg)
    if cfg['traffic'].get('read_schedule') not in ('mixed_full','mixed','full'):
        raise ValueError('current campaign requires an explicit physical READ schedule')
    if cfg.get('diagnostic_mau_snapshot') is not None or cfg.get('host_diagnostics') or cfg.get('host_diagnostic'):
        raise ValueError('diagnostics are outside the current matrix')
    if cfg.get('timing_contract') != 'response_ready_ack_d_no_j_v3':
        raise ValueError('current campaign requires the D-only contract')
    t = cfg['timing_params_ns']
    if set(t) != {'gap', 'budget', 'enabled'} or any((type(v) is not int for v in t.values())) or t['gap'] not in (5000000, 10000000, 15000000, 20000000) or (not 0 < t['budget'] < 1 << 31) or (t['enabled'] not in (0, 1)):
        raise ValueError('invalid current timing parameters')
    if not cfg['arms'] or len({a['build'] for a in cfg['arms']}) != 1:
        raise ValueError('all current arms must use one binary')
    for arm in cfg['arms']:
        build = cfg['builds'].get(arm['build'])
        if build is None or arm['T'] not in (0, 1) or arm['padding'] not in (0, 1):
            raise ValueError('invalid current arm')
        if build.get('timing_contract') != cfg['timing_contract'] or build.get('switch_telemetry') is not False:
            raise ValueError('current build contract/telemetry mismatch')
    if cfg['trials']['trials_per_arm'] < 1 or cfg['trials']['reads_per_trial'] < 1:
        raise ValueError('planned READ/trial counts must be positive')
    validate_profile(cfg)
    return cfg
RETIRED_EVALUATION_KEYS = ('purpose', 'read_precision', 'host_precision_gated', 'precision_reference')

def reported_evaluation(evaluation):
    """The config's evaluation section as recorded: retired timing-threshold keys dropped (also inside
    campaign_block); the stale-source diagnostic purpose is kept because it still selects diagnostic soft failures."""
    out = {k: v for k, v in (evaluation or {}).items() if k not in RETIRED_EVALUATION_KEYS}
    if (evaluation or {}).get('purpose') == 'stale_source_characterization':
        out['purpose'] = 'stale_source_characterization'
    if isinstance(out.get('campaign_block'), dict):
        out['campaign_block'] = {k: v for k, v in out['campaign_block'].items() if k not in RETIRED_EVALUATION_KEYS}
    return out

def gate_ok(record):
    """The block verdict: strictly ok, and never with an invalid host diagnostic."""
    return bool(record.get('ok')) and (not record.get('host_diagnostic_invalid'))

def validate_read_classes(cfg):
    """endpoint.binary, traffic.read_schedule/db and every arm's per-class READ declaration, before anything runs: a
    schedule on an arm whose build declares no read_images/read_images_by_db, or a padded arm whose build does not
    support a scheduled class, is refused here, never run against a native expectation. Loss presets
    identify packets by one READ request/response length, so they do not carry a READ-class schedule."""
    validate_endpoint_profile(cfg)
    return

def validate_profile(cfg):
    """The hardware profile the campaign may run: the 8-bit-range READ, a positive K, non-negative shaping
    rates, and fixture jitter only with a netem distribution on the separate_ack fixture."""
    validate_endpoint_profile(cfg)
    if cfg.get('fixture', {}).get('modes') != ['physical_relay']:
        raise ValueError('sel751 requires the real physical_relay fixture, without emulated ACK delay')
    for key, default in (('read_pause_ms', 25), ('close_grace_ms', 0)):
        value = cfg['traffic'].get(key, default)
        if not isinstance(value, int) or isinstance(value, bool) or (not 0 <= value <= 5000):
            raise ValueError('traffic.%s must be an integer in 0..5000' % key)
    if not isinstance(cfg['traffic'].get('run_sbo', True), bool):
        raise ValueError('traffic.run_sbo must be boolean')
    if 'sbo_cycles' in cfg['traffic']:
        cycles = cfg['traffic']['sbo_cycles']
        if not isinstance(cycles, int) or isinstance(cycles, bool) or (not 1 <= cycles <= checks.MAX_SBO_CYCLES):
            raise ValueError('traffic.sbo_cycles must be an integer in 1..%d' % checks.MAX_SBO_CYCLES)
        if cfg['traffic'].get('run_sbo', True) is not True:
            raise ValueError('traffic.sbo_cycles requires traffic.run_sbo')
        if cfg['trials']['reads_per_trial'] < cycles + 1:
            raise ValueError('trials.reads_per_trial counts every READ and must be >= sbo_cycles + 1')
        if cfg.get('loss', {}).get('presets'):
            raise ValueError('traffic.sbo_cycles is not supported with loss presets (unsupported shape)')
    # E4b: present only as true, and only with sbo_cycles (each SELECT is followed by READs); absent = today
    checks.sbo_select_only(cfg['traffic'])
    validate_read_classes(cfg)
    spec = cfg.get('diagnostic_mau_snapshot')
    if spec is not None and (not (isinstance(spec, str) and MAU_SNAPSHOT_SPEC.fullmatch(spec))):
        raise ValueError('diagnostic_mau_snapshot must be start=S,end=E,field=value/mask[,...]')
    if spec is not None:
        parts = dict((part.split('=', 1) for part in spec.split(',')[:2]))
        names = [part.split('=', 1)[0] for part in spec.split(',')[2:]]
        values = [tuple((int(v, 0) for v in part.split('=', 1)[1].split('/'))) for part in spec.split(',')[2:]]
        if not 0 <= int(parts['start']) <= int(parts['end']) <= 11 or {'start', 'end'} & set(names) or len(set(names)) != len(names) or any((value & ~mask for value, mask in values)):
            raise ValueError('diagnostic_mau_snapshot needs start<=end<=11, distinct trigger fields and value within mask')
    for name, scenario in cfg.get('scenarios', {}).items():
        if scenario.get('policy', 'characterize') not in ('characterize', 'protected'):
            raise ValueError('scenario %s: policy must be characterize or protected' % name)
    if cfg['traffic']['range'] != 8:
        raise ValueError('traffic.range must be 8 (the 20-byte 8-bit-range READ profile); got %r' % cfg['traffic']['range'])
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
                    raise ValueError('shaping preset %s: %s.%s=%r is not an exact shaper ladder value %s (0 = off)' % (name, group, r, v, LADDER))
        bb = p.get('block_burst')
        if bb is not None and (not isinstance(bb, int) or isinstance(bb, bool) or bb < 1):
            raise ValueError('shaping preset %s: block_burst must be null (installer default) or an integer >= 1' % name)
    if cfg.get('trial_mode') not in ('per_trial_cold', 'one_connection'):
        raise ValueError("trial_mode must be 'per_trial_cold' or 'one_connection', got %r" % cfg.get('trial_mode'))
    pr = cfg['traffic'].get('master_port_range', {})
    if not (isinstance(pr.get('first'), int) and isinstance(pr.get('last'), int) and (1024 <= pr['first'] <= pr['last'] <= 65535)):
        raise ValueError('traffic.master_port_range needs integer first <= last within 1024..65535, got %r' % pr)
    for name, b in cfg['builds'].items():
        checks.validate_allowed_gap(b, name)
        checks.validate_max_token_stale(b, name)
        if not isinstance(b.get('mirror_fix', False), bool):
            raise ValueError('build %s: mirror_fix must be true or false' % name)
    exp = cfg['expectations']
    for k in ('mirror_fix',):
        if k not in exp:
            raise ValueError('expectations.%s is missing' % k)
    modes = cfg['fixture'].get('modes')
    if not modes or any((m not in FIXTURES for m in modes)) or len(set(modes)) != len(modes):
        raise ValueError('fixture.modes must be a non-empty list of distinct values from %s, got %r' % (FIXTURES, modes))
    if 'separate_ack' in modes and (not cfg['fixture'].get('delay_ms', 0) > 0):
        raise ValueError('fixture.delay_ms must be > 0 for the separate_ack fixture')
    sd = cfg['traffic'].get('start_delay_ms', 0)
    if not isinstance(sd, int) or isinstance(sd, bool) or sd < 0:
        raise ValueError('traffic.start_delay_ms must be an integer >= 0')
    validate_paired_blocks(cfg)
    validate_loss_and_scenarios(cfg)
    jitter, distribution = (cfg['fixture'].get('jitter_ms', 0), cfg['fixture'].get('distribution'))
    if not isinstance(jitter, int) or isinstance(jitter, bool) or (not 0 <= jitter <= 20):
        raise ValueError('fixture.jitter_ms must be an integer in 0..20, got %r' % (jitter,))
    if jitter and (distribution not in vr.DISTRIBUTIONS or 'separate_ack' not in modes):
        raise ValueError('fixture.jitter_ms needs fixture.distribution in %s and the separate_ack fixture' % (vr.DISTRIBUTIONS,))
    if not jitter and distribution is not None:
        raise ValueError('fixture.distribution is only meaningful with fixture.jitter_ms > 0')

def resolve_shaping(cfg, preset=None):
    """The effective requested shaping: {'preset', 'hold_pps', 'block_pps', 'block_burst'}."""
    sh = cfg['shaping']
    name = preset or sh['preset']
    if name not in sh['presets']:
        raise ValueError('unknown shaping preset %r; the config defines %s' % (name, sorted(sh['presets'])))
    p = sh['presets'][name]
    return {'preset': name, 'hold_pps': dict(p['hold_pps']), 'block_pps': dict(p['block_pps']), 'block_burst': p.get('block_burst')}

def drop_text(entry):
    """A loss preset entry -> the --drop text: CLASS:N, or CLASS:N:identity for an explicit identity target."""
    return '%s:%d' % (entry['class'], entry['n']) + (':identity' if entry.get('target') == 'identity' else '')

def validate_loss_and_scenarios(cfg):
    lc = cfg['loss']
    mr = lc.get('max_recovery_s', 5.0)
    if not isinstance(mr, (int, float)) or isinstance(mr, bool) or mr <= 0:
        raise ValueError('loss.max_recovery_s must be a positive number of seconds')
    for pname, entries in lc.get('presets', {}).items():
        if not entries:
            raise ValueError('loss.presets.%s must list at least one {class, n}' % pname)
        for e in entries:
            if set(e) - {'target'} != {'class', 'n'} or not isinstance(e['n'], int) or isinstance(e['n'], bool):
                raise ValueError('loss.presets.%s: each entry needs exactly class and integer n, got %r' % (pname, e))
            if 'target' in e and e['target'] != 'identity':
                raise ValueError('loss.presets.%s: target must be "identity" and needs the sel751 profile, got %r' % (pname, e))
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
        if not (isinstance(pr, list) and len(pr) == 2 and (pr[0] != pr[1]) and all((p in cfg['shaping']['presets'] for p in pr))):
            raise ValueError('%s.presets must be two distinct shaping presets (A, B) from %s' % (where, sorted(cfg['shaping']['presets'])))
        if not isinstance(blk.get('repeats', 1), int) or blk.get('repeats', 1) < 1:
            raise ValueError('%s.repeats must be an integer >= 1' % where)
        if not blk.get('conditions'):
            raise ValueError('%s.conditions must be a non-empty list' % where)
        for cnd in blk['conditions']:
            if set(cnd) != {'delay_ms', 'gap_ms', 'start_delay_ms', 'seed'} or any((not isinstance(v, int) or isinstance(v, bool) or v < 0 for v in cnd.values())):
                raise ValueError('%s: each condition needs integer delay_ms, gap_ms, start_delay_ms, seed >= 0, got %r' % (where, cnd))
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
            if slot is not None and (not (isinstance(slot, str) and HEX64.fullmatch(slot))):
                errs.append('build %s: hashes[%s]=%r is a placeholder or not a sha256 (use null to fill it from the manifest)' % (name, rel, slot))
                continue
            if rel not in want:
                errs.append('build %s: the compile manifest has no artifact_sha256 for %s' % (name, rel))
                continue
            if slot is not None and slot != want[rel]:
                errs.append('build %s: hashes[%s] disagrees with the compile manifest (%s vs %s)' % (name, rel, slot, want[rel]))
            f = os.path.join(path_of(b['out_dir']), rel)
            got = sha256_file(f) if os.path.isfile(f) else 'missing'
            if got != want[rel]:
                errs.append('build %s: %s on disk is %s but the compile manifest records %s' % (name, rel, got, want[rel]))
    try:
        validate_endpoint_profile(cfg)
    except ValueError as error:
        errs.append(str(error))
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
        need_ns = int((fx['delay_ms'] + fx.get('readiness_margin_ms', 0)) * 1000000)
        if need_ns >= cfg['timing_params_ns']['readiness']:
            w.append('fixture delay %s ms + %s ms margin >= T readiness %d ns: the child response arrives after the readiness deadline (or too close to it), so the normal commit/release path cannot be observed (defect D). Lower the fixture delay or raise readiness.' % (fx['delay_ms'], fx.get('readiness_margin_ms', 0), cfg['timing_params_ns']['readiness']))
    for bname, blk in cfg.get('paired_blocks', {}).items():
        if blk['fixture'] != 'separate_ack':
            continue
        for cnd in blk['conditions']:
            if int((cnd['delay_ms'] + fx.get('readiness_margin_ms', 0)) * 1000000) >= cfg['timing_params_ns']['readiness']:
                w.append('paired_blocks.%s condition delay %d ms + margin >= T readiness: the child response misses the readiness deadline (defect D)' % (bname, cnd['delay_ms']))
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
        detached_ssh = ['-o', 'BatchMode=yes', '-o', 'IdentityAgent=none', '-o', 'ControlMaster=no', '-o', 'ControlPath=none']
        argv = ['ssh'] + detached_ssh + [self.hosts[where], cmd] if where in ('switch', 'vision') else shlex.split(cmd)
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
    src = open(os.path.join(HERE, 'installer_base.py')).read()
    return "'%s'" % flag in src or '"%s"' % flag in src

def installer_read_addresses(cfg):
    """(read_dst, read_src) for the installer, which N compares with the parsed link header octets (wire order).
    Software-fixture configs store wire order already (e.g. 0x0a00/0x0100); the sel751 profile stores the
    logical DNP3 addresses endpoint_profiles.validate requires (relay 0, master 1), which are little-endian on
    the wire. rc01_hw_c51_20261024_11's MAU snapshot: logical src 1 set m.badh and every READ was refused."""
    e = cfg['endpoints']
    return tuple((int.from_bytes(int(e[k]).to_bytes(2, 'little'), 'big') for k in ('read_dst', 'read_src')))
MAU_SNAPSHOT_SPEC = re.compile('start=\\d{1,2},end=\\d{1,2}(,[a-z][a-z0-9_.$]*=(0x[0-9a-f]+|\\d+)/(0x[0-9a-f]+|\\d+))+')

def q(x):
    return shlex.quote(str(x))

def switch_tools():
    return [(str(Path(HERE) / name), name) for name in ('restore_ports.py', 'live_snapshot.py', 'observe_program.py', 'switch_slot.py', 'switch_swap.sh', 'launch_composite.sh')] + [(str(Path(HERE).parent / 'model/response_path_cp.py'), 'response_path_cp.py')]

def installer_sources():
    return [str(Path(HERE).parent / 'model' / name) for name in ('cp.py', 'cp_base.py', 'port_map.py', 'response_path_cp.py')]

def installer_hw_files():
    return [str(p) for p in sorted(Path(HERE).glob('*.py'))]

class Campaign:

    def __init__(self, cfg, runner_, run_id, arms=None, installer_flags=None, out=print, fixtures=None, paired=None, loss=None, scenario=None, reconnect_policy=None, config_path=None):
        self.cfg, self.rn, self.run_id, self.out = (cfg, runner_, run_id, out)
        if 'diag_mirror' in cfg and (loss is not None or scenario is not None or paired is not None):
            raise ValueError('a diagnostic mirror block runs plain trials only '
                             '(no loss preset, scenario or paired block)')
        self.installer_has = installer_flags or (lambda flag: default_installer_flags(flag))
        names = [a['name'] for a in cfg['arms']]
        want = arms or names
        unknown = [n for n in want if n not in names]
        if unknown:
            raise ValueError('unknown arm(s) %s; the config defines %s' % (unknown, names))
        self.paired = paired
        self.loss_preset, self.scenario = (loss, scenario)
        self.reconnect_policy = reconnect_policy or cfg.get('scenarios', {}).get('reconnect', {}).get('policy', 'characterize')
        if self.reconnect_policy not in ('characterize', 'protected'):
            raise ValueError('reconnect policy must be characterize or protected')
        self.config_sha256 = hashlib.sha256(json.dumps(cfg, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        self.config_file_sha256 = sha256_file(config_path) if config_path else None
        self.runner_identity = {str(Path(path).relative_to(ARCH)): sha256_file(path) for path in relay_checker_files()+[str(Path(HERE)/name)for name in ('campaign.py','campaign_base.py','vision_run.py')]}
        self.soft_failures = []
        if loss is not None and loss not in cfg['loss'].get('presets', {}):
            raise ValueError('unknown loss preset %r; the config defines %s' % (loss, sorted(cfg['loss'].get('presets', {}))))
        if scenario is not None:
            if 'sbo_cycles' in cfg['traffic']:
                raise ValueError('scenario %r is not supported with traffic.sbo_cycles (unsupported shape)' % scenario)
            if scenario not in cfg.get('scenarios', {}):
                raise ValueError('unknown scenario %r; the config defines %s' % (scenario, sorted(cfg.get('scenarios', {}))))
            want = [cfg['scenarios'][scenario]['arm']]
        if paired is not None:
            if paired not in cfg.get('paired_blocks', {}):
                raise ValueError('unknown paired block %r; the config defines %s' % (paired, sorted(cfg.get('paired_blocks', {}))))
            want = [cfg['paired_blocks'][paired]['arm']]
        self.arms = [a for a in cfg['arms'] if a['name'] in want]
        modes = cfg['fixture']['modes']
        self.fixtures = [cfg['paired_blocks'][paired]['fixture']] if paired is not None else [cfg['scenarios'][scenario]['fixture']] if scenario is not None else fixtures or list(modes)
        bad = [f for f in self.fixtures if f not in modes and paired is None]
        if bad:
            raise ValueError('unknown or unconfigured fixture(s) %s; fixture.modes is %s' % (bad, modes))
        self.R = cfg['hosts']['switch_remote_dir']
        self.V = cfg['hosts'].get('vision_run_dir', '/home/decps/pad58b_20261011')
        self.prerun = '%s/snap/%s_prerun.json' % (self.R, run_id)
        self.root = os.path.join(path_of(cfg['evidence_dir']), run_id)
        self.record = {'run_id': run_id, 'ok': False, 'failure': None, 'arms': [], 'restore': [], 'bringups': [], 'collections': []}
        self.switch_touched = False
        self.standing = []
        self.vision_touched = False
        if 'diag_mirror' in cfg:
            validate_diag_mirror(cfg, self.arms)
            self.record.update(purpose=cfg['purpose'], diag_mirror=self.diag_label())

    def diag_label(self):
        """The identity every diagnostic-mirror result carries, kept distinct from c72 evidence."""
        keys = ('build_label', 'source_sha256', 'state', 'copy_port', 'capture_interface')
        return {key: self.cfg['diag_mirror'][key] for key in keys}

    def mirror_iface_arg(self):
        if 'diag_mirror' not in self.cfg:
            return ''
        return ' --mirror-iface %s' % q(self.cfg['diag_mirror']['capture_interface'])

    def diag_mirror_evidence(self, trial, dest):
        """Diagnostic blocks: the mirror capture and its evidence, collected with the Vision run directory beside
        in.pcap/out.pcap, hashed into the trial record. A missing or empty file, or a mirror capture that vision_run
        did not report ok, is a trial failure."""
        if 'diag_mirror' not in self.cfg:
            return []
        files, failures = ({}, [])
        for name in vr.MIRROR_FILES:
            path = Path(dest) / name
            if path.is_file() and path.stat().st_size:
                files[name] = sha256_file(path)
            else:
                failures.append('diagnostic mirror evidence missing or empty: ' + name)
        if 'mirror_capture.json' in files:
            try:
                capture = json.loads((Path(dest) / 'mirror_capture.json').read_text())
            except ValueError as error:
                capture = {'failures': ['mirror_capture.json unreadable: %s' % error]}
            if capture.get('ok') is not True:
                reported = capture.get('failures') or ['capture not reported ok']
                failures += ['diagnostic mirror: ' + f for f in reported]
        trial['diag_mirror'] = dict(trial.get('diag_mirror') or {}, files=files)
        return failures

    def standards_context(self, trial, arm, connection_id=None, unbound_native=False):
        build = self.cfg['builds'][arm['build']]
        return dict(config=self.cfg, run_record=dict(self.record, run_id=self.run_id, config_sha256=self.config_sha256, builds=getattr(self, 'bound', None) or {}), trial=trial, connection_id=connection_id or 'primary', arm=arm, candidate_source_sha256=build.get('source_sha256'), checker_files=relay_checker_files(), unbound_native=unbound_native, packet_boundary_required=bool(build.get('packet_boundary_required') or self.cfg.get('standards', {}).get('packet_boundary_required')))

    def standards_captures(self, dest, captures):
        merged = dict(captures or {})
        for name, filename in standards.SEL751_CAPTURE_FILES.items():
            merged[name] = {'path': str(Path(dest) / filename)}
        return merged

    def qualify_capture_arg(self, arm):
        return ''

    def validate_standards_file(self, dest, trial, arm, captures, observed, connection_id=None, unbound_native=False, master_port=None):
        if self.rn.dry:
            return []
        context = self.standards_context(trial, arm, connection_id, unbound_native)
        context['master_port'] = master_port if master_port is not None else trial.get('master_port')
        captures = self.standards_captures(dest, captures)
        artifact = standards.build_standards_artifact(context, captures)
        path = Path(dest) / 'standards.json'
        path.write_text(json.dumps(artifact, indent=2) + '\n')
        result = standards.validate_standards(path, context, captures)
        (Path(dest) / 'standards_verdict.json').write_text(json.dumps(result, indent=2) + '\n')
        return ['standards: ' + error for error in result['failures']]

    def _padded_suffix(self, arm, cls=None):
        return ''

    def units(self):
        """[unit dict]: one cold bring-up and one connection each, with its own recorded conditions.
        per_trial_cold: every trial of every arm (fixture-major); one_connection: one per arm carrying all of its
        READs. A paired block instead lists, per condition and repeat, presets A and B under IDENTICAL conditions,
        the order alternating between consecutive pairs."""
        c, t = (self.cfg, self.cfg['trials'])
        out = []
        base = {'delay_ms': c['fixture']['delay_ms'], 'gap_ms': c['traffic']['gap_ms'], 'start_delay_ms': c['traffic'].get('start_delay_ms', 0)}
        if self.paired is not None:
            blk = c['paired_blocks'][self.paired]
            arm = self.arms[0]
            pair = 0
            for _rep in range(blk.get('repeats', 1)):
                for cnd in blk['conditions']:
                    order = list(blk['presets']) if pair % 2 == 0 else list(reversed(blk['presets']))
                    for preset in order:
                        out.append({'fixture': blk['fixture'], 'arm': arm, 'i': len(out), 'reads': t['reads_per_trial'], 'preset': preset, 'pair': pair, 'order': order, 'condition': dict(cnd), 'delay_ms': cnd['delay_ms'], 'gap_ms': cnd['gap_ms'], 'start_delay_ms': cnd['start_delay_ms'], 'start_seed': cnd['seed']})
                    pair += 1
            return out
        if self.loss_preset is not None or self.scenario is not None:
            for fx in self.fixtures:
                for arm in self.arms:
                    i = 0
                    entries = [None] if self.scenario else c['loss']['presets'][self.loss_preset]
                    for e in entries:
                        out.append(dict(base, fixture=fx, arm=arm, i=i, preset=None, pair=None, reads=t['reads_per_trial'], start_seed=c['seeds']['rng_seed'] + len(out), drop=drop_text(e) + self._padded_suffix(arm, e['class']) if e else None, scenario=self.scenario))
                        i += 1
            return out
        one = c['trial_mode'] == 'one_connection'
        for fx in self.fixtures:
            for arm in self.arms:
                for i in range(1 if one else t['trials_per_arm']):
                    out.append(dict(base, fixture=fx, arm=arm, i=i, preset=None, pair=None, reads=t['reads_per_trial'] * (t['trials_per_arm'] if one else 1), start_seed=c['seeds']['rng_seed'] + len(out)))
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
        if any((a['padding'] == 0 for a in self.arms)) and (not self.installer_has(flag)):
            names = [a['name'] for a in self.arms if a['padding'] == 0]
            return ['arm(s) %s need the padding policy row off, but hw/bringup_composite.py has no %s flag (TODO hw/ owner); run the padding-on arms with --arms' % (names, flag)]
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
            errs.append('%d connections need %d distinct master ports but traffic.master_port_range has %d' % (len(self.units()), len(self.units()), len(self.ports())))
        return errs

    def step(self, where, label, cmd, cwd=None, check=True, timeout=3600):
        r = self.rn.run(where, cmd, cwd=cwd, timeout=timeout, label=label)
        if not self.rn.dry:
            self.out('[%s] %s -> rc %d' % (where, label, r.rc))
        if check and r.rc != 0:
            raise StepFailed('%s failed (rc %d) on %s: %s | %s' % (label, r.rc, where, cmd[:300], (r.err or r.out)[-400:].strip()), r)
        return r

    def switch_cmd(self, script, args):
        return 'python3 %s/%s/%s %s' % (self.R, HW, script, args)

    def hw_env(self, cmd):
        return 'DEFENSE4_HW_AUTHORIZED=1 ' + cmd

    def endpoint_controls(self):
        controls = {key: self.cfg['traffic'].get(key, default) for key, default in (('read_pause_ms', 25), ('run_sbo', True), ('close_grace_ms', 0))}
        if 'sbo_cycles' in self.cfg['traffic']:
            controls['sbo_cycles'] = self.cfg['traffic']['sbo_cycles']
        if 'sbo_select_only' in self.cfg['traffic']:
            controls['sbo_select_only'] = self.cfg['traffic']['sbo_select_only']
        for key in ('read_schedule', 'db'):
            if key in self.cfg['traffic']:
                controls[key] = self.cfg['traffic'][key]
        return controls

    def endpoint_control_args(self):
        prefix = ' --endpoint-profile sel751 --apply'
        return prefix + ''.join((' --%s %s' % (key.replace('_', '-'), value if isinstance(value, str) else int(value)) for key, value in self.endpoint_controls().items()))

    def pad_expect_arg(self, arm):
        """' --pad-expect <class>=<n>,...' on a PADDED arm whose build declares read_padding (the two-READ-target
        profile): the padding the switch is declared to add per scheduled class, so the endpoint's strict check
        requires exactly it. An off arm, or a build without read_padding, passes nothing -- the endpoint then fails on
        any added point."""
        return ' --relay-padding %d' % arm['padding']

    def endpoint_binary_arg(self):
        return ' --endpoint-binary %s' % q(self.cfg['endpoint']['binary']) if 'binary' in self.cfg['endpoint'] else ''

    def execute(self):
        dry = self.rn.dry
        errs = self.preflight()
        if errs and (not dry):
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
            self.bound = {n: {r: self.cfg['builds'][n]['hashes'].get(r) or '<UNBOUND>' for r in BUILD_HASHED} for n in {a['build'] for a in self.arms}}
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
            self.record['state_touched'] = {'switch': bool(self.switch_touched), 'vision': bool(self.vision_touched)}
            self.finish(dry)
        self.record['ok'] = not failed and restore_ok and (not self.soft_failures)
        if self.soft_failures:
            self.record['soft_failures'] = self.soft_failures
        self.record['gate_ok'] = gate_ok(self.record)
        if not dry:
            self.finish(dry)
        return 0 if self.record['gate_ok'] else 1

    def vision_identity(self):
        """Read-only identity checks on Vision (the only change is copying vision_run.py)."""
        return self.relay_vision_identity()

    def relay_vision_identity(self):
        validate_endpoint_profile(self.cfg)
        files = {name: Path(HERE) / name for name in ('vision_run.py', 'relay_master.py', 'loss.py', 'capture_observation.py', 'relay_loss.py')}
        files.update({p.name: p for p in (Path(HERE).parent / 'checks').glob('*.py')})
        files.update({'active_harness/' + p.name: p for p in (Path(HERE) / 'active_harness').glob('*.py')})
        self.step('vision', 'make relay helper directory', 'mkdir -p %s/active_harness' % q(self.V))
        for name, path in files.items():
            self.step('local', 'deploy relay helper ' + name, 'scp -q %s %s:%s' % (q(path), self.cfg['hosts']['vision'], q(self.V + '/' + name)))
        result = self.step('vision', 'verify every relay helper', 'sha256sum ' + ' '.join((q(self.V + '/' + name) for name in files)))
        hashes = {name: sha256_file(path) for name, path in files.items()}
        if not self.rn.dry:
            got = {line.split()[1]: line.split()[0] for line in result.out.splitlines() if len(line.split()) == 2}
            for name, value in hashes.items():
                if got.get(self.V + '/' + name) != value:
                    raise StepFailed('relay helper identity mismatch: ' + name)
        self.record['endpoint_observed'] = dict(endpoint_profile='sel751', source_hashes=hashes, master_ip='192.168.10.1', relay_ip='192.168.10.7')
        result = self.step('vision', 'guarded builder preflight', RELAY_PYTHON + ' %s/relay_master.py --preflight' % q(self.V), check=False)
        self.record['relay_helper_preflight'] = dict(rc=result.rc, stdout=result.out, stderr=result.err)
        self.save(self.root, 'relay_helper_preflight.out', result)
        if result.rc or (not self.rn.dry and runner.last_json(result.out).get('ok') is not True):
            raise StepFailed('deployed guarded relay helper preflight failed', result)

    def deploy_switch(self):
        """Copy every tool and build into the configured switch directory and verify each tool's sha256 there.
        Nothing the campaign runs lives anywhere else."""
        c, R, host = (self.cfg, self.R, self.cfg['hosts']['switch'])
        aux = R + '/aux'
        self.step('switch', 'make remote directories', 'mkdir -p %s %s/src %s/snap' % (aux, R, R))
        tools = switch_tools()
        self.step('local', 'copy the switch tools (ports, snapshot, observe, relay slot, swap/launch) into aux', 'scp -q %s %s:%s/' % (' '.join((q(p) for p, _n in tools)), host, aux))
        rel = [os.path.relpath(p, ARCH) for p in installer_sources()]
        self.step('local', 'copy the installer source tree to the switch (repo-relative paths)', 'rsync -aR --exclude __pycache__ %s %s %s:%s/src/' % (' '.join(rel), RESPONSE_ONLY, host, R), cwd=ARCH)
        for build in sorted({a['build'] for a in self.arms}):
            self.step('local', 'copy build %s out/ to the switch' % build, 'rsync -a %s/ %s:%s/' % (q(path_of(c['builds'][build]['out_dir'])), host, '%s/out_%s' % (R, build)))
        src = [(p, '%s/src/%s' % (R, os.path.relpath(p, ARCH))) for p in installer_sources() + installer_hw_files()]
        want = [(p, '%s/%s' % (aux, n)) for p, n in tools] + src
        r = self.step('switch', 'verify every deployed tool and installer source file by sha256', 'sha256sum ' + ' '.join((remote for _p, remote in want)))
        if not self.rn.dry:
            got = {l.split()[1]: l.split()[0] for l in r.out.splitlines() if len(l.split()) == 2}
            for path, remote in want:
                if got.get(remote) != sha256_file(path):
                    raise StepFailed('deployed %s on the switch has sha256 %s, expected %s' % (remote, got.get(remote), sha256_file(path)))

    def deploy(self):
        self.vision_identity()
        self.deploy_switch()

    def deploy_only(self):
        """The `deploy` mode: put the tools in place and verify them; changes no switch or Vision state."""
        try:
            errs = check_bindings(self.cfg, self.arms)
            if errs and (not self.rn.dry):
                raise StepFailed('refusing to deploy, unbound identity: %s' % '; '.join(errs))
            self.deploy()
            return 0
        except (StepFailed, OSError) as e:
            sys.stderr.write('DEPLOY FAILED: %s\n' % e)
            return 1

    def switch_toolkit(self):
        """Observe (read-only) which program is running, refuse unless it is the configured production program,
        and snapshot its $PORT table for every later replay."""
        c, R, host = (self.cfg, self.R, self.cfg['hosts']['switch'])
        aux = R + '/aux'
        prod = c['production']
        r = self.step('switch', 'observe the running program (read-only, from ps)', 'python3 %s/observe_program.py' % aux)
        observed = prod['program']
        if not self.rn.dry:
            try:
                observed = json.loads([l for l in r.out.splitlines() if l.startswith('{')][-1])['program']
            except (IndexError, ValueError, KeyError):
                raise StepFailed('cannot read the running program from observe_program.py: %s' % (r.out + r.err)[-300:])
            self.record['pre_run_program'] = observed
            if observed != prod['program']:
                raise StepFailed('refusing: the switch is running program %r but the configured production program is %r; nothing was changed' % (observed, prod['program']))
        self.step('switch', "snapshot the running program's $PORT table (read-only) for every later replay", 'python3 %s/live_snapshot.py %s %s' % (aux, observed, self.prerun))
        self.step('local', 'copy the pre-run snapshot back', 'scp -q %s:%s %s/' % (host, self.prerun, q(self.root)), check=not self.rn.dry)

    def vision_setup(self):
        V = self.V
        self.vision_touched = True
        result = self.step('vision', 'record physical master offload baseline before capture', RELAY_PYTHON + ' %s/vision_run.py setup --endpoint-profile sel751' % q(V) + (' --loss-baseline' if self.loss_preset is not None else ''))
        if not self.rn.dry:
            baseline = runner.last_json(result.out)['offload']
            path = Path(self.root) / 'vision_offload_baseline.json'
            path.write_text(json.dumps(baseline, indent=2) + '\n')
            self.record['vision_offload_baseline_sha256'] = sha256_file(path)
        return

    def host_diagnostic_evidence(self, output):
        """The CPU-latency release evidence vision_run.py restore printed, into the record. A diagnostic that was not
        verified in force at release fails the block (a soft failure outside any trial)."""
        for line in (output or '').splitlines():
            if line.startswith('cpu latency release evidence: '):
                try:
                    evidence = json.loads(line.split(': ', 1)[1])
                    if not isinstance(evidence, dict):
                        raise ValueError('not an object')
                except ValueError:
                    evidence = {'applied': True, 'diagnostic_valid': False, 'unparsed': line}
                self.record['cpu_latency_diagnostic'] = evidence
                wanted = (self.cfg.get('host_diagnostic') or {}).get('cpu_latency')
                if evidence.get('applied') and (not wanted):
                    self.soft_failures.append('a CPU-latency hold was in force on a block that did not request it')
                    self.record['host_diagnostic_invalid'] = True
                    return
                if (wanted or evidence.get('applied')) and evidence.get('diagnostic_valid') is not True:
                    self.soft_failures.append('cpu latency diagnostic not verified in force at release')
                    self.record['host_diagnostic_invalid'] = True
                return
        if (self.cfg.get('host_diagnostic') or {}).get('cpu_latency'):
            self.record['cpu_latency_diagnostic'] = None
            self.soft_failures.append('cpu latency diagnostic: no release evidence from vision_run.py restore')
            self.record['host_diagnostic_invalid'] = True

    def set_fixture(self, fixture, delay_ms):
        """separate_ack: the emulated relay (separate ACK, delayed response); piggyback: fixture off."""
        self.record['fixture'] = dict(mode='physical_relay', emulated=False)
        return

    def arm_record(self, fixture, arm):
        for rec in self.record['arms']:
            if rec['arm'] == arm['name'] and rec['fixture'] == fixture:
                return rec
        rec = {'fixture': fixture, 'arm': arm['name'], 'T': arm['T'], 'padding': arm['padding'], 'build': arm['build'], 'trials': [], 'achieved_shaping': None}
        self.record['arms'].append(rec)
        return rec

    def run_unit(self, unit, port):
        """One cold bring-up and one connection: swap, ports, install, T, snapshot, traffic, then ALWAYS the
        collection phase (after snapshot, teardown, logs, manifest, endpoint outputs), then the verdict."""
        c, R = (self.cfg, self.R)
        fixture, arm, i, reads, preset = (unit['fixture'], unit['arm'], unit['i'], unit['reads'], unit['preset'])
        aux, build, tr = (R + '/aux', arm['build'], c['traffic'])
        b = c['builds'][build]
        n, out_remote = (arm['name'], '%s/out_%s' % (R, build))
        label = self.label(unit)
        conf = '%s/response_only_hw_%s.conf' % (R, label)
        manifest, log = ('%s/bringup_manifest_%s.json' % (R, label), '%s/switchd_%s.log' % (R, label))
        rec = self.arm_record(fixture, arm)
        trial = {'fixture': fixture, 'label': label, 'master_port': port, 'reads': reads, 'ok': False, 'failures': [], 'max_token_stale': checks.max_token_stale(b), 'reconnect_policy': self.reconnect_policy, 'diagnostic': b.get('diagnostic', False), 'preset': preset or c['shaping']['preset'], 'conditions': {k: unit[k] for k in ('delay_ms', 'gap_ms', 'start_delay_ms', 'start_seed')}}
        if 'diag_mirror' in c:
            trial['diag_mirror'] = self.diag_label()
        rec['trials'].append(trial)
        pair = None
        if unit['pair'] is not None:
            pairs = self.record.setdefault('pairs', [])
            if not pairs or pairs[-1]['pair'] != unit['pair']:
                pairs.append({'pair': unit['pair'], 'condition': unit['condition'], 'order': unit['order'], 'labels': [], 'ok': False})
            pair = pairs[-1]
            pair['labels'].append(label)
        dest = os.path.join(self.root, fixture, n, label)
        if not self.rn.dry:
            os.makedirs(os.path.join(dest, 'snapshots'))
        err, v, state = (None, None, {'installed': False, 'ran': False, 'before': False, 'after': False})
        try:
            self.step('switch', '%s: PCI vendor must be Barefoot/Intel (0x1d1c)' % label, 'test "$(cat /sys/bus/pci/devices/%s/vendor)" = 0x1d1c' % b['pcie'])
            self.step('switch', '%s: make the bf_switchd conf for this build' % label, 'python3 %s/%s/make_conf.py %s --remote-dir %s --pcie %s -o %s' % (R, HW, out_remote, out_remote, b['pcie'], conf))
            self.switch_touched = True
            self.step('switch', '%s: cold-swap bf_switchd to the composite (stop, launch, wait for :50052)' % label, 'bash %s/switch_swap.sh %s %s/launch_composite.sh %s %s' % (aux, log, aux, conf, b['sde']))
            self.step('switch', '%s: replay the pre-run $PORT snapshot' % label, 'python3 %s/restore_ports.py %s %s --apply --wait 35' % (aux, c['program'], self.prerun))
            comp = self.installer_cmd(build, arm['padding'], out_remote, port, preset)
            self.step('switch', '%s: composite install dry-run (hash check, name check, ports it will loop)' % label, comp)
            self.standing.append(manifest)
            state['installed'] = True
            r = self.step('switch', '%s: composite install apply (loopback first, apps enabled last)' % label, self.hw_env(comp + ' --apply --enable-pktgen --manifest-out %s' % manifest))
            self.save(dest, 'install.log', r)
            self.record['bringups'].append({'label': label, 'fixture': fixture, 'arm': n, 'trial': i, 'master_port': port, 'padding': arm['padding'], 'T': arm['T'], 'manifest': manifest})
            self.step('switch', '%s: select T (0=Timing OFF, 1=Obfuscated)' % label, self.hw_env(self.switch_cmd('set_enabled.py', '--manifest %s --enabled %d' % (manifest, arm['T']))))
            self.snapshot(out_remote, label + '_before', preset=preset)
            state['before'] = True
            state['ran'] = True
            vision = runner.vision_cmd(label, port, reads, tr['range'], unit['gap_ms'], unit['start_delay_ms'],
                                       unit['start_seed'], drop=unit.get('drop'), scenario=unit.get('scenario'),
                                       reconnect_port=port + c['scenarios'][unit['scenario']]['reconnect_port_offset']
                                       if unit.get('scenario') else None)
            vision = (vision.replace(runner.V_RUN, self.V).replace('sudo python3', RELAY_PYTHON)
                      + self.endpoint_control_args() + self.endpoint_binary_arg() + self.pad_expect_arg(arm)
                      + self.qualify_capture_arg(arm) + self.mirror_iface_arg())
            v = self.step('vision', '%s: traffic + capture on master port %d' % (label, port), vision, check=False)
            self.save(dest, 'vision_run.out', v)
            state['after'] = True
            self.snapshot(out_remote, label + '_after', check=False, preset=preset)
        except (StepFailed, OSError) as e:
            err = e
            if isinstance(e, StepFailed) and e.result is not None:
                self.save(dest, 'install.log' if state['installed'] and (not state['before']) else 'failed_step.log', e.result)
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
            pair['ok'] = len(pair['labels']) == 2 and all((t['ok'] for a in self.record['arms'] for t in a['trials'] if t['label'] in pair['labels']))

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
        if not self.rn.dry and (not entry['ok']):
            sys.stderr.write('COLLECTION FAILED: %s %s: %s\n' % (label, what, entry['error']))
        return entry

    def collect_unit(self, label, dest, out_remote, manifest, log, state, preset=None):
        """Runs after success AND failure, before any restore: tear the install down (output kept), then fetch
        everything the unit produced. Every step is independent of the others."""
        R, host, vhost = (self.R, self.cfg['hosts']['switch'], self.cfg['hosts']['vision'])
        if state['installed']:
            if not state['after']:
                state['after'] = True
                try:
                    self.snapshot(out_remote, label + '_after', check=False, preset=preset)
                except Exception:
                    pass
            entry = {'unit': label, 'what': 'teardown', 'ok': False, 'error': None}
            try:
                r = self.rn.run('switch', self.hw_env(self.switch_cmd('bringup_teardown.py', '--manifest %s --apply' % manifest)), timeout=1800, label='%s: teardown the composite (generator and T off, rows out, loopback off last)' % label)
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
            self.collect(label, 'before snapshot', 'local', 'scp -q %s:%s/snap/%s_before.json %s/' % (host, R, label, snapdir))
        if state['after']:
            self.collect(label, 'after snapshot', 'local', 'scp -q %s:%s/snap/%s_after.json %s/' % (host, R, label, snapdir))
        if state['ran']:
            self.collect(label, 'vision run directory', 'local', 'scp -qr %s:%s/runs/%s/* %s/' % (vhost, self.V, label, q(dest)))
        self.collect(label, 'switch log', 'local', fetch(log))
        if state['installed']:
            self.collect(label, 'bring-up manifest', 'local', fetch(manifest))

    def relay_verdict(self, trial, rec, label, dest, v, arm, fixture, connections=None, raise_on_failure=True, close_mode=None):
        """Physical observations and switch counters; no software callbacks or reflected-copy assumptions."""
        if self.rn.dry:
            return
        import relay_check
        failures, observed, application_failures, standards_failures = ([], {}, [], [])
        controls = checks.planned_controls(self.cfg['traffic'])        # OPERATE 0 only for declared select-only
        sbo, planned = controls['SELECT'], dict(READ=trial['reads'], **controls)
        select_only = {'select_only': True} if checks.sbo_select_only(self.cfg['traffic']) else {}
        connections = connections or {'single': (dest, trial['master_port'])}
        reports = {}
        for name, (directory, port) in connections.items():
            try:
                report = relay_check.analyze(directory, port, planned, self.cfg['traffic']['read_schedule'],
                                             **select_only)
                master = json.loads((Path(directory) / 'master.json').read_text())
                for direction, packets in report['packets'].items():
                    for packet in packets:
                        header = 40 if direction == 'out' else 44
                        if packet['flags'] & 2:
                            if packet['tcp_header_bytes'] != header:
                                report['failures'].append('SYN header differs from selected physical TCP profile')
                        elif packet['payload_len'] and (packet['tcp_header_bytes'] != 32 or packet['ipv4_header_bytes'] != 20 or (not packet['tcp_options_hex'].startswith('0101080a'))):
                            report['failures'].append('data header/options differ from selected physical TCP profile')
                native_connection = name == 'c2' and self.scenario == 'reconnect'
                padded = bool(arm['padding'] and (not native_connection))
                for record in master['records']:
                    operation, workload = (record['operation'], record.get('workload'))
                    expected = standards.SEL751_IMAGES[padded].get(workload if operation == 'READ' else operation)
                    if len(bytes.fromhex(record.get('response_wire_hex', ''))) != expected:
                        report['failures'].append('response length differs from selected relay image: ' + operation)
                report['ok'] = not report['failures']
                if close_mode is not None:
                    report['failures'] += relay_check.close_checks(report, close_mode)
                    report['ok'] = not report['failures']
                (Path(directory) / 'relay_wire.json').write_text(json.dumps(report, indent=2) + '\n')
                reports[name] = report
                application_failures += [name + ': ' + error for error in report['failures']]
                observed[name] = dict(application=report['ok'],
                                      master_acceptance=master.get('ok') is True and master.get('counts') == planned,
                                      visible_clrt=relay_check.visible_clrt(report))
            except (OSError, ValueError, KeyError, TypeError) as error:
                application_failures.append(name + ': missing/malformed physical relay evidence: ' + str(error))
            try:
                errors = self.validate_standards_file(directory, trial, arm, {key: {'path': os.path.join(directory, filename)} for key, filename in (('out', 'out.pcap'), ('in', 'in.pcap'), ('master', 'master.json'), ('relay_wire', 'relay_wire.json'))}, None, connection_id=None if name == 'single' else name, unbound_native=name == 'c2' and self.scenario == 'reconnect', master_port=port)
            except Exception as error:
                errors = ['standards not evaluated: %s: %s' % (type(error).__name__, error)]
            standards_failures += [name + ': ' + error for error in errors]
        snapshots = checks.load_evidence_files(before=os.path.join(dest, 'snapshots', label + '_before.json'), after=os.path.join(dest, 'snapshots', label + '_after.json'))
        build = self.cfg['builds'][arm['build']]
        installed = len(connections) - int(self.scenario == 'reconnect')
        installed_reports = [report for name, report in reports.items() if not (self.scenario == 'reconnect' and name == 'c2')]
        read_piggybacks = sum((row['operation'] == 'READ' and row['piggyback'] for report in installed_reports for row in report['exchanges']))
        control_piggybacks = sum((row['operation'] in ('SELECT', 'OPERATE') and row['piggyback'] for report in installed_reports for row in report['exchanges']))
        switch_failures, switch_observed = checks.evaluate_switch(
            self.cfg['expectations'], arm, installed * trial['reads'], snapshots, checks.allowed_gap(build),
            self.cfg['service']['k'] if build.get('mirror_fix') else None, checks.max_token_stale(build),
            diagnostic=build.get('diagnostic', False), sbo_count=installed * sbo, piggyback_reads=read_piggybacks,
            piggyback_controls=control_piggybacks, control_timed=bool(build.get('control_timed')),
            piggyback_bound=bool(build.get('piggyback_bound')),
            gen_exhausted_outcome=build.get('gen_exhausted_outcome'), timing_contract=self.cfg.get('timing_contract'),
            telemetry=build.get('switch_telemetry') is not False,
            operate_count=installed * controls['OPERATE'])
        mirror_failures = self.diag_mirror_evidence(trial, dest)
        failures = application_failures + failures + switch_failures + standards_failures + mirror_failures
        if v is None or v.rc:
            failures.append('physical relay Vision workload failed')
        trial.update(ok=not failures, failures=failures, observed=dict(connections=observed, switch=switch_observed), endpoint_profile='sel751', dimension_verdicts=dict(application=not application_failures, switch=not switch_failures, standards=not standards_failures))
        if 'diag_mirror' in self.cfg:
            trial['dimension_verdicts']['diag_mirror'] = not mirror_failures
        (Path(dest) / 'trial.json').write_text(json.dumps(trial, indent=2) + '\n')
        if raise_on_failure and (application_failures or switch_failures or standards_failures or mirror_failures
                                 or (v is None) or v.rc):
            raise StepFailed('physical relay application/switch gate failed: ' + '; '.join(failures[:4]))
        return trial

    def verdict(self, trial, rec, label, dest, v, arm, fixture):
        return self.relay_verdict(trial, rec, label, dest, v, arm, fixture)

    def verdict_loss(self, trial, rec, label, dest, v, arm, fixture, unit, port):
        self.relay_verdict(trial, rec, label, dest, v, arm, fixture, raise_on_failure=False)
        if self.rn.dry:
            return
        import relay_loss
        loaded = {}
        for name in ('result.json', 'relay_wire.json'):
            try:
                loaded[name] = json.loads(Path(dest, name).read_text())
            except (OSError, ValueError) as error:
                loaded[name] = None
                trial['failures'].append('%s missing or unreadable: %s' % (name, error))
        result = loaded['result.json'] or {}
        failures = relay_loss.target_checks(result.get('loss') or {}, loaded['relay_wire.json'], port) if loaded['relay_wire.json'] is not None else ['physical loss target unverifiable']
        trial['loss'] = result.get('loss')
        trial['failures'] += failures
        trial['dimension_verdicts']['loss_target'] = not failures
        trial['observed']['loss_timing'] = 'capture includes intentionally dropped attempts'
        trial['ok'] = not trial['failures']
        Path(dest, 'trial.json').write_text(json.dumps(trial, indent=2) + '\n')
        if v.rc not in (0, 1):
            raise StepFailed('physical relay loss trial infrastructure failure (Vision run rc %s)' % v.rc)
        if failures or not trial['dimension_verdicts']['application'] or trial['dimension_verdicts'].get('standards') is not True or v.rc:
            self.soft_failures.append(label)
        return

    def verdict_scenario(self, trial, label, dest, v, arm):
        return self.relay_verdict(trial, {}, label, dest, v, arm, 'physical_relay', connections={name: (os.path.join(dest, name), trial['master_port'] + (self.cfg['scenarios']['reconnect']['reconnect_port_offset'] if name == 'c2' else 0)) for name in ('c1', 'c2', 'c3')}, close_mode='graceful')

    def installer_cmd(self, build, padding, out_remote, port, preset=None):
        c = self.cfg
        e = c['endpoints']
        pm = c['ports_map']
        t = c['timing_params_ns']
        expects = ' '.join(('--expect %s=%s' % (name, digest) for name, digest in sorted(self.bound[build].items())))
        timing = '--t-gap %d --t-budget %d --t-enabled %d' % (t['gap'], t['budget'], t['enabled'])
        cmd = ('python3 %s/%s/bringup_composite.py --build-out %s %s --master-ip %s --master-port %d --master-dev %d '
               '--relay-ip %s --relay-port %d --relay-dev %d --read-dst 0x%04x --read-src 0x%04x %s --k %d %s '
               '--pad-enable %d' % (self.R, HW, out_remote, expects, e['master_ip'], port, pm['master_dev'],
                                    e['outstation_ip'], e['outstation_port'], pm['relay_dev'],
                                    *installer_read_addresses(c), timing, c['service']['k'],
                                    shaping_args(c, preset=preset), padding))
        if 'diag_mirror' in c:
            cmd += ' --diag-mirror %s' % c['diag_mirror']['state']
        return cmd

    def snapshot(self, out_remote, name, check=True, preset=None):
        spec = self.cfg.get('diagnostic_mau_snapshot')
        return self.step('switch', 'counter snapshot %s' % name, check=check, cmd=self.hw_env(self.switch_cmd('snapshot_counters.py', '--build-out %s --ports %s %s -o %s/snap/%s.json%s' % (out_remote, self.cfg['ports_map']['stat_ports'], shaping_args(self.cfg, burst=False, preset=preset), self.R, name, ' --mau-snapshot %s' % q(spec) if spec else ''))))

    def restore(self):
        c, R = (self.cfg, self.R)
        ok = True

        def attempt(where, label, cmd):
            nonlocal ok
            try:
                r = self.rn.run(where, cmd, timeout=1800, label=label)
                bad = r.rc != 0
            except Exception as e:
                r, bad = (Result(1, '', str(e)), True)
            self.record['restore'].append({'step': label, 'rc': r.rc, 'ok': not bad})
            if not self.rn.dry:
                self.out('[restore:%s] %s -> rc %d' % (where, label, r.rc))
                if where == 'vision' and 'vision_run.py restore' in cmd:
                    self.save(self.root, 'vision_restore.out', r)
                    self.host_diagnostic_evidence(r.out)
            if bad:
                ok = False
                sys.stderr.write('RESTORE STEP FAILED: %s (rc %d) %s\n' % (label, r.rc, (r.err or r.out)[-300:]))
        for manifest in list(self.standing):
            attempt('switch', 'teardown the composite still installed', self.hw_env(self.switch_cmd('bringup_teardown.py', '--manifest %s --apply' % manifest)))
        p, aux = (c['production'], R + '/aux')
        if self.switch_touched:
            attempt('switch', 'cold-swap bf_switchd back to the observed production program', 'bash %s/switch_swap.sh %s/switchd_production_%s.log %s' % (aux, R, self.run_id, p['launch_script']))
            attempt('switch', 'replay the pre-run $PORT snapshot on the production program', 'python3 %s/restore_ports.py %s %s --apply --wait 35' % (aux, p['program'], self.prerun))
            if p.get('relay_slot'):
                attempt('switch', 'reinstall the relay slot', 'python3 %s/switch_slot.py relay' % aux)
        if self.vision_touched:
            attempt('vision', 'Vision: fixture off, namespace profile and NIC flag restored', RELAY_PYTHON + ' %s/vision_run.py restore' % self.V + ' --endpoint-profile sel751')
        if self.vision_touched or self.switch_touched:
            pg = p['ping']
            attempt('vision', 'ping through the restored switch path', 'ping -c %d -I %s %s' % (pg['count'], pg['src'], pg['dst']))
        return ok

    def finish(self, dry):
        if dry:
            return
        c = self.cfg
        self.record['effective'] = {'timing_params_ns': c['timing_params_ns'], 'timing_contract': c.get('timing_contract'), 'qualification_dimensions': c.get('qualification_dimensions', {}), 'k': c['service']['k'], 'shaping_requested': resolve_shaping(c), 'fixture': c['fixture'], 'trials': c['trials'], 'traffic': dict(c['traffic'], **self.endpoint_controls()), 'ports_map': c['ports_map'], 'endpoints': c['endpoints'], 'evaluation': reported_evaluation(c.get('evaluation', {})), 'reconnect_policy': self.reconnect_policy, 'max_token_stale': {name: checks.max_token_stale(c['builds'][name]) for name in selected_builds(c, self.arms)}, 'endpoint_identity': c['endpoint'], 'vision_run_dir': self.V}
        self.record['config_sha256'] = self.config_sha256
        self.record['config_file_sha256'] = self.config_file_sha256
        self.record['source_identity'] = {'runner_files': self.runner_identity, 'build_sources': {}}
        for name in selected_builds(c, self.arms):
            manifest = json.load(open(path_of(c['builds'][name]['manifest'])))
            self.record['source_identity']['build_sources'][name] = {key: manifest.get(key) for key in ('source_sha256', 'source_files', 'compiler_sha256')}
        self.record['builds'] = getattr(self, 'bound', None)
        self.record['paired_block'] = self.paired
        self.record['time'] = time.time()
        json.dump(self.record, open(os.path.join(self.root, 'campaign_run.json'), 'w'), indent=1, default=str)

def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=('validate', 'plan', 'run'))
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
    ap.add_argument('--all-builds', action='store_true', help='validate: audit every configured build')
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
        print('config OK and bound: %d arms over %d build(s), %d trials/arm' % (len(selected.arms), len(selected_builds(cfg, selected.arms, a.all_builds)), cfg['trials']['trials_per_arm']))
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
