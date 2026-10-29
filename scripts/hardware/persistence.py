"""Current physical SEL-751 persistence: three connections on one installed tuple."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'checks'))
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path[:0] = [str(HERE), str(HERE.parent / 'checks')]
import campaign as candidate_campaign
import campaign_base as base
import checks
VISION_EXTRA = {}
SWITCH_EXTRA = (HERE / 'snapshot_lifecycle.py',)
LIMITATIONS = ('receiver-visible lifecycle and application observations; switch emission is not observed',)

def _load_json(path):
    try:
        data = json.load(open(path))
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None

def _ints(value):
    out = []
    if isinstance(value, bool):
        return out
    if isinstance(value, int):
        return [value]
    if isinstance(value, list):
        for item in value:
            out.extend(_ints(item))
    if isinstance(value, dict):
        for item in value.values():
            out.extend(_ints(item))
    return out

def _field_int(registers, table, field_pat=None):
    values = registers[table]
    if field_pat is None:
        ints = _ints(values)
    else:
        rx = re.compile(field_pat, re.I)
        ints = []
        stack = [('', values)]
        while stack:
            prefix, value = stack.pop()
            if isinstance(value, dict):
                for key, child in value.items():
                    stack.append((key, child))
            elif rx.search(prefix):
                ints.extend(_ints(value))
    if not ints:
        raise ValueError('register %s has no readable integer field%s' % (table, ' matching ' + field_pat if field_pat else ''))
    return ints[0]

def _pick(registers, role, predicate):
    names = sorted((name for name in registers if predicate(name)))
    if len(names) != 1:
        raise ValueError('expected exactly one %s lifecycle register, observed %s' % (role, names))
    return names[0]

def lifecycle_gate(snapshot, close_mode='graceful'):
    """Validate full lifecycle snapshot after the three-incarnation series.

    The snapshot_lifecycle.py output preserves hardware table names and fields.
    This gate records the actual selected schema names and fails closed if the
    candidate no longer exposes an unambiguous N/E/T epoch and N WorkRecord.
    """
    failures, observed = ([], {})
    registers = snapshot.get('registers') if isinstance(snapshot, dict) else None
    if not isinstance(registers, dict) or not registers:
        return (['missing lifecycle register snapshot'], observed)
    if snapshot.get('valid') is not True or snapshot.get('errors') or snapshot.get('software_read_fallbacks'):
        failures.append('lifecycle snapshot is not a complete hardware read')
    try:
        n_epoch = _pick(registers, 'N epoch', lambda name: 'epoch' in name.lower() and 'retry_epoch' not in name.lower() and re.search('(^|[.])n(_|[.]|$)|[.]N[.]', name))
        if 'p0.n_Ingress.retry_epoch' in registers:
            observed['n_retry_epoch'] = _field_int(registers, 'p0.n_Ingress.retry_epoch')
        e_epoch = _pick(registers, 'E epoch', lambda name: 'epoch' in name.lower() and re.search('(^|[.])(e|r)_?egress|[.]E[.]', name, re.I))
        t_epoch = _pick(registers, 'T epoch', lambda name: 'epoch' in name.lower() and re.search('(^|[.])t(_|[.]|$)|[.]T[.]', name))
        work = _pick(registers, 'N WorkRecord', lambda name: 'work' in name.lower() and re.search('(^|[.])n(_|[.]|$)|[.]N[.]', name))
        owner = _pick(registers, 'N owner', lambda name: name.lower().endswith('.owner') and re.search('(^|[.])n(_|[.]|$)|[.]N[.]', name))
        epochs = {'N': _field_int(registers, n_epoch), 'E': _field_int(registers, e_epoch), 'T': _field_int(registers, t_epoch)}
        e_raw = epochs['E']
        t_raw = epochs['T']
        sealed_encoding = snapshot.get('T_epoch_sealed_encoding') is True
        epochs['E'] &= 2147483647
        if sealed_encoding:
            epochs['T'] &= 2147483647
            if not t_raw & 2147483648:
                failures.append('T must be sealed after c3 close')
        phase = _field_int(registers, work, 'phase')
        generation = _field_int(registers, work, 'generation|gen')
        owner_value = _field_int(registers, owner)
        observed['epochs'] = {'registers': {'N': n_epoch, 'E': e_epoch, 'T': t_epoch}, 'values': epochs}
        observed['epochs']['E_raw'] = e_raw
        observed['epochs']['T_raw'] = t_raw
        observed['epochs']['T_sealed'] = bool(t_raw & 2147483648) if sealed_encoding else None
        observed['epochs']['E_FIRST_latched'] = bool(e_raw & 2147483648)
        observed['work'] = {'register': work, 'phase': phase, 'generation': generation}
        observed['owner'] = {'register': owner, 'value': owner_value, 'phase': owner_value >> 16, 'generation': owner_value & 65535}
        if not 0 < epochs['N'] <= 2147483646 or len(set(epochs.values())) != 1:
            failures.append('N/E/T epochs must agree on a nonzero bounded Work generation: %s' % epochs)
        if phase != 4:
            failures.append('N WorkRecord phase must be retired/free phase 4 after c3 close, observed %s' % phase)
        if not 0 < generation <= 2147483646:
            failures.append('N packet WorkRecord generation is not readable and bounded')
        if epochs['N'] > generation:
            failures.append('current epoch exceeds the allocated packet Work generation')
        if not observed['epochs']['E_FIRST_latched']:
            failures.append('E FIRST must be latched for the current connection')
        retired = 512 if close_mode == 'rst' else 271
        if owner_value != retired << 16 | 3:
            failures.append('N owner must be retired with current connection generation3')
    except ValueError as error:
        failures.append(str(error))
    return (failures, observed)

def _mapper_reg(snapshot, name, field=None):
    if snapshot.get('valid') is not True or snapshot.get('errors') or snapshot.get('software_read_fallbacks'):
        raise ValueError('mapper requires a complete hardware lifecycle read')
    registers = snapshot['registers']
    table = _pick(registers, 'E mapper ' + name, lambda table: table.lower().startswith('p0.r_egress.') and table.endswith('.' + name))
    return _field_int(registers, table, re.escape(field) + '$' if field else None)

def scheduled_read_growth(cfg, arm, reads):
    """External growth of one connection's READs under traffic.read_schedule: sum over the scheduled classes of
    count * (image - native), from the per-class expectation for `reads` (vision_candidate issues the schedule)."""
    order = ('mixed', 'integrity') if cfg['traffic']['read_schedule'] == 'mixed_full' else ('mixed',) if cfg['traffic']['read_schedule'] == 'mixed' else ('integrity',)
    native = dict(mixed=91, integrity=134)
    images = cfg['builds'][arm['build']]['read_images']
    return sum((images[order[i % len(order)]] - native[order[i % len(order)]] for i in range(reads))) if arm['padding'] else 0

def series_switch_gate(cfg, arm, reads, ev, lifecycle, piggybacks=None):
    """Switch-only aggregate gate for a three-connection protected candidate series."""
    run_sbo = cfg['traffic'].get('run_sbo', True)
    build = cfg['builds'][arm['build']]
    piggybacks = piggybacks or {}
    failures, observed = checks.evaluate_switch(cfg['expectations'], arm, 3 * reads, ev, checks.allowed_gap(build), cfg['service']['k'] if build.get('mirror_fix') else None, checks.max_token_stale(build), diagnostic=build.get('diagnostic', False), sbo_count=3 * int(run_sbo), complete_reads=3 * reads, piggyback_reads=piggybacks.get('READ', 0), control_timed=bool(build.get('control_timed')), piggyback_bound=bool(build.get('piggyback_bound')), piggyback_controls=piggybacks.get('SELECT', 0) + piggybacks.get('OPERATE', 0), gen_exhausted_outcome=build.get('gen_exhausted_outcome'), timing_contract=cfg.get('timing_contract'), telemetry=build.get('switch_telemetry') is not False)
    try:
        growth = _mapper_reg(lifecycle, 'acct', '.lo') - _mapper_reg(lifecycle, 'front') & 4294967295
        unacked = _mapper_reg(lifecycle, 'acct', '.hi')
        image = build.get('image_len', 58)
        read_growth = scheduled_read_growth(cfg, arm, reads)
        expected = read_growth + (2 * (image - 49) if build.get('control_padding', True) else 0) if arm['padding'] else 0
        observed.update(external_growth_bytes=growth, external_growth_expected=expected, unacked=unacked)
        if growth != expected:
            failures.append('E mapper growth must reflect last generation only: observed %d, expected %d' % (growth, expected))
        if unacked != 0:
            failures.append('E mapper unacked must be zero after c3 close, observed %d' % unacked)
    except (KeyError, IndexError, TypeError, ValueError) as error:
        failures.append('missing or malformed mapper counter evidence: %s' % error)
    return (failures, observed)

class CandidateSeriesCampaign(candidate_campaign.CandidateCampaign):

    def __init__(self, *args, close_mode='graceful', rst_grace_ms=5000, **kwargs):
        if kwargs.get('scenario') is not None or kwargs.get('loss') is not None or kwargs.get('paired') is not None:
            raise ValueError('candidate series uses base scenario=None and its own protected verdict')
        super().__init__(*args, scenario=None, **kwargs)
        self.close_mode = close_mode
        self.rst_grace_ms = rst_grace_ms
        self._validate_series_shape()
        self.record['candidate_series'] = {'close_mode': close_mode, 'rst_grace_ms': rst_grace_ms, 'connections': 3, 'effective_endpoint_controls': {'read_pause_ms': 25, 'run_sbo': True, 'close_grace_ms': rst_grace_ms if close_mode == 'rst' else 0}, 'limitations': list(LIMITATIONS)}

    def _validate_series_shape(self):
        if self.close_mode not in ('graceful', 'rst'):
            raise ValueError('close-mode must be graceful or rst')
        if type(self.rst_grace_ms) is not int or not 500 <= self.rst_grace_ms <= 5000:
            raise ValueError('rst_grace_ms must be an integer in 500..5000')
        if len(self.arms) != 1 or self.arms[0].get('name') != 'combined':
            raise ValueError('candidate series requires exactly one combined arm')
        if self.arms[0].get('T') != 1 or self.arms[0].get('padding') != 1:
            raise ValueError('candidate series requires timing and padding enabled')
        if len(self.fixtures) != 1:
            raise ValueError('candidate series requires exactly one fixture')
        if self.fixtures != ['physical_relay']:
            raise ValueError('candidate series requires separate_ack qualification fixture')
        if self.cfg.get('trial_mode') != 'per_trial_cold' or self.cfg['trials'].get('trials_per_arm') != 1:
            raise ValueError('candidate series requires exactly one cold trial')
        if self.cfg['trials'].get('reads_per_trial') != 20:
            raise ValueError('candidate series reads_per_trial must be 20')
        if self.cfg['traffic'].get('run_sbo', True) is not True:
            raise ValueError('candidate series requires SBO enabled')
        if 'sbo_cycles' in self.cfg['traffic']:
            raise ValueError('candidate series does not carry traffic.sbo_cycles (vision_candidate runs one SBO)')
        base.validate_endpoint_profile(self.cfg)
        if self.cfg['traffic'].get('read_schedule') not in ('mixed_full', 'mixed', 'full'):
            raise ValueError('physical persistence requires a declared relay READ schedule')
        traffic = self.cfg['traffic']
        if (traffic.get('range'), traffic.get('gap_ms'), traffic.get('start_delay_ms'), traffic.get('read_pause_ms', 25), self.cfg['seeds']['rng_seed']) != (8, 0, 0, 25, 12345):
            raise ValueError('physical series requires range8/gap0/start0/pause25/seed12345')
        return

    def endpoint_control_args(self):
        return ''

    def vision_identity(self):
        super().vision_identity()
        return

    def deploy_switch(self):
        super().deploy_switch()
        host = self.cfg['hosts']['switch']
        identity = {str(path): base.sha256_file(path) for path in SWITCH_EXTRA}
        self.step('local', 'copy lifecycle snapshot helper to switch', 'scp -q %s %s:%s/aux/' % (' '.join((base.q(path) for path in SWITCH_EXTRA)), host, self.R))
        result = self.step('switch', 'verify lifecycle snapshot helper identity', 'sha256sum ' + ' '.join(('%s/aux/%s' % (self.R, path.name) for path in SWITCH_EXTRA)))
        if not self.rn.dry:
            got = {line.split()[1].rsplit('/', 1)[-1]: line.split()[0] for line in result.out.splitlines() if len(line.split()) == 2}
            for path in SWITCH_EXTRA:
                if got.get(path.name) != identity[str(path)]:
                    raise base.StepFailed('candidate series switch helper identity mismatch: %s' % path.name)
        self.record['candidate_series_switch_identity'] = identity

    def series_vision_cmd(self, label, master_port, reads, _rng, _gap_ms, _start_delay_ms=0, _start_seed=0, connect_must_fail=False, drop=None, scenario=None, reconnect_port=None):
        if connect_must_fail or drop or scenario or (reconnect_port is not None):
            raise ValueError('candidate series traffic must be one protected installed tuple with no base scenario/drop')
        traffic = self.cfg['traffic']
        return base.RELAY_PYTHON + ' %s/vision_run.py run %s --master-port %d --reads %d --range 8 --gap-ms 0 --scenario persistence --close-mode %s --close-grace-ms %d --read-schedule %s --endpoint-profile sel751 --apply' % (base.runner.V_RUN, label, master_port, reads, self.close_mode, self.rst_grace_ms if self.close_mode == 'rst' else 0, traffic['read_schedule'])

    def run_unit(self, unit, port):
        old = base.runner.vision_cmd
        base.runner.vision_cmd = self.series_vision_cmd
        try:
            return super().run_unit(unit, port)
        finally:
            base.runner.vision_cmd = old

    def snapshot(self, out_remote, name, check=True, preset=None):
        result = super().snapshot(out_remote, name, check=check, preset=preset)
        cmd = 'python3 %s/aux/snapshot_lifecycle.py --build-out %s --switch-tools %s/%s --program response_only --output %s/snap/%s_lifecycle.json' % (self.R, out_remote, self.R, base.HW, self.R, name)
        self.step('switch', 'lifecycle snapshot %s' % name, cmd, check=check)
        return result

    def collect_unit(self, label, dest, out_remote, manifest, log, state, preset=None):
        super().collect_unit(label, dest, out_remote, manifest, log, state, preset=preset)
        host = self.cfg['hosts']['switch']
        snapdir = base.q(os.path.join(dest, 'snapshots'))
        if state.get('before'):
            self.collect(label, 'before lifecycle snapshot', 'local', 'scp -q %s:%s/snap/%s_before_lifecycle.json %s/' % (host, self.R, label, snapdir))
        if state.get('after'):
            self.collect(label, 'after lifecycle snapshot', 'local', 'scp -q %s:%s/snap/%s_after_lifecycle.json %s/' % (host, self.R, label, snapdir))

    def verdict(self, trial, rec, label, dest, v, arm, fixture):
        self.relay_verdict(trial, rec, label, dest, v, arm, fixture, connections={name: (os.path.join(dest, name), trial['master_port']) for name in ('c1', 'c2', 'c3')}, raise_on_failure=False, close_mode=self.close_mode)
        if self.rn.dry:
            return
        snapdir = os.path.join(dest, 'snapshots')
        snapshots = checks.load_evidence_files(before=os.path.join(snapdir, label + '_before.json'), after=os.path.join(snapdir, label + '_after.json'))
        lifecycle = _load_json(os.path.join(snapdir, label + '_after_lifecycle.json')) or {}
        piggybacks = {operation: sum((row['operation'] == operation and row['piggyback'] for name in ('c1', 'c2', 'c3') for row in (_load_json(os.path.join(dest, name, 'relay_wire.json')) or {}).get('exchanges', []))) for operation in ('READ', 'SELECT', 'OPERATE')}
        sfail, sobs = series_switch_gate(self.cfg, arm, trial['reads'], snapshots, lifecycle, piggybacks)
        lfail, lobs = lifecycle_gate(lifecycle, self.close_mode)
        import relay_check
        fresh, previous = ({}, None)
        for name in ('c1', 'c2', 'c3'):
            try:
                previous = relay_check.freshness(_load_json(os.path.join(dest, name, 'relay_wire.json')) or {}, previous)
                fresh[name] = previous
            except (OSError, ValueError, KeyError, TypeError) as error:
                lfail.append(name + ': ' + str(error))
        trial['failures'] += ['switch: ' + error for error in sfail] + ['lifecycle: ' + error for error in lfail]
        trial['observed'].update(series_switch=sobs, lifecycle=lobs, fresh_mapping=fresh)
        trial['scenario'] = dict(policy='physical_same_tuple_protected', installed_connections_expected=3, connections={name: dict(master_port=trial['master_port']) for name in ('c1', 'c2', 'c3')})
        trial['ok'] = not trial['failures']
        Path(dest, 'trial.json').write_text(json.dumps(trial, indent=2) + '\n')
        if sfail or lfail or (not trial['dimension_verdicts']['application']) or (trial['dimension_verdicts'].get('standards') is not True) or v.rc:
            raise base.StepFailed('physical same-tuple application/lifecycle/switch/standards gate failed')
        return

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('validate', 'plan', 'run', 'deploy'))
    parser.add_argument('--config', required=True)
    parser.add_argument('--run-id', default='candidate_series_01')
    parser.add_argument('--arms', default='combined')
    parser.add_argument('--fixtures', default='separate_ack')
    parser.add_argument('--close-mode', choices=('graceful', 'rst'), default='graceful')
    parser.add_argument('--rst-grace-ms', type=int, default=5000)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    cfg = base.load_config(args.config)
    arms = args.arms.split(',') if args.arms else None
    fixtures = args.fixtures.split(',') if args.fixtures else None
    runner = base.DryRunner() if args.mode == 'plan' or args.dry_run or (not args.apply) else base.ShellRunner(cfg['hosts'])
    campaign = CandidateSeriesCampaign(cfg, runner, args.run_id, arms=arms, fixtures=fixtures, close_mode=args.close_mode, rst_grace_ms=args.rst_grace_ms, config_path=args.config)
    if args.mode == 'validate':
        errs = base.check_bindings(cfg, campaign.arms)
        if errs:
            sys.exit('refusing: ' + '; '.join(errs))
        print('candidate series config OK: one install, three same-tuple %s connections' % args.close_mode)
        return 0
    if args.mode == 'deploy':
        return campaign.deploy_only()
    if args.mode == 'run' and (not args.apply) and (not args.dry_run):
        sys.exit('run requires --apply or --dry-run')
    return campaign.execute()
if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        sys.stderr.write('candidate series refused: %s\n' % error)
        sys.exit(2)
