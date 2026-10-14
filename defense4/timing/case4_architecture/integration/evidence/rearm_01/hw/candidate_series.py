#!/usr/bin/env python3
"""Candidate same-tuple series harness.

This is a thin campaign wrapper around candidate_campaign.py.  It keeps the
ordinary guarded install/rollback flow, but replaces the Vision traffic step
with vision_candidate.py so one installed tuple is exercised by three
consecutive connections without a switch reinitialize between incarnations.

This harness proves the protected same-tuple series and lifecycle/readiness
state.  Delayed old-token and retained-old-packet replay remain separate
diagnostic fixtures.
"""
import argparse
import json
import os
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[3]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ARCH / 'protocol' / 'hw_vepa'))

import candidate_campaign  # noqa: E402
import campaign as base  # noqa: E402
import checks  # noqa: E402
import wire_check as wc  # noqa: E402
from privileged_python import authorized_python


VISION_EXTRA = {
    'token_window.py': HERE / 'token_window.py',
    'snapshot_lifecycle.py': HERE / 'snapshot_lifecycle.py',
    'vision_candidate.py': HERE / 'vision_candidate.py',
    'capture_observation.py': ARCH / 'protocol' / 'hw_vepa' / 'capture_observation.py',
    'wire_check.py': ARCH / 'protocol' / 'hw_vepa' / 'wire_check.py',
    'clrt_check.py': ARCH / 'protocol' / 'hw_vepa' / 'clrt_check.py',
    'checks.py': ARCH / 'protocol' / 'hw_vepa' / 'checks.py',
}
SWITCH_EXTRA = (HERE / 'snapshot_lifecycle.py',)
LIMITATIONS = (
    'old retained packet replay is proven by replay_old_packets.py, not this series harness',
    'delayed internal token proof is a separate IPG diagnostic, not a precision qualification',
)


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
        raise ValueError('register %s has no readable integer field%s' %
                         (table, ' matching ' + field_pat if field_pat else ''))
    return ints[0]


def _pick(registers, role, predicate):
    names = sorted(name for name in registers if predicate(name))
    if len(names) != 1:
        raise ValueError('expected exactly one %s lifecycle register, observed %s' % (role, names))
    return names[0]


def lifecycle_gate(snapshot, close_mode='graceful'):
    """Validate full lifecycle snapshot after the three-incarnation series.

    The snapshot_lifecycle.py output preserves hardware table names and fields.
    This gate records the actual selected schema names and fails closed if the
    candidate no longer exposes an unambiguous N/E/T epoch and N WorkRecord.
    """
    failures, observed = [], {}
    registers = snapshot.get('registers') if isinstance(snapshot, dict) else None
    if not isinstance(registers, dict) or not registers:
        return ['missing lifecycle register snapshot'], observed
    if snapshot.get('valid') is not True or snapshot.get('errors') or snapshot.get('software_read_fallbacks'):
        failures.append('lifecycle snapshot is not a complete hardware read')
    try:
        n_epoch = _pick(registers, 'N epoch',
                        lambda name: 'epoch' in name.lower() and re.search(r'(^|[.])n(_|[.]|$)|[.]N[.]', name))
        e_epoch = _pick(registers, 'E epoch',
                        lambda name: 'epoch' in name.lower() and re.search(r'(^|[.])(e|r)_?egress|[.]E[.]', name, re.I))
        t_epoch = _pick(registers, 'T epoch',
                        lambda name: 'epoch' in name.lower() and re.search(r'(^|[.])t(_|[.]|$)|[.]T[.]', name))
        work = _pick(registers, 'N WorkRecord',
                     lambda name: 'work' in name.lower() and re.search(r'(^|[.])n(_|[.]|$)|[.]N[.]', name))
        owner = _pick(registers, 'N owner',
                      lambda name: name.lower().endswith('.owner') and re.search(r'(^|[.])n(_|[.]|$)|[.]N[.]', name))
        epochs = {'N': _field_int(registers, n_epoch), 'E': _field_int(registers, e_epoch),
                  'T': _field_int(registers, t_epoch)}
        e_raw = epochs['E']
        t_raw = epochs['T']
        sealed_encoding = snapshot.get('T_epoch_sealed_encoding') is True
        epochs['E'] &= 0x7fffffff
        if sealed_encoding:
            epochs['T'] &= 0x7fffffff
            if not t_raw & 0x80000000:
                failures.append('T must be sealed after c3 close')
        phase = _field_int(registers, work, r'phase')
        generation = _field_int(registers, work, r'generation|gen')
        owner_value = _field_int(registers, owner)
        observed['epochs'] = {'registers': {'N': n_epoch, 'E': e_epoch, 'T': t_epoch}, 'values': epochs}
        observed['epochs']['E_raw'] = e_raw
        observed['epochs']['T_raw'] = t_raw
        observed['epochs']['T_sealed'] = bool(t_raw & 0x80000000) if sealed_encoding else None
        observed['epochs']['E_FIRST_latched'] = bool(e_raw & 0x80000000)
        observed['work'] = {'register': work, 'phase': phase, 'generation': generation}
        observed['owner'] = {'register': owner, 'value': owner_value,
                             'phase': owner_value >> 16, 'generation': owner_value & 0xffff}
        # FIRST_SYN uses the monotonic packet Work generation as its epoch.
        # The owner's low 16 bits separately count connection incarnations.
        if not 0 < epochs['N'] <= 0x7ffffffe or len(set(epochs.values())) != 1:
            failures.append('N/E/T epochs must agree on a nonzero bounded Work generation: %s' % epochs)
        if phase != 4:
            failures.append('N WorkRecord phase must be retired/free phase 4 after c3 close, observed %s' % phase)
        if not 0 < generation <= 0x7ffffffe:
            failures.append('N packet WorkRecord generation is not readable and bounded')
        if epochs['N'] > generation:
            failures.append('current epoch exceeds the allocated packet Work generation')
        if not observed['epochs']['E_FIRST_latched']:
            failures.append('E FIRST must be latched for the current connection')
        retired = 0x200 if close_mode == 'rst' else 0x10f
        if owner_value != (retired << 16) | 3:
            failures.append('N owner must be retired with current connection generation3')
    except ValueError as error:
        failures.append(str(error))
    return failures, observed


def freshness_gate(sent, returned, port, previous=None):
    flow = tuple(sorted((('192.168.10.61', port), ('192.168.10.62', 20000))))
    sent = [packet for packet in sent if packet['flow'] == flow]
    returned = [packet for packet in returned if packet['flow'] == flow]
    mask = 0xffffffff
    clients = {p['seq'] for p in sent if p['flags'] == wc.SYN and p['dir'] == 'M->O'}
    servers = {p['seq'] for p in sent if p['flags'] == wc.SYN | wc.ACK and p['dir'] == 'O->M'}
    if len(clients) != 1 or len(servers) != 1:
        raise ValueError('missing or ambiguous fresh SYN/SYNACK')
    client, server = next(iter(clients)), next(iter(servers))
    if any(p['ack'] != (client + 1) & mask for p in sent if p['flags'] == wc.SYN | wc.ACK):
        raise ValueError('fresh SYNACK does not acknowledge current client ISN')
    if not any(p['dir'] == 'M->O' and p['flags'] == wc.ACK and not p['len'] and
               p['seq'] == (client + 1) & mask and p['ack'] == (server + 1) & mask for p in sent):
        raise ValueError('fresh handshake final ACK missing')
    observed = {'client_isn': client, 'server_isn': server, 'frontiers': {}}
    for direction, name, isn in (('M->O', 'client', client), ('O->M', 'server', server)):
        spans = [((p['seq'] - isn) & mask) + p['len'] + bool(p['flags'] & wc.SYN) + bool(p['flags'] & wc.FIN)
                 for p in sent if p['dir'] == direction and not p['flags'] & wc.RST]
        if not spans or max(spans) >= 0x80000000:
            raise ValueError('ambiguous current sequence range')
        observed['frontiers'][name] = (isn + max(spans)) & mask
        if previous and not 2 <= (((isn + 1) - previous['frontiers'][name]) & mask) <= 0x7fffffff:
            raise ValueError('new %s ISN overlaps or precedes old connection frontier' % name)
    for packets, label in ((sent, 'native'), (returned, 'returned')):
        responses = [p for p in packets if p['dir'] == 'O->M' and len(p['payload']) >= 17 and
                     p['payload'][12] == 0x81 and p['payload'][15:17] == b'\x0a\x02']
        if not responses or responses[0]['seq'] != (server + 1) & mask:
            raise ValueError('first %s READ response inherited an old mapping offset' % label)
    return observed


def _mapper_reg(snapshot, name, field=None):
    if (snapshot.get('valid') is not True or snapshot.get('errors') or
            snapshot.get('software_read_fallbacks')):
        raise ValueError('mapper requires a complete hardware lifecycle read')
    registers = snapshot['registers']
    table = _pick(registers, 'E mapper ' + name,
                  lambda table: table.lower().startswith('p0.r_egress.') and table.endswith('.' + name))
    return _field_int(registers, table, re.escape(field) + '$' if field else None)


def series_switch_gate(cfg, arm, reads, ev, lifecycle):
    """Switch-only aggregate gate for a three-connection protected candidate series."""
    run_sbo = cfg['traffic'].get('run_sbo', True)
    build = cfg['builds'][arm['build']]
    failures, observed = checks.evaluate_switch(
        cfg['expectations'], arm, 3 * reads, ev, checks.allowed_gap(build),
        cfg['service']['k'] if build.get('mirror_fix') else None,
        checks.max_token_stale(build), diagnostic=build.get('diagnostic', False),
        sbo_count=3 * int(run_sbo), complete_reads=3 * reads, piggyback_reads=0)
    try:
        growth = (_mapper_reg(lifecycle, 'acct', '.lo') - _mapper_reg(lifecycle, 'front')) & 0xffffffff
        unacked = _mapper_reg(lifecycle, 'acct', '.hi')
        image = build.get('image_len', 58)
        expected = (reads * (image - 49) + (2 * (image - 37) if build.get('control_padding', True) else 0)
                    if arm['padding'] else 0)
        observed.update(external_growth_bytes=growth, external_growth_expected=expected, unacked=unacked)
        if growth != expected:
            failures.append('E mapper growth must reflect last generation only: observed %d, expected %d' %
                            (growth, expected))
        if unacked != 0:
            failures.append('E mapper unacked must be zero after c3 close, observed %d' % unacked)
    except (KeyError, IndexError, TypeError, ValueError) as error:
        failures.append('missing or malformed mapper counter evidence: %s' % error)
    # dup_hold_01: an early duplicate OPERATE dropped while held is counted at OUT_OP_DUP_DROP. Required (>= 1)
    # only when the fixture declares it; otherwise any such drop is unexpected.
    dup = (observed.get('outcomes') or {}).get('OUT_OP_DUP_DROP')
    observed['held_operate_dup_drops'] = dup
    if cfg['traffic'].get('expect_held_operate_dup'):
        if type(dup) is not int or dup < 1:
            failures.append('held-OPERATE duplicate expected but OUT_OP_DUP_DROP delta is %r' % (dup,))
    elif dup:
        failures.append('unexpected held-OPERATE duplicate drops: OUT_OP_DUP_DROP delta %d' % dup)
    return failures, observed


class CandidateSeriesCampaign(candidate_campaign.CandidateCampaign):
    def __init__(self, *args, close_mode='graceful', rst_grace_ms=5000, **kwargs):
        if kwargs.get('scenario') is not None or kwargs.get('loss') is not None or kwargs.get('paired') is not None:
            raise ValueError('candidate series uses base scenario=None and its own protected verdict')
        super().__init__(*args, scenario=None, **kwargs)
        self.close_mode = close_mode
        self.rst_grace_ms = rst_grace_ms
        self._series_padding = None
        self._validate_series_shape()
        self.record['candidate_series'] = {
            'close_mode': close_mode, 'rst_grace_ms': rst_grace_ms, 'connections': 3,
            'effective_endpoint_controls': {'read_pause_ms': 25, 'run_sbo': True,
                                            'close_grace_ms': rst_grace_ms if close_mode == 'rst' else 0},
            'limitations': list(LIMITATIONS)}

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
        if self.fixtures != ['separate_ack']:
            raise ValueError('candidate series requires separate_ack qualification fixture')
        if self.cfg.get('trial_mode') != 'per_trial_cold' or self.cfg['trials'].get('trials_per_arm') != 1:
            raise ValueError('candidate series requires exactly one cold trial')
        if self.cfg['trials'].get('reads_per_trial') != 20:
            raise ValueError('candidate series reads_per_trial must be 20')
        if self.cfg['traffic'].get('run_sbo', True) is not True:
            raise ValueError('candidate series requires SBO enabled')
        traffic = self.cfg['traffic']
        if (traffic.get('range'), traffic.get('gap_ms'), traffic.get('start_delay_ms'),
                traffic.get('read_pause_ms', 25), self.cfg['seeds']['rng_seed']) != (8, 0, 0, 25, 12345):
            raise ValueError('candidate series helper requires range8/gap0/start0/pause25/seed12345')
        if self.cfg.get('evaluation', {}).get('read_precision', True) is not True:
            raise ValueError('candidate series requires READ precision gate')

    def endpoint_control_args(self):
        return ''

    def vision_identity(self):
        super().vision_identity()
        host = self.cfg['hosts']['vision']
        identity = {name: base.sha256_file(path) for name, path in VISION_EXTRA.items()}
        self.step('local', 'deploy candidate same-tuple Vision helper and local analyzers',
                  'scp -q %s %s:%s/' %
                  (' '.join(base.q(path) for path in VISION_EXTRA.values()), host, self.V))
        result = self.step('vision', 'verify candidate same-tuple Vision helper identity',
                           'sha256sum ' + ' '.join('%s/%s' % (self.V, name) for name in VISION_EXTRA))
        if not self.rn.dry:
            got = {line.split()[1].rsplit('/', 1)[-1]: line.split()[0]
                   for line in result.out.splitlines() if len(line.split()) == 2}
            for name, want in identity.items():
                if got.get(name) != want:
                    raise base.StepFailed('candidate series Vision helper identity mismatch: %s' % name)
        self.record['candidate_series_vision_identity'] = identity

    def deploy_switch(self):
        super().deploy_switch()
        host = self.cfg['hosts']['switch']
        identity = {str(path): base.sha256_file(path) for path in SWITCH_EXTRA}
        self.step('local', 'copy lifecycle snapshot helper to switch',
                  'scp -q %s %s:%s/aux/' %
                  (' '.join(base.q(path) for path in SWITCH_EXTRA), host, self.R))
        result = self.step('switch', 'verify lifecycle snapshot helper identity',
                           'sha256sum ' + ' '.join('%s/aux/%s' % (self.R, path.name) for path in SWITCH_EXTRA))
        if not self.rn.dry:
            got = {line.split()[1].rsplit('/', 1)[-1]: line.split()[0]
                   for line in result.out.splitlines() if len(line.split()) == 2}
            for path in SWITCH_EXTRA:
                if got.get(path.name) != identity[str(path)]:
                    raise base.StepFailed('candidate series switch helper identity mismatch: %s' % path.name)
        self.record['candidate_series_switch_identity'] = identity

    def series_vision_cmd(self, label, master_port, reads, _rng, _gap_ms, _start_delay_ms=0, _start_seed=0,
                          connect_must_fail=False, drop=None, scenario=None, reconnect_port=None):
        if connect_must_fail or drop or scenario or reconnect_port is not None:
            raise ValueError('candidate series traffic must be one protected installed tuple with no base scenario/drop')
        args = [label, '--master-port', master_port, '--padding', self._series_padding,
                '--control-padding', self._series_control_padding,
                '--image-len', int(self.cfg['builds'][self._series_build].get('image_len', 58)),
                '--expect-held-operate-dup', int(bool(self.cfg['traffic'].get('expect_held_operate_dup', False))),
                '--close-mode', self.close_mode,
                '--rst-grace-ms', self.rst_grace_ms, '--reads', reads, '--apply']
        if self.cfg['builds'][self._series_build].get('profile') == 'candidate61':
            args.append('--qualify-capture')
        return authorized_python(base.runner.V_RUN + '/vision_candidate.py', args)

    def run_unit(self, unit, port):
        old = base.runner.vision_cmd
        self._series_padding = unit['arm']['padding']
        self._series_control_padding = int(self.cfg['builds'][unit['arm']['build']].get('control_padding', True))
        self._series_build = unit['arm']['build']
        base.runner.vision_cmd = self.series_vision_cmd
        try:
            return super().run_unit(unit, port)
        finally:
            base.runner.vision_cmd = old
            self._series_padding = None

    def snapshot(self, out_remote, name, check=True, preset=None):
        result = super().snapshot(out_remote, name, check=check, preset=preset)
        cmd = ('python3 %s/aux/snapshot_lifecycle.py --build-out %s --switch-tools %s/%s '
               '--program response_only --output %s/snap/%s_lifecycle.json' %
               (self.R, out_remote, self.R, base.HW, self.R, name))
        self.step('switch', 'lifecycle snapshot %s' % name, cmd, check=check)
        return result

    def collect_unit(self, label, dest, out_remote, manifest, log, state, preset=None):
        super().collect_unit(label, dest, out_remote, manifest, log, state, preset=preset)
        host = self.cfg['hosts']['switch']
        snapdir = base.q(os.path.join(dest, 'snapshots'))
        if state.get('before'):
            self.collect(label, 'before lifecycle snapshot', 'local',
                         'scp -q %s:%s/snap/%s_before_lifecycle.json %s/' % (host, self.R, label, snapdir))
        if state.get('after'):
            self.collect(label, 'after lifecycle snapshot', 'local',
                         'scp -q %s:%s/snap/%s_after_lifecycle.json %s/' % (host, self.R, label, snapdir))

    def _vision_json(self, result):
        if result is None:
            return {'error': 'vision command did not run'}
        for offset, char in enumerate(result.out):
            if char == '{':
                try:
                    value, _ = json.JSONDecoder().raw_decode(result.out[offset:])
                    if isinstance(value, dict) and value.get('scenario') == 'candidate_same_tuple':
                        return value
                except ValueError:
                    continue
        return {'error': (result.out + result.err)[-500:]}

    def _connection_evidence(self, dest, cn):
        root = os.path.join(dest, cn)
        return checks.load_evidence_files(master=os.path.join(root, 'master.json'),
                                          outstation=os.path.join(root, 'outstation.json'),
                                          wire=os.path.join(root, 'wire.json'),
                                          timing=os.path.join(root, 'timing.json'))

    def verdict(self, trial, rec, label, dest, v, arm, fixture):
        tool_rcs = {}
        for cn in ('c1', 'c2', 'c3'):
            d = os.path.join(dest, cn)
            wire = self.step('local', '%s/%s: independent wire verification' % (label, cn),
                             '%s %s/wire_check.py %s %s --json %s' %
                             (base.runner.PY, base.q(ARCH / 'protocol/hw_vepa'), base.q(d + '/out.pcap'),
                              base.q(d + '/in.pcap'), base.q(d + '/wire.json')), check=False)
            timing = self.step('local', '%s/%s: per-exchange timing extraction' % (label, cn),
                               '%s %s/clrt_check.py %s %s --json %s' %
                               (base.runner.PY, base.q(ARCH / 'protocol/hw_vepa'), base.q(d + '/out.pcap'),
                                base.q(d + '/in.pcap'), base.q(d + '/timing.json')), check=False)
            tool_rcs[cn] = {'wire_rc': wire.rc, 'clrt_rc': timing.rc}
        if self.rn.dry:
            return
        result = self._vision_json(v)
        failures, connections, previous = [], {}, None
        run_sbo = self.cfg['traffic'].get('run_sbo', True)
        for cn in ('c1', 'c2', 'c3'):
            ev = self._connection_evidence(dest, cn)
            cfail = checks.application_checks(self.cfg['expectations'], arm['padding'], trial['reads'], ev, run_sbo)
            fresh = None
            try:
                fresh = freshness_gate(wc.parse(os.path.join(dest, cn, 'out.pcap'))[0],
                                       wc.parse(os.path.join(dest, cn, 'in.pcap'))[0], trial['master_port'], previous)
                previous = fresh
            except (OSError, ValueError, IndexError, KeyError) as error:
                cfail.append('fresh mapping: ' + str(error))
            precision = checks.read_precision(ev.get('timing') or {}, self.cfg['timing_params_ns']['gap'])
            precision['gated'] = bool(arm['T'] and fixture == 'separate_ack' and
                                      self.cfg.get('evaluation', {}).get('read_precision', True))
            if precision['gated'] and not precision['pass']:
                cfail.append('READ precision did not qualify: eligible%d, p99 absolute error%s us' %
                             (precision['eligible'], (precision['absolute_error_us'] or {}).get('p99')))
            for name, rc in tool_rcs[cn].items():
                if rc:
                    cfail.append('%s=%d' % (name, rc))
            scenario = _load_json(os.path.join(dest, cn, 'verdict.json')) or {}
            if scenario.get('ok') is not True:
                cfail.append('vision_candidate per-connection verdict failed')
            outstation = ev.get('outstation') or {}
            cfail.extend(self.validate_standards_file(
                os.path.join(dest, cn), trial, arm,
                {'out': {'path': os.path.join(dest, cn, 'out.pcap')},
                 'in': {'path': os.path.join(dest, cn, 'in.pcap')}},
                self.standards_observed(
                    ev, list(cfail), transport_ok=(tool_rcs[cn]['wire_rc'] == 0),
                    select_ok=(not run_sbo) or outstation.get('select_real') == 1,
                    operate_ok=(not run_sbo) or outstation.get('operate_real') == 1,
                    aggregate_ok=not cfail, precision_required=precision['gated'], precision=precision,
                    precision_reason='series %s: READ precision not gated (timed=%s, fixture=%s)'
                                     % (cn, bool(arm['T']), fixture),
                    checker_result=self.run_standards_checker(os.path.join(dest, cn), trial, arm, cn)),
                connection_id=cn))
            connections[cn] = {'ok': not cfail, 'failures': cfail, 'read_precision': precision,
                               'fresh_mapping': fresh, **tool_rcs[cn]}
            failures.extend('%s: %s' % (cn, failure) for failure in cfail)
        if v.rc or result.get('ok') is not True:
            failures.append('vision_candidate series failed (rc=%d)' % v.rc)
        snapdir = os.path.join(dest, 'snapshots')
        snapshots = checks.load_evidence_files(before=os.path.join(snapdir, '%s_before.json' % label),
                                               after=os.path.join(snapdir, '%s_after.json' % label))
        lifecycle = _load_json(os.path.join(snapdir, '%s_after_lifecycle.json' % label)) or {}
        sfail, sobs = series_switch_gate(self.cfg, arm, trial['reads'], snapshots, lifecycle)
        failures.extend('switch: ' + failure for failure in sfail)
        lfail, lobs = lifecycle_gate(lifecycle, self.close_mode)
        failures.extend('lifecycle: ' + failure for failure in lfail)
        if snapshots.get('after'):
            trial['achieved_shaping'] = rec['achieved_shaping'] = snapshots['after'].get('shaping')
        trial.update(ok=not failures, failures=failures, vision=result,
                     scenario={'policy': 'candidate_same_tuple_protected', 'connections': connections,
                               'installed_connections_expected': 3,
                               'old_replay_and_token_proofs': 'separate diagnostics'},
                     observed={'switch': sobs, 'lifecycle': lobs})
        json.dump(trial, open(os.path.join(dest, 'trial.json'), 'w'), indent=1, default=str)
        if failures:
            raise base.StepFailed('%s failed: %s' % (label, '; '.join(failures)))


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
    runner = base.DryRunner() if args.mode == 'plan' or args.dry_run or not args.apply else base.ShellRunner(cfg['hosts'])
    campaign = CandidateSeriesCampaign(cfg, runner, args.run_id, arms=arms, fixtures=fixtures,
                                       close_mode=args.close_mode, rst_grace_ms=args.rst_grace_ms,
                                       config_path=args.config)
    if args.mode == 'validate':
        errs = base.check_bindings(cfg, campaign.arms)
        if errs:
            sys.exit('refusing: ' + '; '.join(errs))
        print('candidate series config OK: one install, three same-tuple %s connections' % args.close_mode)
        return 0
    if args.mode == 'deploy':
        return campaign.deploy_only()
    if args.mode == 'run' and not args.apply and not args.dry_run:
        sys.exit('run requires --apply or --dry-run')
    return campaign.execute()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        sys.stderr.write('candidate series refused: %s\n' % error)
        sys.exit(2)
