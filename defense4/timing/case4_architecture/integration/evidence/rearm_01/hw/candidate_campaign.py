#!/usr/bin/env python3
"""Explicit candidate CP deployment using the ordinary guarded campaign/rollback.

Uses the same CLI as protocol/hw_vepa/campaign.py. Every selected build must
declare lifecycle_rearm:true; frozen baseline campaigns use their original CLI.
"""
import importlib.util
import sys
import os
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ARCH = HERE.parents[3]
sys.path.insert(0, str(ARCH / 'protocol' / 'hw_vepa'))
import campaign as base

CANDIDATE = 'integration/core/response_only_rearm'
_spec = importlib.util.spec_from_file_location('candidate_generation_headroom',
                                               ARCH / CANDIDATE / 'hw/generation_headroom.py')
HEADROOM = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(HEADROOM)
# Sources whose T admits SELECT and OPERATE on the read lane (ctl_timing_01 m3 and later); a build of one of
# these must declare control_timed, or its generation budget would be READ-only.
CONTROL_TIMED_SOURCES = frozenset({
    'c4819dbac643048c16a9a0534337a938ca2820add0aae5a5bcda43e8b43a9204',   # ctl_timing_01 m3
    '35e896ebcd11f461ea947db3b0fa5198770c547d680ffb4bdec5d885465c79cf',   # ctl_timing_01 m4
    'b758c98199dddd36f8df4a90ce7a1e2301b63e95c2ac766aafa20b5b9f15e981',   # ctl_timing_01 m5 (m5_10)
    '6590141fc68b43788de7e969badf3d6bdf24ba0615a56631497ca39854c0ce0f',   # ctl_timing_01 m9 (m9_01)
    '74c9cdcddbffa89589f2ed656f732328d9cc263d32877a74bab9a19ef269854f',   # DIAGNOSTIC ctl_timing_01 m9d (m9d_01)
})
EXTRA_FILES = (CANDIDATE + '/cp.py', CANDIDATE + '/hw/bringup_composite.py',
               CANDIDATE + '/hw/snapshot_counters.py', CANDIDATE + '/hw/sealed_profile.py',
               CANDIDATE + '/hw/generation_headroom.py')


class CandidateCampaign(base.Campaign):
    def _require_hardware_authorization(self):
        if not self.rn.dry and os.environ.get('DEFENSE4_HW_AUTHORIZED') != '1':
            raise ValueError('candidate hardware execution requires DEFENSE4_HW_AUTHORIZED=1')

    def execute(self):
        self._require_hardware_authorization()
        return super().execute()

    def deploy_only(self):
        self._require_hardware_authorization()
        return super().deploy_only()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for name in base.selected_builds(self.cfg, self.arms):
            if self.cfg['builds'][name].get('lifecycle_rearm') is not True:
                raise ValueError('candidate installer requires lifecycle_rearm:true on selected build ' + name)
        self.candidate_identity = {rel: base.sha256_file(ARCH / rel) for rel in EXTRA_FILES}
        self.record['candidate_source_identity'] = self.candidate_identity

    def deploy_switch(self):
        super().deploy_switch()
        host = self.cfg['hosts']['switch']
        self.step('local', 'copy isolated candidate CP and installer',
                  'rsync -aR %s %s:%s/src/' %
                  (' '.join(base.q(rel) for rel in EXTRA_FILES), host, self.R), cwd=str(ARCH))
        remote = {rel: '%s/src/%s' % (self.R, rel) for rel in EXTRA_FILES}
        result = self.step('switch', 'verify isolated candidate CP and installer identity',
                           'sha256sum ' + ' '.join(base.q(path) for path in remote.values()))
        if not self.rn.dry:
            observed = {line.split()[1]: line.split()[0] for line in result.out.splitlines()
                        if len(line.split()) == 2}
            for rel, path in remote.items():
                if observed.get(path) != self.candidate_identity[rel]:
                    raise base.StepFailed('candidate installer identity mismatch: ' + path)

    def installer_cmd(self, *args, **kwargs):
        command = super().installer_cmd(*args, **kwargs)
        original = '%s/%s/bringup_composite.py' % (self.R, base.HW)
        replacement = '%s/src/%s/hw/bringup_composite.py' % (self.R, CANDIDATE)
        if command.count(original) != 1:
            raise ValueError('baseline installer command no longer has the expected entrypoint')
        return command.replace(original, replacement, 1)

    def switch_cmd(self, script, args):
        if script == 'snapshot_counters.py':
            return 'python3 %s/src/%s/hw/%s %s' % (self.R, CANDIDATE, script, args)
        return super().switch_cmd(script, args)

    def _headroom_trial(self, name):
        if not name.endswith('_before'):
            return None, None
        label = name[:-len('_before')]
        for rec in self.record.get('arms', []):
            for trial in rec.get('trials', []):
                if trial.get('label') == label:
                    return rec, trial
        return None, None

    def _headroom_required(self, rec):
        build = self.cfg.get('builds', {}).get(rec.get('build'), {})
        return bool(build.get('profile') == 'candidate61' or
                    build.get('packet_boundary_required') or
                    self.cfg.get('standards', {}).get('packet_boundary_required'))

    def _headroom_reserve(self, trial, rec=None):
        reads = trial.get('reads')
        if not isinstance(reads, int) or isinstance(reads, bool) or reads < 1:
            raise ValueError('generation headroom requires a positive trial read count')
        connections = int(self.record.get('candidate_series', {}).get('connections') or 1)
        if self.scenario is not None:
            connections = max(connections, 3)
        if rec is None or rec.get('build') not in self.cfg.get('builds', {}):
            raise HEADROOM.HeadroomError('generation budget needs the arm build')
        build = self.cfg['builds'][rec['build']]
        control_timed = build.get('control_timed', False)
        if not isinstance(control_timed, bool):
            raise HEADROOM.HeadroomError('build %s control_timed must be a boolean' % rec['build'])
        if build.get('source_sha256') in CONTROL_TIMED_SOURCES and not control_timed:
            raise HEADROOM.HeadroomError('build %s is a control-timed source but does not declare control_timed'
                                         % rec['build'])
        traffic = self.cfg.get('traffic', {})
        return HEADROOM.workload_reserve(
            reads, base.checks.sbo_count(traffic), connections, control_timed,
            timed=bool(rec.get('T', True)), cancelled_selects=traffic.get('cancelled_selects', 0))

    def preflight(self):
        """Budget every unit before the switch is touched: a refused or malformed budget is a preflight error,
        not an exception between install and collection."""
        errs = super().preflight()
        for unit in self.units():
            arm = unit['arm']
            rec = {'build': arm.get('build'), 'T': arm.get('T')}
            if not self._headroom_required(rec):
                continue
            try:
                reserve, _budget = self._headroom_reserve({'reads': unit['reads']}, rec)
            except (ValueError, TypeError) as error:
                errs.append('generation budget for %s: %s' % (self.label(unit), error))
                continue
            over = {role: value for role, value in reserve.items() if value > HEADROOM.MAX_GENERATION}
            if over:
                errs.append('generation budget for %s exceeds one incarnation: %s' % (self.label(unit), over))
        return errs

    def _parse_headroom_result(self, result):
        lines = [line for line in (result.out or '').splitlines() if line.strip()]
        for line in reversed(lines):
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict):
                return value
        raise base.StepFailed('generation headroom helper did not return JSON', result)

    def _record_headroom(self, trial, evidence):
        trial['generation_headroom'] = evidence
        self.record.setdefault('generation_headroom', []).append({
            'label': trial.get('label'),
            'ok': evidence.get('ok'),
            'reserve': evidence.get('reserve'),
            'current': evidence.get('current'),
            'remaining_after_reserve': evidence.get('remaining_after_reserve'),
            'dry_run': evidence.get('dry_run', False),
            'error': evidence.get('error'),
        })

    def _check_generation_headroom(self, out_remote, name, rec, trial):
        reserve, budget = self._headroom_reserve(trial, rec)
        output = '%s/snap/%s_generation_headroom.json' % (self.R, name)
        cmd = ('python3 %s/src/%s/hw/generation_headroom.py --build-out %s --switch-tools %s/%s '
               '--reserve-read %d --reserve-operate %d --output %s' %
               (self.R, CANDIDATE, out_remote, self.R, base.HW, reserve['read'], reserve['operate'], output))
        if self.rn.dry:
            self.step('switch', 'generation headroom precheck %s' % name, self.hw_env(cmd))
            evidence = {'ok': None, 'dry_run': True, 'reserve': reserve,
                        'budget': budget, 'output': output}
            self._record_headroom(trial, evidence)
            return
        result = self.step('switch', 'generation headroom precheck %s' % name,
                           self.hw_env(cmd), check=False)
        evidence = self._parse_headroom_result(result)
        evidence.setdefault('reserve', reserve)
        evidence['budget'] = budget
        evidence['output'] = output
        self._record_headroom(trial, evidence)
        if result.rc != 0 or evidence.get('ok') is not True:
            raise base.StepFailed('generation headroom refused %s: %s' %
                                  (name, evidence.get('error') or evidence.get('failures')), result)

    def snapshot(self, out_remote, name, check=True, preset=None):
        result = super().snapshot(out_remote, name, check=check, preset=preset)
        rec, trial = self._headroom_trial(name)
        if rec is not None and self._headroom_required(rec):
            self._check_generation_headroom(out_remote, name, rec, trial)
        return result


if __name__ == '__main__':
    # The ordinary CLI continues to own binding checks, authorization and cleanup.
    base.Campaign = CandidateCampaign
    sys.exit(base.main())
