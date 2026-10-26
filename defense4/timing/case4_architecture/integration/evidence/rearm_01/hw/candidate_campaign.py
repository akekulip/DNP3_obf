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
_spec = importlib.util.spec_from_file_location('candidate_timing_profile', ARCH / CANDIDATE / 'hw/sealed_profile.py')
TIMING_PROFILE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(TIMING_PROFILE)
# Sources whose T admits SELECT and OPERATE on the read lane (ctl_timing_01 m3 and later); a build of one of
# these must declare control_timed, or its generation budget would be READ-only.
CONTROL_TIMED_SOURCES = frozenset({
    'c4819dbac643048c16a9a0534337a938ca2820add0aae5a5bcda43e8b43a9204',   # ctl_timing_01 m3
    '35e896ebcd11f461ea947db3b0fa5198770c547d680ffb4bdec5d885465c79cf',   # ctl_timing_01 m4
    'b758c98199dddd36f8df4a90ce7a1e2301b63e95c2ac766aafa20b5b9f15e981',   # ctl_timing_01 m5 (m5_10)
    '6590141fc68b43788de7e969badf3d6bdf24ba0615a56631497ca39854c0ce0f',   # ctl_timing_01 m9 (m9_01)
    'd9b84fcc7ecb1dded4e7fddf47a1e74da568c9b4159c0065e4e780c38d49b5dc',   # ctl_timing_01 m10 (m10_03)
    '74c9cdcddbffa89589f2ed656f732328d9cc263d32877a74bab9a19ef269854f',   # DIAGNOSTIC ctl_timing_01 m9d (m9d_01)
})
EXTRA_FILES = (CANDIDATE + '/cp.py', CANDIDATE + '/hw/bringup_composite.py',
               CANDIDATE + '/hw/snapshot_counters.py', CANDIDATE + '/hw/sealed_profile.py',
               CANDIDATE + '/hw/generation_headroom.py',
               CANDIDATE + '/hw/mau_snapshot.py')   # imported by snapshot_counters only for diagnostic_mau_snapshot


def _native_inputs_supported(encoding, endpoint_profile='software'):
    """The control-timing contract's native inputs: SELECT/OPERATE 37 and either the range READ (49, the single-READ
    builds) or the two-READ-target profile's READ list, which must equal the keys of its declared read_images map,
    each image larger than its native (mixed 91 -> 141, full 247 -> 271). Anything else is refused."""
    native = encoding.get('native_input_octets')
    control_native = 49 if endpoint_profile == 'sel751' else 37
    if not isinstance(native, dict) or set(native) != {'READ', 'SELECT', 'OPERATE'} or \
            native.get('SELECT') != control_native or native.get('OPERATE') != control_native:
        return False
    if endpoint_profile == 'sel751' and native.get('READ') != [91, 134]:
        return False
    if native['READ'] == 49 and 'read_images' not in encoding:
        return True
    reads, images = native['READ'], encoding.get('read_images')
    if type(reads) is not list or not reads or not isinstance(images, dict) or len(set(reads)) != len(reads):
        return False
    if any(type(n) is not int for n in reads) or sorted(images) != sorted(str(n) for n in reads):
        return False
    return all(type(images[str(n)]) is int and images[str(n)] > n for n in reads) and \
        encoding.get('read_output_octets') == [images[str(n)] for n in reads]


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
        identities = dict(self.candidate_identity)
        for name in base.selected_builds(self.cfg, self.arms):
            files = self._profile_files(self.cfg['builds'][name])
            if not files:
                continue
            destinations = {rel: '%s/out_%s/%s' % (self.R, name, rel) for rel in files}
            parents = sorted({str(Path(path).parent) for path in destinations.values()})
            self.step('switch', 'make bound profile directories for ' + name,
                      'mkdir -p ' + ' '.join(base.q(path) for path in parents))
            hashes = {}
            for rel, local in files.items():
                self.step('local', 'copy bound profile %s %s' % (name, rel),
                          'rsync -a %s %s:%s' % (base.q(str(local)), host, base.q(destinations[rel])))
                key = name + ':' + rel
                remote[key] = destinations[rel]
                identities[key] = hashes[rel] = base.sha256_file(local)
            self.record.setdefault('candidate_profile_identity', {})[name] = hashes
        result = self.step('switch', 'verify isolated candidate CP and installer identity',
                           'sha256sum ' + ' '.join(base.q(path) for path in remote.values()))
        if not self.rn.dry:
            observed = {line.split()[1]: line.split()[0] for line in result.out.splitlines()
                        if len(line.split()) == 2}
            for rel, path in remote.items():
                if observed.get(path) != identities[rel]:
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
        return bool(base.endpoint_profiles.is_relay(self.cfg) or build.get('profile') == 'candidate61' or
                    build.get('packet_boundary_required') or
                    self.cfg.get('standards', {}).get('packet_boundary_required'))

    def _profile_control_timed(self, build):
        """Read successor semantics from the existing source-bound build inputs.

        Historical builds without this profile keep the explicit registry/flag
        contract. No compiler output is needed to verify a source-only profile.
        """
        cfg = getattr(self, 'cfg', {})
        directory = Path(base.path_of(build['out_dir'])).parent.parent
        inputs_path = directory / 'response_only.inputs.json'
        inputs = json.loads(inputs_path.read_text()) if inputs_path.is_file() else {}
        if not isinstance(inputs, dict):
            raise HEADROOM.HeadroomError('supported profile build inputs must be an object')
        profile = inputs.get('supported_profile')
        profile_path = directory / 'supported_profile.json'
        if profile_path.is_file():
            separate = json.loads(profile_path.read_text())
            if profile is not None and profile != separate:
                raise HEADROOM.HeadroomError('supported profile file differs from build inputs')
            profile = separate
        if profile is None:
            if build.get('timing_contract') == 'response_ready_ack_d_no_j_v3':
                raise HEADROOM.HeadroomError('no-J candidate requires its source-bound supported profile')
            if base.endpoint_profiles.is_relay(cfg):
                raise HEADROOM.HeadroomError('physical SEL-751 candidate requires its source-bound supported profile')
            return None
        if not isinstance(profile, dict):
            raise HEADROOM.HeadroomError('supported profile must be an object')
        if any(not isinstance(profile.get(key), dict) for key in ('candidate', 'encoding', 'timing_ns')):
            raise HEADROOM.HeadroomError('supported profile candidate, encoding and timing must be objects')
        source = directory / 'response_only.p4'
        digest = build.get('source_sha256')
        if not digest or inputs.get('source_sha256') != digest or \
                profile.get('candidate', {}).get('source_sha256') != digest or \
                not source.is_file() or base.sha256_file(source) != digest:
            raise HEADROOM.HeadroomError('supported profile source identity does not match the build and inputs')
        encoding, timing = profile.get('encoding', {}), profile.get('timing_ns', {})
        try:
            contract = TIMING_PROFILE.validate_timing_contract(profile, source.read_text())
        except ValueError as error:
            raise HEADROOM.HeadroomError(str(error))
        if cfg.get('timing_contract') != contract or build.get('timing_contract') != contract:
            raise HEADROOM.HeadroomError('config/build/source timing contract mismatch')
        if contract == 'response_ready_ack_d_no_j_v3':
            keys = ('D_release_budget',)
            t = cfg.get('timing_params_ns') or {}
            if set(t) != {'gap', 'budget', 'enabled'} or \
                    type(t.get('gap')) is not int or t['gap'] not in (5000000, 10000000, 15000000, 20000000) or \
                    type(t.get('budget')) is not int or not 0 < t['budget'] < 1 << 31 or \
                    type(t.get('enabled')) is not int or t['enabled'] not in (0, 1):
                raise HEADROOM.HeadroomError('no-J response-ready config timing parameter mismatch')
        elif contract == 'response_ready_ack_d_v2':
            keys = ('D_release_budget', 'J_operate_hold')
            t = cfg.get('timing_params_ns') or {}
            if set(t) != {'gap', 'op_j', 'budget', 'enabled'} or \
                    t.get('op_j') != timing['J_operate_hold'] or \
                    t.get('gap') not in (5000000, 10000000, 15000000, 20000000):
                raise HEADROOM.HeadroomError('response-ready config timing parameter mismatch')
        else:
            keys = ('D_release_budget', 'J_operate_hold', 'pb_piggyback_bound', 'readiness', 'da', 'cap')
        endpoint_profile = cfg.get('endpoint_profile', 'software')
        if endpoint_profile == 'sel751' and (profile.get('endpoint_profile') != 'sel751' or
                profile.get('ports', {}).get('master_dev') != 9 or profile.get('ports', {}).get('relay_dev') != 64):
            raise HEADROOM.HeadroomError('SEL-751 profile endpoint/physical port identity mismatch')
        if endpoint_profile == 'sel751' and (profile.get('tcp_profile') != 'sel751_ts' or
                encoding.get('tcp_header_octets') != 32 or encoding.get('syn_tcp_header_octets') != 40 or
                encoding.get('synack_tcp_header_octets') != 44 or encoding.get('ipv4_ihl') != 5 or
                encoding.get('timestamp_option_prefix') != '0101080a'):
            raise HEADROOM.HeadroomError('SEL-751 profile does not bind the observed timestamp/header contract')
        if endpoint_profile == 'sel751' and (encoding.get('read_images') != {'91': 141, '134': 158} or
                build.get('image_len') != 60 or build.get('read_images') != {'mixed': 141, 'integrity': 158} or
                build.get('read_padding') != {'mixed': 26, 'integrity': 4}):
            raise HEADROOM.HeadroomError('SEL-751 config and profile must bind the selected two READ images and control60')
        if not _native_inputs_supported(encoding, endpoint_profile) or \
                encoding.get('output_octets') != (60 if endpoint_profile == 'sel751' else 61) or type(profile.get('t_child_count')) is not int or \
                profile['t_child_count'] not in (1, 3) or \
                any(type(timing.get(key)) is not int or timing[key] <= 0 for key in keys):
            raise HEADROOM.HeadroomError('unsupported control-timing profile contract')
        return True

    def _profile_files(self, build):
        if self._profile_control_timed(build) is None:
            return {}
        out = Path(base.path_of(build['out_dir']))
        directory = out.parent.parent
        compile_name = out.parent.name
        if compile_name not in ('compile_local', 'compile_switch_9132'):
            raise ValueError('supported profile requires an explicitly named SDK compile')
        manifest = Path(base.path_of(build['manifest']))
        if manifest.resolve() != (out.parent / 'manifest.json').resolve():
            raise ValueError('supported profile compile manifest path differs from selected build')
        files = {'profile/' + name: directory / name
                 for name in ('response_only.p4', 'response_only.inputs.json')}
        if (directory / 'supported_profile.json').is_file():
            files['profile/supported_profile.json'] = directory / 'supported_profile.json'
        files['profile/%s/manifest.json' % compile_name] = manifest
        return files

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
        profile_timed = self._profile_control_timed(build)
        control_timed = build.get('control_timed', profile_timed if profile_timed is not None else False)
        if not isinstance(control_timed, bool):
            raise HEADROOM.HeadroomError('build %s control_timed must be a boolean' % rec['build'])
        if (profile_timed or build.get('source_sha256') in CONTROL_TIMED_SOURCES) and not control_timed:
            raise HEADROOM.HeadroomError('build %s is a control-timed source but does not declare control_timed'
                                         % rec['build'])
        traffic = self.cfg.get('traffic', {})
        return HEADROOM.workload_reserve(
            reads, base.checks.sbo_count(traffic), connections, control_timed,
            timed=bool(rec.get('T', True)), cancelled_selects=traffic.get('cancelled_selects', 0),
            timing_contract=build.get('timing_contract'))

    def preflight(self):
        """Budget every unit before the switch is touched: a refused or malformed budget is a preflight error,
        not an exception between install and collection."""
        errs = super().preflight()
        if base.endpoint_profiles.is_relay(self.cfg):
            try:
                base.endpoint_profiles.native_observation_files(self.cfg)
            except (OSError, ValueError, KeyError, TypeError) as error:
                errs.append('physical packet profile provenance: ' + str(error))
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
        reserve_args = ' '.join('--reserve-%s %d' % (role, value) for role, value in reserve.items())
        cmd = ('python3 %s/src/%s/hw/generation_headroom.py --build-out %s --switch-tools %s/%s '
               '%s --output %s' %
               (self.R, CANDIDATE, out_remote, self.R, base.HW, reserve_args, output))
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
