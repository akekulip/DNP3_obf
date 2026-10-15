import json
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[10]
ARCH = REPO / 'defense4/timing/case4_architecture'
HW = ARCH / 'integration/core/response_only_rearm/stage_experiments/seg61_02/hw'
CFG = HW / 'config'
GEN = HW / 'build_candidate61_configs.py'
CANDIDATE_SHA = '1b2d62d16d40427d8b7e5d4b93f9e57b75e721e6a6c7e4c184fb84a1dc3665aa'
STRICT_SHA = '2ad71761399e023b0d3b6b72f9fb71257da012499ffe30ac4758b395fc1bd97c'
CTL_SHA = 'c4819dbac643048c16a9a0534337a938ca2820add0aae5a5bcda43e8b43a9204'
HEX = set('0123456789abcdef')

sys.path.insert(0, str(ARCH / 'protocol/hw_vepa'))
import campaign  # noqa: E402
import loss  # noqa: E402


def load(name):
    with open(CFG / name) as f:
        return json.load(f)


def load_path(path):
    with open(path) as f:
        return json.load(f)


def build_tree_status():
    """(present, stderr): the generator's own precondition check for the ignored compiler outputs."""
    result = subprocess.run([sys.executable, str(GEN), '--check-build'], cwd=str(REPO), text=True,
                            capture_output=True)
    if result.returncode not in (0, 3):                 # anything but 'present' or 'missing' is a real failure
        raise AssertionError('build_candidate61_configs.py --check-build rc=%d: %s' % (result.returncode, result.stderr))
    return result.returncode == 0, result.stderr


BUILD_PRESENT, BUILD_MISSING = build_tree_status()


def sha_file(path):
    import hashlib
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class Candidate61SourceOnlyTests(unittest.TestCase):
    """Tracked source, manifests and configs: no compiler output needed."""

    def test_configs_bind_the_tracked_compile_manifests(self):
        c4 = REPO / 'defense4/timing/case4_architecture'
        for path in sorted(CFG.glob('candidate61_*.json')) + sorted(CFG.glob('strict_comparison_*.json')):
            data = load_path(path)
            for name, build in data['builds'].items():
                manifest = json.load(open(c4 / build['manifest']))
                self.assertEqual(manifest['exit_code'], 0, path.name)
                self.assertEqual(manifest['source_sha256'], build['source_sha256'], path.name)
                for rel, digest in build['hashes'].items():
                    self.assertEqual(manifest['artifact_sha256'][rel], digest, (path.name, rel))
            ident = data['candidate61_identity']
            self.assertEqual(ident['switch_compile']['manifest_sha256'], sha_file(c4 / ident['switch_compile']['manifest']))
            self.assertEqual(ident['full04_source_sha256'], CANDIDATE_SHA)
            self.assertEqual(sha_file(c4 / ident['switch_compile']['manifest'].replace('compile_switch_9132/manifest.json',
                                                                                        'response_only.p4')), CANDIDATE_SHA)

    def test_missing_build_tree_is_an_explicit_precondition(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:                  # a checkout with no compiler outputs at all
            result = subprocess.run([sys.executable, str(GEN)], cwd=tmp, text=True, capture_output=True)
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(result.stderr.count('missing compiler output'), 8, result.stderr)
        self.assertEqual(result.stderr.count('rebuild: '), 8)
        self.assertIn('orchestrator.py', result.stderr)
        self.assertIn('bf-sde-9.13.1', result.stderr)

    def test_hardware_bindings_fail_hard_without_the_build_tree(self):
        import copy
        import tempfile
        cfg = campaign.load_config(str(CFG / 'candidate61_fourarm_smoke.json'))
        with tempfile.TemporaryDirectory() as tmp:
            broken = copy.deepcopy(cfg)
            broken['builds']['rearm_61_full04']['out_dir'] = tmp
            errs = campaign.check_bindings(broken)
        self.assertTrue(any('on disk is missing' in e for e in errs), errs)


class RepeatEndpointPins(unittest.TestCase):
    """The repeated-SBO configs pin the endpoint fork's committed sources, and its build when present."""
    ENDPOINT = REPO / 'defense4/timing/case4_architecture/integration/evidence/rearm_01/repeat_sbo_endpoint'

    def test_repeat_configs_pin_the_committed_endpoint_sources(self):
        configs = sorted(CFG.glob('candidate61_repeat_sbo_*.json'))
        self.assertEqual(len(configs), 3)
        for path in configs:
            data = load_path(path)
            self.assertEqual(data['traffic']['sbo_cycles'], 64, path.name)
            self.assertEqual(data['trials']['reads_per_trial'], 65, path.name)
            for name, digest in data['endpoint']['source_files'].items():
                self.assertEqual(sha_file(self.ENDPOINT / 'sources' / name), digest, (path.name, name))
            self.assertEqual(data['endpoint']['source_sha256'], data['endpoint']['source_files']['SocketGatePad58B.cpp'])

    @unittest.skipUnless((ENDPOINT / 'build/build_manifest.json').is_file(), 'endpoint build tree absent')
    def test_repeat_configs_pin_the_built_binary(self):
        manifest = json.loads((self.ENDPOINT / 'build/build_manifest.json').read_text())
        for path in sorted(CFG.glob('candidate61_repeat_sbo_*.json')):
            endpoint = load_path(path)['endpoint']
            self.assertEqual(endpoint['binary_sha256'], manifest['binary_sha256'], path.name)
            self.assertEqual(endpoint['lib_sha256'], manifest['library_directory_sha256'], path.name)
            self.assertEqual(endpoint['source_files'], manifest['source_hashes'], path.name)


class Candidate61HardwareConfigTests(unittest.TestCase):
    @unittest.skipUnless(BUILD_PRESENT, 'compiler build tree absent (source-only checkout):\n' + BUILD_MISSING)
    def test_generator_is_reproducible(self):
        before = {p.relative_to(CFG): p.read_bytes() for p in CFG.glob('*.json')}
        result = subprocess.run([sys.executable, str(GEN)], cwd=str(REPO), text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = {p.relative_to(CFG): p.read_bytes() for p in CFG.glob('*.json')}
        self.assertEqual(before, after)

    def test_all_builds_have_profile_source_and_hash_pins(self):
        configs = sorted(CFG.glob('candidate61_*.json')) + sorted(CFG.glob('strict_comparison_*.json'))
        self.assertEqual(len(configs), 20)
        self.assertEqual(len(list(CFG.glob('ctl_timing_*.json'))), 12)   # 6 characterization + 6 qualification
        for path in configs:
            data = load_path(path)
            self.assertIn('candidate61_identity', data)
            for name, build in data['builds'].items():
                self.assertIn(build['profile'], ('candidate61', 'strict_comparison'), path.name)
                want_sha = CANDIDATE_SHA if build['profile'] == 'candidate61' else STRICT_SHA
                self.assertEqual(build['source_sha256'], want_sha, path.name)
                self.assertTrue(build.get('lifecycle_rearm'), path.name)
                for rel, digest in build['hashes'].items():
                    self.assertEqual(len(digest), 64, (path.name, rel))
                    self.assertLessEqual(set(digest), HEX, (path.name, rel))

    def test_profile_arm_size_contracts(self):
        for path in sorted(CFG.glob('candidate61_*.json')) + sorted(CFG.glob('strict_comparison_*.json')):
            data = load_path(path)
            build = next(iter(data['builds'].values()))
            profile = build['profile']
            pad0 = data['expectations']['padding']['0']
            pad1 = data['expectations']['padding']['1']
            self.assertEqual(pad0['read_resp_len'], [49], path.name)
            self.assertEqual(pad0['sbo_resp_len'], [37], path.name)
            if profile == 'candidate61':
                self.assertEqual(build['image_len'], 61, path.name)
                self.assertTrue(build['control_padding'], path.name)
                self.assertEqual(pad1['read_resp_len'], [61], path.name)
                self.assertEqual(pad1['sbo_resp_len'], [61], path.name)
            else:
                self.assertEqual(build['image_len'], 58, path.name)
                self.assertFalse(build['control_padding'], path.name)
                self.assertTrue(build['strict_controls_native'], path.name)
                self.assertEqual(pad1['read_resp_len'], [58], path.name)
                self.assertEqual(pad1['sbo_resp_len'], [37], path.name)


    def test_smoke_config_is_profile_bound_and_plans_capture_qualification(self):
        data = load('candidate61_fourarm_smoke.json')
        build = data['builds']['rearm_61_full04']
        self.assertEqual(build['profile'], 'candidate61')
        self.assertEqual(build['source_sha256'], CANDIDATE_SHA)
        self.assertEqual(build['image_len'], 61)
        cmd = [
            sys.executable,
            str(ARCH / 'integration/evidence/rearm_01/hw/candidate_campaign.py'),
            'plan',
            '--config', str(CFG / 'candidate61_fourarm_smoke.json'),
            '--run-id', 'candidate61_fourarm_smoke_plancheck',
            '--arms', 'off,timing_only,size_only,combined',
            '--fixtures', 'separate_ack',
        ]
        result = subprocess.run(cmd, cwd=str(REPO), text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = [line for line in result.stdout.splitlines() if 'vision_run.py run' in line]
        self.assertEqual(len(lines), 4)
        self.assertTrue(all('--qualify-capture' in line for line in lines), result.stdout)

    def test_candidate61_loss_uses_61_octet_padded_classes_and_data_ack(self):
        data = load('candidate61_loss_core_950.json')
        core = data['loss']['presets']['core']
        classes = [entry['class'] for entry in core]
        self.assertIn('select_resp_padded', classes)
        self.assertIn('operate_resp_padded', classes)
        self.assertNotIn('select_resp_native', classes)
        self.assertNotIn('operate_resp_native', classes)
        self.assertIn({'class': 'master_ack_of_padded_data', 'n': 1}, core)
        cfg = campaign.load_config(str(CFG / 'candidate61_loss_core_950.json'))
        runner = campaign.Campaign(cfg, campaign.DryRunner(), 'loss_shape', ['combined'], fixtures=['separate_ack'], loss='core', config_path=str(CFG / 'candidate61_loss_core_950.json'))
        drops = [unit['drop'] for unit in runner.units()]
        self.assertIn('select_resp_padded:1@61', drops)
        self.assertIn('operate_resp_padded:1@61', drops)
        self.assertIn('master_ack_of_padded_data:1@61', drops)
        self.assertEqual(loss.parse_drop('select_resp_padded:1@61', 20)['ip_len'], 101)
        self.assertEqual(loss.parse_drop('operate_resp_padded:1@61', 20)['ip_len'], 101)
        ack = loss.parse_drop('master_ack_of_padded_data:1@61', 20)
        self.assertTrue(ack['data_ack'])
        self.assertEqual(ack['occurrence'], 2)

    def test_high_read_candidate_eval_has_no_unusable_candidate61_loss_presets(self):
        for name in ('candidate61_eval_59570_950_b1.json', 'candidate61_eval_59570_950_b2.json', 'candidate61_eval_59570_950_b3.json'):
            data = load(name)
            self.assertEqual(data['trials']['reads_per_trial'], 500, name)
            self.assertEqual(data['loss']['presets'], {}, name)

    def test_strict_comparison_native_control_and_capture_boundary_flag(self):
        data = load('strict_comparison_59570_950_b1.json')
        build = data['builds']['strict_dup_hold_full02']
        self.assertEqual(build['profile'], 'strict_comparison')
        self.assertEqual(build['source_sha256'], STRICT_SHA)
        self.assertFalse(build['control_padding'])
        self.assertEqual(data['expectations']['padding']['1']['read_resp_len'], [58])
        self.assertEqual(data['expectations']['padding']['1']['sbo_resp_len'], [37])
        self.assertEqual(data['standards']['packet_boundary_required'], True)
        self.assertEqual(data['standards']['runner_qualification_status'],
                         'capture qualification enabled; silicon comparison pending')
        for name in ('strict_comparison_59570_950_b1.json', 'strict_comparison_59570_950_b2.json',
                     'strict_comparison_59570_950_b3.json'):
            strict = load(name)
            self.assertEqual(strict['builds']['strict_dup_hold_full02']['profile'], 'strict_comparison', name)
            self.assertIs(strict['standards']['packet_boundary_required'], True, name)
            self.assertEqual(strict['standards']['capture_boundary_scope'], 'strict_comparison_fairness', name)
        core = data['loss']['presets']['core']
        classes = [entry['class'] for entry in core]
        self.assertIn('select_resp_native', classes)
        self.assertIn('operate_resp_native', classes)
        self.assertNotIn('select_resp_padded', classes)
        self.assertNotIn('operate_resp_padded', classes)


    def test_fixed_port_diagnostics_match_runner_constraints(self):
        external = load('candidate61_old_external_950.json')
        self.assertEqual(external['traffic']['master_port_range'], {'first': 59400, 'last': 59400})
        stale = load('candidate61_stale_tokens_950.json')
        self.assertEqual(stale['traffic']['master_port_range'], {'first': 59412, 'last': 59412})

    def test_model_gate_metadata_is_derived_from_actual_successes(self):
        data = load('candidate61_fourarm_smoke.json')
        gates = data['candidate61_identity']['model_gates']
        self.assertIn('model_smoke', gates['latest_successful'])
        self.assertIn('model_packets', gates['latest_successful'])
        self.assertIn('model_rearm', gates['latest_successful'])
        packets = gates['latest_successful']['model_packets']
        smoke = gates['latest_successful']['model_smoke']
        rearm = gates['latest_successful']['model_rearm']
        self.assertTrue(smoke['path'].endswith('model_smoke_02/smoke_results.json'))
        self.assertEqual(smoke['summary'], {'failed': [], 'passed': 30, 'total': 30})
        self.assertTrue(packets['path'].endswith('model_packets_04/packet_results.json'))
        self.assertEqual(packets['summary'], {'failed': [], 'passed': 622, 'total': 622})
        self.assertTrue(rearm['path'].endswith('model_rearm_02/rearm_results.json'))
        self.assertEqual(rearm['summary'], {'failed': [], 'passed': 399, 'total': 399})
        failed_paths = [item['path'] for item in gates['retained_failed']]
        self.assertTrue(any(path.endswith('model_packets_01/packet_results.json') for path in failed_paths))
        self.assertTrue(any(path.endswith('model_packets_02/packet_results.json') for path in failed_paths))
        self.assertTrue(any(path.endswith('model_packets_03/packet_results.json') for path in failed_paths))



class ControlTimingConfigs(unittest.TestCase):
    """Gate 3 silicon configs: the m3 build, its flags, pb, the repeated-SBO endpoint and both fixtures."""

    def test_ctl_configs_bind_the_m3_build(self):
        fixtures = []
        for path in sorted(CFG.glob('ctl_timing_*.json')):
            data = load_path(path)
            (name, build), = data['builds'].items()
            self.assertEqual((name, build['profile'], build['source_sha256']), ('ctl_timing_m3_01', 'candidate61', CTL_SHA))
            self.assertTrue(build['control_timed'] and build['piggyback_bound'], path.name)
            self.assertTrue(0 < data['timing_params_ns']['pb'] < data['timing_params_ns']['readiness'], path.name)
            self.assertEqual(data['traffic']['sbo_cycles'], 64)
            self.assertEqual(data['hosts']['vision_run_dir'], '/home/decps/pad58b_repeat_sbo_20261014c')
            campaign.load_config(str(path))
            fixtures += data['fixture']['modes']
            qual = path.name.startswith('ctl_timing_qual_')
            self.assertEqual(data['evaluation']['purpose'],
                             'qualification' if qual else 'timing_precision_characterization', path.name)
            ports = data['traffic']['master_port_range']
            want = {('separate_ack', False): 59600, ('piggyback', False): 59610,
                    ('separate_ack', True): 59620, ('piggyback', True): 59630}[(data['fixture']['modes'][0], qual)]
            self.assertEqual((ports['first'], ports['last']), (want, want + 3), path.name)
        self.assertEqual(sorted(fixtures), ['piggyback'] * 6 + ['separate_ack'] * 6)


if __name__ == '__main__':
    unittest.main()
