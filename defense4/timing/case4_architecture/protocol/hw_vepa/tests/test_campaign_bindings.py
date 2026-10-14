"""Config binding: a build's hashes are verified against its compile manifest.json AND the files on disk, a
placeholder or malformed hash is an error (never a warning), the endpoint identity must be pinned, and the
hardware profile defaults (READ range 8, production K=2, shaping off) are what the shipped config says."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import campaign as cp  # noqa: E402

CONFIG = HERE.parent / 'campaign.json'
H64 = 'a' * 64


def fake_build(root, tamper=None):
    """A tiny compiled out/ tree plus the compile manifest.json that records its sha256s."""
    out = Path(root) / 'out'
    files = {'bfrt.json': b'{}', 'p0/tofino.bin': b'p0', 'p1/tofino.bin': b'p1', 'p1/response_only.bfa': b'bfa'}
    for rel, data in files.items():
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_bytes(data)
    man = {'artifact_sha256': {r: hashlib.sha256(d).hexdigest() for r, d in files.items()}}
    (Path(root) / 'manifest.json').write_text(json.dumps(man))
    if tamper:
        (out / tamper).write_bytes(b'changed after the manifest was written')
    return man['artifact_sha256']


def build_name(cfg):
    """The build the shipped arms run on (tests follow the config rather than naming one)."""
    return cfg['arms'][0]['build']


def cfg_for(root, hashes, tamper=None):
    cfg = json.load(open(CONFIG))
    sha = fake_build(root, tamper)
    b = cfg['builds'][build_name(cfg)]
    b['allowed_loop_octet_gap'] = {}                       # a fake build has no known gap, whatever the shipped one has
    b['profile'] = 'strict_comparison'
    b['image_len'] = 58
    b['source_sha256'] = H64
    b['out_dir'], b['manifest'] = str(Path(root) / 'out'), str(Path(root) / 'manifest.json')
    b['hashes'] = {r: (sha[r] if hashes == 'match' else hashes) for r in sha}
    cfg['endpoint'].update(binary_sha256=H64, lib_sha256=H64)
    return cfg


class Bindings(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = td.name

    def test_matching_manifest_hashes_and_files_bind(self):
        cfg = cfg_for(self.tmp, 'match')
        self.assertEqual(cp.check_bindings(cfg), [])
        bound = cp.bind_builds(cfg)
        self.assertEqual(set(next(iter(bound.values()))), {'bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin', 'p1/response_only.bfa'})

    def test_placeholder_hash_is_an_error_not_a_warning(self):
        cfg = cfg_for(self.tmp, '<sha256 from manifest.json>')
        errs = cp.check_bindings(cfg)
        self.assertTrue(any('placeholder' in e or 'not a sha256' in e for e in errs), errs)
        with self.assertRaises(ValueError):
            cp.bind_builds(cfg)

    def test_config_hash_that_disagrees_with_manifest_is_refused(self):
        errs = cp.check_bindings(cfg_for(self.tmp, H64))
        self.assertTrue(any('disagrees with the compile manifest' in e for e in errs), errs)

    def test_file_changed_after_the_manifest_is_refused(self):
        errs = cp.check_bindings(cfg_for(self.tmp, 'match', tamper='p0/tofino.bin'))
        self.assertTrue(any('p0/tofino.bin' in e and 'on disk' in e for e in errs), errs)

    def test_null_slot_is_filled_from_the_manifest(self):
        cfg = cfg_for(self.tmp, None)
        self.assertEqual(cp.check_bindings(cfg), [])
        bound = cp.bind_builds(cfg)
        self.assertTrue(all(len(v) == 64 for v in next(iter(bound.values())).values()))

    def test_missing_manifest_is_refused(self):
        cfg = cfg_for(self.tmp, 'match')
        cfg['builds'][build_name(cfg)]['manifest'] = str(Path(self.tmp) / 'nope.json')
        self.assertTrue(any('manifest' in e for e in cp.check_bindings(cfg)))

    def test_unpinned_endpoint_identity_is_refused(self):
        cfg = cfg_for(self.tmp, 'match')
        cfg['endpoint']['binary_sha256'] = None
        self.assertTrue(any('endpoint' in e and 'binary_sha256' in e for e in cp.check_bindings(cfg)))

    @pytest.mark.build_tree
    def test_shipped_config_is_fully_bound_with_the_real_pins(self):
        cfg = cp.load_config(str(CONFIG))
        self.assertEqual(cp.check_bindings(cfg), [])
        ep = cfg['endpoint']
        self.assertEqual(ep['binary_sha256'], 'f66ad08cce45407483c505edf4547c3d222d9ac3b959f3ba9540281f3c793097')
        self.assertEqual(ep['lib_sha256'], '6c7a6892d5b9fddb0c09a5ae1d63067f17034b4edf93f8f295f4c4bb32a6d23d')

    @pytest.mark.build_tree
    def test_validate_passes_with_the_real_pins(self):
        self.assertEqual(cp.main(['validate', '--config', str(CONFIG)]), 0)


class BfaPin(unittest.TestCase):
    """p1/response_only.bfa is the file the installer's mirror-defect guard reads; pinning its hash ties the checked
    file to the loaded binaries. It is enforced like the other three."""
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = td.name

    def test_bfa_is_in_the_hashed_set(self):
        self.assertIn('p1/response_only.bfa', cp.BUILD_HASHED)

    def test_mismatching_bfa_on_disk_is_refused(self):
        errs = cp.check_bindings(cfg_for(self.tmp, 'match', tamper='p1/response_only.bfa'))
        self.assertTrue(any('p1/response_only.bfa' in e and 'on disk' in e for e in errs), errs)

    def test_config_bfa_hash_that_disagrees_with_the_manifest_is_refused(self):
        cfg = cfg_for(self.tmp, 'match')
        cfg['builds'][build_name(cfg)]['hashes']['p1/response_only.bfa'] = H64
        errs = cp.check_bindings(cfg)
        self.assertTrue(any('p1/response_only.bfa' in e and 'disagrees with the compile manifest' in e for e in errs), errs)

    def test_placeholder_bfa_hash_is_an_error(self):
        cfg = cfg_for(self.tmp, 'match')
        cfg['builds'][build_name(cfg)]['hashes']['p1/response_only.bfa'] = '<sha256 from manifest.json>'
        self.assertTrue(any('p1/response_only.bfa' in e for e in cp.check_bindings(cfg)))

    def test_manifest_without_a_bfa_entry_is_refused(self):
        cfg = cfg_for(self.tmp, 'match')
        mp = Path(cfg['builds'][build_name(cfg)]['manifest'])
        m = json.loads(mp.read_text())
        del m['artifact_sha256']['p1/response_only.bfa']
        mp.write_text(json.dumps(m))
        self.assertTrue(any('no artifact_sha256 for p1/response_only.bfa' in e for e in cp.check_bindings(cfg)))

    def test_missing_bfa_file_is_refused(self):
        cfg = cfg_for(self.tmp, 'match')
        (Path(cfg['builds'][build_name(cfg)]['out_dir']) / 'p1' / 'response_only.bfa').unlink()
        self.assertTrue(any('p1/response_only.bfa' in e and 'missing' in e for e in cp.check_bindings(cfg)))

    def test_null_slot_is_filled_from_the_manifest(self):
        cfg = cfg_for(self.tmp, None)
        self.assertEqual(cp.check_bindings(cfg), [])
        self.assertEqual(len(cp.bind_builds(cfg)[build_name(cfg)]['p1/response_only.bfa']), 64)

    def test_shipped_builds_pin_their_bfa_and_validate_enforces_it(self):
        cfg = cp.load_config(str(CONFIG))
        want = {'mirror_fix_01': 'eea04489a6ad5da5a3d2ca91201223af26458d1516c2a7a4b6d3b5843893ff96',
                'close_reset_fix_01': '89ccc96a383c379d72342e0bb3cd4663bb7db2b8a5e7cca13e9bb805842abf91',
                'sbo_admission_01': '94350238b895cbcb0b377e3a6bddf95a490af2386c132526fcc5ac703cb1040c'}
        for name, sha in want.items():
            self.assertEqual(cfg['builds'][name]['hashes']['p1/response_only.bfa'], sha, name)


class ShippedBuilds(unittest.TestCase):
    """What the shipped config deliberately says (the one place tests name builds)."""
    def setUp(self):
        self.cfg = cp.load_config(str(CONFIG))

    def test_all_four_arms_run_the_mirror_fix_build(self):
        self.assertEqual({a['build'] for a in self.cfg['arms']}, {'mirror_fix_01'})
        self.assertEqual(len(self.cfg['arms']), 4)

    def test_comparison_builds_are_kept_by_name(self):
        self.assertIn('close_reset_fix_01', self.cfg['builds'])
        self.assertIn('sbo_admission_01', self.cfg['builds'])

    def test_loop_gap_allowances(self):
        b = self.cfg['builds']
        self.assertEqual(b['mirror_fix_01']['allowed_loop_octet_gap'], {})
        self.assertEqual(b['close_reset_fix_01']['allowed_loop_octet_gap'], {})
        self.assertEqual(b['sbo_admission_01']['allowed_loop_octet_gap'], {'t_in': 80})

    def test_mirror_fix_build_hashes_are_the_verified_ones(self):
        h = self.cfg['builds']['mirror_fix_01']['hashes']
        self.assertEqual(h['bfrt.json'], '4e24bc8a84313b16bfb268aa640bc005548a93bfd63f392abaa8a96909070caa')
        self.assertEqual(h['p0/tofino.bin'], 'aff15250cc9af232f99c4d759fd801dd3d4a7b750b712fe760dc637550af2edb')
        self.assertEqual(h['p1/tofino.bin'], '296444ce43e28e3228edd8e1d61c52f2a6f233dc4be357e3e96610e896e02309')

    def test_close_reset_fix_hashes_are_unchanged(self):
        h = self.cfg['builds']['close_reset_fix_01']['hashes']
        self.assertEqual(h['bfrt.json'], '7c7e7f3bbe1220b6abcc7cbc1fdc9cc18d7854428447529f79b6c4ed7808d2e3')

    def test_unused_historical_build_is_checked_only_by_explicit_audit(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = cfg_for(td, 'match')
            cfg['builds']['sbo_admission_01']['manifest'] = str(Path(td) / 'missing.json')
            self.assertEqual(cp.check_bindings(cfg), [])
            self.assertTrue(any('sbo_admission_01' in e for e in cp.check_bindings(cfg, all_builds=True)))

    def test_final_arm_selection_controls_preflight_and_binding(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = cfg_for(td, 'match')
            cfg['arms'][0]['build'] = 'sbo_admission_01'
            cfg['builds']['sbo_admission_01']['manifest'] = str(Path(td) / 'missing.json')
            c = cp.Campaign(cfg, cp.DryRunner(), 'fresh', arms=['combined'])
            self.assertEqual(c.preflight(), [])
            self.assertEqual(set(cp.bind_builds(cfg, c.arms)), {'mirror_fix_01'})

    def test_scenario_and_paired_overrides_select_their_final_build(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = cfg_for(td, 'match')
            cfg['arms'][0]['build'] = 'sbo_admission_01'
            cfg['builds']['sbo_admission_01']['manifest'] = str(Path(td) / 'missing.json')
            for kw in ({'scenario': 'reconnect'}, {'paired': 'shape_14892_vs_3723'}):
                c = cp.Campaign(cfg, cp.DryRunner(), 'fresh', arms=['off'], **kw)
                self.assertEqual(c.preflight(), [])


class Profile(unittest.TestCase):
    def setUp(self):
        self.cfg = cp.load_config(str(CONFIG))

    def test_read_range_is_the_8bit_profile(self):
        self.assertEqual(self.cfg['traffic']['range'], 8)

    def test_range_16_is_rejected(self):
        bad = copy.deepcopy(self.cfg)
        bad['traffic']['range'] = 16
        with self.assertRaises(ValueError):
            cp.validate_profile(bad)

    def test_k_is_the_production_value(self):
        self.assertEqual(self.cfg['service']['k'], 2)

    def test_default_preset_is_unshaped_with_every_rate_off(self):
        sh = self.cfg['shaping']
        self.assertEqual(sh['preset'], 'unshaped')
        eff = cp.resolve_shaping(self.cfg)
        self.assertEqual(eff['hold_pps'], {'ack': 0, 'resp': 0, 'op': 0})
        self.assertEqual(eff['block_pps'], {'ack': 0, 'resp': 0, 'op': 0})
        self.assertIsNone(eff['block_burst'])

    def test_named_candidate_presets_use_exact_ladder_rates(self):
        pre = self.cfg['shaping']['presets']
        for name, rate in (('shape_3723', 3723), ('shape_14892', 14892), ('shape_59570', 59570), ('slow_232', 232)):
            eff = cp.resolve_shaping(self.cfg, name)
            self.assertEqual(eff['hold_pps'], {'ack': rate, 'resp': rate, 'op': rate}, name)
            self.assertEqual(eff['block_pps'], {'ack': rate, 'resp': rate, 'op': rate}, name)
        self.assertEqual(cp.resolve_shaping(self.cfg, 'shape_3723')['block_burst'], 64)
        for name, p in pre.items():
            for g in ('hold_pps', 'block_pps'):
                self.assertTrue(all(v in cp.LADDER for v in p[g].values()), name)

    def test_off_ladder_rate_is_rejected(self):
        bad = copy.deepcopy(self.cfg)
        bad['shaping']['presets']['shape_3723']['hold_pps']['ack'] = 3000     # the shaper realizes 3723
        with self.assertRaises(ValueError):
            cp.validate_profile(bad)

    def test_unknown_preset_is_rejected(self):
        bad = copy.deepcopy(self.cfg)
        bad['shaping']['preset'] = 'fast'
        with self.assertRaises(ValueError):
            cp.validate_profile(bad)
        with self.assertRaises(ValueError):
            cp.resolve_shaping(self.cfg, 'fast')

    def test_installer_args_carry_every_shaping_flag_of_the_preset(self):
        a = cp.shaping_args(self.cfg, preset='shape_3723')
        for flag in ('--shape-ack-pps 3723', '--shape-resp-pps 3723', '--shape-op-pps 3723',
                     '--shape-ack-blk-pps 3723', '--shape-resp-blk-pps 3723', '--shape-op-blk-pps 3723',
                     '--block-burst 64'):
            self.assertIn(flag, a)

    def test_unshaped_args_are_explicit_zeros_and_no_burst(self):
        a = cp.shaping_args(self.cfg)
        self.assertIn('--shape-ack-pps 0', a)
        self.assertIn('--shape-op-blk-pps 0', a)
        self.assertNotIn('--block-burst', a)

    def test_snapshot_args_never_carry_block_burst(self):
        self.assertNotIn('--block-burst', cp.shaping_args(self.cfg, burst=False, preset='shape_3723'))

    def test_fixture_jitter_is_rejected_because_vision_run_cannot_apply_it(self):
        bad = copy.deepcopy(self.cfg)
        bad['fixture']['jitter_ms'] = 5
        with self.assertRaises(ValueError):
            cp.validate_profile(bad)


if __name__ == '__main__':
    unittest.main()
