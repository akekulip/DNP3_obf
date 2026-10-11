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

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import campaign as cp  # noqa: E402

CONFIG = HERE.parent / 'campaign.json'
H64 = 'a' * 64


def fake_build(root, tamper=None):
    """A tiny compiled out/ tree plus the compile manifest.json that records its sha256s."""
    out = Path(root) / 'out'
    files = {'bfrt.json': b'{}', 'p0/tofino.bin': b'p0', 'p1/tofino.bin': b'p1'}
    for rel, data in files.items():
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_bytes(data)
    man = {'artifact_sha256': {r: hashlib.sha256(d).hexdigest() for r, d in files.items()}}
    (Path(root) / 'manifest.json').write_text(json.dumps(man))
    if tamper:
        (out / tamper).write_bytes(b'changed after the manifest was written')
    return man['artifact_sha256']


def cfg_for(root, hashes, tamper=None):
    cfg = json.load(open(CONFIG))
    sha = fake_build(root, tamper)
    b = cfg['builds'][next(iter(cfg['builds']))]
    b['out_dir'], b['manifest'] = str(Path(root) / 'out'), str(Path(root) / 'manifest.json')
    b['hashes'] = {r: (sha[r] if hashes == 'match' else hashes) for r in sha}
    cfg['endpoint'].update(binary_sha256=H64, lib_sha256=H64)
    return cfg


class Bindings(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_matching_manifest_hashes_and_files_bind(self):
        cfg = cfg_for(self.tmp, 'match')
        self.assertEqual(cp.check_bindings(cfg), [])
        bound = cp.bind_builds(cfg)
        self.assertEqual(set(next(iter(bound.values()))), {'bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin'})

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
        next(iter(cfg['builds'].values()))['manifest'] = str(Path(self.tmp) / 'nope.json')
        self.assertTrue(any('manifest' in e for e in cp.check_bindings(cfg)))

    def test_unpinned_endpoint_identity_is_refused(self):
        cfg = cfg_for(self.tmp, 'match')
        cfg['endpoint']['binary_sha256'] = None
        self.assertTrue(any('endpoint' in e and 'binary_sha256' in e for e in cp.check_bindings(cfg)))

    def test_shipped_config_build_is_bound_to_its_real_manifest(self):
        cfg = cp.load_config(str(CONFIG))
        errs = [e for e in cp.check_bindings(cfg) if 'endpoint' not in e]
        self.assertEqual(errs, [])           # the build binds; only the endpoint pin is outstanding

    def test_validate_exits_nonzero_while_anything_is_unbound(self):
        self.assertNotEqual(cp.main(['validate', '--config', str(CONFIG)]), 0)


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

    def test_all_shaping_fields_exist_and_default_off(self):
        sh = self.cfg['shaping']
        for group in ('hold_pps', 'block_pps'):
            self.assertEqual(sh[group], {'ack': 0, 'resp': 0, 'op': 0})
        self.assertIsNone(sh['block_burst'])

    def test_negative_shaping_rate_is_rejected(self):
        bad = copy.deepcopy(self.cfg)
        bad['shaping']['hold_pps']['ack'] = -1
        with self.assertRaises(ValueError):
            cp.validate_profile(bad)

    def test_installer_args_carry_every_shaping_flag(self):
        cfg = copy.deepcopy(self.cfg)
        cfg['shaping']['hold_pps']['resp'] = 300
        cfg['shaping']['block_pps']['op'] = 40
        cfg['shaping']['block_burst'] = 96
        a = cp.shaping_args(cfg)
        for flag in ('--shape-ack-pps 0', '--shape-resp-pps 300', '--shape-op-pps 0', '--shape-ack-blk-pps 0',
                     '--shape-resp-blk-pps 0', '--shape-op-blk-pps 40', '--block-burst 96'):
            self.assertIn(flag, a)

    def test_block_burst_omitted_when_null(self):
        self.assertNotIn('--block-burst', cp.shaping_args(self.cfg))

    def test_fixture_jitter_is_rejected_because_vision_run_cannot_apply_it(self):
        bad = copy.deepcopy(self.cfg)
        bad['fixture']['jitter_ms'] = 5
        with self.assertRaises(ValueError):
            cp.validate_profile(bad)


if __name__ == '__main__':
    unittest.main()
