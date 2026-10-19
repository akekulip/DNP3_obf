"""Device-classification study: frozen order, configs and the locked analysis (DEVICE_STUDY_PROTOCOL.md)."""
import csv
import json
import random
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / 'hw'))
sys.path.insert(0, str(HERE.parent / 'analysis'))
import device_prepare as dp  # noqa: E402

DEVICES = {'dev_const5': (5.3, 0.05), 'dev_sel': (2.6, 1.5), 'dev_slow': (9.3, 0.8)}


class Order(unittest.TestCase):
    def setUp(self):
        self.order = dp.collection_order('dev_test')

    def test_shape(self):
        pilots = [b for b in self.order if b['phase'] == 'pilot']
        main = [b for b in self.order if b['phase'] == 'main']
        self.assertEqual(len(pilots), 3)
        self.assertEqual(len(main), 48)
        self.assertTrue(all(b['sbo'] == 0 and b['condition_id'] == 'D10_J2p4' for b in self.order))
        self.assertEqual({b['split'] for b in main if b['round'] <= 8}, {'training'})
        self.assertEqual({b['split'] for b in main if b['round'] > 8}, {'testing'})
        self.assertEqual(sum(b['expected_exchanges'] for b in main), 48 * 2 * 512)

    def test_rotation(self):
        first = [b['device'] for b in self.order if b.get('round') == 2]
        self.assertEqual(first, ['dev_sel', 'dev_slow', 'dev_const5'])
        self.assertEqual([b['arms'] for b in self.order if b.get('round') == 2][0], ['combined', 'off'])
        self.assertEqual([b['arms'] for b in self.order if b.get('round') == 3][0], ['off', 'combined'])

    def test_netem_bound_stays_inside_the_acknowledgment_deadline(self):
        da = dp.ep.load(dp.ENVELOPE)['requested_ns']['da'] / dp.ep.MS
        for _, delay, jitter, _ in dp.DEVICES:
            self.assertLess(delay + 4 * jitter + 1, da)


class Prepare(unittest.TestCase):
    def test_configs_carry_the_device_and_validate(self):
        sys.path.insert(0, str(dp.ep.ARCH / 'protocol/hw_vepa'))
        import campaign as cp
        with tempfile.TemporaryDirectory() as tmp:
            root = dp.prepare(Path(tmp) / 'c', 'dev_test')
            order = json.loads((root / 'collection_order.json').read_text())
            for block in order:
                cfg = json.loads(dp.ep.config_path(root, block).read_text())
                cp.validate_profile(cfg)
                self.assertEqual(cfg['fixture']['delay_ms'], block['delay_ms'])
                self.assertEqual(cfg['fixture'].get('jitter_ms', 0), block['jitter_ms'])
                self.assertEqual(cfg['fixture'].get('distribution'), block['distribution'])
                self.assertEqual([a['name'] for a in cfg['arms']], block['arms'])
                self.assertEqual(cfg['trials']['reads_per_trial'], block['reads'])
                self.assertFalse(cfg['traffic']['run_sbo'])
                self.assertEqual(cfg['timing_params_ns']['gap'], 10 * dp.ep.MS)
            steps = json.loads((root / 'controller_manifest.json').read_text())['steps']
            ids = [s['id'] for s in steps]
            self.assertEqual(ids.index('qualify'), 3)
            self.assertLess(ids.index('dev_test_r08_dev_sel'), ids.index('fit'))
            self.assertLess(ids.index('fit'), ids.index('dev_test_r09_dev_slow'))
            self.assertEqual(ids[-1], 'export')
            self.assertTrue(all('postcheck_argv' in s for s in steps if s['kind'] == 'block'))


def synthetic(path, split, combined_flat):
    rng = random.Random(7 if split == 'training' else 11)
    rows = []
    rounds = range(1, 9) if split == 'training' else range(9, 17)
    for rnd in rounds:
        for device, (mean, sd) in DEVICES.items():
            for arm in ('off', 'combined'):
                block = '%s_r%02d_%s' % (split, rnd, device)
                for i in range(128):
                    clrt = (10.02 + rng.gauss(0, .003)) if (arm == 'combined' and combined_flat) else max(.2, rng.gauss(mean, sd))
                    rows.append(dict(example_id='%s_%s_%d' % (block, arm, i), block_id=block, device=device,
                                     condition_id='D10_J2p4', round=rnd, split=split, arm=arm, operation='READ',
                                     connection_id=block + arm, session_id=block + arm, sequence=i,
                                     observed_at_ms=float(i * 40), clrt_ms=clrt))
    with open(path, 'w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


class Analysis(unittest.TestCase):
    def run_study(self, combined_flat):
        import device_analysis as da
        tmp = Path(tempfile.mkdtemp())
        synthetic(tmp / 'train.csv', 'training', combined_flat)
        synthetic(tmp / 'test.csv', 'testing', combined_flat)
        da.fit(tmp / 'train.csv', tmp / 'lock.json')
        da.evaluate(tmp / 'train.csv', tmp / 'test.csv', tmp / 'lock.json', tmp / 'out')
        table = {(r['attacker'], r['arm'], int(r['k'])): float(r['balanced_accuracy'])
                 for r in csv.DictReader(open(tmp / 'out/device_attacks.csv'))}
        return table, json.loads((tmp / 'out/device_primary.json').read_text()), tmp

    def test_flat_timing_hides_devices_but_a_constant_delay_does_not(self):
        table, primary, _ = self.run_study(True)
        self.assertGreater(table[('retrained', 'off', 32)], .9)
        self.assertGreater(table[('constant_delay', 'off+c', 32)], .9)
        self.assertLess(table[('retrained', 'combined', 32)], .5)
        self.assertGreater(primary['primary']['lower'], .3)

    def test_unobfuscated_combined_is_not_reported_as_hidden(self):
        table, primary, _ = self.run_study(False)
        self.assertGreater(table[('retrained', 'combined', 32)], .9)
        self.assertLess(primary['primary']['lower'], .1)

    def test_evaluate_refuses_a_different_training_set(self):
        import device_analysis as da
        _, _, tmp = self.run_study(True)
        synthetic(tmp / 'other.csv', 'training', False)
        with self.assertRaises(ValueError):
            da.evaluate(tmp / 'other.csv', tmp / 'test.csv', tmp / 'lock.json', tmp / 'out2')

    def test_fit_refuses_testing_rows(self):
        import device_analysis as da
        tmp = Path(tempfile.mkdtemp())
        synthetic(tmp / 'test.csv', 'testing', True)
        with self.assertRaises(ValueError):
            da.fit(tmp / 'test.csv', tmp / 'lock.json')


if __name__ == '__main__':
    unittest.main()
