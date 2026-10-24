"""hw/mau_snapshot.py spec handling and the counter snapshot's option stripping (switch I/O is proven on the model:
ctl_timing_01/model_mau_snapshot.py)."""
import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


mau = load('test_mau_snapshot_module', HERE / 'hw' / 'mau_snapshot.py')
BFRT = HERE / 'stage_experiments/ctl_timing_01/evidence/m12p_c51_sdk9132/compile_local/out/bfrt.json'
SPEC = 'start=0,end=10,m.packet_kind=9/0xff,m.lap=1/1,m.stage=0/3'


class Untouched:
    """Any switch access fails the test: refusals must happen before the first write."""
    def __getattr__(self, name):
        raise AssertionError('switch touched: ' + name)


class MauSnapshot(unittest.TestCase):
    def test_spec_parses(self):
        spec = mau.parse(SPEC)
        self.assertEqual((spec['start'], spec['end']), (0, 10))
        self.assertEqual(spec['trigger'], {'m.packet_kind': (9, 0xff), 'm.lap': (1, 1), 'm.stage': (0, 3)})

    def test_bad_specs_are_refused(self):
        for text in ('start=0,end=10', 'start=3,end=2,m.lap=1/1', 'start=0,end=12,m.lap=1/1',
                     'start=0,end=10,m.lap=1', 'start=0,end=10,m.lap=2/1'):
            with self.assertRaises(ValueError, msg=text):
                mau.parse(text)

    def test_build_trigger_widths(self):
        widths = mau.trigger_widths(BFRT)
        self.assertEqual((widths['m.packet_kind'], widths['m.lap'], widths['m.stage']), (8, 1, 2))
        self.assertEqual(mau.encode(0x1ff, 9), bytearray(b'\x01\xff'))

    def test_unknown_field_or_wide_mask_refused_before_any_write(self):
        for text in ('start=0,end=10,m.not_a_field=1/1', 'start=0,end=10,m.lap=1/3'):
            with self.assertRaises(ValueError, msg=text):
                mau.arm(Untouched(), mau.parse(text), BFRT)

    def test_counter_snapshot_strips_the_option(self):
        sys.path.insert(0, str(HERE.parent / 'response_only' / 'hw' / 'tests'))
        import fixture  # noqa: F401  (binds the baseline installer)
        counters = load('test_mau_snapshot_counters', HERE / 'hw' / 'snapshot_counters.py')
        args = ['--build-out', 'x', '--mau-snapshot', SPEC, '-o', 'y_before.json']
        self.assertEqual(counters.mau_snapshot_option(args), (['--build-out', 'x', '-o', 'y_before.json'], SPEC))
        self.assertEqual(counters.mau_snapshot_option(['-o', 'y']), (['-o', 'y'], None))
        with self.assertRaises(SystemExit):
            counters.mau_snapshot_option(['--mau-snapshot'])


if __name__ == '__main__':
    unittest.main()
