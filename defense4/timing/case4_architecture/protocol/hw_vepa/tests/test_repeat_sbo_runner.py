"""Repeated SELECT/OPERATE cycles on one connection: config validation, counts and per-cycle record checks.

The endpoint itself is gated by rearm_01/repeat_sbo_endpoint/tests (real loopback processes); these tests cover
how the campaign turns traffic.sbo_cycles into expectations and rejects records that do not show exactly one
paired SELECT and OPERATE per cycle."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import campaign as cp  # noqa: E402
import checks  # noqa: E402
import standards  # noqa: E402
import vision_run as vr  # noqa: E402

CONFIG = HERE.parent / 'campaign.json'


def master_record(cycles, **override):
    rows = [dict(cycle=c, on_time_ms=100 + c, callbacks=1, ok=True, index=1, status=0, points=1,
                 read_matches_seed=True, issued_ns=10 * c, completed_ns=10 * c + 5) for c in range(cycles)]
    for c, change in override.items():
        rows[int(c)].update(change)
    return {'sbo_cycles': cycles, 'cycles': rows}


def outstation_record(cycles, events=None):
    events = events if events is not None else [
        dict(seq=i, kind=('SELECT', 'OPERATE')[i % 2], index=1, status=0, on_time_ms=100 + i // 2, off_time_ms=100)
        for i in range(2 * cycles)]
    return {'select_real': cycles, 'operate_real': cycles, 'select_decoy': 0, 'operate_decoy': 0,
            'actuation': 'software_handler', 'physical_actuations': 0, 'events': events}


class SboCount(unittest.TestCase):
    def test_counts(self):
        self.assertEqual(checks.sbo_count({}), 1)
        self.assertEqual(checks.sbo_count({'run_sbo': False}), 0)
        self.assertEqual(checks.sbo_count({'run_sbo': True, 'sbo_cycles': 64}), 64)
        self.assertEqual(checks.sbo_count({'run_sbo': False, 'sbo_cycles': 64}), 0)

    def test_standards_expect_one_select_and_operate_per_cycle(self):
        context = {'trial': {'reads': 65}, 'config': {'traffic': {'run_sbo': True, 'sbo_cycles': 64}}}
        self.assertEqual(standards.expected_counts(context), {'READ': 65, 'SELECT': 64, 'OPERATE': 64})
        context['config']['traffic'] = {'run_sbo': True}
        self.assertEqual(standards.expected_counts(context), {'READ': 65, 'SELECT': 1, 'OPERATE': 1})


class RepeatedRecords(unittest.TestCase):
    def test_clean_cycles_pass(self):
        self.assertEqual(checks.repeated_sbo_checks(master_record(64), outstation_record(64), 64), [])

    def test_every_defect_is_named(self):
        cases = {
            'duplicate callback': (master_record(4, **{'2': {'callbacks': 2}}), outstation_record(4)),
            'failed status': (master_record(4, **{'1': {'status': 3, 'ok': False}}), outstation_record(4)),
            'wrong cycle identity': (master_record(4, **{'3': {'on_time_ms': 100}}), outstation_record(4)),
            'stale READ after a cycle': (master_record(4, **{'0': {'read_matches_seed': False}}), outstation_record(4)),
            'missing cycle': (dict(master_record(4), cycles=master_record(4)['cycles'][:3]), outstation_record(4)),
            'operate before select': (master_record(2), outstation_record(2, [
                dict(kind='OPERATE', index=1, status=0, on_time_ms=100), dict(kind='SELECT', index=1, status=0, on_time_ms=100),
                dict(kind='SELECT', index=1, status=0, on_time_ms=101), dict(kind='OPERATE', index=1, status=0, on_time_ms=101)])),
            'duplicate operate callback': (master_record(2), outstation_record(2, outstation_record(2)['events'] + [
                dict(kind='OPERATE', index=1, status=0, on_time_ms=101)])),
            'operate paired with another cycle': (master_record(2), outstation_record(2, [
                dict(kind='SELECT', index=1, status=0, on_time_ms=100), dict(kind='OPERATE', index=1, status=0, on_time_ms=101),
                dict(kind='SELECT', index=1, status=0, on_time_ms=101), dict(kind='OPERATE', index=1, status=0, on_time_ms=101)])),
            'decoy index': (master_record(1), outstation_record(1, [
                dict(kind='SELECT', index=201, status=0, on_time_ms=100), dict(kind='OPERATE', index=201, status=0, on_time_ms=100)])),
            'physical actuation': (master_record(1), dict(outstation_record(1), physical_actuations=1)),
            'no events': (master_record(1), {k: v for k, v in outstation_record(1).items() if k != 'events'}),
        }
        for name, (master, outstation) in cases.items():
            with self.subTest(name):
                self.assertTrue(checks.repeated_sbo_checks(master, outstation, master['sbo_cycles']), name)

    def test_application_checks_count_every_cycle(self):
        exp = json.load(open(CONFIG))['expectations']
        reads = 65
        master = dict(master_record(64), success=True, all_reads_match_seed=True, reads_completed=reads,
                      reads_requested=reads, reads=[dict(points_received=exp['common']['read_points'], matches_seed=True,
                                                         completed=True)] * reads)
        outstation = outstation_record(64)
        summary = {'READ': {'logical_requests': reads, 'complete': reads, 'incomplete': 0, 'piggyback': 0,
                            'req_crc_bad': 0, 'resp_crc_bad': 0, 'resp_len': exp['padding']['1']['read_resp_len']}}
        for kind in ('SELECT', 'OPERATE'):
            summary[kind] = {'logical_requests': 64, 'complete': 64, 'incomplete': 0, 'piggyback': 0,
                             'req_crc_bad': 0, 'resp_crc_bad': 0, 'resp_len': exp['padding']['1']['sbo_resp_len']}
        ev = {'master': master, 'outstation': outstation, 'timing': {'summary': summary},
              'wire': {'returned_integrity': {'dnp3_crc_bad': [], 'tcp_checksum_bad': []}}}
        self.assertEqual(checks.application_checks(exp, 1, reads, ev, 64), [])
        one = checks.application_checks(exp, 1, reads, ev, 1)                   # a single-cycle claim fails
        self.assertTrue(any('select_real=64' in f for f in one), one)
        short = copy.deepcopy(ev)
        short['timing']['summary']['OPERATE']['complete'] = 63
        self.assertTrue(any('OPERATE' in f for f in checks.application_checks(exp, 1, reads, short, 64)))
        dup = copy.deepcopy(ev)
        dup['master']['cycles'][10]['callbacks'] = 2
        self.assertTrue(any('SBO cycle 10' in f for f in checks.application_checks(exp, 1, reads, dup, 64)))


class ConfigValidation(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = Path(td.name)

    def load(self, change):
        cfg = json.load(open(CONFIG))
        change(cfg)
        path = self.tmp / 'c.json'
        path.write_text(json.dumps(cfg))
        return cp.load_config(str(path))

    def repeat(self, cycles=64, reads=65):
        def change(cfg):
            cfg['traffic']['sbo_cycles'] = cycles
            cfg['trials']['reads_per_trial'] = reads
            cfg.setdefault('loss', {})['presets'] = {}
        return change

    def test_valid_repeated_config_and_control_arguments(self):
        cfg = self.load(self.repeat())
        campaign = cp.Campaign.__new__(cp.Campaign)
        campaign.cfg = cfg
        self.assertEqual(campaign.endpoint_controls()['sbo_cycles'], 64)
        self.assertIn('--sbo-cycles 64', campaign.endpoint_control_args())
        plain = cp.Campaign.__new__(cp.Campaign)
        plain.cfg = cp.load_config(str(CONFIG))
        self.assertNotIn('sbo_cycles', plain.endpoint_controls())               # unchanged for the old endpoint
        self.assertNotIn('--sbo-cycles', plain.endpoint_control_args())

    def test_invalid_repeated_configs_are_rejected(self):
        bad = {
            'zero': self.repeat(0), 'too many': self.repeat(65, 66), 'bool': self.repeat(True),
            'reads too few': self.repeat(64, 64),
        }
        for name, change in bad.items():
            with self.subTest(name), self.assertRaises(ValueError):
                self.load(change)
        with self.assertRaises(ValueError):
            self.load(lambda cfg: (self.repeat()(cfg), cfg['traffic'].update(run_sbo=False)))
        with self.assertRaises(ValueError):
            self.load(lambda cfg: (self.repeat()(cfg), cfg['loss'].update(presets={'core': [{'class': 'x', 'n': 1}]})))


class VisionRunValidation(unittest.TestCase):
    def test_bad_cycle_controls_fail_before_creating_the_run_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            for kwargs in (dict(sbo_cycles=65), dict(sbo_cycles=-1), dict(sbo_cycles=True),
                           dict(sbo_cycles=4, run_sbo=False), dict(sbo_cycles=4, reads=4)):
                run_dir = Path(tmp) / 'run'
                args = dict(reads=kwargs.pop('reads', 65))
                with self.subTest(kwargs), self.assertRaises(ValueError):
                    vr.run_connection(str(run_dir), 'x', 59500, args['reads'], 8, 0, 0, 0, **kwargs)
                self.assertFalse(run_dir.exists())


if __name__ == '__main__':
    unittest.main()
