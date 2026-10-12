"""Start-phase and spacing controls, and the paired_blocks plan type: presets A and B run under identical conditions
in alternating order and are recorded as pairs."""
import contextlib
import copy
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import campaign as cp  # noqa: E402
import run as runmod  # noqa: E402
import vision_run as vr  # noqa: E402
from test_campaign_bindings import cfg_for  # noqa: E402
from test_campaign_run import FakeRunner  # noqa: E402

CONDS = [{'delay_ms': 5, 'gap_ms': 0, 'start_delay_ms': 20, 'seed': 11},
         {'delay_ms': 5, 'gap_ms': 20, 'start_delay_ms': 40, 'seed': 12},
         {'delay_ms': 3, 'gap_ms': 0, 'start_delay_ms': 0, 'seed': 13}]


class StartDelay(unittest.TestCase):
    def test_start_delay_is_seeded_and_bounded(self):
        a = [vr.start_delay_ms(50, s) for s in range(40)]
        self.assertEqual(a, [vr.start_delay_ms(50, s) for s in range(40)])      # deterministic per seed
        self.assertTrue(all(0 <= x <= 50 for x in a))
        self.assertGreater(len(set(a)), 10)                                     # and actually randomized across seeds

    def test_zero_max_is_no_delay(self):
        self.assertEqual(vr.start_delay_ms(0, 99), 0)

    def test_vision_run_accepts_the_flags(self):
        out = subprocess.run([sys.executable, str(HERE.parent / 'vision_run.py'), '--help'],
                             capture_output=True, text=True).stdout
        self.assertIn('--start-delay-ms', out)
        self.assertIn('--start-seed', out)
        self.assertIn('--gap-ms', out)

    def test_run_py_threads_the_controls_into_the_vision_command(self):
        cmd = runmod.vision_cmd('lbl', 54500, 20, 8, 20, 40, 7, False)
        for s in ('--master-port 54500', '--reads 20', '--range 8', '--gap-ms 20', '--start-delay-ms 40',
                  '--start-seed 7'):
            self.assertIn(s, cmd)


class Base(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = td.name
        self.cfg = cfg_for(Path(self.tmp) / 'b', 'match')
        (Path(self.tmp) / 'b').mkdir(exist_ok=True)
        self.cfg['evidence_dir'] = str(Path(self.tmp) / 'ev')
        self.cfg['trials']['trials_per_arm'] = 1
        self.cfg['fixture']['modes'] = ['separate_ack', 'piggyback']
        self.cfg['traffic']['master_port_range'] = {'first': 54500, 'last': 54599}
        self.cfg['paired_blocks'] = {'ab': {'arm': 'combined', 'fixture': 'separate_ack',
                                            'presets': ['shape_14892', 'shape_3723'], 'repeats': 1,
                                            'conditions': CONDS}}

    def rec(self):
        return json.load(open(Path(self.tmp) / 'ev' / 'c1' / 'campaign_run.json'))

    def execute(self, runner=None, paired='ab'):
        r = runner or FakeRunner()
        rc = cp.Campaign(self.cfg, r, 'c1', paired=paired, installer_flags=lambda f: True).execute()
        return rc, r


class TrialConditions(Base):
    def test_every_trial_records_its_seeded_start_delay_gap_and_fixture_delay(self):
        rc, r = self.execute(paired=None)
        self.assertEqual(rc, 0)
        for rec in self.rec()['arms']:
            for t in rec['trials']:
                c = t['conditions']
                self.assertEqual(set(c), {'delay_ms', 'gap_ms', 'start_delay_ms', 'start_seed'})

    def test_per_trial_seed_is_derived_from_the_configured_seed_and_distinct(self):
        self.cfg['trials']['trials_per_arm'] = 3
        self.cfg['traffic']['start_delay_ms'] = 30
        rc, r = self.execute(paired=None)
        seeds = [t['conditions']['start_seed'] for rec in self.rec()['arms'] for t in rec['trials']]
        self.assertEqual(len(set(seeds)), len(seeds))
        run = [r.calls[i][1] for i in r.cmds('vision_run.py run')]
        self.assertTrue(all('--start-delay-ms 30' in c and '--start-seed' in c for c in run))

    def test_default_start_delay_is_zero(self):
        self.assertEqual(json.load(open(HERE.parent / 'campaign.json'))['traffic']['start_delay_ms'], 0)


class PairedBlocks(Base):
    def test_each_condition_runs_both_presets_with_identical_conditions(self):
        rc, r = self.execute()
        self.assertEqual(rc, 0)
        runs = [r.calls[i][1] for i in r.cmds('vision_run.py run')]
        self.assertEqual(len(runs), 6)                                     # 3 conditions x 2 presets
        for k in range(3):
            a, b = runs[2 * k], runs[2 * k + 1]
            norm = lambda c: re.sub(r'run \S+ --master-port \d+', '', c)
            self.assertEqual(norm(a), norm(b))                             # identical reads/range/gap/start delay/seed
        self.assertIn('--gap-ms 20', runs[2])
        self.assertIn('--start-delay-ms 40 --start-seed 12', runs[2])

    def test_order_alternates_between_pairs(self):
        rc, r = self.execute()
        pairs = self.rec()['pairs']
        self.assertEqual([p['order'] for p in pairs],
                         [['shape_14892', 'shape_3723'], ['shape_3723', 'shape_14892'],
                          ['shape_14892', 'shape_3723']])

    def test_installer_gets_the_preset_of_its_slot(self):
        rc, r = self.execute()
        applies = [r.calls[i][1] for i in r.cmds('bringup_composite.py') if '--apply' in r.calls[i][1]]
        self.assertEqual(len(applies), 6)
        for cmd, preset in zip(applies, ['shape_14892', 'shape_3723', 'shape_3723', 'shape_14892',
                                         'shape_14892', 'shape_3723']):
            rate = {'shape_14892': 14892, 'shape_3723': 3723}[preset]
            self.assertIn('--shape-resp-blk-pps %d' % rate, cmd)
        snaps = [r.calls[i][1] for i in r.cmds('snapshot_counters.py')]
        self.assertIn('--shape-ack-pps 14892', snaps[0])

    def test_fixture_delay_changes_only_when_the_condition_changes(self):
        rc, r = self.execute()
        ons = [r.calls[i][1] for i in r.runs('casea on')]
        self.assertEqual([re.search(r'--delay-ms (\d+)', c).group(1) for c in ons], ['5', '3'])

    def test_pairs_are_recorded_with_labels_conditions_and_results(self):
        rc, r = self.execute()
        rec = self.rec()
        self.assertEqual(len(rec['pairs']), 3)
        p = rec['pairs'][1]
        self.assertEqual(p['condition'], CONDS[1])
        self.assertEqual(len(p['labels']), 2)
        self.assertEqual(p['ok'], True)
        trials = {t['label']: t for a in rec['arms'] for t in a['trials']}
        self.assertEqual({trials[l]['preset'] for l in p['labels']}, {'shape_14892', 'shape_3723'})
        self.assertEqual(rec['paired_block'], 'ab')

    def test_each_run_is_its_own_cold_bring_up_on_a_new_port(self):
        rc, r = self.execute()
        ports = [int(re.search(r'--master-port (\d+)', r.calls[i][1]).group(1)) for i in r.cmds('vision_run.py run')]
        self.assertEqual(ports, list(range(54500, 54506)))
        self.assertEqual(len([i for i in r.swaps() if 'launch_composite.sh' in r.calls[i][1]]), 6)

    def test_repeats_multiply_the_pairs(self):
        self.cfg['paired_blocks']['ab']['repeats'] = 2
        rc, r = self.execute()
        self.assertEqual(len(self.rec()['pairs']), 6)

    def test_plan_prints_the_paired_block_without_running(self):
        import cp_main_helper
        rc, out = cp_main_helper.plan(self.cfg, self.tmp, ['--paired', 'ab', '--run-id', 'c1'])
        self.assertEqual(rc, 0)
        self.assertEqual(out.count('vision_run.py run c1_'), 6)
        self.assertIn('--shape-resp-blk-pps 14892', out)
        self.assertIn('--start-delay-ms 40 --start-seed 12', out)

    def test_bad_blocks_are_rejected(self):
        for mutate in (lambda b: b.update(presets=['shape_14892']),
                       lambda b: b.update(presets=['shape_14892', 'shape_14892']),
                       lambda b: b.update(presets=['shape_14892', 'nope']),
                       lambda b: b.update(conditions=[]),
                       lambda b: b.update(arm='nope'),
                       lambda b: b.update(fixture='jittered'),
                       lambda b: b['conditions'][0].update(start_delay_ms=-1)):
            bad = copy.deepcopy(self.cfg)
            mutate(bad['paired_blocks']['ab'])
            with self.assertRaises(ValueError):
                cp.validate_profile(bad)

    def test_unknown_paired_block_is_refused(self):
        with self.assertRaises(ValueError):
            cp.Campaign(self.cfg, FakeRunner(), 'c1', paired='nope')

    def test_a_failed_run_stops_the_block_and_the_pair_is_not_ok(self):
        rc, r = self.execute(FakeRunner(vision_out='{"ok": false}', vision_rc=1))
        self.assertEqual(rc, 1)
        self.assertEqual(len(r.cmds('vision_run.py run')), 1)
        self.assertFalse(self.rec()['pairs'][0]['ok'])


if __name__ == '__main__':
    unittest.main()
