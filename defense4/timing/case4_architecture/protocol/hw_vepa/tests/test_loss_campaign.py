"""Loss and reconnect trials through the campaign orchestration (fake process boundary, REAL analyzers on synthetic
pcaps): the commands emitted, the loss gate, soft-failing of a lost-recovery trial, and the reconnect record."""
import copy
import io
import json
import re
import shlex
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import campaign as cp  # noqa: E402
import clrt_check  # noqa: E402
import loss  # noqa: E402
import pcaptk as tk  # noqa: E402
import wire_check  # noqa: E402
from test_campaign_bindings import cfg_for  # noqa: E402
from test_campaign_run import FakeRunner, parse_label, ARMS  # noqa: E402
from test_loss_analysis import conversation  # noqa: E402

RULE_OK = {'class': 'read_resp_padded', 'n': 2, 'occurrence': 2, 'exact': True, 'removed': True, 'state_restored': True,
           'dropped_packets': 1, 'dropped_bytes': 98, 'remove_errors': []}


class LossFake(FakeRunner):
    """Writes real synthetic pcaps for loss/scenario units so identify() and the analyzers run for real."""
    def __init__(self, resp_len=58, retransmit=True, rule=None, c3='native_ok', **kw):
        super().__init__(**kw)
        self.resp_len, self.retransmit, self.rule, self.c3 = resp_len, retransmit, rule, c3
        self.drops, self.scenarios, self.ports = {}, {}, {}

    def write_conv(self, d, reads, resp_len, retx_resp=None, issued=10, dur_s=3, sbo=False):
        d.mkdir(parents=True, exist_ok=True)
        out, inn = conversation(reads=reads, retx_resp=retx_resp, resp_len=resp_len)
        if sbo:
            master, station, mport, oport = '192.168.10.61', '192.168.10.62', 54500, 20000
            seq, ack = 1000 + 20 * reads, 5000 + resp_len * reads
            for offset, function in enumerate((3, 4)):
                t = (reads + offset + 1) * 1000000
                request = tk.read_request(reads + offset, func=function)
                response = tk.read_response(reads + offset, body_len=37 if resp_len == 58 else 18)
                frames = [(t, tk.frame(master, station, mport, oport, seq, ack, tk.PSH | tk.ACK, request)),
                          (t + 300, tk.frame(station, master, oport, mport, ack, seq + len(request), tk.ACK)),
                          (t + 5000, tk.frame(station, master, oport, mport, ack, seq + len(request), tk.PSH | tk.ACK, response))]
                out.extend(frames)
                inn.extend((time + 50, frame) for time, frame in frames)
                seq, ack = seq + len(request), ack + len(response)
        tk.write_pcap(str(d / 'out.pcap'), out)
        tk.write_pcap(str(d / 'in.pcap'), inn)
        (d / 'master.json').write_text(json.dumps({'success': True, 'reads_requested': reads, 'reads_completed': reads,
                                                   'all_reads_match_seed': True,
                                                   'reads': [{'completed': True, 'points_received': 23, 'matches_seed': True} for _ in range(reads)],
                                                   'issued_ns': issued,
                                                   'completed_ns': issued + dur_s * 10 ** 9}))
        (d / 'outstation.json').write_text(json.dumps({'select_real': 1, 'select_decoy': 0, 'operate_real': 1,
                                                       'operate_decoy': 0}))

    def run(self, where, cmd, **kw):
        if where == 'vision' and 'vision_run.py run' in cmd and ('--drop' in cmd or '--scenario' in cmd):
            self.calls.append((where, cmd))
            label = re.search(r'run (\S+)', cmd).group(1)
            reads = int(re.search(r'--reads (\d+)', cmd).group(1))
            self.reads[label] = reads
            self.ports[label] = int(re.search(r'--master-port (\d+)', cmd).group(1))
            if '--drop' in cmd:
                self.drops[label] = re.search(r'--drop (\S+)', cmd).group(1)
                res = {'ok': True, 'master_rc': 0, 'label': label, 'loss': self.rule or RULE_OK}
                return cp.Result(0, json.dumps(res) + '\n', '')
            self.scenarios[label] = True
            res = {'scenario': 'reconnect', 'ok': True, 'connections': {
                'c1': {'ok': True, 'master_rc': 0, 'master_port': self.ports[label], 'role': 'installed'},
                'c2': {'ok': True, 'master_rc': 0, 'master_port': self.ports[label] + 1000, 'role': 'unknown_port'},
                'c3': {'ok': self.c3 == 'native_ok', 'master_rc': 0 if self.c3 == 'native_ok' else 1,
                       'master_timeout': self.c3 == 'timeout', 'master_port': self.ports[label], 'role': 'installed_again'}}}
            return cp.Result(0, json.dumps(res) + '\n', '')
        if where == 'local' and cmd.startswith('scp') and '/runs/' in cmd:
            label = re.search(r'runs/(\S+?)/\*', cmd).group(1)
            dest = Path(shlex.split(cmd)[-1])
            if label in self.drops:
                self.calls.append((where, cmd))
                spec = loss.parse_drop(self.drops[label], self.reads[label])
                self.write_conv(dest, self.reads[label], self.resp_len, retx_resp=1 if self.retransmit else None)
                return cp.Result(0, '', '')
            if label in self.scenarios:
                self.calls.append((where, cmd))
                fx, arm = parse_label(label)
                padded = 58 if arm['padding'] else 49
                self.write_conv(dest / 'c1', self.reads[label], padded, sbo=True)
                self.write_conv(dest / 'c2', self.reads[label], 49, sbo=True)
                self.write_conv(dest / 'c3', self.reads[label], 49 if self.c3 == 'native_ok' else padded, sbo=True)
                return cp.Result(0, '', '')
        if where == 'local' and ('wire_check.py' in cmd or 'clrt_check.py' in cmd):
            tool = 'wire' if 'wire_check.py' in cmd else 'clrt'
            args = shlex.split(cmd)
            outp, inp = args[args.index('--json') - 2], args[args.index('--json') - 1]
            if Path(outp).exists() and Path(outp).stat().st_size > 100:        # real pcap: run the real analyzer
                self.calls.append((where, cmd))
                rep = wire_check.analyze(outp, inp) if tool == 'wire' else clrt_check.analyze(outp, inp)
                Path(args[args.index('--json') + 1]).write_text(json.dumps(rep, default=str))
                return cp.Result(0, '', '')
        return super().run(where, cmd, **kw)


class Base(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.tmp = td.name
        self.cfg = cfg_for(Path(self.tmp) / 'b', 'match')
        (Path(self.tmp) / 'b').mkdir(exist_ok=True)
        self.cfg['evidence_dir'] = str(Path(self.tmp) / 'ev')
        self.cfg['trials']['trials_per_arm'] = 1
        self.cfg['trials']['reads_per_trial'] = 3
        self.cfg['fixture']['modes'] = ['separate_ack']
        self.cfg['loss']['presets'] = {'one': [{'class': 'read_resp_padded', 'n': 2}],
                                       'two': [{'class': 'read_resp_padded', 'n': 2}, {'class': 'request', 'n': 1}]}

    def execute(self, runner, loss_preset='one', scenario=None, arms=('combined',)):
        rc = cp.Campaign(self.cfg, runner, 'c1', arms=list(arms), installer_flags=lambda f: True,
                         loss=loss_preset if scenario is None else None, scenario=scenario).execute()
        return rc

    def rec(self):
        return json.load(open(Path(self.tmp) / 'ev' / 'c1' / 'campaign_run.json'))


class ConfigAndPlan(Base):
    def test_shipped_config_carries_loss_presets_scenario_and_default_bound(self):
        cfg = json.load(open(HERE.parent / 'campaign.json'))
        self.assertEqual(cfg['loss']['max_recovery_s'], 5.0)
        self.assertTrue(cfg['loss']['presets'])
        self.assertIn('reconnect', cfg['scenarios'])
        cp.validate_profile(cp.load_config(str(HERE.parent / 'campaign.json')))

    def test_bad_loss_config_is_rejected(self):
        for mutate in (lambda c: c['loss'].update(max_recovery_s=0),
                       lambda c: c['loss']['presets'].update(bad=[{'class': 'nope', 'n': 1}]),
                       lambda c: c['loss']['presets'].update(bad=[{'class': 'request', 'n': 0}]),
                       lambda c: c['loss']['presets'].update(bad=[]),
                       lambda c: c['scenarios']['reconnect'].update(reconnect_port_offset=0),
                       lambda c: c['scenarios'].update(other={})):
            bad = copy.deepcopy(json.load(open(HERE.parent / 'campaign.json')))
            mutate(bad)
            with self.assertRaises(ValueError):
                cp.validate_profile(bad)

    def test_unknown_preset_or_scenario_is_refused(self):
        with self.assertRaises(ValueError):
            cp.Campaign(self.cfg, FakeRunner(), 'c1', loss='nope')
        with self.assertRaises(ValueError):
            cp.Campaign(self.cfg, FakeRunner(), 'c1', scenario='nope')

    def test_plan_prints_the_exact_drop_command(self):
        dry = cp.DryRunner()
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            cp.Campaign(self.cfg, dry, 'c1', arms=['combined'], installer_flags=lambda f: True, loss='two').execute()
        runs = [c for _w, c in dry.calls if 'vision_run.py run' in c]
        self.assertEqual(len(runs), 2)
        self.assertIn('--drop read_resp_padded:2', runs[0])
        self.assertIn('--drop request:1', runs[1])
        self.assertEqual(len({re.search(r'run (\S+)', c).group(1) for c in runs}), 2)       # labels never reused

    def test_plan_prints_the_reconnect_commands_including_per_connection_analysis(self):
        dry = cp.DryRunner()
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            cp.Campaign(self.cfg, dry, 'c1', arms=['combined'], installer_flags=lambda f: True,
                        scenario='reconnect').execute()
        run = [c for _w, c in dry.calls if 'vision_run.py run' in c][0]
        self.assertRegex(run, r'--scenario reconnect --reconnect-port \d+')
        analyses = [c for _w, c in dry.calls if 'wire_check.py' in c or 'clrt_check.py' in c]
        self.assertEqual(len(analyses), 6)
        for cn in ('c1', 'c2', 'c3'):
            self.assertTrue(any('/%s/out.pcap' % cn in c for c in analyses), cn)


class LossTrials(Base):
    def test_a_recovered_loss_passes_and_records_the_packet_and_recovery(self):
        r = LossFake()
        self.assertEqual(self.execute(r), 0)
        t = self.rec()['arms'][0]['trials'][0]
        self.assertTrue(t['ok'], t['failures'])
        l = t['loss']
        self.assertEqual((l['class'], l['n']), ('read_resp_padded', 2))
        self.assertEqual(l['packet']['len'], 58)
        self.assertTrue(l['retransmitted'])
        self.assertEqual(l['first_retx_delay_ms'], 200.0)
        self.assertEqual(l['recovery_s'], 0.2)
        self.assertTrue(l['exactly_once'])
        self.assertTrue(l['completed'])
        self.assertEqual(l['growth_bytes'], l['expected_growth_bytes'])
        self.assertEqual(l['max_recovery_s'], 5.0)
        self.assertEqual(t['observed']['token_stale'], 0)

    def test_the_vision_command_carries_the_drop_and_the_bound_comes_from_config(self):
        self.cfg['loss']['max_recovery_s'] = 0.1
        r = LossFake()
        self.assertEqual(self.execute(r), 1)                    # 0.2 s recovery exceeds 0.1 s
        t = self.rec()['arms'][0]['trials'][0]
        self.assertTrue(any('recovery' in f for f in t['failures']))

    def test_unrecovered_loss_is_recorded_and_the_campaign_continues_to_the_next_trial(self):
        r = LossFake(retransmit=False)
        self.assertEqual(self.execute(r, 'two'), 1)             # nonzero exit overall
        rec = self.rec()
        self.assertEqual(len(rec['arms'][0]['trials']), 2)      # not fail-fast: the second loss trial still ran
        self.assertFalse(rec['arms'][0]['trials'][0]['ok'])
        self.assertTrue(rec['restore'])
        self.assertTrue(any('never retransmitted' in f for f in rec['arms'][0]['trials'][0]['failures']))

    def test_inexact_rule_fails_the_trial(self):
        r = LossFake(rule=dict(RULE_OK, exact=False, dropped_packets=0))
        self.assertEqual(self.execute(r), 1)
        self.assertTrue(any('not exact' in f for f in self.rec()['arms'][0]['trials'][0]['failures']))

    def test_every_loss_trial_is_its_own_cold_bring_up_and_the_switch_is_restored(self):
        r = LossFake()
        self.execute(r, 'two')
        applies = [c for _w, c in r.calls if 'bringup_composite.py' in c and '--apply' in c and not c.startswith('sha256sum')]
        self.assertEqual(len(applies), 2)
        self.assertTrue([c for _w, c in r.calls if 'launch_case4_response_path.sh' in c])


class Reconnect(Base):
    def test_c1_c2_c3_are_analysed_separately_and_recorded(self):
        r = LossFake()
        self.assertEqual(self.execute(r, scenario='reconnect'), 0)
        t = self.rec()['arms'][0]['trials'][0]
        s = t['scenario']
        self.assertTrue(t['ok'], t['failures'])
        self.assertEqual(sorted(s['connections']), ['c1', 'c2', 'c3'])
        self.assertEqual(s['connections']['c1']['resp_lens'], [58])
        self.assertEqual(s['connections']['c1']['padded'], True)
        self.assertEqual(s['connections']['c2']['resp_lens'], [37, 49])
        self.assertEqual(s['connections']['c2']['padded'], False)
        self.assertEqual(s['connections']['c3']['padded'], False)
        for c in ('c1', 'c2', 'c3'):
            self.assertIn('retransmitted', s['connections'][c])
            self.assertIn('completed', s['connections'][c])
        self.assertTrue((Path(self.tmp) / 'ev' / 'c1' / 'separate_ack' / 'combined' /
                         'c1_separate_ack_combined_t0' / 'c2' / 'timing.json').exists())

    def test_c2_padded_violates_the_native_expectation(self):
        class PaddedC2(LossFake):
            def run(self, where, cmd, **kw):
                res = super().run(where, cmd, **kw)
                return res
        r = PaddedC2()
        orig = r.write_conv

        def wc(d, reads, resp_len, **k):
            orig(d, reads, 58 if d.name == 'c2' else resp_len, **k)
        r.write_conv = wc
        self.assertEqual(self.execute(r, scenario='reconnect'), 1)
        t = self.rec()['arms'][0]['trials'][0]
        self.assertTrue(any('c2' in f and 'native' in f for f in t['failures']), t['failures'])

    def test_c3_refused_is_characterized_not_asserted(self):
        self.assertEqual(self.execute(LossFake(c3='refused'), scenario='reconnect'), 0)
        c3 = self.rec()['arms'][0]['trials'][0]['scenario']['connections']['c3']
        self.assertFalse(c3['connect_ok'])
        self.assertEqual(c3['master_rc'], 1)

    def test_c3_timeout_is_characterized_not_asserted(self):
        self.assertEqual(self.execute(LossFake(c3='timeout'), scenario='reconnect'), 0)
        c3 = self.rec()['arms'][0]['trials'][0]['scenario']['connections']['c3']
        self.assertTrue(c3['master_timeout'])

    def test_c3_padding_is_recorded_when_it_happens(self):
        r = LossFake(c3='padded')
        self.assertEqual(self.execute(r, scenario='reconnect'), 0)
        c3 = self.rec()['arms'][0]['trials'][0]['scenario']['connections']['c3']
        self.assertTrue(c3['padded'])

    def test_c1_failure_fails_the_trial(self):
        class C1Bad(LossFake):
            def run(self, where, cmd, **kw):
                res = super().run(where, cmd, **kw)
                if where == 'vision' and '--scenario' in cmd:
                    d = json.loads(res.out)
                    d['connections']['c1']['ok'] = False
                    d['ok'] = False
                    return cp.Result(1, json.dumps(d), '')
                return res
        self.assertEqual(self.execute(C1Bad(), scenario='reconnect'), 1)


if __name__ == '__main__':
    unittest.main()
