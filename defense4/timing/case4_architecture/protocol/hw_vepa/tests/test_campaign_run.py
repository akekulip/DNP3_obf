"""campaign.py `run` orchestrates the reviewed components. The ONLY thing faked is the process boundary (ssh, scp,
local subprocess): FakeRunner records every command the orchestrator emits and returns scripted results, so the
sequence, the gating and the finally-restore are the real orchestration code. A second class checks that every
flag an emitted command passes to a reviewed script really exists in that script's argparse."""
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
from test_campaign_bindings import cfg_for, H64  # noqa: E402

HWDIR = HERE.parents[2] / 'integration' / 'core' / 'response_only' / 'hw'
SNAP = {'shaping': {'ACK_HOLD': {'requested_pps': 300, 'achieved_pps': 281, 'dev_port': 68, 'qid': 6}},
        'outcomes': {'OUT_RESP_RELEASE': 20}}
GOOD_VISION = '{"ok": true, "master_rc": 0, "label": "x"}'


class FakeRunner:
    dry = False

    def __init__(self, wire_rc=0, clrt_rc=0, vision_out=GOOD_VISION, vision_rc=0, fail_on=None):
        self.calls = []
        self.wire_rc, self.clrt_rc, self.vision_out, self.vision_rc = wire_rc, clrt_rc, vision_out, vision_rc
        self.fail_on = fail_on or []                      # substrings that make a command return rc 1

    def run(self, where, cmd, cwd=None, timeout=None, label=None):
        self.calls.append((where, cmd))
        rc, out = 0, ''
        if any(s in cmd for s in self.fail_on):
            return runmod_result(1, '', 'forced failure')
        if 'sha256sum' in cmd and where == 'vision':
            if 'vision_run.py' in cmd:
                out = '%s  vision_run.py\n' % cp.sha256_file(str(HERE.parent / 'vision_run.py'))
            else:
                out = '%s  -\n' % H64
        elif 'vision_run.py run' in cmd:
            rc, out = self.vision_rc, self.vision_out
        elif cmd.startswith('scp') and '/runs/' in cmd:
            dest = Path(shlex_last(cmd))
            dest.mkdir(parents=True, exist_ok=True)
            for f in ('out.pcap', 'in.pcap'):
                (dest / f).write_bytes(b'x')
        elif cmd.startswith('scp') and 'snap/' in cmd:
            dest = Path(shlex_last(cmd))
            dest.mkdir(parents=True, exist_ok=True)
            for tok in shlex_split(cmd)[2:-1]:               # scp -q host:/path/x.json host:/path/y.json DEST
                (dest / tok.rsplit('/', 1)[1]).write_text(json.dumps(SNAP))
        elif 'wire_check.py' in cmd:
            rc = self.wire_rc
            (Path(cmd.split('--json ')[1].split()[0])).write_text('{}')
        elif 'clrt_check.py' in cmd:
            rc = self.clrt_rc
            (Path(cmd.split('--json ')[1].split()[0])).write_text('{}')
        return runmod_result(rc, out, '')

    def cmds(self, needle):
        return [i for i, (_w, c) in enumerate(self.calls) if needle in c]

    def swaps(self):
        """Indexes of the commands that actually stop/launch bf_switchd (not the scp that copies the script)."""
        return [i for i, (_w, c) in enumerate(self.calls) if c.startswith('bash ') and 'switch_swap.sh' in c]


def shlex_split(cmd):
    import shlex
    return shlex.split(cmd)


def shlex_last(cmd):
    return shlex_split(cmd)[-1]


def runmod_result(rc, out, err):
    return cp.Result(rc, out, err)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.cfg = cfg_for(Path(self.tmp) / 'b', 'match')
        (Path(self.tmp) / 'b').mkdir(exist_ok=True)
        self.cfg['evidence_dir'] = str(Path(self.tmp) / 'ev')
        self.cfg['trials']['trials_per_arm'] = 1
        self.cfg['shaping']['hold_pps']['ack'] = 300

    def campaign(self, runner, arms=('size_only', 'combined'), flags=None, cfg=None):
        return cp.Campaign(cfg or self.cfg, runner, 'c1', arms=list(arms),
                           installer_flags=(lambda f: bool(flags and f in flags)))


class Sequence(Base):
    def test_full_sequence_is_in_the_reviewed_order(self):
        r = FakeRunner()
        self.assertEqual(self.campaign(r).execute(), 0)
        order = ['vision_run.py setup', 'switch_swap.sh', 'restore_ports.py response_only', 'bringup_composite.py',
                 '--apply', 'set_enabled.py', 'snapshot_counters.py', 'vision_run.py run', 'wire_check.py',
                 'clrt_check.py', 'bringup_teardown.py', 'vision_run.py restore']
        pos = 0
        for needle in order:
            hits = [i for i in r.cmds(needle) if i >= pos]
            self.assertTrue(hits, 'missing %r after position %d' % (needle, pos))
            pos = hits[0]
        # production restore comes last: cold swap to the production launch script, then its ports
        last_swap = r.swaps()[-1]
        last_ports = r.cmds('restore_ports.py')[-1]
        self.assertIn(self.cfg['production']['launch_script'], r.calls[last_swap][1])
        self.assertIn(self.cfg['production']['program'], r.calls[last_ports][1])
        self.assertGreater(last_swap, r.cmds('bringup_teardown.py')[-1])

    def test_each_arm_has_its_own_before_and_after_snapshot_around_its_traffic(self):
        r = FakeRunner()
        self.campaign(r).execute()
        for arm in ('size_only', 'combined'):
            before = [i for i in r.cmds('c1_%s_before.json' % arm)]
            after = [i for i in r.cmds('c1_%s_after.json' % arm)]
            run = [i for i in r.cmds('vision_run.py run c1_%s_t0' % arm)]
            self.assertTrue(before and after and run, arm)
            self.assertLess(before[0], run[0])
            self.assertLess(run[0], after[0])

    def test_T_bit_per_arm_and_one_install_for_a_shared_group(self):
        r = FakeRunner()
        self.campaign(r).execute()
        sets = [r.calls[i][1] for i in r.cmds('set_enabled.py')]
        self.assertEqual([('--enabled 0' in c, '--enabled 1' in c) for c in sets], [(True, False), (False, True)])
        applies = [i for i in r.cmds('bringup_composite.py') if '--apply' in r.calls[i][1]]
        self.assertEqual(len(applies), 1)           # size_only + combined share (build, padding=1): one install
        self.assertEqual(len(r.swaps()), 2)   # one composite launch + the production restore

    def test_shaping_k_range_and_timing_reach_the_installer_and_the_snapshots(self):
        r = FakeRunner()
        self.campaign(r).execute()
        apply_cmd = r.calls[[i for i in r.cmds('bringup_composite.py') if '--apply' in r.calls[i][1]][0]][1]
        for s in ('--k 2', '--shape-ack-pps 300', '--shape-op-blk-pps 0', '--t-readiness 30000000', '--enable-pktgen',
                  'DEFENSE4_HW_AUTHORIZED=1', '--expect bfrt.json='):
            self.assertIn(s, apply_cmd)
        snap = r.calls[r.cmds('snapshot_counters.py')[0]][1]
        self.assertIn('--shape-ack-pps 300', snap)
        run = r.calls[r.cmds('vision_run.py run')[0]][1]
        self.assertIn('--range 8', run)

    def test_run_record_persists_effective_params_and_achieved_rates(self):
        r = FakeRunner()
        self.campaign(r).execute()
        rec = json.load(open(Path(self.tmp) / 'ev' / 'c1' / 'campaign_run.json'))
        self.assertTrue(rec['ok'])
        self.assertEqual(rec['effective']['k'], 2)
        self.assertEqual(rec['effective']['shaping_requested']['hold_pps']['ack'], 300)
        self.assertEqual(rec['arms'][0]['achieved_shaping']['ACK_HOLD']['achieved_pps'], 281)
        self.assertEqual(set(rec['builds']['sbo_admission_01']), {'bfrt.json', 'p0/tofino.bin', 'p1/tofino.bin'})
        self.assertEqual(rec['endpoint_observed']['binary_sha256'], H64)


class Refusals(Base):
    def test_placeholder_hash_refuses_before_any_command(self):
        cfg = cfg_for(Path(self.tmp) / 'b2', '<sha256 from manifest.json>')
        cfg['evidence_dir'] = self.cfg['evidence_dir']
        r = FakeRunner()
        self.assertEqual(self.campaign(r, cfg=cfg).execute(), 1)
        self.assertEqual(r.calls, [])

    def test_unpinned_endpoint_refuses_before_any_command(self):
        self.cfg['endpoint']['binary_sha256'] = None
        r = FakeRunner()
        self.assertEqual(self.campaign(r).execute(), 1)
        self.assertEqual(r.calls, [])

    def test_endpoint_binary_mismatch_on_vision_stops_before_the_switch_is_touched(self):
        self.cfg['endpoint']['binary_sha256'] = 'b' * 64          # Vision reports H64
        r = FakeRunner()
        self.assertEqual(self.campaign(r).execute(), 1)
        self.assertFalse([c for w, c in r.calls if w == 'switch'])
        self.assertTrue(r.cmds('vision_run.py restore'))          # the Vision setup that did happen is undone

    def test_padding_off_arm_is_refused_while_the_installer_has_no_flag(self):
        r = FakeRunner()
        rc = self.campaign(r, arms=('off', 'size_only'), flags=()).execute()
        self.assertEqual(rc, 1)
        self.assertEqual(r.calls, [])

    def test_padding_off_arm_emits_the_flag_when_the_installer_supports_it(self):
        r = FakeRunner()
        self.assertEqual(self.campaign(r, arms=('off',), flags=('--pad-enable',)).execute(), 0)
        apply_cmd = r.calls[[i for i in r.cmds('bringup_composite.py') if '--apply' in r.calls[i][1]][0]][1]
        self.assertIn('--pad-enable 0', apply_cmd)


class FailurePropagation(Base):
    def assert_restored(self, r):
        self.assertTrue(r.cmds('bringup_teardown.py'), 'composite not torn down')
        self.assertTrue(r.cmds('vision_run.py restore'), 'Vision profile not restored')
        self.assertIn(self.cfg['production']['launch_script'], r.calls[r.swaps()[-1]][1])
        self.assertIn(self.cfg['production']['program'], r.calls[r.cmds('restore_ports.py')[-1]][1])

    def test_endpoint_failure_fails_the_run_stops_the_campaign_and_restores(self):
        r = FakeRunner(vision_out='{"ok": false, "master_rc": 3}', vision_rc=1)
        self.assertEqual(self.campaign(r).execute(), 1)
        self.assert_restored(r)
        self.assertEqual(len(r.cmds('vision_run.py run')), 1)       # fail-fast: the second arm never starts
        rec = json.load(open(Path(self.tmp) / 'ev' / 'c1' / 'campaign_run.json'))
        self.assertFalse(rec['ok'])
        self.assertTrue(rec['failure'])

    def test_run_is_not_green_when_wire_check_exits_nonzero(self):
        r = FakeRunner(wire_rc=1)
        self.assertEqual(self.campaign(r).execute(), 1)
        self.assert_restored(r)
        rec = json.load(open(Path(self.tmp) / 'ev' / 'c1' / 'campaign_run.json'))
        self.assertIn('wire extractor', ' '.join(rec['arms'][0]['trials'][0]['failures']))

    def test_clrt_check_failure_fails_the_run(self):
        r = FakeRunner(clrt_rc=1)
        self.assertEqual(self.campaign(r).execute(), 1)

    def test_install_failure_still_restores_the_switch_and_vision(self):
        r = FakeRunner(fail_on=['--apply --enable-pktgen'])
        self.assertEqual(self.campaign(r).execute(), 1)
        self.assertTrue(r.cmds('vision_run.py restore'))
        self.assertIn(self.cfg['production']['launch_script'], r.calls[r.swaps()[-1]][1])
        self.assertFalse(r.cmds('vision_run.py run'))

    def test_a_failed_restore_step_fails_the_run_but_later_restore_steps_still_run(self):
        r = FakeRunner(fail_on=['bringup_teardown.py'])
        self.assertEqual(self.campaign(r).execute(), 1)             # traffic was fine; the restore was not
        self.assertTrue(r.cmds('vision_run.py restore'))
        self.assertIn(self.cfg['production']['launch_script'], r.calls[r.swaps()[-1]][1])

    def test_switch_is_not_swapped_to_production_if_it_was_never_touched(self):
        r = FakeRunner(fail_on=['pcie'])                            # fails at the first switch command? use PCI check
        self.cfg['builds']['sbo_admission_01']['pcie'] = '0000:04:00.0'
        r = FakeRunner(fail_on=['/sys/bus/pci/devices'])
        self.assertEqual(self.campaign(r).execute(), 1)
        self.assertEqual(len(r.swaps()), 0)          # daemon never stopped, nothing to restore


class DryRun(Base):
    def render(self, argv):
        buf = io.StringIO()
        real = subprocess.run
        subprocess.run = lambda *a, **k: (_ for _ in ()).throw(AssertionError('plan must not run anything'))
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
                rc = cp.main(argv)
        finally:
            subprocess.run = real
        return rc, buf.getvalue()

    def cfgfile(self):
        p = Path(self.tmp) / 'cfg.json'
        p.write_text(json.dumps(self.cfg))
        return str(p)

    def test_plan_prints_the_exact_commands_and_runs_none(self):
        rc, out = self.render(['plan', '--config', self.cfgfile(), '--arms', 'combined', '--run-id', 'c1'])
        self.assertEqual(rc, 0)
        for s in ('switch_swap.sh', 'restore_ports.py response_only', 'bringup_composite.py', '--enabled 1',
                  'snapshot_counters.py', 'vision_run.py run c1_combined_t0', 'wire_check.py', 'clrt_check.py',
                  'bringup_teardown.py', 'vision_run.py restore', self.cfg['production']['launch_script']):
            self.assertIn(s, out)

    def test_run_dry_run_is_the_same_as_plan(self):
        a = self.render(['plan', '--config', self.cfgfile(), '--arms', 'combined', '--run-id', 'c1'])
        b = self.render(['run', '--dry-run', '--config', self.cfgfile(), '--arms', 'combined', '--run-id', 'c1'])
        self.assertEqual(a, b)

    def test_padding_off_arm_plans_with_the_installers_pad_enable_flag(self):
        rc, out = self.render(['plan', '--config', self.cfgfile(), '--arms', 'off', '--run-id', 'c1'])
        self.assertEqual(rc, 0)
        self.assertIn('--pad-enable 0', out)
        self.assertNotIn('BLOCKED', out)         # the installer now has the flag, so nothing blocks the arm

    def test_a_genuinely_blocked_arm_is_still_flagged_when_the_installer_lacks_the_flag(self):
        real = cp.default_installer_flags
        cp.default_installer_flags = lambda flag: False        # an installer source without --pad-enable
        try:
            rc, out = self.render(['plan', '--config', self.cfgfile(), '--arms', 'off', '--run-id', 'c1'])
        finally:
            cp.default_installer_flags = real
        self.assertIn('BLOCKED', out)
        self.assertIn('--pad-enable', out)
        self.assertNotIn('--pad-enable 0', out)

    def test_run_still_needs_apply_and_authorization(self):
        with self.assertRaises(SystemExit):
            cp.main(['run', '--config', self.cfgfile()])


class EmittedFlagsExist(Base):
    """Every `--flag` an emitted command hands to a reviewed script must exist in that script's argparse."""
    def help_flags(self, script):
        r = subprocess.run([sys.executable, str(script), '--help'], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr[-400:])
        return set(re.findall(r'--[a-z0-9][a-z0-9-]*', r.stdout))

    def source_flags(self, script):
        return set(re.findall(r'''add_argument\(\s*["'](--[a-z0-9-]+)''', Path(script).read_text()))

    def test_flags_passed_to_reviewed_scripts_are_real(self):
        self.cfg['shaping']['block_pps']['resp'] = 40
        self.cfg['shaping']['block_burst'] = 96
        r = FakeRunner()
        self.campaign(r, arms=('off', 'combined'), flags=('--pad-enable',)).execute()
        known = {
            'bringup_composite.py': self.help_flags(HWDIR / 'bringup_composite.py') | {'--pad-enable'},
            'snapshot_counters.py': self.help_flags(HWDIR / 'snapshot_counters.py'),
            'set_enabled.py': self.help_flags(HWDIR / 'set_enabled.py'),
            'bringup_teardown.py': self.help_flags(HWDIR / 'bringup_teardown.py'),
            'make_conf.py': self.help_flags(HWDIR / 'make_conf.py'),
            'vision_run.py': self.help_flags(HERE.parent / 'vision_run.py'),
            'wire_check.py': self.help_flags(HERE.parent / 'wire_check.py'),
            'clrt_check.py': self.help_flags(HERE.parent / 'clrt_check.py'),
            'restore_ports.py': self.source_flags(HERE.parents[3] / 'framework' / 'control' / 'restore_ports.py'),
        }
        checked = set()
        for _w, cmd in r.calls:
            for script, flags in known.items():
                if script in cmd:
                    checked.add(script)
                    for f in re.findall(r'(?<=\s)--[a-z0-9][a-z0-9-]*', cmd.split(script, 1)[1]):
                        self.assertIn(f, flags, '%s does not accept %s (in: %s)' % (script, f, cmd))
        self.assertEqual(checked, set(known))               # every reviewed script was actually exercised


if __name__ == '__main__':
    unittest.main()
